/*
 * livepatch_bsc1258073
 *
 * Fix for CVE-2025-38375, bsc#1258073
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


/* klp-ccp: from drivers/net/virtio_net.c */
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <linux/filter.h>
#include <linux/kernel.h>

#include <net/xdp.h>

#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN	128

#define VIRTNET_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

#define VIRTIO_XDP_HEADROOM 256

#define VIRTIO_XDP_TX		BIT(0)
#define VIRTIO_XDP_REDIR	BIT(1)

DECLARE_EWMA(pkt_len, 0, 64)

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64_stats_t packets;
	u64_stats_t bytes;
	u64_stats_t drops;
	u64_stats_t xdp_packets;
	u64_stats_t xdp_tx;
	u64_stats_t xdp_redirects;
	u64_stats_t xdp_drops;
	u64_stats_t kicks;
};

struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	unsigned int min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[16];

	struct xdp_rxq_info xdp_rxq;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* # of XDP queue pairs currently used by the driver */
	u16 xdp_queue_pairs;

	/* xdp_queue_pairs may be 0, when xdp is already loaded. So add this. */
	bool xdp_enabled;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* number of sg entries allocated for big packets */
	unsigned int big_packets_num_skbfrags;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Host supports rss and/or hash report */
	bool has_rss;
	bool has_rss_hash_report;
	u8 rss_key_size;
	u16 rss_indir_table_size;
	u32 rss_hash_types_supported;
	u32 rss_hash_types_saved;

	/* Has control virtqueue */
	bool has_cvq;

	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;

	/* Packet virtio header size */
	u8 hdr_len;

	/* Work struct for delayed refilling if we run low on memory. */
	struct delayed_work refill;

	/* Is delayed refill enabled? */
	bool refill_enabled;

	/* The lock to synchronize the access to refill_enabled */
	spinlock_t refill_lock;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;

	struct control_buf *ctrl;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;

	/* Interrupt coalescing settings */
	u32 tx_usecs;
	u32 rx_usecs;
	u32 tx_max_packets;
	u32 rx_max_packets;

	unsigned long guest_offloads;
	unsigned long guest_offloads_capable;

	/* failover when STANDBY feature enabled */
	struct failover *failover;
};

struct padded_vnet_hdr {
	struct virtio_net_hdr_v1_hash hdr;
	/*
	 * hdr is in a separate sg buffer, and data sg buffer shares same page
	 * with this header sg. This padding makes next sg 16 byte aligned
	 * after the header.
	 */
	char padding[12];
};

extern void virtnet_rq_free_unused_buf(struct virtqueue *vq, void *buf);

static int vq2rxq(struct virtqueue *vq)
{
	return vq->index / 2;
}

/* klp-ccp: from drivers/net/virtio_net.c */
static inline struct virtio_net_hdr_mrg_rxbuf *skb_vnet_hdr(struct sk_buff *skb)
{
	return (struct virtio_net_hdr_mrg_rxbuf *)skb->cb;
}

static void give_pages(struct receive_queue *rq, struct page *page)
{
	struct page *end;

	/* Find end of list, sew whole thing into vi->rq.pages. */
	for (end = page; end->private; end = (struct page *)end->private);
	end->private = (unsigned long)rq->pages;
	rq->pages = page;
}

#define MRG_CTX_HEADER_SHIFT 22

static unsigned int mergeable_ctx_to_headroom(void *mrg_ctx)
{
	return (unsigned long)mrg_ctx >> MRG_CTX_HEADER_SHIFT;
}

static unsigned int mergeable_ctx_to_truesize(void *mrg_ctx)
{
	return (unsigned long)mrg_ctx & ((1 << MRG_CTX_HEADER_SHIFT) - 1);
}

static int check_mergeable_len(struct net_device *dev, void *mrg_ctx,
			       unsigned int len)
{
	unsigned int headroom, tailroom, room, truesize;

	truesize = mergeable_ctx_to_truesize(mrg_ctx);
	headroom = mergeable_ctx_to_headroom(mrg_ctx);
	tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
	room = SKB_DATA_ALIGN(headroom + tailroom);

	if (len > truesize - room) {
		pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
			 dev->name, len, (unsigned long)(truesize - room));
		DEV_STATS_INC(dev, rx_length_errors);
		return -1;
	}

	return 0;
}

static struct sk_buff *page_to_skb(struct virtnet_info *vi,
				   struct receive_queue *rq,
				   struct page *page, unsigned int offset,
				   unsigned int len, unsigned int truesize,
				   unsigned int headroom)
{
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	unsigned int copy, hdr_len, hdr_padded_len;
	struct page *page_to_free = NULL;
	int tailroom, shinfo_size;
	char *p, *hdr_p, *buf;

	p = page_address(page) + offset;
	hdr_p = p;

	hdr_len = vi->hdr_len;
	if (vi->mergeable_rx_bufs)
		hdr_padded_len = hdr_len;
	else
		hdr_padded_len = sizeof(struct padded_vnet_hdr);

	buf = p - headroom;
	len -= hdr_len;
	offset += hdr_padded_len;
	p += hdr_padded_len;
	tailroom = truesize - headroom  - hdr_padded_len - len;

	shinfo_size = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));

	/* copy small packet so we can reuse these pages */
	if (!NET_IP_ALIGN && len > GOOD_COPY_LEN && tailroom >= shinfo_size) {
		skb = build_skb(buf, truesize);
		if (unlikely(!skb))
			return NULL;

		skb_reserve(skb, p - buf);
		skb_put(skb, len);

		page = (struct page *)page->private;
		if (page)
			give_pages(rq, page);
		goto ok;
	}

	/* copy small packet so we can reuse these pages for small data */
	skb = napi_alloc_skb(&rq->napi, GOOD_COPY_LEN);
	if (unlikely(!skb))
		return NULL;

	/* Copy all frame if it fits skb->head, otherwise
	 * we let virtio_net_hdr_to_skb() and GRO pull headers as needed.
	 */
	if (len <= skb_tailroom(skb))
		copy = len;
	else
		copy = ETH_HLEN;
	skb_put_data(skb, p, copy);

	len -= copy;
	offset += copy;

	if (vi->mergeable_rx_bufs) {
		if (len)
			skb_add_rx_frag(skb, 0, page, offset, len, truesize);
		else
			page_to_free = page;
		goto ok;
	}

	/*
	 * Verify that we can indeed put this data into a skb.
	 * This is here to handle cases when the device erroneously
	 * tries to receive more than is possible. This is usually
	 * the case of a broken device.
	 */
	if (unlikely(len > MAX_SKB_FRAGS * PAGE_SIZE)) {
		net_dbg_ratelimited("%s: too much data\n", skb->dev->name);
		dev_kfree_skb(skb);
		return NULL;
	}
	BUG_ON(offset >= PAGE_SIZE);
	while (len) {
		unsigned int frag_size = min((unsigned)PAGE_SIZE - offset, len);
		skb_add_rx_frag(skb, skb_shinfo(skb)->nr_frags, page, offset,
				frag_size, truesize);
		len -= frag_size;
		page = (struct page *)page->private;
		offset = 0;
	}

	if (page)
		give_pages(rq, page);

ok:
	hdr = skb_vnet_hdr(skb);
	memcpy(hdr, hdr_p, hdr_len);
	if (page_to_free)
		put_page(page_to_free);

	return skb;
}

extern int virtnet_xdp_xmit(struct net_device *dev,
			    int n, struct xdp_frame **frames, u32 flags);

static unsigned int virtnet_get_headroom(struct virtnet_info *vi)
{
	return vi->xdp_enabled ? VIRTIO_XDP_HEADROOM : 0;
}

static struct page *xdp_linearize_page(struct net_device *dev,
				       struct receive_queue *rq,
				       int *num_buf,
				       struct page *p,
				       int offset,
				       int page_off,
				       unsigned int *len)
{
	int tailroom = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	struct page *page;

	if (page_off + *len + tailroom > PAGE_SIZE)
		return NULL;

	page = alloc_page(GFP_ATOMIC);
	if (!page)
		return NULL;

	memcpy(page_address(page) + page_off, page_address(p) + offset, *len);
	page_off += *len;

	/* Only mergeable mode can go inside this while loop. In small mode,
	 * *num_buf == 1, so it cannot go inside.
	 */
	while (--*num_buf) {
		unsigned int buflen;
		void *buf;
		void *ctx;
		int off;

		buf = virtqueue_get_buf_ctx(rq->vq, &buflen, &ctx);
		if (unlikely(!buf))
			goto err_buf;

		p = virt_to_head_page(buf);
		off = buf - page_address(p);

		if (check_mergeable_len(dev, ctx, buflen)) {
			put_page(p);
			goto err_buf;
		}

		/* guard against a misconfigured or uncooperative backend that
		 * is sending packet larger than the MTU.
		 */
		if ((page_off + buflen + tailroom) > PAGE_SIZE) {
			put_page(p);
			goto err_buf;
		}

		memcpy(page_address(page) + page_off,
		       page_address(p) + off, buflen);
		page_off += buflen;
		put_page(p);
	}

	/* Headroom does not contribute to packet length */
	*len = page_off - VIRTIO_XDP_HEADROOM;
	return page;
err_buf:
	__free_pages(page, 0);
	return NULL;
}

static struct sk_buff *receive_small(struct net_device *dev,
				     struct virtnet_info *vi,
				     struct receive_queue *rq,
				     void *buf, void *ctx,
				     unsigned int len,
				     unsigned int *xdp_xmit,
				     struct virtnet_rq_stats *stats)
{
	struct sk_buff *skb;
	struct bpf_prog *xdp_prog;
	unsigned int xdp_headroom = (unsigned long)ctx;
	unsigned int header_offset = VIRTNET_RX_PAD + xdp_headroom;
	unsigned int headroom = vi->hdr_len + header_offset;
	unsigned int buflen = SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
			      SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	struct page *page = virt_to_head_page(buf);
	unsigned int delta = 0;
	struct page *xdp_page;
	int err;
	unsigned int metasize = 0;

	len -= vi->hdr_len;
	u64_stats_add(&stats->bytes, len);

	if (unlikely(len > GOOD_PACKET_LEN)) {
		pr_debug("%s: rx error: len %u exceeds max size %d\n",
			 dev->name, len, GOOD_PACKET_LEN);
		DEV_STATS_INC(dev, rx_length_errors);
		goto err;
	}

	if (likely(!vi->xdp_enabled)) {
		xdp_prog = NULL;
		goto skip_xdp;
	}

	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		struct virtio_net_hdr_mrg_rxbuf *hdr = buf + header_offset;
		struct xdp_frame *xdpf;
		struct xdp_buff xdp;
		void *orig_data;
		u32 act;

		if (unlikely(hdr->hdr.gso_type))
			goto err_xdp;

		/* Partially checksummed packets must be dropped. */
		if (unlikely(hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
			goto err_xdp;

		if (unlikely(xdp_headroom < virtnet_get_headroom(vi))) {
			int offset = buf - page_address(page) + header_offset;
			unsigned int tlen = len + vi->hdr_len;
			int num_buf = 1;

			xdp_headroom = virtnet_get_headroom(vi);
			header_offset = VIRTNET_RX_PAD + xdp_headroom;
			headroom = vi->hdr_len + header_offset;
			buflen = SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
				 SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
			xdp_page = xdp_linearize_page(dev, rq, &num_buf, page,
						      offset, header_offset,
						      &tlen);
			if (!xdp_page)
				goto err_xdp;

			buf = page_address(xdp_page);
			put_page(page);
			page = xdp_page;
		}

		xdp_init_buff(&xdp, buflen, &rq->xdp_rxq);
		xdp_prepare_buff(&xdp, buf + VIRTNET_RX_PAD + vi->hdr_len,
				 xdp_headroom, len, true);
		orig_data = xdp.data;
		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		u64_stats_inc(&stats->xdp_packets);

		switch (act) {
		case XDP_PASS:
			/* Recalculate length in case bpf program changed it */
			delta = orig_data - xdp.data;
			len = xdp.data_end - xdp.data;
			metasize = xdp.data - xdp.data_meta;
			break;
		case XDP_TX:
			u64_stats_inc(&stats->xdp_tx);
			xdpf = xdp_convert_buff_to_frame(&xdp);
			if (unlikely(!xdpf))
				goto err_xdp;
			err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
			if (unlikely(!err)) {
				xdp_return_frame_rx_napi(xdpf);
			} else if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			u64_stats_inc(&stats->xdp_redirects);
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err)
				goto err_xdp;
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(vi->dev, xdp_prog, act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
			goto err_xdp;
		case XDP_DROP:
			goto err_xdp;
		}
	}
	rcu_read_unlock();

skip_xdp:
	skb = build_skb(buf, buflen);
	if (!skb)
		goto err;
	skb_reserve(skb, headroom - delta);
	skb_put(skb, len);
	if (!xdp_prog) {
		buf += header_offset;
		memcpy(skb_vnet_hdr(skb), buf, vi->hdr_len);
	} /* keep zeroed vnet hdr since XDP is loaded */

	if (metasize)
		skb_metadata_set(skb, metasize);

	return skb;

err_xdp:
	rcu_read_unlock();
	u64_stats_inc(&stats->xdp_drops);
err:
	u64_stats_inc(&stats->drops);
	put_page(page);
xdp_xmit:
	return NULL;
}

static struct sk_buff *receive_big(struct net_device *dev,
				   struct virtnet_info *vi,
				   struct receive_queue *rq,
				   void *buf,
				   unsigned int len,
				   struct virtnet_rq_stats *stats)
{
	struct page *page = buf;
	struct sk_buff *skb =
		page_to_skb(vi, rq, page, 0, len, PAGE_SIZE, 0);

	u64_stats_add(&stats->bytes, len - vi->hdr_len);
	if (unlikely(!skb))
		goto err;

	return skb;

err:
	u64_stats_inc(&stats->drops);
	give_pages(rq, page);
	return NULL;
}

static struct sk_buff *build_skb_from_xdp_buff(struct net_device *dev,
					       struct virtnet_info *vi,
					       struct xdp_buff *xdp,
					       unsigned int xdp_frags_truesz)
{
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	unsigned int headroom, data_len;
	struct sk_buff *skb;
	int metasize;
	u8 nr_frags;

	if (unlikely(xdp->data_end > xdp_data_hard_end(xdp))) {
		pr_debug("Error building skb as missing reserved tailroom for xdp");
		return NULL;
	}

	if (unlikely(xdp_buff_has_frags(xdp)))
		nr_frags = sinfo->nr_frags;

	skb = build_skb(xdp->data_hard_start, xdp->frame_sz);
	if (unlikely(!skb))
		return NULL;

	headroom = xdp->data - xdp->data_hard_start;
	data_len = xdp->data_end - xdp->data;
	skb_reserve(skb, headroom);
	__skb_put(skb, data_len);

	metasize = xdp->data - xdp->data_meta;
	metasize = metasize > 0 ? metasize : 0;
	if (metasize)
		skb_metadata_set(skb, metasize);

	if (unlikely(xdp_buff_has_frags(xdp)))
		xdp_update_skb_shared_info(skb, nr_frags,
					   sinfo->xdp_frags_size,
					   xdp_frags_truesz,
					   xdp_buff_is_frag_pfmemalloc(xdp));

	return skb;
}

static int virtnet_build_xdp_buff_mrg(struct net_device *dev,
				      struct virtnet_info *vi,
				      struct receive_queue *rq,
				      struct xdp_buff *xdp,
				      void *buf,
				      unsigned int len,
				      unsigned int frame_sz,
				      int *num_buf,
				      unsigned int *xdp_frags_truesize,
				      struct virtnet_rq_stats *stats)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr = buf;
	unsigned int headroom, tailroom, room;
	unsigned int truesize, cur_frag_size;
	struct skb_shared_info *shinfo;
	unsigned int xdp_frags_truesz = 0;
	struct page *page;
	skb_frag_t *frag;
	int offset;
	void *ctx;

	xdp_init_buff(xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(xdp, buf - VIRTIO_XDP_HEADROOM,
			 VIRTIO_XDP_HEADROOM + vi->hdr_len, len - vi->hdr_len, true);

	if (!*num_buf)
		return 0;

	if (*num_buf > 1) {
		/* If we want to build multi-buffer xdp, we need
		 * to specify that the flags of xdp_buff have the
		 * XDP_FLAGS_HAS_FRAG bit.
		 */
		if (!xdp_buff_has_frags(xdp))
			xdp_buff_set_frags_flag(xdp);

		shinfo = xdp_get_shared_info_from_buff(xdp);
		shinfo->nr_frags = 0;
		shinfo->xdp_frags_size = 0;
	}

	if (*num_buf > MAX_SKB_FRAGS + 1)
		return -EINVAL;

	while (--*num_buf > 0) {
		buf = virtqueue_get_buf_ctx(rq->vq, &len, &ctx);
		if (unlikely(!buf)) {
			pr_debug("%s: rx error: %d buffers out of %d missing\n",
				 dev->name, *num_buf,
				 virtio16_to_cpu(vi->vdev, hdr->num_buffers));
			DEV_STATS_INC(dev, rx_length_errors);
			return -EINVAL;
		}

		u64_stats_add(&stats->bytes, len);
		page = virt_to_head_page(buf);
		offset = buf - page_address(page);

		truesize = mergeable_ctx_to_truesize(ctx);
		headroom = mergeable_ctx_to_headroom(ctx);
		tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
		room = SKB_DATA_ALIGN(headroom + tailroom);

		cur_frag_size = truesize;
		xdp_frags_truesz += cur_frag_size;
		if (unlikely(len > truesize - room || cur_frag_size > PAGE_SIZE)) {
			put_page(page);
			pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
				 dev->name, len, (unsigned long)(truesize - room));
			DEV_STATS_INC(dev, rx_length_errors);
			return -EINVAL;
		}

		frag = &shinfo->frags[shinfo->nr_frags++];
		skb_frag_fill_page_desc(frag, page, offset, len);
		if (page_is_pfmemalloc(page))
			xdp_buff_set_frag_pfmemalloc(xdp);

		shinfo->xdp_frags_size += len;
	}

	*xdp_frags_truesize = xdp_frags_truesz;
	return 0;
}

static struct sk_buff *receive_mergeable(struct net_device *dev,
					 struct virtnet_info *vi,
					 struct receive_queue *rq,
					 void *buf,
					 void *ctx,
					 unsigned int len,
					 unsigned int *xdp_xmit,
					 struct virtnet_rq_stats *stats)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr = buf;
	int num_buf = virtio16_to_cpu(vi->vdev, hdr->num_buffers);
	struct page *page = virt_to_head_page(buf);
	int offset = buf - page_address(page);
	struct sk_buff *head_skb, *curr_skb;
	struct bpf_prog *xdp_prog;
	unsigned int truesize = mergeable_ctx_to_truesize(ctx);
	unsigned int headroom = mergeable_ctx_to_headroom(ctx);
	unsigned int tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
	unsigned int room = SKB_DATA_ALIGN(headroom + tailroom);
	unsigned int frame_sz, xdp_room;
	int err;

	head_skb = NULL;
	u64_stats_add(&stats->bytes, len - vi->hdr_len);

	if (unlikely(len > truesize - room)) {
		pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
			 dev->name, len, (unsigned long)(truesize - room));
		DEV_STATS_INC(dev, rx_length_errors);
		goto err_skb;
	}

	if (likely(!vi->xdp_enabled)) {
		xdp_prog = NULL;
		goto skip_xdp;
	}

	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		unsigned int xdp_frags_truesz = 0;
		struct skb_shared_info *shinfo;
		struct xdp_frame *xdpf;
		struct page *xdp_page;
		struct xdp_buff xdp;
		void *data;
		u32 act;
		int i;

		/* Transient failure which in theory could occur if
		 * in-flight packets from before XDP was enabled reach
		 * the receive path after XDP is loaded.
		 */
		if (unlikely(hdr->hdr.gso_type))
			goto err_xdp;

		/* Partially checksummed packets must be dropped. */
		if (unlikely(hdr->hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
			goto err_xdp;

		/* Now XDP core assumes frag size is PAGE_SIZE, but buffers
		 * with headroom may add hole in truesize, which
		 * make their length exceed PAGE_SIZE. So we disabled the
		 * hole mechanism for xdp. See add_recvbuf_mergeable().
		 */
		frame_sz = truesize;

		/* This happens when headroom is not enough because
		 * of the buffer was prefilled before XDP is set.
		 * This should only happen for the first several packets.
		 * In fact, vq reset can be used here to help us clean up
		 * the prefilled buffers, but many existing devices do not
		 * support it, and we don't want to bother users who are
		 * using xdp normally.
		 */
		if (!xdp_prog->aux->xdp_has_frags &&
		    (num_buf > 1 || headroom < virtnet_get_headroom(vi))) {
			/* linearize data for XDP */
			xdp_page = xdp_linearize_page(vi->dev, rq, &num_buf,
						      page, offset,
						      VIRTIO_XDP_HEADROOM,
						      &len);
			frame_sz = PAGE_SIZE;

			if (!xdp_page)
				goto err_xdp;
			offset = VIRTIO_XDP_HEADROOM;
		} else if (unlikely(headroom < virtnet_get_headroom(vi))) {
			xdp_room = SKB_DATA_ALIGN(VIRTIO_XDP_HEADROOM +
						  sizeof(struct skb_shared_info));
			if (len + xdp_room > PAGE_SIZE)
				goto err_xdp;

			xdp_page = alloc_page(GFP_ATOMIC);
			if (!xdp_page)
				goto err_xdp;

			memcpy(page_address(xdp_page) + VIRTIO_XDP_HEADROOM,
			       page_address(page) + offset, len);
			frame_sz = PAGE_SIZE;
			offset = VIRTIO_XDP_HEADROOM;
		} else {
			xdp_page = page;
		}

		data = page_address(xdp_page) + offset;
		err = virtnet_build_xdp_buff_mrg(dev, vi, rq, &xdp, data, len, frame_sz,
						 &num_buf, &xdp_frags_truesz, stats);
		if (unlikely(err))
			goto err_xdp_frags;

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		u64_stats_inc(&stats->xdp_packets);

		switch (act) {
		case XDP_PASS:
			head_skb = build_skb_from_xdp_buff(dev, vi, &xdp, xdp_frags_truesz);
			if (unlikely(!head_skb))
				goto err_xdp_frags;

			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			return head_skb;
		case XDP_TX:
			u64_stats_inc(&stats->xdp_tx);
			xdpf = xdp_convert_buff_to_frame(&xdp);
			if (unlikely(!xdpf)) {
				netdev_dbg(dev, "convert buff to frame failed for xdp\n");
				goto err_xdp_frags;
			}
			err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
			if (unlikely(!err)) {
				xdp_return_frame_rx_napi(xdpf);
			} else if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				goto err_xdp_frags;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			u64_stats_inc(&stats->xdp_redirects);
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err)
				goto err_xdp_frags;
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(vi->dev, xdp_prog, act);
			fallthrough;
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
			fallthrough;
		case XDP_DROP:
			goto err_xdp_frags;
		}
err_xdp_frags:
		if (unlikely(xdp_page != page))
			__free_pages(xdp_page, 0);

		if (xdp_buff_has_frags(&xdp)) {
			shinfo = xdp_get_shared_info_from_buff(&xdp);
			for (i = 0; i < shinfo->nr_frags; i++) {
				xdp_page = skb_frag_page(&shinfo->frags[i]);
				put_page(xdp_page);
			}
		}

		goto err_xdp;
	}
	rcu_read_unlock();

skip_xdp:
	head_skb = page_to_skb(vi, rq, page, offset, len, truesize, headroom);
	curr_skb = head_skb;

	if (unlikely(!curr_skb))
		goto err_skb;
	while (--num_buf) {
		int num_skb_frags;

		buf = virtqueue_get_buf_ctx(rq->vq, &len, &ctx);
		if (unlikely(!buf)) {
			pr_debug("%s: rx error: %d buffers out of %d missing\n",
				 dev->name, num_buf,
				 virtio16_to_cpu(vi->vdev,
						 hdr->num_buffers));
			DEV_STATS_INC(dev, rx_length_errors);
			goto err_buf;
		}

		u64_stats_add(&stats->bytes, len);
		page = virt_to_head_page(buf);

		truesize = mergeable_ctx_to_truesize(ctx);
		headroom = mergeable_ctx_to_headroom(ctx);
		tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
		room = SKB_DATA_ALIGN(headroom + tailroom);
		if (unlikely(len > truesize - room)) {
			pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
				 dev->name, len, (unsigned long)(truesize - room));
			DEV_STATS_INC(dev, rx_length_errors);
			goto err_skb;
		}

		num_skb_frags = skb_shinfo(curr_skb)->nr_frags;
		if (unlikely(num_skb_frags == MAX_SKB_FRAGS)) {
			struct sk_buff *nskb = alloc_skb(0, GFP_ATOMIC);

			if (unlikely(!nskb))
				goto err_skb;
			if (curr_skb == head_skb)
				skb_shinfo(curr_skb)->frag_list = nskb;
			else
				curr_skb->next = nskb;
			curr_skb = nskb;
			head_skb->truesize += nskb->truesize;
			num_skb_frags = 0;
		}
		if (curr_skb != head_skb) {
			head_skb->data_len += len;
			head_skb->len += len;
			head_skb->truesize += truesize;
		}
		offset = buf - page_address(page);
		if (skb_can_coalesce(curr_skb, num_skb_frags, page, offset)) {
			put_page(page);
			skb_coalesce_rx_frag(curr_skb, num_skb_frags - 1,
					     len, truesize);
		} else {
			skb_add_rx_frag(curr_skb, num_skb_frags, page,
					offset, len, truesize);
		}
	}

	ewma_pkt_len_add(&rq->mrg_avg_pkt_len, head_skb->len);
	return head_skb;

err_xdp:
	rcu_read_unlock();
	u64_stats_inc(&stats->xdp_drops);
err_skb:
	put_page(page);
	while (num_buf-- > 1) {
		buf = virtqueue_get_buf(rq->vq, &len);
		if (unlikely(!buf)) {
			pr_debug("%s: rx error: %d buffers missing\n",
				 dev->name, num_buf);
			DEV_STATS_INC(dev, rx_length_errors);
			break;
		}
		u64_stats_add(&stats->bytes, len);
		page = virt_to_head_page(buf);
		put_page(page);
	}
err_buf:
	u64_stats_inc(&stats->drops);
	dev_kfree_skb(head_skb);
xdp_xmit:
	return NULL;
}

static void virtio_skb_set_hash(const struct virtio_net_hdr_v1_hash *hdr_hash,
				struct sk_buff *skb)
{
	enum pkt_hash_types rss_hash_type;

	if (!hdr_hash || !skb)
		return;

	switch (__le16_to_cpu(hdr_hash->hash_report)) {
	case VIRTIO_NET_HASH_REPORT_TCPv4:
	case VIRTIO_NET_HASH_REPORT_UDPv4:
	case VIRTIO_NET_HASH_REPORT_TCPv6:
	case VIRTIO_NET_HASH_REPORT_UDPv6:
	case VIRTIO_NET_HASH_REPORT_TCPv6_EX:
	case VIRTIO_NET_HASH_REPORT_UDPv6_EX:
		rss_hash_type = PKT_HASH_TYPE_L4;
		break;
	case VIRTIO_NET_HASH_REPORT_IPv4:
	case VIRTIO_NET_HASH_REPORT_IPv6:
	case VIRTIO_NET_HASH_REPORT_IPv6_EX:
		rss_hash_type = PKT_HASH_TYPE_L3;
		break;
	case VIRTIO_NET_HASH_REPORT_NONE:
	default:
		rss_hash_type = PKT_HASH_TYPE_NONE;
	}
	skb_set_hash(skb, __le32_to_cpu(hdr_hash->hash_value), rss_hash_type);
}

void klpp_receive_buf(struct virtnet_info *vi, struct receive_queue *rq,
			void *buf, unsigned int len, void **ctx,
			unsigned int *xdp_xmit,
			struct virtnet_rq_stats *stats)
{
	struct net_device *dev = vi->dev;
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	u8 flags;

	if (unlikely(len < vi->hdr_len + ETH_HLEN)) {
		pr_debug("%s: short packet %i\n", dev->name, len);
		DEV_STATS_INC(dev, rx_length_errors);
		virtnet_rq_free_unused_buf(rq->vq, buf);
		return;
	}

	/* 1. Save the flags early, as the XDP program might overwrite them.
	 * These flags ensure packets marked as VIRTIO_NET_HDR_F_DATA_VALID
	 * stay valid after XDP processing.
	 * 2. XDP doesn't work with partially checksummed packets (refer to
	 * virtnet_xdp_set()), so packets marked as
	 * VIRTIO_NET_HDR_F_NEEDS_CSUM get dropped during XDP processing.
	 */
	flags = ((struct virtio_net_hdr_mrg_rxbuf *)buf)->hdr.flags;

	if (vi->mergeable_rx_bufs)
		skb = receive_mergeable(dev, vi, rq, buf, ctx, len, xdp_xmit,
					stats);
	else if (vi->big_packets)
		skb = receive_big(dev, vi, rq, buf, len, stats);
	else
		skb = receive_small(dev, vi, rq, buf, ctx, len, xdp_xmit, stats);

	if (unlikely(!skb))
		return;

	hdr = skb_vnet_hdr(skb);
	if (dev->features & NETIF_F_RXHASH && vi->has_rss_hash_report)
		virtio_skb_set_hash((const struct virtio_net_hdr_v1_hash *)hdr, skb);

	if (flags & VIRTIO_NET_HDR_F_DATA_VALID)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (virtio_net_hdr_to_skb(skb, &hdr->hdr,
				  virtio_is_little_endian(vi->vdev))) {
		net_warn_ratelimited("%s: bad gso: type: %u, size: %u\n",
				     dev->name, hdr->hdr.gso_type,
				     hdr->hdr.gso_size);
		goto frame_err;
	}

	skb_record_rx_queue(skb, vq2rxq(rq->vq));
	skb->protocol = eth_type_trans(skb, dev);
	pr_debug("Receiving skb proto 0x%04x len %i type %i\n",
		 ntohs(skb->protocol), skb->len, skb->pkt_type);

	napi_gro_receive(&rq->napi, skb);
	return;

frame_err:
	DEV_STATS_INC(dev, rx_frame_errors);
	dev_kfree_skb(skb);
}

void virtnet_rq_free_unused_buf(struct virtqueue *vq, void *buf);


#include "livepatch_bsc1258073.h"

#include <linux/livepatch.h>

extern typeof(virtnet_rq_free_unused_buf) virtnet_rq_free_unused_buf
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_rq_free_unused_buf);
extern typeof(virtnet_xdp_xmit) virtnet_xdp_xmit
	 KLP_RELOC_SYMBOL(virtio_net, virtio_net, virtnet_xdp_xmit);
