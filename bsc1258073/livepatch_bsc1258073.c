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
#include <linux/ethtool.h>

#include <linux/virtio.h>
#include <linux/virtio_net.h>

/* klp-ccp: from drivers/net/virtio_net.c */
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>

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
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 xdp_packets;
	u64 xdp_tx;
	u64 xdp_redirects;
	u64 xdp_drops;
	u64 kicks;
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
	char name[40];

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

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

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

	unsigned long guest_offloads;

	/* failover when STANDBY feature enabled */
	struct failover *failover;
};

struct padded_vnet_hdr {
	struct virtio_net_hdr_mrg_rxbuf hdr;
	/*
	 * hdr is in a separate sg buffer, and data sg buffer shares same page
	 * with this header sg. This padding makes next sg 16 byte aligned
	 * after the header.
	 */
	char padding[4];
};

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
		dev->stats.rx_length_errors++;
		return -1;
	}

	return 0;
}

static struct sk_buff *page_to_skb(struct virtnet_info *vi,
				   struct receive_queue *rq,
				   struct page *page, unsigned int offset,
				   unsigned int len, unsigned int truesize,
				   bool hdr_valid)
{
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;
	unsigned int copy, hdr_len, hdr_padded_len;
	char *p;

	p = page_address(page) + offset;

	/* copy small packet so we can reuse these pages for small data */
	skb = napi_alloc_skb(&rq->napi, GOOD_COPY_LEN);
	if (unlikely(!skb))
		return NULL;

	hdr = skb_vnet_hdr(skb);

	hdr_len = vi->hdr_len;
	if (vi->mergeable_rx_bufs)
		hdr_padded_len = sizeof(*hdr);
	else
		hdr_padded_len = sizeof(struct padded_vnet_hdr);

	if (hdr_valid)
		memcpy(hdr, p, hdr_len);

	len -= hdr_len;
	offset += hdr_padded_len;
	p += hdr_padded_len;

	copy = len;
	if (copy > skb_tailroom(skb))
		copy = skb_tailroom(skb);
	skb_put_data(skb, p, copy);

	len -= copy;
	offset += copy;

	if (vi->mergeable_rx_bufs) {
		if (len)
			skb_add_rx_frag(skb, 0, page, offset, len, truesize);
		else
			put_page(page);
		return skb;
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

	return skb;
}

static int (*klpe_virtnet_xdp_xmit)(struct net_device *dev,
			    int n, struct xdp_frame **frames, u32 flags);

static unsigned int virtnet_get_headroom(struct virtnet_info *vi)
{
	return vi->xdp_queue_pairs ? VIRTIO_XDP_HEADROOM : 0;
}

static struct page *xdp_linearize_page(struct net_device *dev,
				       struct receive_queue *rq,
				       u16 *num_buf,
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

static struct sk_buff *klpr_receive_small(struct net_device *dev,
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

	len -= vi->hdr_len;
	stats->bytes += len;

	if (unlikely(len > GOOD_PACKET_LEN)) {
		pr_debug("%s: rx error: len %u exceeds max size %d\n",
			 dev->name, len, GOOD_PACKET_LEN);
		dev->stats.rx_length_errors++;
		goto err_len;
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

		if (unlikely(xdp_headroom < virtnet_get_headroom(vi))) {
			int offset = buf - page_address(page) + header_offset;
			unsigned int tlen = len + vi->hdr_len;
			u16 num_buf = 1;

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

		xdp.data_hard_start = buf + VIRTNET_RX_PAD + vi->hdr_len;
		xdp.data = xdp.data_hard_start + xdp_headroom;
		xdp_set_data_meta_invalid(&xdp);
		xdp.data_end = xdp.data + len;
		xdp.rxq = &rq->xdp_rxq;
		orig_data = xdp.data;
		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		stats->xdp_packets++;

		switch (act) {
		case XDP_PASS:
			/* Recalculate length in case bpf program changed it */
			delta = orig_data - xdp.data;
			len = xdp.data_end - xdp.data;
			break;
		case XDP_TX:
			stats->xdp_tx++;
			xdpf = convert_to_xdp_frame(&xdp);
			if (unlikely(!xdpf))
				goto err_xdp;
			err = (*klpe_virtnet_xdp_xmit)(dev, 1, &xdpf, 0);
			if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			stats->xdp_redirects++;
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err)
				goto err_xdp;
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(act);
			/* fall through */
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
		case XDP_DROP:
			goto err_xdp;
		}
	}
	rcu_read_unlock();

	skb = build_skb(buf, buflen);
	if (!skb) {
		put_page(page);
		goto err;
	}
	skb_reserve(skb, headroom - delta);
	skb_put(skb, len);
	if (!xdp_prog) {
		buf += header_offset;
		memcpy(skb_vnet_hdr(skb), buf, vi->hdr_len);
	} /* keep zeroed vnet hdr since XDP is loaded */

err:
	return skb;

err_xdp:
	rcu_read_unlock();
	stats->xdp_drops++;
err_len:
	stats->drops++;
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
	struct sk_buff *skb = page_to_skb(vi, rq, page, 0, len,
					  PAGE_SIZE, true);

	stats->bytes += len - vi->hdr_len;
	if (unlikely(!skb))
		goto err;

	return skb;

err:
	stats->drops++;
	give_pages(rq, page);
	return NULL;
}

static struct sk_buff *klpr_receive_mergeable(struct net_device *dev,
					 struct virtnet_info *vi,
					 struct receive_queue *rq,
					 void *buf,
					 void *ctx,
					 unsigned int len,
					 unsigned int *xdp_xmit,
					 struct virtnet_rq_stats *stats)
{
	struct virtio_net_hdr_mrg_rxbuf *hdr = buf;
	u16 num_buf = virtio16_to_cpu(vi->vdev, hdr->num_buffers);
	struct page *page = virt_to_head_page(buf);
	int offset = buf - page_address(page);
	struct sk_buff *head_skb, *curr_skb;
	struct bpf_prog *xdp_prog;
	unsigned int truesize = mergeable_ctx_to_truesize(ctx);
	unsigned int headroom = mergeable_ctx_to_headroom(ctx);
	int err;

	head_skb = NULL;
	stats->bytes += len - vi->hdr_len;

	if (unlikely(len > truesize)) {
		pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
			 dev->name, len, (unsigned long)ctx);
		dev->stats.rx_length_errors++;
		goto err_skb;
	}
	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (xdp_prog) {
		struct xdp_frame *xdpf;
		struct page *xdp_page;
		struct xdp_buff xdp;
		void *data;
		u32 act;

		/* Transient failure which in theory could occur if
		 * in-flight packets from before XDP was enabled reach
		 * the receive path after XDP is loaded.
		 */
		if (unlikely(hdr->hdr.gso_type))
			goto err_xdp;

		/* This happens when rx buffer size is underestimated
		 * or headroom is not enough because of the buffer
		 * was refilled before XDP is set. This should only
		 * happen for the first several packets, so we don't
		 * care much about its performance.
		 */
		if (unlikely(num_buf > 1 ||
			     headroom < virtnet_get_headroom(vi))) {
			/* linearize data for XDP */
			xdp_page = xdp_linearize_page(vi->dev, rq, &num_buf,
						      page, offset,
						      VIRTIO_XDP_HEADROOM,
						      &len);
			if (!xdp_page)
				goto err_xdp;
			offset = VIRTIO_XDP_HEADROOM;
		} else {
			xdp_page = page;
		}

		/* Allow consuming headroom but reserve enough space to push
		 * the descriptor on if we get an XDP_TX return code.
		 */
		data = page_address(xdp_page) + offset;
		xdp.data_hard_start = data - VIRTIO_XDP_HEADROOM + vi->hdr_len;
		xdp.data = data + vi->hdr_len;
		xdp_set_data_meta_invalid(&xdp);
		xdp.data_end = xdp.data + (len - vi->hdr_len);
		xdp.rxq = &rq->xdp_rxq;

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		stats->xdp_packets++;

		switch (act) {
		case XDP_PASS:
			/* recalculate offset to account for any header
			 * adjustments. Note other cases do not build an
			 * skb and avoid using offset
			 */
			offset = xdp.data -
					page_address(xdp_page) - vi->hdr_len;

			/* recalculate len if xdp.data or xdp.data_end were
			 * adjusted
			 */
			len = xdp.data_end - xdp.data + vi->hdr_len;
			/* We can only create skb based on xdp_page. */
			if (unlikely(xdp_page != page)) {
				rcu_read_unlock();
				put_page(page);
				head_skb = page_to_skb(vi, rq, xdp_page,
						       offset, len,
						       PAGE_SIZE, false);
				return head_skb;
			}
			break;
		case XDP_TX:
			stats->xdp_tx++;
			xdpf = convert_to_xdp_frame(&xdp);
			if (unlikely(!xdpf)) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			err = (*klpe_virtnet_xdp_xmit)(dev, 1, &xdpf, 0);
			if (unlikely(err < 0)) {
				trace_xdp_exception(vi->dev, xdp_prog, act);
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_TX;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		case XDP_REDIRECT:
			stats->xdp_redirects++;
			err = xdp_do_redirect(dev, &xdp, xdp_prog);
			if (err) {
				if (unlikely(xdp_page != page))
					put_page(xdp_page);
				goto err_xdp;
			}
			*xdp_xmit |= VIRTIO_XDP_REDIR;
			if (unlikely(xdp_page != page))
				put_page(page);
			rcu_read_unlock();
			goto xdp_xmit;
		default:
			bpf_warn_invalid_xdp_action(act);
			/* fall through */
		case XDP_ABORTED:
			trace_xdp_exception(vi->dev, xdp_prog, act);
			/* fall through */
		case XDP_DROP:
			if (unlikely(xdp_page != page))
				__free_pages(xdp_page, 0);
			goto err_xdp;
		}
	}
	rcu_read_unlock();

	head_skb = page_to_skb(vi, rq, page, offset, len, truesize, !xdp_prog);
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
			dev->stats.rx_length_errors++;
			goto err_buf;
		}

		stats->bytes += len;
		page = virt_to_head_page(buf);

		truesize = mergeable_ctx_to_truesize(ctx);
		if (unlikely(len > truesize)) {
			pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
				 dev->name, len, (unsigned long)ctx);
			dev->stats.rx_length_errors++;
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
	stats->xdp_drops++;
err_skb:
	put_page(page);
	while (num_buf-- > 1) {
		buf = virtqueue_get_buf(rq->vq, &len);
		if (unlikely(!buf)) {
			pr_debug("%s: rx error: %d buffers missing\n",
				 dev->name, num_buf);
			dev->stats.rx_length_errors++;
			break;
		}
		stats->bytes += len;
		page = virt_to_head_page(buf);
		put_page(page);
	}
err_buf:
	stats->drops++;
	dev_kfree_skb(head_skb);
xdp_xmit:
	return NULL;
}

void klpp_receive_buf(struct virtnet_info *vi, struct receive_queue *rq,
			void *buf, unsigned int len, void **ctx,
			unsigned int *xdp_xmit,
			struct virtnet_rq_stats *stats)
{
	struct net_device *dev = vi->dev;
	struct sk_buff *skb;
	struct virtio_net_hdr_mrg_rxbuf *hdr;

	if (unlikely(len < vi->hdr_len + ETH_HLEN)) {
		pr_debug("%s: short packet %i\n", dev->name, len);
		dev->stats.rx_length_errors++;
		if (vi->mergeable_rx_bufs) {
			put_page(virt_to_head_page(buf));
		} else if (vi->big_packets) {
			give_pages(rq, buf);
		} else {
			put_page(virt_to_head_page(buf));
		}
		return;
	}

	if (vi->mergeable_rx_bufs)
		skb = klpr_receive_mergeable(dev, vi, rq, buf, ctx, len, xdp_xmit,
					stats);
	else if (vi->big_packets)
		skb = receive_big(dev, vi, rq, buf, len, stats);
	else
		skb = klpr_receive_small(dev, vi, rq, buf, ctx, len, xdp_xmit, stats);

	if (unlikely(!skb))
		return;

	hdr = skb_vnet_hdr(skb);

	if (hdr->hdr.flags & VIRTIO_NET_HDR_F_DATA_VALID)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (virtio_net_hdr_to_skb(skb, &hdr->hdr,
				  virtio_is_little_endian(vi->vdev))) {
		net_warn_ratelimited("%s: bad gso: type: %u, size: %u\n",
				     dev->name, hdr->hdr.gso_type,
				     hdr->hdr.gso_size);
		goto frame_err;
	}

	skb->protocol = eth_type_trans(skb, dev);
	pr_debug("Receiving skb proto 0x%04x len %i type %i\n",
		 ntohs(skb->protocol), skb->len, skb->pkt_type);

	napi_gro_receive(&rq->napi, skb);
	return;

frame_err:
	dev->stats.rx_frame_errors++;
	dev_kfree_skb(skb);
}


#include "livepatch_bsc1258073.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "virtio_net"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "virtnet_xdp_xmit", (void *)&klpe_virtnet_xdp_xmit, "virtio_net" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1258073_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1258073_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
