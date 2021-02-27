/*
 * livepatch_bsc1180859
 *
 * Fix for CVE-2021-0342, bsc#1180859
 *
 *  Upstream commit:
 *  96aa1b22bd6b ("tun: correct header offsets in napi frags mode")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 and SLE15 commit:
 *  not affected
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  0ae29aafc2a76eb39865787d497123dcadf833d1
 *
 *  SLE15-SP2 commit:
 *  3aeb0561716f7f323603b88139727907af58a403
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_TUN)
#error "Live patch supports only CONFIG_TUN=m"
#endif

/* klp-ccp: from drivers/net/tun.c */
#define pr_fmt(fmt) "tun" ": " fmt

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/major.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/if_vlan.h>
#include <linux/nsproxy.h>
#include <linux/virtio_net.h>
#include <linux/rcupdate.h>
#include <net/net_namespace.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/xdp.h>
#include <linux/seq_file.h>
#include <linux/uio.h>
#include <linux/skb_array.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

#define TUN_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

#define TUN_VNET_LE     0x80000000

#define GOODCOPY_LEN 128

#define FLT_EXACT_COUNT 8
struct tap_filter {
	unsigned int    count;    /* Number of addrs. Zero means disabled */
	u32             mask[2];  /* Mask of the hashed addrs */
	unsigned char	addr[FLT_EXACT_COUNT][ETH_ALEN];
};

#define MAX_TAP_QUEUES 256

struct tun_pcpu_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	struct u64_stats_sync syncp;
	u32 rx_dropped;
	u32 tx_dropped;
	u32 rx_frame_errors;
};

struct tun_file {
	struct sock sk;
	struct socket socket;
	struct socket_wq wq;
	struct tun_struct __rcu *tun;
	struct fasync_struct *fasync;
	/* only used for fasnyc */
	unsigned int flags;
	union {
		u16 queue_index;
		unsigned int ifindex;
	};
	struct napi_struct napi;
	bool napi_enabled;
	bool napi_frags_enabled;
	struct mutex napi_mutex;	/* Protects access to the above napi */
	struct list_head next;
	struct tun_struct *detached;
	struct ptr_ring tx_ring;
	struct xdp_rxq_info xdp_rxq;
};

#define TUN_NUM_FLOW_ENTRIES 1024

struct tun_prog {
	struct rcu_head rcu;
	struct bpf_prog *prog;
};

struct tun_struct {
	struct tun_file __rcu	*tfiles[MAX_TAP_QUEUES];
	unsigned int            numqueues;
	unsigned int 		flags;
	kuid_t			owner;
	kgid_t			group;

	struct net_device	*dev;
	netdev_features_t	set_features;

	int			align;
	int			vnet_hdr_sz;
	int			sndbuf;
	struct tap_filter	txflt;
	struct sock_fprog	fprog;
	/* protected by rtnl lock */
	bool			filter_attached;
#ifdef TUN_DEBUG
#error "klp-ccp: non-taken branch"
#endif
	spinlock_t lock;
	struct hlist_head flows[TUN_NUM_FLOW_ENTRIES];
	struct timer_list flow_gc_timer;
	unsigned long ageing_time;
	unsigned int numdisabled;
	struct list_head disabled;
	void *security;
	u32 flow_count;
	u32 rx_batched;
	struct tun_pcpu_stats __percpu *pcpu_stats;
	struct bpf_prog __rcu *xdp_prog;
	struct tun_prog __rcu *steering_prog;
	struct tun_prog __rcu *filter_prog;
	struct ethtool_link_ksettings link_ksettings;
};

static bool tun_napi_frags_enabled(const struct tun_file *tfile)
{
	return tfile->napi_frags_enabled;
}

#ifdef CONFIG_TUN_VNET_CROSS_LE
#error "klp-ccp: non-taken branch"
#else
static inline bool tun_legacy_is_little_endian(struct tun_struct *tun)
{
	return virtio_legacy_is_little_endian();
}

#endif /* CONFIG_TUN_VNET_CROSS_LE */

static inline bool tun_is_little_endian(struct tun_struct *tun)
{
	return tun->flags & TUN_VNET_LE ||
		tun_legacy_is_little_endian(tun);
}

static inline u16 tun16_to_cpu(struct tun_struct *tun, __virtio16 val)
{
	return __virtio16_to_cpu(tun_is_little_endian(tun), val);
}

static inline __virtio16 cpu_to_tun16(struct tun_struct *tun, u16 val)
{
	return __cpu_to_virtio16(tun_is_little_endian(tun), val);
}

static void (*klpe_tun_flow_update)(struct tun_struct *tun, u32 rxhash,
			    struct tun_file *tfile);

static int (*klpe_tun_xdp_xmit)(struct net_device *dev, int n,
			struct xdp_frame **frames, u32 flags);

static int klpr_tun_xdp_tx(struct net_device *dev, struct xdp_buff *xdp)
{
	struct xdp_frame *frame = convert_to_xdp_frame(xdp);

	if (unlikely(!frame))
		return -EOVERFLOW;

	return (*klpe_tun_xdp_xmit)(dev, 1, &frame, XDP_XMIT_FLUSH);
}

static struct sk_buff *tun_napi_alloc_frags(struct tun_file *tfile,
					    size_t len,
					    const struct iov_iter *it)
{
	struct sk_buff *skb;
	size_t linear;
	int err;
	int i;

	if (it->nr_segs > MAX_SKB_FRAGS + 1)
		return ERR_PTR(-ENOMEM);

	local_bh_disable();
	skb = napi_get_frags(&tfile->napi);
	local_bh_enable();
	if (!skb)
		return ERR_PTR(-ENOMEM);

	linear = iov_iter_single_seg_count(it);
	err = __skb_grow(skb, linear);
	if (err)
		goto free;

	skb->len = len;
	skb->data_len = len - linear;
	skb->truesize += skb->data_len;

	for (i = 1; i < it->nr_segs; i++) {
		size_t fragsz = it->iov[i].iov_len;
		struct page *page;
		void *frag;

		if (fragsz == 0 || fragsz > PAGE_SIZE) {
			err = -EINVAL;
			goto free;
		}
		frag = netdev_alloc_frag(fragsz);
		if (!frag) {
			err = -ENOMEM;
			goto free;
		}
		page = virt_to_head_page(frag);
		skb_fill_page_desc(skb, i - 1, page,
				   frag - page_address(page), fragsz);
	}

	return skb;
free:
	/* frees skb and all frags allocated with napi_alloc_frag() */
	napi_free_frags(&tfile->napi);
	return ERR_PTR(err);
}

static struct sk_buff *tun_alloc_skb(struct tun_file *tfile,
				     size_t prepad, size_t len,
				     size_t linear, int noblock)
{
	struct sock *sk = tfile->socket.sk;
	struct sk_buff *skb;
	int err;

	/* Under a page?  Don't bother with paged skb. */
	if (prepad + len < PAGE_SIZE || !linear)
		linear = len;

	skb = sock_alloc_send_pskb(sk, prepad + linear, len - linear, noblock,
				   &err, 0);
	if (!skb)
		return ERR_PTR(err);

	skb_reserve(skb, prepad);
	skb_put(skb, linear);
	skb->data_len = len - linear;
	skb->len += len - linear;

	return skb;
}

static void tun_rx_batched(struct tun_struct *tun, struct tun_file *tfile,
			   struct sk_buff *skb, int more)
{
	struct sk_buff_head *queue = &tfile->sk.sk_write_queue;
	struct sk_buff_head process_queue;
	u32 rx_batched = tun->rx_batched;
	bool rcv = false;

	if (!rx_batched || (!more && skb_queue_empty(queue))) {
		local_bh_disable();
		skb_record_rx_queue(skb, tfile->queue_index);
		netif_receive_skb(skb);
		local_bh_enable();
		return;
	}

	spin_lock(&queue->lock);
	if (!more || skb_queue_len(queue) == rx_batched) {
		__skb_queue_head_init(&process_queue);
		skb_queue_splice_tail_init(queue, &process_queue);
		rcv = true;
	} else {
		__skb_queue_tail(queue, skb);
	}
	spin_unlock(&queue->lock);

	if (rcv) {
		struct sk_buff *nskb;

		local_bh_disable();
		while ((nskb = __skb_dequeue(&process_queue))) {
			skb_record_rx_queue(nskb, tfile->queue_index);
			netif_receive_skb(nskb);
		}
		skb_record_rx_queue(skb, tfile->queue_index);
		netif_receive_skb(skb);
		local_bh_enable();
	}
}

static bool tun_can_build_skb(struct tun_struct *tun, struct tun_file *tfile,
			      int len, int noblock, bool zerocopy)
{
	if ((tun->flags & TUN_TYPE_MASK) != IFF_TAP)
		return false;

	if (tfile->socket.sk->sk_sndbuf != INT_MAX)
		return false;

	if (!noblock)
		return false;

	if (zerocopy)
		return false;

	if (SKB_DATA_ALIGN(len + TUN_RX_PAD) +
	    SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) > PAGE_SIZE)
		return false;

	return true;
}

static struct sk_buff *(*klpe___tun_build_skb)(struct tun_file *tfile,
				       struct page_frag *alloc_frag, char *buf,
				       int buflen, int len, int pad);

static int klpr_tun_xdp_act(struct tun_struct *tun, struct bpf_prog *xdp_prog,
		       struct xdp_buff *xdp, u32 act)
{
	int err;

	switch (act) {
	case XDP_REDIRECT:
		err = xdp_do_redirect(tun->dev, xdp, xdp_prog);
		if (err)
			return err;
		break;
	case XDP_TX:
		err = klpr_tun_xdp_tx(tun->dev, xdp);
		if (err < 0)
			return err;
		break;
	case XDP_PASS:
		break;
	default:
		bpf_warn_invalid_xdp_action(act);
		/* fall through */
	case XDP_ABORTED:
		trace_xdp_exception(tun->dev, xdp_prog, act);
		/* fall through */
	case XDP_DROP:
		this_cpu_inc(tun->pcpu_stats->rx_dropped);
		break;
	}

	return act;
}

static struct sk_buff *klpr_tun_build_skb(struct tun_struct *tun,
				     struct tun_file *tfile,
				     struct iov_iter *from,
				     struct virtio_net_hdr *hdr,
				     int len, int *skb_xdp)
{
	struct page_frag *alloc_frag = &current->task_frag;
	struct bpf_prog *xdp_prog;
	int buflen = SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	char *buf;
	size_t copied;
	int pad = TUN_RX_PAD;
	int err = 0;

	rcu_read_lock();
	xdp_prog = rcu_dereference(tun->xdp_prog);
	if (xdp_prog)
		pad += XDP_PACKET_HEADROOM;
	buflen += SKB_DATA_ALIGN(len + pad);
	rcu_read_unlock();

	alloc_frag->offset = ALIGN((u64)alloc_frag->offset, SMP_CACHE_BYTES);
	if (unlikely(!skb_page_frag_refill(buflen, alloc_frag, GFP_KERNEL)))
		return ERR_PTR(-ENOMEM);

	buf = (char *)page_address(alloc_frag->page) + alloc_frag->offset;
	copied = copy_page_from_iter(alloc_frag->page,
				     alloc_frag->offset + pad,
				     len, from);
	if (copied != len)
		return ERR_PTR(-EFAULT);

	/* There's a small window that XDP may be set after the check
	 * of xdp_prog above, this should be rare and for simplicity
	 * we do XDP on skb in case the headroom is not enough.
	 */
	if (hdr->gso_type || !xdp_prog) {
		*skb_xdp = 1;
		return (*klpe___tun_build_skb)(tfile, alloc_frag, buf, buflen, len,
				       pad);
	}

	*skb_xdp = 0;

	local_bh_disable();
	rcu_read_lock();
	xdp_prog = rcu_dereference(tun->xdp_prog);
	if (xdp_prog) {
		struct xdp_buff xdp;
		u32 act;

		xdp.data_hard_start = buf;
		xdp.data = buf + pad;
		xdp_set_data_meta_invalid(&xdp);
		xdp.data_end = xdp.data + len;
		xdp.rxq = &tfile->xdp_rxq;

		act = bpf_prog_run_xdp(xdp_prog, &xdp);
		if (act == XDP_REDIRECT || act == XDP_TX) {
			get_page(alloc_frag->page);
			alloc_frag->offset += buflen;
		}
		err = klpr_tun_xdp_act(tun, xdp_prog, &xdp, act);
		if (err < 0) {
			if (act == XDP_REDIRECT || act == XDP_TX)
				put_page(alloc_frag->page);
			goto out;
		}

		if (err == XDP_REDIRECT)
			xdp_do_flush_map();
		if (err != XDP_PASS)
			goto out;

		pad = xdp.data - xdp.data_hard_start;
		len = xdp.data_end - xdp.data;
	}
	rcu_read_unlock();
	local_bh_enable();

	return (*klpe___tun_build_skb)(tfile, alloc_frag, buf, buflen, len, pad);

out:
	rcu_read_unlock();
	local_bh_enable();
	return NULL;
}

ssize_t klpp_tun_get_user(struct tun_struct *tun, struct tun_file *tfile,
			    void *msg_control, struct iov_iter *from,
			    int noblock, bool more)
{
	struct tun_pi pi = { 0, cpu_to_be16(ETH_P_IP) };
	struct sk_buff *skb;
	size_t total_len = iov_iter_count(from);
	size_t len = total_len, align = tun->align, linear;
	struct virtio_net_hdr gso = { 0 };
	struct tun_pcpu_stats *stats;
	int good_linear;
	int copylen;
	bool zerocopy = false;
	int err;
	u32 rxhash = 0;
	int skb_xdp = 1;
	bool frags = tun_napi_frags_enabled(tfile);

	if (!(tun->flags & IFF_NO_PI)) {
		if (len < sizeof(pi))
			return -EINVAL;
		len -= sizeof(pi);

		if (!copy_from_iter_full(&pi, sizeof(pi), from))
			return -EFAULT;
	}

	if (tun->flags & IFF_VNET_HDR) {
		int vnet_hdr_sz = READ_ONCE(tun->vnet_hdr_sz);

		if (len < vnet_hdr_sz)
			return -EINVAL;
		len -= vnet_hdr_sz;

		if (!copy_from_iter_full(&gso, sizeof(gso), from))
			return -EFAULT;

		if ((gso.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) &&
		    tun16_to_cpu(tun, gso.csum_start) + tun16_to_cpu(tun, gso.csum_offset) + 2 > tun16_to_cpu(tun, gso.hdr_len))
			gso.hdr_len = cpu_to_tun16(tun, tun16_to_cpu(tun, gso.csum_start) + tun16_to_cpu(tun, gso.csum_offset) + 2);

		if (tun16_to_cpu(tun, gso.hdr_len) > len)
			return -EINVAL;
		iov_iter_advance(from, vnet_hdr_sz - sizeof(gso));
	}

	if ((tun->flags & TUN_TYPE_MASK) == IFF_TAP) {
		align += NET_IP_ALIGN;
		if (unlikely(len < ETH_HLEN ||
			     (gso.hdr_len && tun16_to_cpu(tun, gso.hdr_len) < ETH_HLEN)))
			return -EINVAL;
	}

	good_linear = SKB_MAX_HEAD(align);

	if (msg_control) {
		struct iov_iter i = *from;

		/* There are 256 bytes to be copied in skb, so there is
		 * enough room for skb expand head in case it is used.
		 * The rest of the buffer is mapped from userspace.
		 */
		copylen = gso.hdr_len ? tun16_to_cpu(tun, gso.hdr_len) : GOODCOPY_LEN;
		if (copylen > good_linear)
			copylen = good_linear;
		linear = copylen;
		iov_iter_advance(&i, copylen);
		if (iov_iter_npages(&i, INT_MAX) <= MAX_SKB_FRAGS)
			zerocopy = true;
	}

	if (!frags && tun_can_build_skb(tun, tfile, len, noblock, zerocopy)) {
		/* For the packet that is not easy to be processed
		 * (e.g gso or jumbo packet), we will do it at after
		 * skb was created with generic XDP routine.
		 */
		skb = klpr_tun_build_skb(tun, tfile, from, &gso, len, &skb_xdp);
		if (IS_ERR(skb)) {
			this_cpu_inc(tun->pcpu_stats->rx_dropped);
			return PTR_ERR(skb);
		}
		if (!skb)
			return total_len;
	} else {
		if (!zerocopy) {
			copylen = len;
			if (tun16_to_cpu(tun, gso.hdr_len) > good_linear)
				linear = good_linear;
			else
				linear = tun16_to_cpu(tun, gso.hdr_len);
		}

		if (frags) {
			mutex_lock(&tfile->napi_mutex);
			skb = tun_napi_alloc_frags(tfile, copylen, from);
			/* tun_napi_alloc_frags() enforces a layout for the skb.
			 * If zerocopy is enabled, then this layout will be
			 * overwritten by zerocopy_sg_from_iter().
			 */
			zerocopy = false;
		} else {
			skb = tun_alloc_skb(tfile, align, copylen, linear,
					    noblock);
		}

		if (IS_ERR(skb)) {
			if (PTR_ERR(skb) != -EAGAIN)
				this_cpu_inc(tun->pcpu_stats->rx_dropped);
			if (frags)
				mutex_unlock(&tfile->napi_mutex);
			return PTR_ERR(skb);
		}

		if (zerocopy)
			err = zerocopy_sg_from_iter(skb, from);
		else
			err = skb_copy_datagram_from_iter(skb, 0, from, len);

		if (err) {
			err = -EFAULT;
drop:
			this_cpu_inc(tun->pcpu_stats->rx_dropped);
			kfree_skb(skb);
			if (frags) {
				tfile->napi.skb = NULL;
				mutex_unlock(&tfile->napi_mutex);
			}

			return err;
		}
	}

	if (virtio_net_hdr_to_skb(skb, &gso, tun_is_little_endian(tun))) {
		this_cpu_inc(tun->pcpu_stats->rx_frame_errors);
		kfree_skb(skb);
		if (frags) {
			tfile->napi.skb = NULL;
			mutex_unlock(&tfile->napi_mutex);
		}

		return -EINVAL;
	}

	switch (tun->flags & TUN_TYPE_MASK) {
	case IFF_TUN:
		if (tun->flags & IFF_NO_PI) {
			u8 ip_version = skb->len ? (skb->data[0] >> 4) : 0;

			switch (ip_version) {
			case 4:
				pi.proto = htons(ETH_P_IP);
				break;
			case 6:
				pi.proto = htons(ETH_P_IPV6);
				break;
			default:
				this_cpu_inc(tun->pcpu_stats->rx_dropped);
				kfree_skb(skb);
				return -EINVAL;
			}
		}

		skb_reset_mac_header(skb);
		skb->protocol = pi.proto;
		skb->dev = tun->dev;
		break;
	case IFF_TAP:
		/*
		 * Fix CVE-2021-0342
		 *  -2 lines, +5 lines
		 */
		if (frags && !pskb_may_pull(skb, ETH_HLEN)) {
			err = -ENOMEM;
			goto drop;
		}
		skb->protocol = eth_type_trans(skb, tun->dev);

		break;
	}

	/* copy skb_ubuf_info for callback when skb has no error */
	if (zerocopy) {
		skb_shinfo(skb)->destructor_arg = msg_control;
		skb_shinfo(skb)->tx_flags |= SKBTX_DEV_ZEROCOPY;
		skb_shinfo(skb)->tx_flags |= SKBTX_SHARED_FRAG;
	} else if (msg_control) {
		struct ubuf_info *uarg = msg_control;
		uarg->callback(uarg, false);
	}

	skb_reset_network_header(skb);
	skb_probe_transport_header(skb, 0);

	if (skb_xdp) {
		struct bpf_prog *xdp_prog;
		int ret;

		local_bh_disable();
		rcu_read_lock();
		xdp_prog = rcu_dereference(tun->xdp_prog);
		if (xdp_prog) {
			ret = do_xdp_generic(xdp_prog, skb);
			if (ret != XDP_PASS) {
				rcu_read_unlock();
				local_bh_enable();
				if (frags) {
					tfile->napi.skb = NULL;
					mutex_unlock(&tfile->napi_mutex);
				}
				return total_len;
			}
		}
		rcu_read_unlock();
		local_bh_enable();
	}

	/* Compute the costly rx hash only if needed for flow updates.
	 * We may get a very small possibility of OOO during switching, not
	 * worth to optimize.
	 */
	if (!rcu_access_pointer(tun->steering_prog) && tun->numqueues > 1 &&
	    !tfile->detached)
		rxhash = __skb_get_hash_symmetric(skb);

	rcu_read_lock();
	if (unlikely(!(tun->dev->flags & IFF_UP))) {
		err = -EIO;
		rcu_read_unlock();
		goto drop;
	}


	if (frags) {
		/*
		 * Fix CVE-2021-0342
		 *  +1 line
		 */
		u32 headlen;

		/* Exercise flow dissector code path. */
		/*
		 * Fix CVE-2021-0342
		 *  -1 line, +2 lines
		 */
		skb_push(skb, ETH_HLEN);
		headlen = eth_get_headlen(skb->data, skb_headlen(skb));

		if (unlikely(headlen > skb_headlen(skb))) {
			this_cpu_inc(tun->pcpu_stats->rx_dropped);
			napi_free_frags(&tfile->napi);
			mutex_unlock(&tfile->napi_mutex);
			WARN_ON(1);
			return -ENOMEM;
		}

		local_bh_disable();
		napi_gro_frags(&tfile->napi);
		local_bh_enable();
		mutex_unlock(&tfile->napi_mutex);
	} else if (tfile->napi_enabled) {
		struct sk_buff_head *queue = &tfile->sk.sk_write_queue;
		int queue_len;

		spin_lock_bh(&queue->lock);
		__skb_queue_tail(queue, skb);
		queue_len = skb_queue_len(queue);
		spin_unlock(&queue->lock);

		if (!more || queue_len > NAPI_POLL_WEIGHT)
			napi_schedule(&tfile->napi);

		local_bh_enable();
	} else if (!IS_ENABLED(CONFIG_4KSTACKS)) {
		tun_rx_batched(tun, tfile, skb, more);
	} else {
		netif_rx_ni(skb);
	}
	rcu_read_unlock();

	stats = get_cpu_ptr(tun->pcpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += len;
	u64_stats_update_end(&stats->syncp);
	put_cpu_ptr(stats);

	if (rxhash)
		(*klpe_tun_flow_update)(tun, rxhash, tfile);

	return total_len;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1180859.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "tun"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tun_flow_update", (void *)&klpe_tun_flow_update, "tun" },
	{ "tun_xdp_xmit", (void *)&klpe_tun_xdp_xmit, "tun" },
	{ "__tun_build_skb", (void *)&klpe___tun_build_skb, "tun" },
};

static int livepatch_bsc1180859_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1180859_module_nb = {
	.notifier_call = livepatch_bsc1180859_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1180859_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1180859_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1180859_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1180859_module_nb);
}
