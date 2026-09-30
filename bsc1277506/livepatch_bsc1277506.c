/*
 * livepatch_bsc1277506
 *
 * Fix for CVE-2026-74612, bsc#1277506
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1277506.h"


/* klp-ccp: from drivers/net/veth.c */
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/u64_stats_sync.h>
#include <net/rtnetlink.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/xdp.h>
#include <linux/veth.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/ptr_ring.h>
#include <linux/bpf_trace.h>
#include <linux/net_tstamp.h>
#include <linux/skbuff_ref.h>
#include <net/page_pool/helpers.h>

struct veth_stats {
	u64	rx_drops;
	/* xdp */
	u64	xdp_packets;
	u64	xdp_bytes;
	u64	xdp_redirect;
	u64	xdp_drops;
	u64	xdp_tx;
	u64	xdp_tx_err;
	u64	peer_tq_xdp_xmit;
	u64	peer_tq_xdp_xmit_err;
};

struct veth_rq_stats {
	struct veth_stats	vs;
	struct u64_stats_sync	syncp;
};

struct veth_rq {
	struct napi_struct	xdp_napi;
	struct napi_struct __rcu *napi; /* points to xdp_napi when the latter is initialized */
	struct net_device	*dev;
	struct bpf_prog __rcu	*xdp_prog;
	struct xdp_mem_info	xdp_mem;
	struct veth_rq_stats	stats;
	bool			rx_notify_masked;
	struct ptr_ring		xdp_ring;
	struct xdp_rxq_info	xdp_rxq;
	struct page_pool	*page_pool;
};

struct veth_xdp_tx_bq;

struct veth_xdp_buff {
	struct xdp_buff xdp;
	struct sk_buff *skb;
};

extern int veth_xdp_tx(struct veth_rq *rq, struct xdp_buff *xdp,
		       struct veth_xdp_tx_bq *bq);

extern void veth_xdp_get(struct xdp_buff *xdp);

static int veth_convert_skb_to_xdp_buff(struct veth_rq *rq,
					struct xdp_buff *xdp,
					struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	u32 frame_sz;

	if (skb_shared(skb) || skb_head_is_locked(skb) ||
	    skb_shinfo(skb)->nr_frags ||
	    skb_headroom(skb) < XDP_PACKET_HEADROOM) {
		if (skb_pp_cow_data(rq->page_pool, pskb, XDP_PACKET_HEADROOM))
			goto drop;

		skb = *pskb;
	}

	/* SKB "head" area always have tailroom for skb_shared_info */
	frame_sz = skb_end_pointer(skb) - skb->head;
	frame_sz += SKB_DATA_ALIGN(sizeof(struct skb_shared_info));
	xdp_init_buff(xdp, frame_sz, &rq->xdp_rxq);
	xdp_prepare_buff(xdp, skb->head, skb_headroom(skb),
			 skb_headlen(skb), true);

	if (skb_is_nonlinear(skb)) {
		skb_shinfo(skb)->xdp_frags_size = skb->data_len;
		xdp_buff_set_frags_flag(xdp);
	} else {
		xdp_buff_clear_frags_flag(xdp);
	}
	*pskb = skb;

	return 0;
drop:
	consume_skb(skb);
	*pskb = NULL;

	return -ENOMEM;
}

struct sk_buff *klpp_veth_xdp_rcv_skb(struct veth_rq *rq, struct sk_buff *skb, struct veth_xdp_tx_bq *bq, struct veth_stats *stats)
{
	void *orig_data, *orig_data_end;
	struct bpf_prog *xdp_prog;
	struct veth_xdp_buff vxbuf;
	struct xdp_buff *xdp = &vxbuf.xdp;
	u32 act, metalen;
	int off;

	skb_prepare_for_gro(skb);

	rcu_read_lock();
	xdp_prog = rcu_dereference(rq->xdp_prog);
	if (unlikely(!xdp_prog)) {
		rcu_read_unlock();
		goto out;
	}

	__skb_push(skb, skb->data - skb_mac_header(skb));
	if (veth_convert_skb_to_xdp_buff(rq, xdp, &skb))
		goto drop;
	vxbuf.skb = skb;

	orig_data = xdp->data;
	orig_data_end = xdp->data_end;

	act = bpf_prog_run_xdp(xdp_prog, xdp);

	switch (act) {
	case XDP_PASS:
		break;
	case XDP_TX:
		veth_xdp_get(xdp);
		consume_skb(skb);
		xdp->rxq->mem = rq->xdp_mem;
		if (unlikely(veth_xdp_tx(rq, xdp, bq) < 0)) {
			trace_xdp_exception(rq->dev, xdp_prog, act);
			stats->rx_drops++;
			goto err_xdp;
		}
		stats->xdp_tx++;
		rcu_read_unlock();
		goto xdp_xmit;
	case XDP_REDIRECT:
		veth_xdp_get(xdp);
		consume_skb(skb);
		xdp->rxq->mem = rq->xdp_mem;
		if (xdp_do_redirect(rq->dev, xdp, xdp_prog)) {
			stats->rx_drops++;
			goto err_xdp;
		}
		stats->xdp_redirect++;
		rcu_read_unlock();
		goto xdp_xmit;
	default:
		bpf_warn_invalid_xdp_action(rq->dev, xdp_prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(rq->dev, xdp_prog, act);
		fallthrough;
	case XDP_DROP:
		stats->xdp_drops++;
		goto xdp_drop;
	}
	rcu_read_unlock();

	/* check if bpf_xdp_adjust_head was used */
	off = orig_data - xdp->data;
	if (off > 0)
		__skb_push(skb, off);
	else if (off < 0)
		__skb_pull(skb, -off);

	skb_reset_mac_header(skb);

	/* XDP frag metadata (e.g. nr_frags) are updated in eBPF helpers
	 * (e.g. bpf_xdp_adjust_tail). Remove the old fragment contribution
	 * from skb->len before updating data_len, then add the new one back.
	 */
	skb->len -= skb->data_len;
	if (xdp_buff_has_frags(xdp)) {
		skb->data_len = skb_shinfo(skb)->xdp_frags_size;
		skb->len += skb->data_len;
	} else {
		skb->data_len = 0;
	}

	/* Synchronize the skb tail with XDP's updated linear area. */
	off = xdp->data_end - orig_data_end;
	if (off != 0) {
		skb_set_tail_pointer(skb, xdp->data_end - xdp->data);
		skb->len += off; /* positive on grow, negative on shrink */
	}

	skb->protocol = eth_type_trans(skb, rq->dev);

	metalen = xdp->data - xdp->data_meta;
	if (metalen)
		skb_metadata_set(skb, metalen);
out:
	return skb;
drop:
	stats->rx_drops++;
xdp_drop:
	rcu_read_unlock();
	kfree_skb(skb);
	return NULL;
err_xdp:
	rcu_read_unlock();
	xdp_return_buff(xdp);
xdp_xmit:
	return NULL;
}


#include <linux/livepatch.h>

extern typeof(veth_xdp_get) veth_xdp_get
	 KLP_RELOC_SYMBOL(veth, veth, veth_xdp_get);
extern typeof(veth_xdp_tx) veth_xdp_tx KLP_RELOC_SYMBOL(veth, veth, veth_xdp_tx);
