/*
 * livepatch_bsc1228714
 *
 * Fix for CVE-2024-41090, bsc#1228714
 *
 *  Upstream commit:
 *  ed7f2afdd0e0 ("tap: add missing verification for short frame")
 *
 *  SLE12-SP5 commit:
 *  307669f84652aa44383a8706e56a5e1fd44c41e8
 *
 *  SLE15-SP3 commit:
 *  ebf78ce2a9f8c3f545b0e5dce6e1b505ad975ead
 *
 *  SLE15-SP4 and -SP5 commit:
 *  e64bcfc12637d2b91c752191dfec0d47089a03e9
 *
 *  SLE15-SP6 commit:
 *  c6c3ad079625215fc2156d32433b745216975e0a
 *
 *  SLE MICRO-6-0 commit:
 *  c6c3ad079625215fc2156d32433b745216975e0a
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

/* klp-ccp: from drivers/net/tap.c */
#include <linux/etherdevice.h>
#include <linux/if_tap.h>
#include <linux/if_vlan.h>
#include <linux/interrupt.h>
#include <linux/nsproxy.h>
#include <linux/compat.h>
#include <linux/if_tun.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/cache.h>
#include <linux/sched/signal.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/uio.h>

#include <net/net_namespace.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include <net/xdp.h>
#include <linux/virtio_net.h>
#include <linux/skb_array.h>

#define TAP_VNET_LE 0x80000000

#ifdef CONFIG_TUN_VNET_CROSS_LE
#error "klp-ccp: non-taken branch"
#else
static inline bool tap_legacy_is_little_endian(struct tap_queue *q)
{
	return virtio_legacy_is_little_endian();
}

#endif /* CONFIG_TUN_VNET_CROSS_LE */

static inline bool tap_is_little_endian(struct tap_queue *q)
{
	return q->flags & TAP_VNET_LE ||
		tap_legacy_is_little_endian(q);
}

extern ssize_t tap_get_user(struct tap_queue *q, void *msg_control,
			    struct iov_iter *from, int noblock);

static int klpp_tap_get_user_xdp(struct tap_queue *q, struct xdp_buff *xdp)
{
	struct tun_xdp_hdr *hdr = xdp->data_hard_start;
	struct virtio_net_hdr *gso = &hdr->gso;
	int buflen = hdr->buflen;
	int vnet_hdr_len = 0;
	struct tap_dev *tap;
	struct sk_buff *skb;
	int err, depth;

	if (unlikely(xdp->data_end - xdp->data < ETH_HLEN)) {
		err = -EINVAL;
		goto err;
	}

	if (q->flags & IFF_VNET_HDR)
		vnet_hdr_len = READ_ONCE(q->vnet_hdr_sz);

	skb = build_skb(xdp->data_hard_start, buflen);
	if (!skb) {
		err = -ENOMEM;
		goto err;
	}

	skb_reserve(skb, xdp->data - xdp->data_hard_start);
	skb_put(skb, xdp->data_end - xdp->data);

	skb_set_network_header(skb, ETH_HLEN);
	skb_reset_mac_header(skb);
	skb->protocol = eth_hdr(skb)->h_proto;

	if (vnet_hdr_len) {
		err = virtio_net_hdr_to_skb(skb, gso, tap_is_little_endian(q));
		if (err)
			goto err_kfree;
	}

	/* Move network header to the right position for VLAN tagged packets */
	if (eth_type_vlan(skb->protocol) &&
	    vlan_get_protocol_and_depth(skb, skb->protocol, &depth) != 0)
		skb_set_network_header(skb, depth);

	rcu_read_lock();
	tap = rcu_dereference(q->tap);
	if (tap) {
		skb->dev = tap->dev;
		skb_probe_transport_header(skb);
		dev_queue_xmit(skb);
	} else {
		kfree_skb(skb);
	}
	rcu_read_unlock();

	return 0;

err_kfree:
	kfree_skb(skb);
err:
	rcu_read_lock();
	tap = rcu_dereference(q->tap);
	if (tap && tap->count_tx_dropped)
		tap->count_tx_dropped(tap);
	rcu_read_unlock();
	return err;
}

int klpp_tap_sendmsg(struct socket *sock, struct msghdr *m,
		       size_t total_len)
{
	struct tap_queue *q = container_of(sock, struct tap_queue, sock);
	struct tun_msg_ctl *ctl = m->msg_control;
	struct xdp_buff *xdp;
	int i;

	if (m->msg_controllen == sizeof(struct tun_msg_ctl) &&
	    ctl && ctl->type == TUN_MSG_PTR) {
		for (i = 0; i < ctl->num; i++) {
			xdp = &((struct xdp_buff *)ctl->ptr)[i];
			klpp_tap_get_user_xdp(q, xdp);
		}
		return 0;
	}

	return tap_get_user(q, ctl ? ctl->ptr : NULL, &m->msg_iter,
			    m->msg_flags & MSG_DONTWAIT);
}


#include "livepatch_bsc1228714.h"

#include <linux/livepatch.h>

extern typeof(tap_get_user) tap_get_user
	 KLP_RELOC_SYMBOL(tap, tap, tap_get_user);
