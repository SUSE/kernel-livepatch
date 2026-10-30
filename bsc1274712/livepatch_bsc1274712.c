/*
 * livepatch_bsc1274712
 *
 * Fix for CVE-2026-68426, bsc#1274712
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


#include "livepatch_bsc1274712.h"

/* klp-ccp: from net/xfrm/xfrm_device.c */
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>

/* klp-ccp: from net/xfrm/xfrm_device.c */
#include <linux/notifier.h>

#ifdef CONFIG_XFRM_OFFLOAD
struct sk_buff *klpp_validate_xmit_xfrm(struct sk_buff *skb, netdev_features_t features, bool *again)
{
	int err;
	unsigned long flags;
	struct xfrm_state *x;
	struct softnet_data *sd;
	struct sk_buff *skb2, *pskb = NULL;
	netdev_features_t esp_features = features;
	struct xfrm_offload *xo = xfrm_offload(skb);

	if (!xo)
		return skb;

	if (!(features & NETIF_F_HW_ESP))
		esp_features = features & ~(NETIF_F_SG | NETIF_F_CSUM_MASK);

	x = skb->sp->xvec[skb->sp->len - 1];
	if (xo->flags & XFRM_GRO || x->xso.flags & XFRM_OFFLOAD_INBOUND)
		return skb;

	local_irq_save(flags);
	sd = this_cpu_ptr(&softnet_data);
	err = !skb_queue_empty(&sd->xfrm_backlog);
	local_irq_restore(flags);

	if (err) {
		*again = true;
		return skb;
	}

	if (skb_is_gso(skb)) {
		struct net_device *dev = skb->dev;

		if (unlikely(!x->xso.offload_handle || (x->xso.dev != dev))) {
			struct sk_buff *segs;

			/* Packet got rerouted, fixup features and segment it. */
			esp_features = esp_features & ~(NETIF_F_HW_ESP
							| NETIF_F_GSO_ESP);

			segs = skb_gso_segment(skb, esp_features);
			if (IS_ERR(segs)) {
				kfree_skb(skb);
				atomic_long_inc(&dev->tx_dropped);
				return NULL;
			} else {
				consume_skb(skb);
				skb = segs;
			}
		}
	}

	if (!skb->next) {
		x->outer_mode->xmit(x, skb);

		xo->flags |= XFRM_DEV_RESUME;

		err = x->type_offload->xmit(x, skb, esp_features);
		if (err) {
			if (err == -EINPROGRESS)
				return NULL;

			XFRM_INC_STATS(xs_net(x), LINUX_MIB_XFRMOUTSTATEPROTOERROR);
			kfree_skb(skb);
			return NULL;
		}

		skb_push(skb, skb->data - skb_mac_header(skb));

		return skb;
	}

	skb2 = skb;

	do {
		struct sk_buff *nskb = skb2->next;
		skb_mark_not_on_list(skb2);

		xo = xfrm_offload(skb2);
		xo->flags |= XFRM_DEV_RESUME;

		x->outer_mode->xmit(x, skb2);

		err = x->type_offload->xmit(x, skb2, esp_features);
		if (!err) {
			skb2->next = nskb;
		} else if (err != -EINPROGRESS) {
			XFRM_INC_STATS(xs_net(x), LINUX_MIB_XFRMOUTSTATEPROTOERROR);
			skb2->next = nskb;
			kfree_skb_list(skb2);
			return NULL;
		} else {
			if (skb == skb2)
				skb = nskb;
			else
				pskb->next = nskb;

			goto skip_push;
		}

		skb_push(skb2, skb2->data - skb_mac_header(skb2));
		pskb = skb2;

skip_push:
		skb2 = nskb;
	} while (skb2);

	/* skb_gso_segment() set skb->prev to the last segment, but async
	 * crypto may have stolen it above without updating ->prev.  Repoint
	 * it at the last retained segment so validate_xmit_skb_list() does
	 * not chain onto a segment now owned by the crypto engine.
	 */
	if (skb)
		skb->prev = pskb;

	return skb;
}
#endif


