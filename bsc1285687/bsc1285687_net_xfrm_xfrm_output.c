/*
 * bsc1285687_net_xfrm_xfrm_output
 *
 * Fix for CVE-2026-99999, bsc#1285687
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1285687.h"


/* klp-ccp: from net/xfrm/xfrm_output.c */
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>

/* klp-ccp: from include/net/xfrm.h */
int klpp_xfrm_output(struct sock *sk, struct sk_buff *skb);

/* klp-ccp: from net/xfrm/xfrm_output.c */
static int xfrm_output2(struct net *net, struct sock *sk, struct sk_buff *skb);

int xfrm_output_resume(struct sk_buff *skb, int err);

static int xfrm_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	return xfrm_output_resume(skb, 1);
}

static int xfrm_output_gso(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff *segs;

	BUILD_BUG_ON(sizeof(*IPCB(skb)) > SKB_SGO_CB_OFFSET);
	BUILD_BUG_ON(sizeof(*IP6CB(skb)) > SKB_SGO_CB_OFFSET);
	segs = skb_gso_segment(skb, 0);
	kfree_skb(skb);
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (segs == NULL)
		return -EINVAL;

	do {
		struct sk_buff *nskb = segs->next;
		int err;

		skb_mark_not_on_list(segs);
		err = xfrm_output2(net, sk, segs);

		if (unlikely(err)) {
			kfree_skb_list(nskb);
			return err;
		}

		segs = nskb;
	} while (segs);

	return 0;
}

int klpp_xfrm_output(struct sock *sk, struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct xfrm_state *x = skb_dst(skb)->xfrm;
	int err;

	secpath_reset(skb);

	if (xfrm_dev_offload_ok(skb, x)) {
		struct sec_path *sp;

		sp = secpath_dup(skb->sp);
		if (!sp) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sp)
			secpath_put(skb->sp);
		skb->sp = sp;
		skb->encapsulation = 1;

		sp->olen++;
		sp->xvec[skb->sp->len++] = x;
		xfrm_state_hold(x);

		if (skb_is_gso(skb)) {
			skb_shinfo(skb)->gso_type |= SKB_GSO_ESP;

			return xfrm_output2(net, sk, skb);
		}

		if (x->xso.dev && x->xso.dev->features & NETIF_F_HW_ESP_TX_CSUM)
			goto out;
	}

	if (skb_is_gso(skb))
		return xfrm_output_gso(net, sk, skb);

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if (skb->protocol == htons(ETH_P_IP)) {
			err = ip_check_csum_start(skb);
			if (err)
				goto error;
		}
		err = skb_checksum_help(skb);
		if (err)
			goto error;
	}

out:
	return xfrm_output2(net, sk, skb);
error:
	XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
	kfree_skb(skb);
	return err;
}


