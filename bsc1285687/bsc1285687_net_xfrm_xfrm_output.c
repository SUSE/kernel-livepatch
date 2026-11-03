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

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/gso.h>
#include <net/icmp.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>

/* klp-ccp: from include/net/xfrm.h */
int klpp_xfrm_output(struct sock *sk, struct sk_buff *skb);

/* klp-ccp: from net/xfrm/xfrm_output.c */
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_route.h>
#include <net/ipv6_stubs.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from net/xfrm/xfrm_inout.h */
#include <linux/ipv6.h>
#include <net/dsfield.h>
#include <net/xfrm.h>

/* klp-ccp: from net/xfrm/xfrm_output.c */
extern int xfrm_output2(struct net *net, struct sock *sk, struct sk_buff *skb);

int xfrm_output_resume(struct sock *sk, struct sk_buff *skb, int err);

int xfrm_output2(struct net *net, struct sock *sk, struct sk_buff *skb);

static int xfrm_output_gso(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct sk_buff *segs, *nskb;

	BUILD_BUG_ON(sizeof(*IPCB(skb)) > SKB_GSO_CB_OFFSET);
	BUILD_BUG_ON(sizeof(*IP6CB(skb)) > SKB_GSO_CB_OFFSET);
	segs = skb_gso_segment(skb, 0);
	kfree_skb(skb);
	if (IS_ERR(segs))
		return PTR_ERR(segs);
	if (segs == NULL)
		return -EINVAL;

	skb_list_walk_safe(segs, segs, nskb) {
		int err;

		skb_mark_not_on_list(segs);
		err = xfrm_output2(net, sk, segs);

		if (unlikely(err)) {
			kfree_skb_list(nskb);
			return err;
		}
	}

	return 0;
}

static void xfrm_get_inner_ipproto(struct sk_buff *skb, struct xfrm_state *x)
{
	struct xfrm_offload *xo = xfrm_offload(skb);
	const struct ethhdr *eth;

	if (!xo)
		return;

	if (x->outer_mode.encap == XFRM_MODE_TUNNEL) {
		switch (x->outer_mode.family) {
		case AF_INET:
			xo->inner_ipproto = ip_hdr(skb)->protocol;
			break;
		case AF_INET6:
			xo->inner_ipproto = ipv6_hdr(skb)->nexthdr;
			break;
		default:
			break;
		}

		return;
	}

	/* non-Tunnel Mode */
	if (!skb->encapsulation)
		return;

	if (skb->inner_protocol_type == ENCAP_TYPE_IPPROTO) {
		xo->inner_ipproto = skb->inner_ipproto;
		return;
	}

	if (skb->inner_protocol_type != ENCAP_TYPE_ETHER)
		return;

	eth = (struct ethhdr *)skb_inner_mac_header(skb);

	switch (ntohs(eth->h_proto)) {
	case ETH_P_IPV6:
		xo->inner_ipproto = inner_ipv6_hdr(skb)->nexthdr;
		break;
	case ETH_P_IP:
		xo->inner_ipproto = inner_ip_hdr(skb)->protocol;
		break;
	}
}

int klpp_xfrm_output(struct sock *sk, struct sk_buff *skb)
{
	struct net *net = dev_net(skb_dst(skb)->dev);
	struct xfrm_state *x = skb_dst(skb)->xfrm;
	int err;

	switch (x->outer_mode.family) {
	case AF_INET:
		memset(IPCB(skb), 0, sizeof(*IPCB(skb)));
		IPCB(skb)->flags |= IPSKB_XFRM_TRANSFORMED;
		break;
	case AF_INET6:
		memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));

		IP6CB(skb)->flags |= IP6SKB_XFRM_TRANSFORMED;
		break;
	}

	if (x->xso.type == XFRM_DEV_OFFLOAD_PACKET) {
		if (!xfrm_dev_offload_ok(skb, x)) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			return -EHOSTUNREACH;
		}

		return xfrm_output_resume(sk, skb, 0);
	}

	secpath_reset(skb);

	if (xfrm_dev_offload_ok(skb, x)) {
		struct sec_path *sp;

		sp = secpath_set(skb);
		if (!sp) {
			XFRM_INC_STATS(net, LINUX_MIB_XFRMOUTERROR);
			kfree_skb(skb);
			return -ENOMEM;
		}

		sp->olen++;
		sp->xvec[sp->len++] = x;
		xfrm_state_hold(x);

		xfrm_get_inner_ipproto(skb, x);
		skb->encapsulation = 1;

		if (skb_is_gso(skb)) {
			if (skb->inner_protocol)
				return xfrm_output_gso(net, sk, skb);

			skb_shinfo(skb)->gso_type |= SKB_GSO_ESP;
			goto out;
		}

		if (x->xso.dev && x->xso.dev->features & NETIF_F_HW_ESP_TX_CSUM)
			goto out;
	} else {
		if (skb_is_gso(skb))
			return xfrm_output_gso(net, sk, skb);
	}

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

#include <linux/livepatch.h>

extern typeof(xfrm_output2) xfrm_output2
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, xfrm_output2);
