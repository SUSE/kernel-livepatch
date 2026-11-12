/*
 * bsc1285687_net_bridge_netfilter_nf_conntrack_bridge
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

/* klp-ccp: from net/bridge/netfilter/nf_conntrack_bridge.c */
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter_bridge.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/icmp.h>
#include <linux/sysctl.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_bridge.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
/* klp-ccp: from net/bridge/br_private.h */
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/netpoll.h>
#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <net/pkt_cls.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>

struct br_input_skb_cb {
	struct net_device *brdev;

	u16 frag_max_size;
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	u8 igmp;
	u8 mrouters_only:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u8 proxyarp_replied:1;
	u8 src_port_isolated:1;
	u8 promisc:1;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	u8 vlan_filtered:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
	u8 br_netfilter_broute:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NET_SWITCHDEV
	/* Set if TX data plane offloading is used towards at least one
	 * hardware domain.
	 */
	u8 tx_fwd_offload:1;
	/* The switchdev hardware domain from which this packet was received.
	 * If skb->offload_fwd_mark was set, then this packet was already
	 * forwarded by hardware to the other ports in the source hardware
	 * domain, otherwise it wasn't.
	 */
	int src_hwdom;
	/* Bit mask of hardware domains towards this packet has already been
	 * transmitted using the TX data plane offload.
	 */
	unsigned long fwd_hwdoms;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

	u32 backup_nhid;
};

#define BR_INPUT_SKB_CB(__skb)	((struct br_input_skb_cb *)(__skb)->cb)

/* klp-ccp: from net/bridge/netfilter/nf_conntrack_bridge.c */
static int klpp_nf_br_ip_fragment(struct net *net, struct sock *sk,
			     struct sk_buff *skb,
			     struct nf_bridge_frag_data *data,
			     int (*output)(struct net *, struct sock *sk,
					   const struct nf_bridge_frag_data *data,
					   struct sk_buff *))
{
	int frag_max_size = BR_INPUT_SKB_CB(skb)->frag_max_size;
	bool mono_delivery_time = skb->mono_delivery_time;
	unsigned int hlen, ll_rs, mtu;
	ktime_t tstamp = skb->tstamp;
	struct ip_frag_state state;
	struct iphdr *iph;
	int err = 0;

	/* for offloaded checksums cleanup checksum before fragmentation */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = ip_check_csum_start(skb);
		if (!err)
			err = skb_checksum_help(skb);
		if (err)
			goto blackhole;
	}

	iph = ip_hdr(skb);

	/*
	 *	Setup starting values
	 */

	hlen = iph->ihl * 4;
	frag_max_size -= hlen;
	ll_rs = LL_RESERVED_SPACE(skb->dev);
	mtu = skb->dev->mtu;

	if (skb_has_frag_list(skb)) {
		unsigned int first_len = skb_pagelen(skb);
		struct ip_fraglist_iter iter;
		struct sk_buff *frag;

		if (first_len - hlen > mtu ||
		    skb_headroom(skb) < ll_rs)
			goto blackhole;

		if (skb_cloned(skb))
			goto slow_path;

		skb_walk_frags(skb, frag) {
			if (frag->len > mtu ||
			    skb_headroom(frag) < hlen + ll_rs)
				goto blackhole;

			if (skb_shared(frag))
				goto slow_path;
		}

		ip_fraglist_init(skb, iph, hlen, &iter);

		for (;;) {
			if (iter.frag)
				ip_fraglist_prepare(skb, &iter);

			skb_set_delivery_time(skb, tstamp, mono_delivery_time);
			err = output(net, sk, data, skb);
			if (err || !iter.frag)
				break;

			skb = ip_fraglist_next(&iter);
		}

		if (!err)
			return 0;

		kfree_skb_list(iter.frag);

		return err;
	}
slow_path:
	/* This is a linearized skbuff, the original geometry is lost for us.
	 * This may also be a clone skbuff, we could preserve the geometry for
	 * the copies but probably not worth the effort.
	 */
	ip_frag_init(skb, hlen, ll_rs, frag_max_size, false, &state);

	while (state.left > 0) {
		struct sk_buff *skb2;

		skb2 = ip_frag_next(skb, &state);
		if (IS_ERR(skb2)) {
			err = PTR_ERR(skb2);
			goto blackhole;
		}

		skb_set_delivery_time(skb2, tstamp, mono_delivery_time);
		err = output(net, sk, data, skb2);
		if (err)
			goto blackhole;
	}
	consume_skb(skb);
	return err;

blackhole:
	kfree_skb(skb);
	return 0;
}

static void nf_ct_bridge_frag_save(struct sk_buff *skb,
				   struct nf_bridge_frag_data *data)
{
	if (skb_vlan_tag_present(skb)) {
		data->vlan_present = true;
		data->vlan_tci = skb->vlan_tci;
		data->vlan_proto = skb->vlan_proto;
	} else {
		data->vlan_present = false;
	}
	skb_copy_from_linear_data_offset(skb, -ETH_HLEN, data->mac, ETH_HLEN);
}

static unsigned int
klpr_nf_ct_bridge_refrag(struct sk_buff *skb, const struct nf_hook_state *state,
		    int (*output)(struct net *, struct sock *sk,
				  const struct nf_bridge_frag_data *data,
				  struct sk_buff *))
{
	struct nf_bridge_frag_data data;

	if (!BR_INPUT_SKB_CB(skb)->frag_max_size)
		return NF_ACCEPT;

	nf_ct_bridge_frag_save(skb, &data);
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		klpp_nf_br_ip_fragment(state->net, state->sk, skb, &data, output);
		break;
	case htons(ETH_P_IPV6):
		nf_br_ip6_fragment(state->net, state->sk, skb, &data, output);
		break;
	default:
		WARN_ON_ONCE(1);
		return NF_DROP;
	}

	return NF_STOLEN;
}

extern int nf_ct_bridge_refrag_post(struct net *net, struct sock *sk,
				    const struct nf_bridge_frag_data *data,
				    struct sk_buff *skb);

extern unsigned int klpp_nf_ct_bridge_post(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	int ret;

	ret = nf_confirm(priv, skb, state);
	if (ret != NF_ACCEPT)
		return ret;

	return klpr_nf_ct_bridge_refrag(skb, state, nf_ct_bridge_refrag_post);
}


#include <linux/livepatch.h>

extern typeof(nf_confirm) nf_confirm
	 KLP_RELOC_SYMBOL(nf_conntrack_bridge, nf_conntrack, nf_confirm);
extern typeof(nf_ct_bridge_refrag_post) nf_ct_bridge_refrag_post
	 KLP_RELOC_SYMBOL(nf_conntrack_bridge, nf_conntrack_bridge, nf_ct_bridge_refrag_post);
