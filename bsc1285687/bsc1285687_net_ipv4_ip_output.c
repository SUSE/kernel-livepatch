/*
 * bsc1285687_net_ipv4_ip_output
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

/* klp-ccp: from net/ipv4/ip_output.c */
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <net/snmp.h>
#include <net/ip.h>

/* klp-ccp: from include/net/ip.h */
int klpp_ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		   int (*output)(struct net *, struct sock *, struct sk_buff *));

/* klp-ccp: from net/ipv4/ip_output.c */
#include <net/protocol.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <net/gso.h>
#include <net/inetpeer.h>
#include <net/inet_ecn.h>
#include <net/lwtunnel.h>
#include <linux/bpf-cgroup.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/netlink.h>
#include <linux/tcp.h>

void ip_send_check(struct iphdr *iph);

void ip_fraglist_init(struct sk_buff *skb, struct iphdr *iph,
		      unsigned int hlen, struct ip_fraglist_iter *iter);

void ip_fraglist_prepare(struct sk_buff *skb, struct ip_fraglist_iter *iter);

void ip_frag_init(struct sk_buff *skb, unsigned int hlen,
		  unsigned int ll_rs, unsigned int mtu, bool DF,
		  struct ip_frag_state *state);

static void ip_frag_ipcb(struct sk_buff *from, struct sk_buff *to,
			 bool first_frag)
{
	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

	/* ANK: dirty, but effective trick. Upgrade options only if
	 * the segment to be fragmented was THE FIRST (otherwise,
	 * options are already fixed) and make it ONCE
	 * on the initial skb, so that all the following fragments
	 * will inherit fixed options.
	 */
	if (first_frag)
		ip_options_fragment(from);
}

struct sk_buff *ip_frag_next(struct sk_buff *skb, struct ip_frag_state *state);

int klpp_ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		   int (*output)(struct net *, struct sock *, struct sk_buff *))
{
	struct iphdr *iph;
	struct sk_buff *skb2;
	bool mono_delivery_time = skb->mono_delivery_time;
	struct rtable *rt = skb_rtable(skb);
	unsigned int mtu, hlen, ll_rs;
	struct ip_fraglist_iter iter;
	ktime_t tstamp = skb->tstamp;
	struct ip_frag_state state;
	int err = 0;

	/* for offloaded checksums cleanup checksum before fragmentation */
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		err = ip_check_csum_start(skb);
		if (!err)
			err = skb_checksum_help(skb);
		if (err)
			goto fail;
	}

	/*
	 *	Point into the IP datagram header.
	 */

	iph = ip_hdr(skb);

	mtu = ip_skb_dst_mtu(sk, skb);
	if (IPCB(skb)->frag_max_size && IPCB(skb)->frag_max_size < mtu)
		mtu = IPCB(skb)->frag_max_size;

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	if (mtu < hlen + 8) {
		err = -EMSGSIZE;
		goto fail;
	}
	mtu = mtu - hlen;	/* Size of data space */
	IPCB(skb)->flags |= IPSKB_FRAG_COMPLETE;
	ll_rs = LL_RESERVED_SPACE(rt->dst.dev);

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	if (skb_has_frag_list(skb)) {
		struct sk_buff *frag, *frag2;
		unsigned int first_len = skb_pagelen(skb);

		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    ip_is_fragment(iph) ||
		    skb_cloned(skb) ||
		    skb_headroom(skb) < ll_rs)
			goto slow_path;

		skb_walk_frags(skb, frag) {
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen + ll_rs)
				goto slow_path_clean;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path_clean;

			BUG_ON(frag->sk);
			if (skb->sk) {
				frag->sk = skb->sk;
				frag->destructor = sock_wfree;
			}
			skb->truesize -= frag->truesize;
		}

		/* Everything is OK. Generate! */
		ip_fraglist_init(skb, iph, hlen, &iter);

		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (iter.frag) {
				bool first_frag = (iter.offset == 0);

				IPCB(iter.frag)->flags = IPCB(skb)->flags;
				ip_fraglist_prepare(skb, &iter);
				if (first_frag && IPCB(skb)->opt.optlen) {
					/* ipcb->opt is not populated for frags
					 * coming from __ip_make_skb(),
					 * ip_options_fragment() needs optlen
					 */
					IPCB(iter.frag)->opt.optlen =
						IPCB(skb)->opt.optlen;
					ip_options_fragment(iter.frag);
					ip_send_check(iter.iph);
				}
			}

			skb_set_delivery_time(skb, tstamp, mono_delivery_time);
			err = output(net, sk, skb);

			if (!err)
				IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
			if (err || !iter.frag)
				break;

			skb = ip_fraglist_next(&iter);
		}

		if (err == 0) {
			IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		kfree_skb_list(iter.frag);

		IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
		return err;

slow_path_clean:
		skb_walk_frags(skb, frag2) {
			if (frag2 == frag)
				break;
			frag2->sk = NULL;
			frag2->destructor = NULL;
			skb->truesize += frag2->truesize;
		}
	}

slow_path:
	/*
	 *	Fragment the datagram.
	 */

	ip_frag_init(skb, hlen, ll_rs, mtu, IPCB(skb)->flags & IPSKB_FRAG_PMTU,
		     &state);

	/*
	 *	Keep copying data until we run out.
	 */

	while (state.left > 0) {
		bool first_frag = (state.offset == 0);

		skb2 = ip_frag_next(skb, &state);
		if (IS_ERR(skb2)) {
			err = PTR_ERR(skb2);
			goto fail;
		}
		ip_frag_ipcb(skb, skb2, first_frag);

		/*
		 *	Put this fragment into the sending queue.
		 */
		skb_set_delivery_time(skb2, tstamp, mono_delivery_time);
		err = output(net, sk, skb2);
		if (err)
			goto fail;

		IP_INC_STATS(net, IPSTATS_MIB_FRAGCREATES);
	}
	consume_skb(skb);
	IP_INC_STATS(net, IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb);
	IP_INC_STATS(net, IPSTATS_MIB_FRAGFAILS);
	return err;
}


#include <linux/livepatch.h>

extern typeof(ip_options_fragment) ip_options_fragment
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip_options_fragment);
