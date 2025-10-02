/*
 * bsc1240744_net_ipv6_output_core
 *
 * Fix for CVE-2025-21791, bsc#1240744
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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


#define __KERNEL__ 1
#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1

/* klp-ccp: from include/linux/export.h */
#define _LINUX_EXPORT_H

#define THIS_MODULE ((struct module *)0)

/* klp-ccp: from net/ipv6/output_core.c */
#include <net/ip.h>

/* klp-ccp: from include/net/l3mdev.h */
#ifdef CONFIG_NET_L3_MASTER_DEV

static inline
struct sk_buff *klpp_l3mdev_l3_out(struct sock *sk, struct sk_buff *skb, u16 proto)
{
	struct net_device *dev = skb_dst(skb)->dev;

	if (netif_is_l3_slave(dev)) {
		struct net_device *master;

		rcu_read_lock();
		master = netdev_master_upper_dev_get_rcu(dev);
		if (master && master->l3mdev_ops->l3mdev_l3_out)
			skb = master->l3mdev_ops->l3mdev_l3_out(master, sk,
								skb, proto);
		rcu_read_unlock();
	}

	return skb;
}

static inline
struct sk_buff *klpr_l3mdev_ip6_out(struct sock *sk, struct sk_buff *skb)
{
	return klpp_l3mdev_l3_out(sk, skb, AF_INET6);
}
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/ipv6/output_core.c */
#include <net/ipv6.h>

#include <linux/netfilter.h>

int klpp___ip6_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int len;

	len = skb->len - sizeof(struct ipv6hdr);
	if (len > IPV6_MAXPLEN)
		len = 0;
	ipv6_hdr(skb)->payload_len = htons(len);
	IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = klpr_l3mdev_ip6_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IPV6);

	return nf_hook(NFPROTO_IPV6, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}

typeof(klpp___ip6_local_out) klpp___ip6_local_out;


#include "livepatch_bsc1240744.h"

