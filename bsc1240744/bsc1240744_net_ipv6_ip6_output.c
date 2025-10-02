/*
 * bsc1240744_net_ipv6_ip6_output
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

/* klp-ccp: from net/ipv6/ip6_output.c */
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netdevice.h>

/* klp-ccp: from include/linux/if_arp.h */
#define _LINUX_IF_ARP_H

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/ipv6/ip6_output.c */
#include <linux/in6.h>
#include <linux/tcp.h>

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

/* klp-ccp: from include/uapi/linux/route.h */
#define _LINUX_ROUTE_H

#define	RTF_GATEWAY	0x0002		/* destination is a gateway	*/

/* klp-ccp: from net/ipv6/ip6_output.c */
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/bpf-cgroup.h>
#include <linux/netfilter.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>

/* klp-ccp: from include/net/ipv6.h */
static bool (*klpe_ip6_autoflowlabel)(struct net *net, const struct ipv6_pinfo *np);

static void (*klpe_ipv6_push_nfrag_opts)(struct sk_buff *skb, struct ipv6_txoptions *opt,
			  u8 *proto, struct in6_addr **daddr_p,
			  struct in6_addr *saddr);

static void (*klpe_ipv6_local_error)(struct sock *sk, int err, struct flowi6 *fl6, u32 info);

/* klp-ccp: from net/ipv6/ip6_output.c */
#include <net/ndisc.h>

#include <net/ip6_route.h>
#include <net/addrconf.h>

#include <net/checksum.h>

#include <net/l3mdev.h>
#include <net/lwtunnel.h>

int klpp_ip6_xmit(const struct sock *sk, struct sk_buff *skb, struct flowi6 *fl6,
	     __u32 mark, struct ipv6_txoptions *opt, int tclass)
{
	struct net *net = sock_net(sk);
	const struct ipv6_pinfo *np = inet6_sk(sk);
	struct in6_addr *first_hop = &fl6->daddr;
	struct dst_entry *dst = skb_dst(skb);
	unsigned int head_room;
	struct ipv6hdr *hdr;
	u8  proto = fl6->flowi6_proto;
	int seg_len = skb->len;
	int hlimit = -1;
	u32 mtu;

	head_room = sizeof(struct ipv6hdr) + LL_RESERVED_SPACE(dst->dev);
	if (opt)
		head_room += opt->opt_nflen + opt->opt_flen;

	if (unlikely(skb_headroom(skb) < head_room)) {
		struct sk_buff *skb2 = skb_realloc_headroom(skb, head_room);
		if (!skb2) {
			IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
				      IPSTATS_MIB_OUTDISCARDS);
			kfree_skb(skb);
			return -ENOBUFS;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		consume_skb(skb);
		skb = skb2;
	}

	if (opt) {
		seg_len += opt->opt_nflen + opt->opt_flen;

		if (opt->opt_flen)
			ipv6_push_frag_opts(skb, opt, &proto);

		if (opt->opt_nflen)
			(*klpe_ipv6_push_nfrag_opts)(skb, opt, &proto, &first_hop,
					     &fl6->saddr);
	}

	skb_push(skb, sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	hdr = ipv6_hdr(skb);

	/*
	 *	Fill in the IPv6 header
	 */
	if (np)
		hlimit = np->hop_limit;
	if (hlimit < 0)
		hlimit = ip6_dst_hoplimit(dst);

	ip6_flow_hdr(hdr, tclass, ip6_make_flowlabel(net, skb, fl6->flowlabel,
				(*klpe_ip6_autoflowlabel)(net, np), fl6));

	hdr->payload_len = htons(seg_len);
	hdr->nexthdr = proto;
	hdr->hop_limit = hlimit;

	hdr->saddr = fl6->saddr;
	hdr->daddr = *first_hop;

	skb->protocol = htons(ETH_P_IPV6);
	skb->priority = sk->sk_priority;
	skb->mark = mark;

	mtu = dst_mtu(dst);
	if ((skb->len <= mtu) || skb->ignore_df || skb_is_gso(skb)) {
		IP6_UPD_PO_STATS(net, ip6_dst_idev(skb_dst(skb)),
			      IPSTATS_MIB_OUT, skb->len);

		/* if egress device is enslaved to an L3 master device pass the
		 * skb to its handler for processing
		 */
		skb = klpr_l3mdev_ip6_out((struct sock *)sk, skb);
		if (unlikely(!skb))
			return 0;

		/* hooks should never assume socket lock is held.
		 * we promote our socket to non const
		 */
		return NF_HOOK(NFPROTO_IPV6, NF_INET_LOCAL_OUT,
			       net, (struct sock *)sk, skb, NULL, dst->dev,
			       dst_output);
	}

	skb->dev = dst->dev;
	/* ipv6_local_error() does not require socket lock,
	 * we promote our socket to non const
	 */
	(*klpe_ipv6_local_error)((struct sock *)sk, EMSGSIZE, fl6, mtu);

	IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)), IPSTATS_MIB_FRAGFAILS);
	kfree_skb(skb);
	return -EMSGSIZE;
}

typeof(klpp_ip6_xmit) klpp_ip6_xmit;


#include "livepatch_bsc1240744.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ip6_autoflowlabel", (void *)&klpe_ip6_autoflowlabel },
	{ "ipv6_local_error", (void *)&klpe_ipv6_local_error },
	{ "ipv6_push_nfrag_opts", (void *)&klpe_ipv6_push_nfrag_opts },
};

int bsc1240744_net_ipv6_ip6_output_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

