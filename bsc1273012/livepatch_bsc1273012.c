/*
 * livepatch_bsc1273012
 *
 * Fix for CVE-2026-63920, bsc#1273012
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


#include "livepatch_bsc1273012.h"


/* klp-ccp: from net/ipv6/datagram.c */
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in6.h>
#include <linux/ipv6.h>
#include <linux/route.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/icmp.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/addrconf.h>
#include <net/transp_v6.h>

/* klp-ccp: from include/net/transp_v6.h */
/* klp-ccp: from net/ipv6/datagram.c */
#include <net/ip6_route.h>
#include <net/tcp_states.h>
#include <net/dsfield.h>
#include <net/sock_reuseport.h>
#include <linux/errqueue.h>
#include <linux/uaccess.h>

static u16 klpp_ipv6_get_exthdr_len(const struct sk_buff *skb, const u8 *ptr)
{
	u16 len;

	if (ptr + 2 > skb_tail_pointer(skb))
		return 0;

	len = (ptr[1] + 1) << 3;

	return (len <= skb_tail_pointer(skb) - ptr) ? len : 0;
}

void klpp_ip6_datagram_recv_specific_ctl(struct sock *sk, struct msghdr *msg,
				    struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct inet6_skb_parm *opt = IP6CB(skb);
	unsigned char *nh = skb_network_header(skb);

	if (np->rxopt.bits.rxhlim) {
		int hlim = ipv6_hdr(skb)->hop_limit;
		put_cmsg(msg, SOL_IPV6, IPV6_HOPLIMIT, sizeof(hlim), &hlim);
	}

	if (np->rxopt.bits.rxtclass) {
		int tclass = ipv6_get_dsfield(ipv6_hdr(skb));
		put_cmsg(msg, SOL_IPV6, IPV6_TCLASS, sizeof(tclass), &tclass);
	}

	if (np->rxopt.bits.rxflow) {
		__be32 flowinfo = ip6_flowinfo((struct ipv6hdr *)nh);
		if (flowinfo)
			put_cmsg(msg, SOL_IPV6, IPV6_FLOWINFO, sizeof(flowinfo), &flowinfo);
	}

	/* HbH is allowed only once */
	if (np->rxopt.bits.hopopts && (opt->flags & IP6SKB_HOPBYHOP)) {
		u8 *ptr = nh + sizeof(struct ipv6hdr);
		u16 len = klpp_ipv6_get_exthdr_len(skb, ptr);

		if (len)
			put_cmsg(msg, SOL_IPV6, IPV6_HOPOPTS, len, ptr);
	}

	if (opt->lastopt &&
	    (np->rxopt.bits.dstopts || np->rxopt.bits.srcrt)) {
		/*
		 * Silly enough, but we need to reparse in order to
		 * report extension headers (except for HbH)
		 * in order.
		 *
		 * Also note that IPV6_RECVRTHDRDSTOPTS is NOT
		 * (and WILL NOT be) defined because
		 * IPV6_RECVDSTOPTS is more generic. --yoshfuji
		 */
		unsigned int off = sizeof(struct ipv6hdr);
		u8 nexthdr = ipv6_hdr(skb)->nexthdr;

		while (off <= opt->lastopt) {
			unsigned int len;
			u8 *ptr = nh + off;

			if (ptr + 2 > skb_tail_pointer(skb))
				return;

			switch (nexthdr) {
			case IPPROTO_DSTOPTS:
				nexthdr = ptr[0];
				len = klpp_ipv6_get_exthdr_len(skb, ptr);
				if (!len)
					return;
				if (np->rxopt.bits.dstopts)
					put_cmsg(msg, SOL_IPV6, IPV6_DSTOPTS, len, ptr);
				break;
			case IPPROTO_ROUTING:
				nexthdr = ptr[0];
				len = klpp_ipv6_get_exthdr_len(skb, ptr);
				if (!len)
					return;
				if (np->rxopt.bits.srcrt)
					put_cmsg(msg, SOL_IPV6, IPV6_RTHDR, len, ptr);
				break;
			case IPPROTO_AH:
				nexthdr = ptr[0];
				len = (ptr[1] + 2) << 2;
				if (ptr + len > skb_tail_pointer(skb))
					return;
				break;
			default:
				nexthdr = ptr[0];
				len = klpp_ipv6_get_exthdr_len(skb, ptr);
				if (!len)
					return;
				break;
			}

			off += len;
		}
	}

	/* socket options in old style */
	if (np->rxopt.bits.rxoinfo) {
		struct in6_pktinfo src_info;

		src_info.ipi6_ifindex = opt->iif;
		src_info.ipi6_addr = ipv6_hdr(skb)->daddr;
		put_cmsg(msg, SOL_IPV6, IPV6_2292PKTINFO, sizeof(src_info), &src_info);
	}
	if (np->rxopt.bits.rxohlim) {
		int hlim = ipv6_hdr(skb)->hop_limit;
		put_cmsg(msg, SOL_IPV6, IPV6_2292HOPLIMIT, sizeof(hlim), &hlim);
	}
	if (np->rxopt.bits.ohopopts && (opt->flags & IP6SKB_HOPBYHOP)) {
		u8 *ptr = nh + sizeof(struct ipv6hdr);
		u16 len = klpp_ipv6_get_exthdr_len(skb, ptr);

		if (len)
			put_cmsg(msg, SOL_IPV6, IPV6_2292HOPOPTS, len, ptr);
	}
	if (np->rxopt.bits.odstopts && opt->dst0) {
		u8 *ptr = nh + opt->dst0;
		u16 len = klpp_ipv6_get_exthdr_len(skb, ptr);

		if (len)
			put_cmsg(msg, SOL_IPV6, IPV6_2292DSTOPTS, len, ptr);
	}
	if (np->rxopt.bits.osrcrt && opt->srcrt) {
		struct ipv6_rt_hdr *rthdr = (struct ipv6_rt_hdr *)(nh + opt->srcrt);
		u16 len = klpp_ipv6_get_exthdr_len(skb, (u8 *)rthdr);

		if (len)
			put_cmsg(msg, SOL_IPV6, IPV6_2292RTHDR, len, rthdr);
	}
	if (np->rxopt.bits.odstopts && opt->dst1) {
		u8 *ptr = nh + opt->dst1;
		u16 len = klpp_ipv6_get_exthdr_len(skb, ptr);

		if (len)
			put_cmsg(msg, SOL_IPV6, IPV6_2292DSTOPTS, len, ptr);
	}
	if (np->rxopt.bits.rxorigdstaddr) {
		struct sockaddr_in6 sin6;
		__be16 _ports[2], *ports;

		ports = skb_header_pointer(skb, skb_transport_offset(skb),
					   sizeof(_ports), &_ports);
		if (ports) {
			/* All current transport protocols have the port numbers in the
			 * first four bytes of the transport header and this function is
			 * written with this assumption in mind.
			 */
			sin6.sin6_family = AF_INET6;
			sin6.sin6_addr = ipv6_hdr(skb)->daddr;
			sin6.sin6_port = ports[1];
			sin6.sin6_flowinfo = 0;
			sin6.sin6_scope_id =
				ipv6_iface_scope_id(&ipv6_hdr(skb)->daddr,
						    opt->iif);

			put_cmsg(msg, SOL_IPV6, IPV6_ORIGDSTADDR, sizeof(sin6), &sin6);
		}
	}
	if (np->rxopt.bits.recvfragsize && opt->frag_max_size) {
		int val = opt->frag_max_size;

		put_cmsg(msg, SOL_IPV6, IPV6_RECVFRAGSIZE, sizeof(val), &val);
	}
}


