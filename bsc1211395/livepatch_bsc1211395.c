/*
 * livepatch_bsc1211395
 *
 * Fix for CVE-2023-2156, bsc#1211395
 *
 *  Upstream commit:
 *  4e006c7a6dac ("net: rpl: fix rpl header size calculation")
 *  a2f4c143d76b ("ipv6: rpl: Fix Route of Death.")
 *
 *  SLE12-SP5, SLE15-SP1 and -SP2 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  884cd150671de4ac3ebfe4313762074df22e33e8
 *  5601bfa509d6145f887513f07bb8cdc614152857
 *
 *  SLE15-SP4 and -SP5 commit:
 *  c308d834c6e6432315236add3121669ce763f368
 *  c2f8329a79699ffcbf510db4ab1238f8c778a187
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from net/ipv6/exthdrs.c */
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/icmpv6.h>

/* klp-ccp: from include/linux/icmpv6.h */
static void				(*klpe_icmpv6_param_prob)(struct sk_buff *skb,
							  u8 code, int pos);

/* klp-ccp: from net/ipv6/exthdrs.c */
#include <linux/slab.h>
#include <linux/export.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/snmp.h>
#include <net/ipv6.h>
#include <net/ndisc.h>
#include <net/ip6_route.h>

/* klp-ccp: from include/net/addrconf.h */
#if defined(CONFIG_IPV6_MIP6) || defined(CONFIG_IPV6_MIP6_MODULE)
static int (*klpe_ipv6_chk_home_addr)(struct net *net, const struct in6_addr *addr);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static int (*klpe_ipv6_chk_rpl_srh_loop)(struct net *net, const struct in6_addr *segs,
			  unsigned char nsegs);

/* klp-ccp: from include/net/ip6_route.h */
static void (*klpe_ip6_route_input)(struct sk_buff *skb);

/* klp-ccp: from net/ipv6/exthdrs.c */
#include <net/addrconf.h>

#if IS_ENABLED(CONFIG_IPV6_MIP6)
#include <net/xfrm.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <linux/seg6.h>
#include <net/seg6.h>
#ifdef CONFIG_IPV6_SEG6_HMAC
#include <net/seg6_hmac.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <net/rpl.h>

/* klp-ccp: from include/net/rpl.h */
static size_t (*klpe_ipv6_rpl_srh_size)(unsigned char n, unsigned char cmpri,
			 unsigned char cmpre);

static void (*klpe_ipv6_rpl_srh_decompress)(struct ipv6_rpl_sr_hdr *outhdr,
			     const struct ipv6_rpl_sr_hdr *inhdr,
			     const struct in6_addr *daddr, unsigned char n);

static void (*klpe_ipv6_rpl_srh_compress)(struct ipv6_rpl_sr_hdr *outhdr,
			   const struct ipv6_rpl_sr_hdr *inhdr,
			   const struct in6_addr *daddr, unsigned char n);

/* klp-ccp: from net/ipv6/exthdrs.c */
#include <linux/uaccess.h>

static void seg6_update_csum(struct sk_buff *skb)
{
	struct ipv6_sr_hdr *hdr;
	struct in6_addr *addr;
	__be32 from, to;

	/* srh is at transport offset and seg_left is already decremented
	 * but daddr is not yet updated with next segment
	 */

	hdr = (struct ipv6_sr_hdr *)skb_transport_header(skb);
	addr = hdr->segments + hdr->segments_left;

	hdr->segments_left++;
	from = *(__be32 *)hdr;

	hdr->segments_left--;
	to = *(__be32 *)hdr;

	/* update skb csum with diff resulting from seg_left decrement */

	update_csum_diff4(skb, from, to);

	/* compute csum diff between current and next segment and update */

	update_csum_diff16(skb, (__be32 *)(&ipv6_hdr(skb)->daddr),
			   (__be32 *)addr);
}

static int klpr_ipv6_srh_rcv(struct sk_buff *skb)
{
	struct inet6_skb_parm *opt = IP6CB(skb);
	struct net *net = dev_net(skb->dev);
	struct ipv6_sr_hdr *hdr;
	struct inet6_dev *idev;
	struct in6_addr *addr;
	int accept_seg6;

	hdr = (struct ipv6_sr_hdr *)skb_transport_header(skb);

	idev = __in6_dev_get(skb->dev);

	accept_seg6 = net->ipv6.devconf_all->seg6_enabled;
	if (accept_seg6 > idev->cnf.seg6_enabled)
		accept_seg6 = idev->cnf.seg6_enabled;

	if (!accept_seg6) {
		kfree_skb(skb);
		return -1;
	}

#ifdef CONFIG_IPV6_SEG6_HMAC
	if (!seg6_hmac_validate_skb(skb)) {
		kfree_skb(skb);
		return -1;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
looped_back:
	if (hdr->segments_left == 0) {
		if (hdr->nexthdr == NEXTHDR_IPV6 || hdr->nexthdr == NEXTHDR_IPV4) {
			int offset = (hdr->hdrlen + 1) << 3;

			skb_postpull_rcsum(skb, skb_network_header(skb),
					   skb_network_header_len(skb));

			if (!pskb_pull(skb, offset)) {
				kfree_skb(skb);
				return -1;
			}
			skb_postpull_rcsum(skb, skb_transport_header(skb),
					   offset);

			skb_reset_network_header(skb);
			skb_reset_transport_header(skb);
			skb->encapsulation = 0;
			if (hdr->nexthdr == NEXTHDR_IPV4)
				skb->protocol = htons(ETH_P_IP);
			__skb_tunnel_rx(skb, skb->dev, net);

			netif_rx(skb);
			return -1;
		}

		opt->srcrt = skb_network_header_len(skb);
		opt->lastopt = opt->srcrt;
		skb->transport_header += (hdr->hdrlen + 1) << 3;
		opt->nhoff = (&hdr->nexthdr) - skb_network_header(skb);

		return 1;
	}

	if (hdr->segments_left >= (hdr->hdrlen >> 1)) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
		(*klpe_icmpv6_param_prob)(skb, ICMPV6_HDR_FIELD,
				  ((&hdr->segments_left) -
				   skb_network_header(skb)));
		return -1;
	}

	if (skb_cloned(skb)) {
		if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) {
			__IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
					IPSTATS_MIB_OUTDISCARDS);
			kfree_skb(skb);
			return -1;
		}
	}

	hdr = (struct ipv6_sr_hdr *)skb_transport_header(skb);

	hdr->segments_left--;
	addr = hdr->segments + hdr->segments_left;

	skb_push(skb, sizeof(struct ipv6hdr));

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		seg6_update_csum(skb);

	ipv6_hdr(skb)->daddr = *addr;

	skb_dst_drop(skb);

	(*klpe_ip6_route_input)(skb);

	if (skb_dst(skb)->error) {
		dst_input(skb);
		return -1;
	}

	if (skb_dst(skb)->dev->flags & IFF_LOOPBACK) {
		if (ipv6_hdr(skb)->hop_limit <= 1) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			icmpv6_send(skb, ICMPV6_TIME_EXCEED,
				    ICMPV6_EXC_HOPLIMIT, 0);
			kfree_skb(skb);
			return -1;
		}
		ipv6_hdr(skb)->hop_limit--;

		skb_pull(skb, sizeof(struct ipv6hdr));
		goto looped_back;
	}

	dst_input(skb);

	return -1;
}

static int klpp_ipv6_rpl_srh_rcv(struct sk_buff *skb)
{
	struct ipv6_rpl_sr_hdr *hdr, *ohdr, *chdr;
	struct inet6_skb_parm *opt = IP6CB(skb);
	struct net *net = dev_net(skb->dev);
	struct inet6_dev *idev;
	struct ipv6hdr *oldhdr;
	struct in6_addr addr;
	unsigned char *buf;
	int accept_rpl_seg;
	int i, err;
	u64 n = 0;
	u32 r;

	idev = __in6_dev_get(skb->dev);

	accept_rpl_seg = net->ipv6.devconf_all->rpl_seg_enabled;
	if (accept_rpl_seg > idev->cnf.rpl_seg_enabled)
		accept_rpl_seg = idev->cnf.rpl_seg_enabled;

	if (!accept_rpl_seg) {
		kfree_skb(skb);
		return -1;
	}

looped_back:
	hdr = (struct ipv6_rpl_sr_hdr *)skb_transport_header(skb);

	if (hdr->segments_left == 0) {
		if (hdr->nexthdr == NEXTHDR_IPV6) {
			int offset = (hdr->hdrlen + 1) << 3;

			skb_postpull_rcsum(skb, skb_network_header(skb),
					   skb_network_header_len(skb));

			if (!pskb_pull(skb, offset)) {
				kfree_skb(skb);
				return -1;
			}
			skb_postpull_rcsum(skb, skb_transport_header(skb),
					   offset);

			skb_reset_network_header(skb);
			skb_reset_transport_header(skb);
			skb->encapsulation = 0;

			__skb_tunnel_rx(skb, skb->dev, net);

			netif_rx(skb);
			return -1;
		}

		opt->srcrt = skb_network_header_len(skb);
		opt->lastopt = opt->srcrt;
		skb->transport_header += (hdr->hdrlen + 1) << 3;
		opt->nhoff = (&hdr->nexthdr) - skb_network_header(skb);

		return 1;
	}

	if (!pskb_may_pull(skb, sizeof(*hdr))) {
		kfree_skb(skb);
		return -1;
	}

	n = (hdr->hdrlen << 3) - hdr->pad - (16 - hdr->cmpre);
	r = do_div(n, (16 - hdr->cmpri));
	/* checks if calculation was without remainder and n fits into
	 * unsigned char which is segments_left field. Should not be
	 * higher than that.
	 */
	if (r || (n + 1) > 255) {
		kfree_skb(skb);
		return -1;
	}

	if (hdr->segments_left > n + 1) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
		(*klpe_icmpv6_param_prob)(skb, ICMPV6_HDR_FIELD,
				  ((&hdr->segments_left) -
				   skb_network_header(skb)));
		return -1;
	}

	hdr = (struct ipv6_rpl_sr_hdr *)skb_transport_header(skb);

	if (!pskb_may_pull(skb, (*klpe_ipv6_rpl_srh_size)(n, hdr->cmpri,
						  hdr->cmpre))) {
		kfree_skb(skb);
		return -1;
	}

	hdr->segments_left--;
	i = n - hdr->segments_left;

	buf = kcalloc(struct_size(hdr, segments.addr, n + 2), 2, GFP_ATOMIC);
	if (unlikely(!buf)) {
		kfree_skb(skb);
		return -1;
	}

	ohdr = (struct ipv6_rpl_sr_hdr *)buf;
	(*klpe_ipv6_rpl_srh_decompress)(ohdr, hdr, &ipv6_hdr(skb)->daddr, n);
	chdr = (struct ipv6_rpl_sr_hdr *)(buf + ((ohdr->hdrlen + 1) << 3));

	if ((ipv6_addr_type(&ipv6_hdr(skb)->daddr) & IPV6_ADDR_MULTICAST) ||
	    (ipv6_addr_type(&ohdr->rpl_segaddr[i]) & IPV6_ADDR_MULTICAST)) {
		kfree_skb(skb);
		kfree(buf);
		return -1;
	}

	err = (*klpe_ipv6_chk_rpl_srh_loop)(net, ohdr->rpl_segaddr, n + 1);
	if (err) {
		icmpv6_send(skb, ICMPV6_PARAMPROB, 0, 0);
		kfree_skb(skb);
		kfree(buf);
		return -1;
	}

	addr = ipv6_hdr(skb)->daddr;
	ipv6_hdr(skb)->daddr = ohdr->rpl_segaddr[i];
	ohdr->rpl_segaddr[i] = addr;

	(*klpe_ipv6_rpl_srh_compress)(chdr, ohdr, &ipv6_hdr(skb)->daddr, n);

	oldhdr = ipv6_hdr(skb);

	skb_pull(skb, ((hdr->hdrlen + 1) << 3));
	skb_postpull_rcsum(skb, oldhdr,
			   sizeof(struct ipv6hdr) + ((hdr->hdrlen + 1) << 3));
	if (unlikely(!hdr->segments_left)) {
		if (pskb_expand_head(skb, sizeof(struct ipv6hdr) + ((chdr->hdrlen + 1) << 3), 0,
				     GFP_ATOMIC)) {
			__IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
					IPSTATS_MIB_OUTDISCARDS);
			kfree_skb(skb);
			kfree(buf);
			return -1;
		}

		oldhdr = ipv6_hdr(skb);
	}
	skb_push(skb, ((chdr->hdrlen + 1) << 3) + sizeof(struct ipv6hdr));
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	memmove(ipv6_hdr(skb), oldhdr, sizeof(struct ipv6hdr));
	memcpy(skb_transport_header(skb), chdr, (chdr->hdrlen + 1) << 3);

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_postpush_rcsum(skb, ipv6_hdr(skb),
			   sizeof(struct ipv6hdr) + ((chdr->hdrlen + 1) << 3));

	kfree(buf);

	skb_dst_drop(skb);

	(*klpe_ip6_route_input)(skb);

	if (skb_dst(skb)->error) {
		dst_input(skb);
		return -1;
	}

	if (skb_dst(skb)->dev->flags & IFF_LOOPBACK) {
		if (ipv6_hdr(skb)->hop_limit <= 1) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			icmpv6_send(skb, ICMPV6_TIME_EXCEED,
				    ICMPV6_EXC_HOPLIMIT, 0);
			kfree_skb(skb);
			return -1;
		}
		ipv6_hdr(skb)->hop_limit--;

		skb_pull(skb, sizeof(struct ipv6hdr));
		goto looped_back;
	}

	dst_input(skb);

	return -1;
}

int klpp_ipv6_rthdr_rcv(struct sk_buff *skb)
{
	struct inet6_dev *idev = __in6_dev_get(skb->dev);
	struct inet6_skb_parm *opt = IP6CB(skb);
	struct in6_addr *addr = NULL;
	struct in6_addr daddr;
	int n, i;
	struct ipv6_rt_hdr *hdr;
	struct rt0_hdr *rthdr;
	struct net *net = dev_net(skb->dev);
	int accept_source_route = net->ipv6.devconf_all->accept_source_route;

	idev = __in6_dev_get(skb->dev);
	if (idev && accept_source_route > idev->cnf.accept_source_route)
		accept_source_route = idev->cnf.accept_source_route;

	if (!pskb_may_pull(skb, skb_transport_offset(skb) + 8) ||
	    !pskb_may_pull(skb, (skb_transport_offset(skb) +
				 ((skb_transport_header(skb)[1] + 1) << 3)))) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
		kfree_skb(skb);
		return -1;
	}

	hdr = (struct ipv6_rt_hdr *)skb_transport_header(skb);

	if (ipv6_addr_is_multicast(&ipv6_hdr(skb)->daddr) ||
	    skb->pkt_type != PACKET_HOST) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INADDRERRORS);
		kfree_skb(skb);
		return -1;
	}

	switch (hdr->type) {
	case IPV6_SRCRT_TYPE_4:
		/* segment routing */
		return klpr_ipv6_srh_rcv(skb);
	case IPV6_SRCRT_TYPE_3:
		/* rpl segment routing */
		return klpp_ipv6_rpl_srh_rcv(skb);
	default:
		break;
	}

looped_back:
	if (hdr->segments_left == 0) {
		switch (hdr->type) {
#if IS_ENABLED(CONFIG_IPV6_MIP6)
		case IPV6_SRCRT_TYPE_2:
			/* Silently discard type 2 header unless it was
			 * processed by own
			 */
			if (!addr) {
				__IP6_INC_STATS(net, idev,
						IPSTATS_MIB_INADDRERRORS);
				kfree_skb(skb);
				return -1;
			}
			break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		default:
			break;
		}

		opt->lastopt = opt->srcrt = skb_network_header_len(skb);
		skb->transport_header += (hdr->hdrlen + 1) << 3;
		opt->dst0 = opt->dst1;
		opt->dst1 = 0;
		opt->nhoff = (&hdr->nexthdr) - skb_network_header(skb);
		return 1;
	}

	switch (hdr->type) {
#if IS_ENABLED(CONFIG_IPV6_MIP6)
	case IPV6_SRCRT_TYPE_2:
		if (accept_source_route < 0)
			goto unknown_rh;
		/* Silently discard invalid RTH type 2 */
		if (hdr->hdrlen != 2 || hdr->segments_left != 1) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			kfree_skb(skb);
			return -1;
		}
		break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	default:
		goto unknown_rh;
	}

	/*
	 *	This is the routing header forwarding algorithm from
	 *	RFC 2460, page 16.
	 */

	n = hdr->hdrlen >> 1;

	if (hdr->segments_left > n) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
		(*klpe_icmpv6_param_prob)(skb, ICMPV6_HDR_FIELD,
				  ((&hdr->segments_left) -
				   skb_network_header(skb)));
		return -1;
	}

	/* We are about to mangle packet header. Be careful!
	   Do not damage packets queued somewhere.
	 */
	if (skb_cloned(skb)) {
		/* the copy is a forwarded packet */
		if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) {
			__IP6_INC_STATS(net, ip6_dst_idev(skb_dst(skb)),
					IPSTATS_MIB_OUTDISCARDS);
			kfree_skb(skb);
			return -1;
		}
		hdr = (struct ipv6_rt_hdr *)skb_transport_header(skb);
	}

	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->ip_summed = CHECKSUM_NONE;

	i = n - --hdr->segments_left;

	rthdr = (struct rt0_hdr *) hdr;
	addr = rthdr->addr;
	addr += i - 1;

	switch (hdr->type) {
#if IS_ENABLED(CONFIG_IPV6_MIP6)
	case IPV6_SRCRT_TYPE_2:
		if (xfrm6_input_addr(skb, (xfrm_address_t *)addr,
				     (xfrm_address_t *)&ipv6_hdr(skb)->saddr,
				     IPPROTO_ROUTING) < 0) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INADDRERRORS);
			kfree_skb(skb);
			return -1;
		}
		if (!(*klpe_ipv6_chk_home_addr)(dev_net(skb_dst(skb)->dev), addr)) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INADDRERRORS);
			kfree_skb(skb);
			return -1;
		}
		break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	default:
		break;
	}

	if (ipv6_addr_is_multicast(addr)) {
		__IP6_INC_STATS(net, idev, IPSTATS_MIB_INADDRERRORS);
		kfree_skb(skb);
		return -1;
	}

	daddr = *addr;
	*addr = ipv6_hdr(skb)->daddr;
	ipv6_hdr(skb)->daddr = daddr;

	skb_dst_drop(skb);
	(*klpe_ip6_route_input)(skb);
	if (skb_dst(skb)->error) {
		skb_push(skb, skb->data - skb_network_header(skb));
		dst_input(skb);
		return -1;
	}

	if (skb_dst(skb)->dev->flags&IFF_LOOPBACK) {
		if (ipv6_hdr(skb)->hop_limit <= 1) {
			__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
			icmpv6_send(skb, ICMPV6_TIME_EXCEED, ICMPV6_EXC_HOPLIMIT,
				    0);
			kfree_skb(skb);
			return -1;
		}
		ipv6_hdr(skb)->hop_limit--;
		goto looped_back;
	}

	skb_push(skb, skb->data - skb_network_header(skb));
	dst_input(skb);
	return -1;

unknown_rh:
	__IP6_INC_STATS(net, idev, IPSTATS_MIB_INHDRERRORS);
	(*klpe_icmpv6_param_prob)(skb, ICMPV6_HDR_FIELD,
			  (&hdr->type) - skb_network_header(skb));
	return -1;
}



#include "livepatch_bsc1211395.h"
#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "icmpv6_param_prob", (void *)&klpe_icmpv6_param_prob },
	{ "ip6_route_input", (void *)&klpe_ip6_route_input },
	{ "ipv6_chk_home_addr", (void *)&klpe_ipv6_chk_home_addr },
	{ "ipv6_chk_rpl_srh_loop", (void *)&klpe_ipv6_chk_rpl_srh_loop },
	{ "ipv6_rpl_srh_compress", (void *)&klpe_ipv6_rpl_srh_compress },
	{ "ipv6_rpl_srh_decompress", (void *)&klpe_ipv6_rpl_srh_decompress },
	{ "ipv6_rpl_srh_size", (void *)&klpe_ipv6_rpl_srh_size },
};


int livepatch_bsc1211395_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
