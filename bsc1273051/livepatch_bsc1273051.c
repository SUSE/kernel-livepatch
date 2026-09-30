/*
 * livepatch_bsc1273051
 *
 * Fix for CVE-2026-63994, bsc#1273051
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


#include "livepatch_bsc1273051.h"


/* klp-ccp: from net/ipv4/ip_tunnel_core.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/static_key.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/ip_tunnels.h>

/* klp-ccp: from include/net/ip_tunnels.h */
#ifdef CONFIG_INET

int klpp_skb_tunnel_check_pmtu(struct sk_buff *skb, struct dst_entry *encap_dst,
			  int headroom, bool reply);

#else /* CONFIG_INET */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_INET */

/* klp-ccp: from net/ipv4/ip_tunnel_core.c */
#include <net/ip6_tunnel.h>
#include <net/ip6_checksum.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/dst_metadata.h>
#include <net/geneve.h>
#include <net/vxlan.h>
#include <net/erspan.h>

static int klpp_iptunnel_pmtud_build_icmp(struct sk_buff *skb, int mtu)
{
	const struct iphdr *iph;
	struct icmphdr *icmph;
	struct iphdr *niph;
	struct ethhdr eh;
	int len, err;

	if (!pskb_may_pull(skb, ETH_HLEN + sizeof(struct iphdr)))
		return -EINVAL;

	skb_copy_bits(skb, skb_mac_offset(skb), &eh, ETH_HLEN);
	pskb_pull(skb, ETH_HLEN);

	err = pskb_trim(skb, 576 - sizeof(*niph) - sizeof(*icmph));
	if (err)
		return err;

	len = skb->len + sizeof(*icmph);
	err = skb_cow(skb, sizeof(*niph) + sizeof(*icmph) + ETH_HLEN);
	if (err)
		return err;
	iph = ip_hdr(skb);
	icmph = skb_push(skb, sizeof(*icmph));
	*icmph = (struct icmphdr) {
		.type			= ICMP_DEST_UNREACH,
		.code			= ICMP_FRAG_NEEDED,
		.checksum		= 0,
		.un.frag.__unused	= 0,
		.un.frag.mtu		= htons(mtu),
	};
	icmph->checksum = csum_fold(skb_checksum(skb, 0, len, 0));
	skb_reset_transport_header(skb);

	niph = skb_push(skb, sizeof(*niph));
	*niph = (struct iphdr) {
		.ihl			= sizeof(*niph) / 4u,
		.version 		= 4,
		.tos 			= 0,
		.tot_len		= htons(len + sizeof(*niph)),
		.id			= 0,
		.frag_off		= htons(IP_DF),
		.ttl			= iph->ttl,
		.protocol		= IPPROTO_ICMP,
		.saddr			= iph->daddr,
		.daddr			= iph->saddr,
	};
	ip_send_check(niph);
	skb_reset_network_header(skb);

	skb->ip_summed = CHECKSUM_NONE;

	eth_header(skb, skb->dev, ntohs(eh.h_proto), eh.h_source, eh.h_dest, 0);
	skb_reset_mac_header(skb);

	return skb->len;
}

static int klpr_iptunnel_pmtud_check_icmp(struct sk_buff *skb, int mtu)
{
	const struct icmphdr *icmph = icmp_hdr(skb);
	const struct iphdr *iph = ip_hdr(skb);

	if (mtu < 576 || iph->frag_off != htons(IP_DF))
		return 0;

	if (ipv4_is_lbcast(iph->daddr)  || ipv4_is_multicast(iph->daddr) ||
	    ipv4_is_zeronet(iph->saddr) || ipv4_is_loopback(iph->saddr)  ||
	    ipv4_is_lbcast(iph->saddr)  || ipv4_is_multicast(iph->saddr))
		return 0;

	if (iph->protocol == IPPROTO_ICMP && icmp_is_err(icmph->type))
		return 0;

	return klpp_iptunnel_pmtud_build_icmp(skb, mtu);
}

#if IS_ENABLED(CONFIG_IPV6)

static int klpp_iptunnel_pmtud_build_icmpv6(struct sk_buff *skb, int mtu)
{
	const struct ipv6hdr *ip6h;
	struct icmp6hdr *icmp6h;
	struct ipv6hdr *nip6h;
	struct ethhdr eh;
	int len, err;
	__wsum csum;

	if (!pskb_may_pull(skb, ETH_HLEN + sizeof(struct ipv6hdr)))
		return -EINVAL;

	skb_copy_bits(skb, skb_mac_offset(skb), &eh, ETH_HLEN);
	pskb_pull(skb, ETH_HLEN);

	err = pskb_trim(skb, IPV6_MIN_MTU - sizeof(*nip6h) - sizeof(*icmp6h));
	if (err)
		return err;

	len = skb->len + sizeof(*icmp6h);
	err = skb_cow(skb, sizeof(*nip6h) + sizeof(*icmp6h) + ETH_HLEN);
	if (err)
		return err;

	ip6h = ipv6_hdr(skb);
	icmp6h = skb_push(skb, sizeof(*icmp6h));
	*icmp6h = (struct icmp6hdr) {
		.icmp6_type		= ICMPV6_PKT_TOOBIG,
		.icmp6_code		= 0,
		.icmp6_cksum		= 0,
		.icmp6_mtu		= htonl(mtu),
	};
	skb_reset_transport_header(skb);

	nip6h = skb_push(skb, sizeof(*nip6h));
	*nip6h = (struct ipv6hdr) {
		.priority		= 0,
		.version		= 6,
		.flow_lbl		= { 0 },
		.payload_len		= htons(len),
		.nexthdr		= IPPROTO_ICMPV6,
		.hop_limit		= ip6h->hop_limit,
		.saddr			= ip6h->daddr,
		.daddr			= ip6h->saddr,
	};
	skb_reset_network_header(skb);

	csum = skb_checksum(skb, skb_transport_offset(skb), len, 0);
	icmp6h->icmp6_cksum = csum_ipv6_magic(&nip6h->saddr, &nip6h->daddr, len,
					      IPPROTO_ICMPV6, csum);

	skb->ip_summed = CHECKSUM_NONE;

	eth_header(skb, skb->dev, ntohs(eh.h_proto), eh.h_source, eh.h_dest, 0);
	skb_reset_mac_header(skb);

	return skb->len;
}

static int klpr_iptunnel_pmtud_check_icmpv6(struct sk_buff *skb, int mtu)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	int stype = ipv6_addr_type(&ip6h->saddr);
	u8 proto = ip6h->nexthdr;
	__be16 frag_off;
	int offset;

	if (mtu < IPV6_MIN_MTU)
		return 0;

	if (stype == IPV6_ADDR_ANY || stype == IPV6_ADDR_MULTICAST ||
	    stype == IPV6_ADDR_LOOPBACK)
		return 0;

	offset = ipv6_skip_exthdr(skb, sizeof(struct ipv6hdr), &proto,
				  &frag_off);
	if (offset < 0 || (frag_off & htons(~0x7)))
		return 0;

	if (proto == IPPROTO_ICMPV6) {
		struct icmp6hdr *icmp6h;

		if (!pskb_may_pull(skb, skb_network_header(skb) +
					offset + 1 - skb->data))
			return 0;

		icmp6h = (struct icmp6hdr *)(skb_network_header(skb) + offset);
		if (icmpv6_is_err(icmp6h->icmp6_type) ||
		    icmp6h->icmp6_type == NDISC_REDIRECT)
			return 0;
	}

	return klpp_iptunnel_pmtud_build_icmpv6(skb, mtu);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* IS_ENABLED(CONFIG_IPV6) */

int klpp_skb_tunnel_check_pmtu(struct sk_buff *skb, struct dst_entry *encap_dst,
			  int headroom, bool reply)
{
	u32 mtu = dst_mtu(encap_dst) - headroom;

	if ((skb_is_gso(skb) && skb_gso_validate_network_len(skb, mtu)) ||
	    (!skb_is_gso(skb) && (skb->len - skb_network_offset(skb)) <= mtu))
		return 0;

	skb_dst_update_pmtu_no_confirm(skb, mtu);

	if (!reply || skb->pkt_type == PACKET_HOST)
		return 0;

	if (skb->protocol == htons(ETH_P_IP))
		return klpr_iptunnel_pmtud_check_icmp(skb, mtu);

#if IS_ENABLED(CONFIG_IPV6)
	if (skb->protocol == htons(ETH_P_IPV6))
		return klpr_iptunnel_pmtud_check_icmpv6(skb, mtu);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return 0;
}

typeof(klpp_skb_tunnel_check_pmtu) klpp_skb_tunnel_check_pmtu;


