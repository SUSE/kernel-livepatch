/*
 * livepatch_bsc1277399
 *
 * Fix for CVE-2026-74669, bsc#1277399
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


#include "livepatch_bsc1277399.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/icmp.h>
#include <linux/slab.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>                   /* for icmp_send */
#include <net/gue.h>
#include <net/gre.h>
#include <net/route.h>
#include <net/ip6_checksum.h>
#include <net/netns/generic.h>		/* net_generic() */

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#ifdef CONFIG_IP_VS_IPV6
#include <net/ipv6.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip6_route.h>
#endif

#include <net/ip_vs.h>
#include <linux/indirect_call_wrapper.h>

extern typeof(ip_vs_conn_put) ip_vs_conn_put;

static inline void
ip_vs_in_stats(struct ip_vs_conn *cp, struct sk_buff *skb)
{
	struct ip_vs_dest *dest = cp->dest;
	struct netns_ipvs *ipvs = cp->ipvs;

	if (dest && (dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		struct ip_vs_cpu_stats *s;
		struct ip_vs_service *svc;

		local_bh_disable();

		s = this_cpu_ptr(dest->stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		u64_stats_inc(&s->cnt.inpkts);
		u64_stats_add(&s->cnt.inbytes, skb->len);
		u64_stats_update_end(&s->syncp);

		svc = rcu_dereference(dest->svc);
		s = this_cpu_ptr(svc->stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		u64_stats_inc(&s->cnt.inpkts);
		u64_stats_add(&s->cnt.inbytes, skb->len);
		u64_stats_update_end(&s->syncp);

		s = this_cpu_ptr(ipvs->tot_stats->s.cpustats);
		u64_stats_update_begin(&s->syncp);
		u64_stats_inc(&s->cnt.inpkts);
		u64_stats_add(&s->cnt.inbytes, skb->len);
		u64_stats_update_end(&s->syncp);

		local_bh_enable();
	}
}

static inline void
ip_vs_out_stats(struct ip_vs_conn *cp, struct sk_buff *skb)
{
	struct ip_vs_dest *dest = cp->dest;
	struct netns_ipvs *ipvs = cp->ipvs;

	if (dest && (dest->flags & IP_VS_DEST_F_AVAILABLE)) {
		struct ip_vs_cpu_stats *s;
		struct ip_vs_service *svc;

		local_bh_disable();

		s = this_cpu_ptr(dest->stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		u64_stats_inc(&s->cnt.outpkts);
		u64_stats_add(&s->cnt.outbytes, skb->len);
		u64_stats_update_end(&s->syncp);

		svc = rcu_dereference(dest->svc);
		s = this_cpu_ptr(svc->stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		u64_stats_inc(&s->cnt.outpkts);
		u64_stats_add(&s->cnt.outbytes, skb->len);
		u64_stats_update_end(&s->syncp);

		s = this_cpu_ptr(ipvs->tot_stats->s.cpustats);
		u64_stats_update_begin(&s->syncp);
		u64_stats_inc(&s->cnt.outpkts);
		u64_stats_add(&s->cnt.outbytes, skb->len);
		u64_stats_update_end(&s->syncp);

		local_bh_enable();
	}
}

__sum16 ip_vs_checksum_complete(struct sk_buff *skb, int offset);

static inline enum ip_defrag_users ip_vs_defrag_user(unsigned int hooknum)
{
	if (NF_INET_LOCAL_IN == hooknum)
		return IP_DEFRAG_VS_IN;
	if (NF_INET_FORWARD == hooknum)
		return IP_DEFRAG_VS_FWD;
	return IP_DEFRAG_VS_OUT;
}

static inline int ip_vs_gather_frags(struct netns_ipvs *ipvs,
				     struct sk_buff *skb, u_int32_t user)
{
	int err;

	local_bh_disable();
	err = ip_defrag(ipvs->net, skb, user);
	local_bh_enable();
	if (!err)
		ip_send_check(ip_hdr(skb));

	return err;
}

static unsigned int
ip_vs_try_to_schedule(struct netns_ipvs *ipvs, int af, struct sk_buff *skb,
		      struct ip_vs_proto_data *pd,
		      int *verdict, struct ip_vs_conn **cpp,
		      struct ip_vs_iphdr *iph)
{
	struct ip_vs_protocol *pp = pd->pp;

	if (!iph->fragoffs) {
		/* No (second) fragments need to enter here, as nf_defrag_ipv6
		 * replayed fragment zero will already have created the cp
		 */

		/* Schedule and create new connection entry into cpp */
		if (!pp->conn_schedule(ipvs, af, skb, pd, verdict, cpp, iph))
			return 0;
	}

	if (unlikely(!*cpp)) {
		/* sorry, all this trouble for a no-hit :) */
		IP_VS_DBG_PKT(12, af, pp, skb, iph->off,
			      "ip_vs_in: packet continues traversal as normal");

		/* Fragment couldn't be mapped to a conn entry */
		if (iph->fragoffs)
			IP_VS_DBG_PKT(7, af, pp, skb, iph->off,
				      "unhandled fragment");

		*verdict = NF_ACCEPT;
		return 0;
	}

	return 1;
}

static int ipvs_udp_decap(struct netns_ipvs *ipvs, struct sk_buff *skb,
			  unsigned int offset, __u16 af,
			  const union nf_inet_addr *daddr, __u8 *proto)
{
	struct udphdr _udph, *udph;
	struct ip_vs_dest *dest;

	udph = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
	if (!udph)
		goto unk;
	offset += sizeof(struct udphdr);
	dest = ip_vs_find_tunnel(ipvs, af, daddr, udph->dest);
	if (!dest)
		goto unk;
	if (dest->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GUE) {
		struct guehdr _gueh, *gueh;

		gueh = skb_header_pointer(skb, offset, sizeof(_gueh), &_gueh);
		if (!gueh)
			goto unk;
		if (gueh->control != 0 || gueh->version != 0)
			goto unk;
		/* Later we can support also IPPROTO_IPV6 */
		if (gueh->proto_ctype != IPPROTO_IPIP)
			goto unk;
		*proto = gueh->proto_ctype;
		return sizeof(struct udphdr) + sizeof(struct guehdr) +
		       (gueh->hlen << 2);
	}

unk:
	return 0;
}

static int ipvs_gre_decap(struct netns_ipvs *ipvs, struct sk_buff *skb,
			  unsigned int offset, __u16 af,
			  const union nf_inet_addr *daddr, __u8 *proto)
{
	struct gre_base_hdr _greh, *greh;
	struct ip_vs_dest *dest;

	greh = skb_header_pointer(skb, offset, sizeof(_greh), &_greh);
	if (!greh)
		goto unk;
	dest = ip_vs_find_tunnel(ipvs, af, daddr, 0);
	if (!dest)
		goto unk;
	if (dest->tun_type == IP_VS_CONN_F_TUNNEL_TYPE_GRE) {
		IP_TUNNEL_DECLARE_FLAGS(flags);
		__be16 type;

		/* Only support version 0 and C (csum) */
		if ((greh->flags & ~GRE_CSUM) != 0)
			goto unk;
		type = greh->protocol;
		/* Later we can support also IPPROTO_IPV6 */
		if (type != htons(ETH_P_IP))
			goto unk;
		*proto = IPPROTO_IPIP;

		gre_flags_to_tnl_flags(flags, greh->flags);

		return gre_calc_hlen(flags);
	}

unk:
	return 0;
}

int
klpp_ip_vs_in_icmp(struct netns_ipvs *ipvs, struct sk_buff *skb, int *related,
	      unsigned int hooknum)
{
	struct iphdr *iph;
	struct icmphdr	_icmph, *ic;
	struct iphdr	_ciph, *cih;	/* The ip header contained within the ICMP */
	struct ip_vs_iphdr ciph;
	struct ip_vs_conn *cp;
	struct ip_vs_protocol *pp;
	struct ip_vs_proto_data *pd;
	unsigned int offset, offset2, ihl, verdict;
	bool tunnel, new_cp = false;
	union nf_inet_addr *raddr;
	char *outer_proto = "IPIP";

	*related = 1;

	/* reassemble IP fragments */
	if (ip_is_fragment(ip_hdr(skb))) {
		if (ip_vs_gather_frags(ipvs, skb, ip_vs_defrag_user(hooknum)))
			return NF_STOLEN;
	}

	iph = ip_hdr(skb);
	offset = ihl = iph->ihl * 4;
	ic = skb_header_pointer(skb, offset, sizeof(_icmph), &_icmph);
	if (ic == NULL)
		return NF_DROP;

	IP_VS_DBG(12, "Incoming ICMP (%d,%d) %pI4->%pI4\n",
		  ic->type, ntohs(icmp_id(ic)),
		  &iph->saddr, &iph->daddr);

	/*
	 * Work through seeing if this is for us.
	 * These checks are supposed to be in an order that means easy
	 * things are checked first to speed up processing.... however
	 * this means that some packets will manage to get a long way
	 * down this stack and then be rejected, but that's life.
	 */
	if ((ic->type != ICMP_DEST_UNREACH) &&
	    (ic->type != ICMP_SOURCE_QUENCH) &&
	    (ic->type != ICMP_TIME_EXCEEDED)) {
		*related = 0;
		return NF_ACCEPT;
	}

	/* Now find the contained IP header */
	offset += sizeof(_icmph);
	cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
	if (cih == NULL)
		return NF_ACCEPT; /* The packet looks wrong, ignore */
	raddr = (union nf_inet_addr *)&cih->daddr;

	/* Special case for errors for IPIP/UDP/GRE tunnel packets */
	tunnel = false;
	if (cih->protocol == IPPROTO_IPIP) {
		struct ip_vs_dest *dest;

		if (unlikely(cih->frag_off & htons(IP_OFFSET)))
			return NF_ACCEPT;
		/* Error for our IPIP must arrive at LOCAL_IN */
		if (!(skb_rtable(skb)->rt_flags & RTCF_LOCAL))
			return NF_ACCEPT;
		dest = ip_vs_find_tunnel(ipvs, AF_INET, raddr, 0);
		/* Only for known tunnel */
		if (!dest || dest->tun_type != IP_VS_CONN_F_TUNNEL_TYPE_IPIP)
			return NF_ACCEPT;
		offset += cih->ihl * 4;
		cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
		if (cih == NULL)
			return NF_ACCEPT; /* The packet looks wrong, ignore */
		tunnel = true;
	} else if ((cih->protocol == IPPROTO_UDP ||	/* Can be UDP encap */
		    cih->protocol == IPPROTO_GRE) &&	/* Can be GRE encap */
		   /* Error for our tunnel must arrive at LOCAL_IN */
		   (skb_rtable(skb)->rt_flags & RTCF_LOCAL)) {
		__u8 iproto;
		int ulen;

		/* Non-first fragment has no UDP/GRE header */
		if (unlikely(cih->frag_off & htons(IP_OFFSET)))
			return NF_ACCEPT;
		offset2 = offset + cih->ihl * 4;
		if (cih->protocol == IPPROTO_UDP) {
			ulen = ipvs_udp_decap(ipvs, skb, offset2, AF_INET,
					      raddr, &iproto);
			outer_proto = "UDP";
		} else {
			ulen = ipvs_gre_decap(ipvs, skb, offset2, AF_INET,
					      raddr, &iproto);
			outer_proto = "GRE";
		}
		if (ulen > 0) {
			/* Skip IP and UDP/GRE tunnel headers */
			offset = offset2 + ulen;
			/* Now we should be at the original IP header */
			cih = skb_header_pointer(skb, offset, sizeof(_ciph),
						 &_ciph);
			if (cih && cih->version == 4 && cih->ihl >= 5 &&
			    iproto == IPPROTO_IPIP)
				tunnel = true;
			else
				return NF_ACCEPT;
		}
	}

	pd = ip_vs_proto_data_get(ipvs, cih->protocol);
	if (!pd)
		return NF_ACCEPT;
	pp = pd->pp;

	/* Is the embedded protocol header present? */
	if (unlikely(cih->frag_off & htons(IP_OFFSET) &&
		     pp->dont_defrag))
		return NF_ACCEPT;

	IP_VS_DBG_PKT(11, AF_INET, pp, skb, offset,
		      "Checking incoming ICMP for");

	offset2 = offset;
	ip_vs_fill_iph_skb_icmp(AF_INET, skb, offset, !tunnel, &ciph);
	offset = ciph.len;

	/* The embedded headers contain source and dest in reverse order.
	 * For IPIP/UDP/GRE tunnel this is error for request, not for reply.
	 */
	cp = INDIRECT_CALL_1(pp->conn_in_get, ip_vs_conn_in_get_proto,
			     ipvs, AF_INET, skb, &ciph);

	if (!cp) {
		int v;

		if (tunnel || !sysctl_schedule_icmp(ipvs))
			return NF_ACCEPT;

		if (!ip_vs_try_to_schedule(ipvs, AF_INET, skb, pd, &v, &cp, &ciph))
			return v;
		new_cp = true;
	}

	verdict = NF_DROP;

	/* Ensure the checksum is correct */
	if (!skb_csum_unnecessary(skb) && ip_vs_checksum_complete(skb, ihl)) {
		/* Failed checksum! */
		IP_VS_DBG(1, "Incoming ICMP: failed checksum from %pI4!\n",
			  &iph->saddr);
		goto out;
	}

	if (tunnel) {
		__be32 info = ic->un.gateway;
		__u8 type = ic->type;
		__u8 code = ic->code;

		/* Update the MTU */
		if (ic->type == ICMP_DEST_UNREACH &&
		    ic->code == ICMP_FRAG_NEEDED) {
			struct ip_vs_dest *dest = cp->dest;
			u32 mtu = ntohs(ic->un.frag.mtu);
			__be16 frag_off = cih->frag_off;

			/* Strip outer IP and ICMP, go to IPIP/UDP/GRE header */
			if (pskb_pull(skb, ihl + sizeof(_icmph)) == NULL)
				goto ignore_tunnel;
			offset2 -= ihl + sizeof(_icmph);
			skb_reset_network_header(skb);
			IP_VS_DBG(12, "ICMP for %s %pI4->%pI4: mtu=%u\n",
				  outer_proto, &ip_hdr(skb)->saddr,
				  &ip_hdr(skb)->daddr, mtu);
			ipv4_update_pmtu(skb, ipvs->net, mtu, 0, 0);
			/* Client uses PMTUD? */
			if (!(frag_off & htons(IP_DF)))
				goto ignore_tunnel;
			/* Prefer the resulting PMTU */
			if (dest) {
				struct ip_vs_dest_dst *dest_dst;

				dest_dst = rcu_dereference(dest->dest_dst);
				if (dest_dst)
					mtu = dst_mtu(dest_dst->dst_cache);
			}
			if (mtu > 68 + sizeof(struct iphdr))
				mtu -= sizeof(struct iphdr);
			info = htonl(mtu);
		}
		/* Strip outer IP, ICMP and IPIP/UDP/GRE, go to IP header of
		 * original request.
		 */
		if (pskb_pull(skb, offset2) == NULL)
			goto ignore_tunnel;
		skb_reset_network_header(skb);
		memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
		IP_VS_DBG(12, "Sending ICMP for %pI4->%pI4: t=%u, c=%u, i=%u\n",
			&ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr,
			type, code, ntohl(info));
		icmp_send(skb, type, code, info);
		/* ICMP can be shorter but anyways, account it */
		ip_vs_out_stats(cp, skb);

ignore_tunnel:
		consume_skb(skb);
		verdict = NF_STOLEN;
		goto out;
	}

	/* do the statistics and put it back */
	ip_vs_in_stats(cp, skb);
	if (IPPROTO_TCP == cih->protocol || IPPROTO_UDP == cih->protocol ||
	    IPPROTO_SCTP == cih->protocol)
		offset += 2 * sizeof(__u16);
	verdict = ip_vs_icmp_xmit(skb, cp, pp, offset, hooknum, &ciph);

out:
	if (likely(!new_cp))
		__ip_vs_conn_put(cp);
	else
		ip_vs_conn_put(cp);

	return verdict;
}


#include <linux/livepatch.h>

extern typeof(ip_vs_checksum_complete) ip_vs_checksum_complete
	 KLP_RELOC_SYMBOL(ip_vs, ip_vs, ip_vs_checksum_complete);
extern typeof(ip_vs_conn_in_get_proto) ip_vs_conn_in_get_proto
	 KLP_RELOC_SYMBOL(ip_vs, ip_vs, ip_vs_conn_in_get_proto);
extern typeof(ip_vs_conn_put) ip_vs_conn_put
	 KLP_RELOC_SYMBOL(ip_vs, ip_vs, ip_vs_conn_put);
extern typeof(ip_vs_find_tunnel) ip_vs_find_tunnel
	 KLP_RELOC_SYMBOL(ip_vs, ip_vs, ip_vs_find_tunnel);
extern typeof(ip_vs_icmp_xmit) ip_vs_icmp_xmit
	 KLP_RELOC_SYMBOL(ip_vs, ip_vs, ip_vs_icmp_xmit);
extern typeof(ip_vs_proto_data_get) ip_vs_proto_data_get
	 KLP_RELOC_SYMBOL(ip_vs, ip_vs, ip_vs_proto_data_get);
