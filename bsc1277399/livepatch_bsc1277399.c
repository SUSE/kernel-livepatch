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

/* klp-ccp: from include/net/ip_vs.h */
static struct ip_vs_proto_data *(*klpe_ip_vs_proto_data_get)(struct netns_ipvs *ipvs,
					      unsigned short proto);

static void (*klpe_ip_vs_conn_put)(struct ip_vs_conn *cp);

static int (*klpe_ip_vs_icmp_xmit)(struct sk_buff *skb, struct ip_vs_conn *cp,
		    struct ip_vs_protocol *pp, int offset,
		    unsigned int hooknum, struct ip_vs_iphdr *iph);

static __sum16 (*klpe_ip_vs_checksum_complete)(struct sk_buff *skb, int offset);

/* klp-ccp: from net/netfilter/ipvs/ip_vs_core.c */

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
		s->cnt.inpkts++;
		s->cnt.inbytes += skb->len;
		u64_stats_update_end(&s->syncp);

		rcu_read_lock();
		svc = rcu_dereference(dest->svc);
		s = this_cpu_ptr(svc->stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		s->cnt.inpkts++;
		s->cnt.inbytes += skb->len;
		u64_stats_update_end(&s->syncp);
		rcu_read_unlock();

		s = this_cpu_ptr(ipvs->tot_stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		s->cnt.inpkts++;
		s->cnt.inbytes += skb->len;
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
		s->cnt.outpkts++;
		s->cnt.outbytes += skb->len;
		u64_stats_update_end(&s->syncp);

		rcu_read_lock();
		svc = rcu_dereference(dest->svc);
		s = this_cpu_ptr(svc->stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		s->cnt.outpkts++;
		s->cnt.outbytes += skb->len;
		u64_stats_update_end(&s->syncp);
		rcu_read_unlock();

		s = this_cpu_ptr(ipvs->tot_stats.cpustats);
		u64_stats_update_begin(&s->syncp);
		s->cnt.outpkts++;
		s->cnt.outbytes += skb->len;
		u64_stats_update_end(&s->syncp);

		local_bh_enable();
	}
}
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
		if (iph->fragoffs) {
			/* Fragment that couldn't be mapped to a conn entry
			 * is missing module nf_defrag_ipv6
			 */
			IP_VS_DBG_RL("Unhandled frag, load nf_defrag_ipv6\n");
			IP_VS_DBG_PKT(7, af, pp, skb, iph->off,
				      "unhandled fragment");
		}
		*verdict = NF_ACCEPT;
		return 0;
	}

	return 1;
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
	bool ipip, new_cp = false;

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

	/* Special case for errors for IPIP packets */
	ipip = false;
	if (cih->protocol == IPPROTO_IPIP) {
		if (unlikely(cih->frag_off & htons(IP_OFFSET)))
			return NF_ACCEPT;
		/* Error for our IPIP must arrive at LOCAL_IN */
		if (!(skb_rtable(skb)->rt_flags & RTCF_LOCAL))
			return NF_ACCEPT;
		offset += cih->ihl * 4;
		cih = skb_header_pointer(skb, offset, sizeof(_ciph), &_ciph);
		if (cih == NULL)
			return NF_ACCEPT; /* The packet looks wrong, ignore */
		ipip = true;
	}

	pd = (*klpe_ip_vs_proto_data_get)(ipvs, cih->protocol);
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
	ip_vs_fill_iph_skb_icmp(AF_INET, skb, offset, !ipip, &ciph);
	offset = ciph.len;

	/* The embedded headers contain source and dest in reverse order.
	 * For IPIP this is error for request, not for reply.
	 */
	cp = pp->conn_in_get(ipvs, AF_INET, skb, &ciph);

	if (!cp) {
		int v;

		if (!sysctl_schedule_icmp(ipvs))
			return NF_ACCEPT;

		if (!ip_vs_try_to_schedule(ipvs, AF_INET, skb, pd, &v, &cp, &ciph))
			return v;
		new_cp = true;
	}

	verdict = NF_DROP;

	/* Ensure the checksum is correct */
	if (!skb_csum_unnecessary(skb) && (*klpe_ip_vs_checksum_complete)(skb, ihl)) {
		/* Failed checksum! */
		IP_VS_DBG(1, "Incoming ICMP: failed checksum from %pI4!\n",
			  &iph->saddr);
		goto out;
	}

	if (ipip) {
		__be32 info = ic->un.gateway;
		__u8 type = ic->type;
		__u8 code = ic->code;

		/* Update the MTU */
		if (ic->type == ICMP_DEST_UNREACH &&
		    ic->code == ICMP_FRAG_NEEDED) {
			struct ip_vs_dest *dest = cp->dest;
			u32 mtu = ntohs(ic->un.frag.mtu);
			__be16 frag_off = cih->frag_off;

			/* Strip outer IP and ICMP, go to IPIP header */
			if (pskb_pull(skb, ihl + sizeof(_icmph)) == NULL)
				goto ignore_ipip;
			offset2 -= ihl + sizeof(_icmph);
			skb_reset_network_header(skb);
			IP_VS_DBG(12, "ICMP for IPIP %pI4->%pI4: mtu=%u\n",
				&ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr, mtu);
			ipv4_update_pmtu(skb, ipvs->net,
					 mtu, 0, 0, 0, 0);
			/* Client uses PMTUD? */
			if (!(frag_off & htons(IP_DF)))
				goto ignore_ipip;
			/* Prefer the resulting PMTU */
			if (dest) {
				struct ip_vs_dest_dst *dest_dst;

				rcu_read_lock();
				dest_dst = rcu_dereference(dest->dest_dst);
				if (dest_dst)
					mtu = dst_mtu(dest_dst->dst_cache);
				rcu_read_unlock();
			}
			if (mtu > 68 + sizeof(struct iphdr))
				mtu -= sizeof(struct iphdr);
			info = htonl(mtu);
		}
		/* Strip outer IP, ICMP and IPIP, go to IP header of
		 * original request.
		 */
		if (pskb_pull(skb, offset2) == NULL)
			goto ignore_ipip;
		skb_reset_network_header(skb);
		memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
		IP_VS_DBG(12, "Sending ICMP for %pI4->%pI4: t=%u, c=%u, i=%u\n",
			&ip_hdr(skb)->saddr, &ip_hdr(skb)->daddr,
			type, code, ntohl(info));
		icmp_send(skb, type, code, info);
		/* ICMP can be shorter but anyways, account it */
		ip_vs_out_stats(cp, skb);

ignore_ipip:
		consume_skb(skb);
		verdict = NF_STOLEN;
		goto out;
	}

	/* do the statistics and put it back */
	ip_vs_in_stats(cp, skb);
	if (IPPROTO_TCP == cih->protocol || IPPROTO_UDP == cih->protocol ||
	    IPPROTO_SCTP == cih->protocol)
		offset += 2 * sizeof(__u16);
	verdict = (*klpe_ip_vs_icmp_xmit)(skb, cp, pp, offset, hooknum, &ciph);

out:
	if (likely(!new_cp))
		__ip_vs_conn_put(cp);
	else
		(*klpe_ip_vs_conn_put)(cp);

	return verdict;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ip_vs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ip_vs_checksum_complete", (void *)&klpe_ip_vs_checksum_complete,
	  "ip_vs" },
	{ "ip_vs_conn_put", (void *)&klpe_ip_vs_conn_put, "ip_vs" },
	{ "ip_vs_icmp_xmit", (void *)&klpe_ip_vs_icmp_xmit, "ip_vs" },
	{ "ip_vs_proto_data_get", (void *)&klpe_ip_vs_proto_data_get,
	  "ip_vs" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1277399_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1277399_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
