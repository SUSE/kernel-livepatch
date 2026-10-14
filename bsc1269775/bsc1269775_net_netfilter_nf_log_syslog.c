/*
 * bsc1269775_net_netfilter_nf_log_syslog
 *
 * Fix for CVE-2026-53131, bsc#1269775
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


#include "livepatch_bsc1269775.h"


/* klp-ccp: from net/netfilter/nf_log_syslog.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <net/icmp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/route.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/xt_LOG.h>
#include <net/netfilter/nf_log.h>

extern const struct nf_loginfo default_loginfo;

struct arppayload {
	unsigned char mac_src[ETH_ALEN];
	unsigned char ip_src[4];
	unsigned char mac_dst[ETH_ALEN];
	unsigned char ip_dst[4];
};

static bool nf_log_allowed(const struct net *net)
{
	return net_eq(net, &init_net) || sysctl_nf_log_all_netns;
}

static void nf_log_dump_vlan(struct nf_log_buf *m, const struct sk_buff *skb)
{
	u16 vid;

	if (!skb_vlan_tag_present(skb))
		return;

	vid = skb_vlan_tag_get(skb);
	nf_log_buf_add(m, "VPROTO=%04x VID=%u ", ntohs(skb->vlan_proto), vid);
}
void noinline_for_stack klpp_dump_arp_packet(struct nf_log_buf *m, const struct nf_loginfo *info, const struct sk_buff *skb, unsigned int nhoff)
{
	const struct arppayload *ap;
	struct arppayload _arpp;
	const struct arphdr *ah;
	unsigned int logflags;
	struct arphdr _arph;

	ah = skb_header_pointer(skb, nhoff, sizeof(_arph), &_arph);
	if (!ah) {
		nf_log_buf_add(m, "TRUNCATED");
		return;
	}

	if (info->type == NF_LOG_TYPE_LOG)
		logflags = info->u.log.logflags;
	else
		logflags = NF_LOG_DEFAULT_MASK;

	if ((logflags & NF_LOG_MACDECODE) &&
	    skb->dev && skb->dev->type == ARPHRD_ETHER &&
	    skb_mac_header_was_set(skb) &&
	    skb_mac_header_len(skb) >= ETH_HLEN) {
		nf_log_buf_add(m, "MACSRC=%pM MACDST=%pM ",
			       eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest);
		nf_log_dump_vlan(m, skb);
		nf_log_buf_add(m, "MACPROTO=%04x ",
			       ntohs(eth_hdr(skb)->h_proto));
	}

	nf_log_buf_add(m, "ARP HTYPE=%d PTYPE=0x%04x OPCODE=%d",
		       ntohs(ah->ar_hrd), ntohs(ah->ar_pro), ntohs(ah->ar_op));
	/* If it's for Ethernet and the lengths are OK, then log the ARP
	 * payload.
	 */
	if (ah->ar_hrd != htons(ARPHRD_ETHER) ||
	    ah->ar_hln != ETH_ALEN ||
	    ah->ar_pln != sizeof(__be32))
		return;

	ap = skb_header_pointer(skb, nhoff + sizeof(_arph), sizeof(_arpp), &_arpp);
	if (!ap) {
		nf_log_buf_add(m, " INCOMPLETE [%zu bytes]",
			       skb->len - sizeof(_arph));
		return;
	}
	nf_log_buf_add(m, " MACSRC=%pM IPSRC=%pI4 MACDST=%pM IPDST=%pI4",
		       ap->mac_src, ap->ip_src, ap->mac_dst, ap->ip_dst);
}

static void
nf_log_dump_packet_common(struct nf_log_buf *m, u8 pf,
			  unsigned int hooknum, const struct sk_buff *skb,
			  const struct net_device *in,
			  const struct net_device *out,
			  const struct nf_loginfo *loginfo, const char *prefix,
			  struct net *net)
{
	const struct net_device *physoutdev __maybe_unused;
	const struct net_device *physindev __maybe_unused;

	nf_log_buf_add(m, KERN_SOH "%c%sIN=%s OUT=%s ",
		       '0' + loginfo->u.log.level, prefix,
			in ? in->name : "",
			out ? out->name : "");
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	physindev = nf_bridge_get_physindev(skb, net);
	if (physindev && in != physindev)
		nf_log_buf_add(m, "PHYSIN=%s ", physindev->name);
	physoutdev = nf_bridge_get_physoutdev(skb);
	if (physoutdev && out != physoutdev)
		nf_log_buf_add(m, "PHYSOUT=%s ", physoutdev->name);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

extern void nf_log_arp_packet(struct net *net, u_int8_t pf,
			      unsigned int hooknum, const struct sk_buff *skb,
			      const struct net_device *in,
			      const struct net_device *out,
			      const struct nf_loginfo *loginfo,
			      const char *prefix);

extern void
dump_ipv4_packet(struct net *net, struct nf_log_buf *m,
		 const struct nf_loginfo *info,
		 const struct sk_buff *skb, unsigned int iphoff);

extern void
dump_ipv6_packet(struct net *net, struct nf_log_buf *m,
		 const struct nf_loginfo *info,
		 const struct sk_buff *skb, unsigned int ip6hoff,
		 int recurse);

static void klpp_dump_mac_header(struct nf_log_buf *m,
			    const struct nf_loginfo *info,
			    const struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	unsigned int logflags = 0;

	if (info->type == NF_LOG_TYPE_LOG)
		logflags = info->u.log.logflags;

	if (!(logflags & NF_LOG_MACDECODE))
		goto fallback;

	switch (dev->type) {
	case ARPHRD_ETHER:
		if (!skb_mac_header_was_set(skb) || skb_mac_header_len(skb) < ETH_HLEN)
			return;

		nf_log_buf_add(m, "MACSRC=%pM MACDST=%pM ",
			       eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest);
		nf_log_dump_vlan(m, skb);
		nf_log_buf_add(m, "MACPROTO=%04x ",
			       ntohs(eth_hdr(skb)->h_proto));
		return;
	default:
		break;
	}

fallback:
	nf_log_buf_add(m, "MAC=");
	if (dev->hard_header_len &&
	    skb->mac_header != skb->network_header) {
		const unsigned char *p = skb_mac_header(skb);
		unsigned int i;

		if (dev->type == ARPHRD_SIT) {
			p -= ETH_HLEN;

			if (p < skb->head)
				p = NULL;
		}

		if (p) {
			nf_log_buf_add(m, "%02x", *p++);
			for (i = 1; i < dev->hard_header_len; i++)
				nf_log_buf_add(m, ":%02x", *p++);
		}

		if (dev->type == ARPHRD_SIT) {
			const struct iphdr *iph =
				(struct iphdr *)skb_mac_header(skb);

			nf_log_buf_add(m, " TUNNEL=%pI4->%pI4", &iph->saddr,
				       &iph->daddr);
		}
	}
	nf_log_buf_add(m, " ");
}

void klpp_nf_log_ip_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix)
{
	struct nf_log_buf *m;

	if (!nf_log_allowed(net))
		return;

	m = nf_log_buf_open();

	if (!loginfo)
		loginfo = &default_loginfo;

	nf_log_dump_packet_common(m, pf, hooknum, skb, in,
				  out, loginfo, prefix, net);

	if (in)
		klpp_dump_mac_header(m, loginfo, skb);

	dump_ipv4_packet(net, m, loginfo, skb, skb_network_offset(skb));

	nf_log_buf_close(m);
}

void klpp_nf_log_ip6_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix)
{
	struct nf_log_buf *m;

	if (!nf_log_allowed(net))
		return;

	m = nf_log_buf_open();

	if (!loginfo)
		loginfo = &default_loginfo;

	nf_log_dump_packet_common(m, pf, hooknum, skb, in, out,
				  loginfo, prefix, net);

	if (in)
		klpp_dump_mac_header(m, loginfo, skb);

	dump_ipv6_packet(net, m, loginfo, skb, skb_network_offset(skb), 1);

	nf_log_buf_close(m);
}

static void klpr_nf_log_unknown_packet(struct net *net, u_int8_t pf,
				  unsigned int hooknum,
				  const struct sk_buff *skb,
				  const struct net_device *in,
				  const struct net_device *out,
				  const struct nf_loginfo *loginfo,
				  const char *prefix)
{
	struct nf_log_buf *m;

	if (!nf_log_allowed(net))
		return;

	m = nf_log_buf_open();

	if (!loginfo)
		loginfo = &default_loginfo;

	nf_log_dump_packet_common(m, pf, hooknum, skb, in, out, loginfo,
				  prefix, net);

	klpp_dump_mac_header(m, loginfo, skb);

	nf_log_buf_close(m);
}

void klpp_nf_log_netdev_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):		break;
	case htons(ETH_P_IPV6):		break;
	case htons(ETH_P_ARP):
	case htons(ETH_P_RARP):
		nf_log_arp_packet(net, pf, hooknum, skb, in, out, loginfo, prefix);
		break;
	default:
		klpr_nf_log_unknown_packet(net, pf, hooknum, skb,
				      in, out, loginfo, prefix);
		break;
	}
}


#include <linux/livepatch.h>

extern typeof(default_loginfo) default_loginfo
	 KLP_RELOC_SYMBOL(nf_log_syslog, nf_log_syslog, default_loginfo);
extern typeof(dump_ipv4_packet) dump_ipv4_packet
	 KLP_RELOC_SYMBOL(nf_log_syslog, nf_log_syslog, dump_ipv4_packet);
extern typeof(dump_ipv6_packet) dump_ipv6_packet
	 KLP_RELOC_SYMBOL(nf_log_syslog, nf_log_syslog, dump_ipv6_packet);
extern typeof(nf_log_arp_packet) nf_log_arp_packet
	 KLP_RELOC_SYMBOL(nf_log_syslog, nf_log_syslog, nf_log_arp_packet);
