/*
 * bsc1269775_net_ipv4_netfilter_nf_log_ipv4
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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/ipv4/netfilter/nf_log_ipv4.c */
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
#include <linux/netfilter/xt_LOG.h>
#include <net/netfilter/nf_log.h>

/* klp-ccp: from include/net/netfilter/nf_log.h */
static void (*klpe___nf_log_dump_packet_common)(struct nf_log_buf *m, u_int8_t pf,
				 unsigned int hooknum, const struct sk_buff *skb,
				 const struct net_device *in,
				 const struct net_device *out,
				 const struct nf_loginfo *loginfo,
				 const char *prefix,
				 struct net *net);

/* klp-ccp: from net/ipv4/netfilter/nf_log_ipv4.c */
static struct nf_loginfo (*klpe_default_loginfo);

static void (*klpe_dump_ipv4_packet)(struct nf_log_buf *m,
			     const struct nf_loginfo *info,
			     const struct sk_buff *skb, unsigned int iphoff);

static void klpp_dump_ipv4_mac_header(struct nf_log_buf *m,
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

		nf_log_buf_add(m, "MACSRC=%pM MACDST=%pM MACPROTO=%04x ",
			       eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest,
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

		nf_log_buf_add(m, "%02x", *p++);
		for (i = 1; i < dev->hard_header_len; i++, p++)
			nf_log_buf_add(m, ":%02x", *p);
	}
	nf_log_buf_add(m, " ");
}

void klpp_nf_log_ip_packet(struct net *net, u_int8_t pf, unsigned int hooknum, const struct sk_buff *skb, const struct net_device *in, const struct net_device *out, const struct nf_loginfo *loginfo, const char *prefix)
{
	struct nf_log_buf *m;

	/* FIXME: Disabled from containers until syslog ns is supported */
	if (!net_eq(net, &init_net) && !sysctl_nf_log_all_netns)
		return;

	m = nf_log_buf_open();

	if (!loginfo)
		loginfo = &(*klpe_default_loginfo);

	(*klpe___nf_log_dump_packet_common)(m, pf, hooknum, skb, in,
				    out, loginfo, prefix, net);

	if (in != NULL)
		klpp_dump_ipv4_mac_header(m, loginfo, skb);

	(*klpe_dump_ipv4_packet)(m, loginfo, skb, 0);

	nf_log_buf_close(m);
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_log_ipv4"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__nf_log_dump_packet_common",
	  (void *)&klpe___nf_log_dump_packet_common, "nf_log_common" },
	{ "default_loginfo", (void *)&klpe_default_loginfo, "nf_log_ipv4" },
	{ "dump_ipv4_packet", (void *)&klpe_dump_ipv4_packet, "nf_log_ipv4" },
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

int bsc1269775_net_ipv4_netfilter_nf_log_ipv4_init(void)
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

void bsc1269775_net_ipv4_netfilter_nf_log_ipv4_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
