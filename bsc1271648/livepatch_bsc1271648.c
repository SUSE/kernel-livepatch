/*
 * livepatch_bsc1271648
 *
 * Fix for CVE-2026-43038, bsc#1271648
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


#include "livepatch_bsc1271648.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/ipv6/icmp.c */
#define pr_fmt(fmt) "IPv6: " fmt

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/slab.h>

#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/icmpv6.h>

/* klp-ccp: from include/linux/icmpv6.h */
#if IS_ENABLED(CONFIG_IPV6)

int klpp_ip6_err_gen_icmpv6_unreach(struct sk_buff *skb, int nhs, int type,
			       unsigned int data_len);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/ipv6/icmp.c */
#include <net/ip.h>
#include <net/sock.h>

#include <net/ipv6.h>
#include <net/ip6_checksum.h>
#include <net/ping.h>
#include <net/protocol.h>
#include <net/raw.h>
#include <net/rawv6.h>
#include <net/transp_v6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/icmp.h>
#include <net/xfrm.h>
#include <net/inet_common.h>
#include <net/dsfield.h>
#include <net/l3mdev.h>

#include <linux/uaccess.h>

static void (*klpe_icmp6_send)(struct sk_buff *skb, u8 type, u8 code, __u32 info,
		       const struct in6_addr *force_saddr);

int klpp_ip6_err_gen_icmpv6_unreach(struct sk_buff *skb, int nhs, int type,
			       unsigned int data_len)
{
	struct in6_addr temp_saddr;
	struct rt6_info *rt;
	struct sk_buff *skb2;
	u32 info = 0;

	if (!pskb_may_pull(skb, nhs + sizeof(struct ipv6hdr) + 8))
		return 1;

	/* RFC 4884 (partial) support for ICMP extensions */
	if (data_len < 128 || (data_len & 7) || skb->len < data_len)
		data_len = 0;

	skb2 = data_len ? skb_copy(skb, GFP_ATOMIC) : skb_clone(skb, GFP_ATOMIC);

	if (!skb2)
		return 1;

	/* Remove debris left by IPv4 stack. */
	memset(IP6CB(skb2), 0, sizeof(*IP6CB(skb2)));

	skb_dst_drop(skb2);
	skb_pull(skb2, nhs);
	skb_reset_network_header(skb2);

	rt = rt6_lookup(dev_net_rcu(skb->dev), &ipv6_hdr(skb2)->saddr, NULL, 0, 0);

	if (rt && rt->dst.dev)
		skb2->dev = rt->dst.dev;

	ipv6_addr_set_v4mapped(ip_hdr(skb)->saddr, &temp_saddr);

	if (data_len) {
		/* RFC 4884 (partial) support :
		 * insert 0 padding at the end, before the extensions
		 */
		__skb_push(skb2, nhs);
		skb_reset_network_header(skb2);
		memmove(skb2->data, skb2->data + nhs, data_len - nhs);
		memset(skb2->data + data_len - nhs, 0, nhs);
		/* RFC 4884 4.5 : Length is measured in 64-bit words,
		 * and stored in reserved[0]
		 */
		info = (data_len/8) << 24;
	}
	if (type == ICMP_TIME_EXCEEDED)
		(*klpe_icmp6_send)(skb2, ICMPV6_TIME_EXCEED, ICMPV6_EXC_HOPLIMIT,
			   info, &temp_saddr);
	else
		(*klpe_icmp6_send)(skb2, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH,
			   info, &temp_saddr);
	if (rt)
		ip6_rt_put(rt);

	kfree_skb(skb2);

	return 0;
}

typeof(klpp_ip6_err_gen_icmpv6_unreach) klpp_ip6_err_gen_icmpv6_unreach;


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "icmp6_send", (void *)&klpe_icmp6_send },
};

int livepatch_bsc1271648_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

