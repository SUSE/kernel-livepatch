/*
 * livepatch_bsc1263670
 *
 * Fix for CVE-2026-31685, bsc#1263670
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


#include "livepatch_bsc1263670.h"


/* klp-ccp: from net/ipv6/netfilter/ip6t_eui64.c */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

bool
klpp_eui64_mt6(const struct sk_buff *skb, struct xt_action_param *par)
{
	unsigned char eui64[8];

	if (!(skb_mac_header(skb) >= skb->head &&
	      skb_mac_header(skb) + ETH_HLEN <= skb->data)) {
		par->hotdrop = true;
		return false;
	}

	memset(eui64, 0, sizeof(eui64));

	if (eth_hdr(skb)->h_proto == htons(ETH_P_IPV6)) {
		if (ipv6_hdr(skb)->version == 0x6) {
			memcpy(eui64, eth_hdr(skb)->h_source, 3);
			memcpy(eui64 + 5, eth_hdr(skb)->h_source + 3, 3);
			eui64[3] = 0xff;
			eui64[4] = 0xfe;
			eui64[0] ^= 0x02;

			if (!memcmp(ipv6_hdr(skb)->saddr.s6_addr + 8, eui64,
				    sizeof(eui64)))
				return true;
		}
	}

	return false;
}


