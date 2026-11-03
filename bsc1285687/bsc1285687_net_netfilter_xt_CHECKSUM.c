/*
 * bsc1285687_net_netfilter_xt_CHECKSUM
 *
 * Fix for CVE-2026-99999, bsc#1285687
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


#include "livepatch_bsc1285687.h"

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_CHECKSUM.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netdevice.h>

extern unsigned int
klpp_checksum_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	if (skb->ip_summed == CHECKSUM_PARTIAL && !skb_is_gso(skb)) {
		if (xt_family(par) == NFPROTO_IPV4 && ip_check_csum_start(skb))
			return NF_DROP;
		skb_checksum_help(skb);
	}

	return XT_CONTINUE;
}


