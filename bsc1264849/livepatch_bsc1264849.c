/*
 * livepatch_bsc1264849
 *
 * Fix for CVE-2026-43190, bsc#1264849
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


#include "livepatch_bsc1264849.h"


/* klp-ccp: from net/netfilter/xt_tcpmss.c */
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netfilter/xt_tcpmss.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

bool
klpp_tcpmss_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_tcpmss_match_info *info = par->matchinfo;
	const struct tcphdr *th;
	struct tcphdr _tcph;
	/* tcp.doff is only 4 bits, ie. max 15 * 4 bytes */
	const u_int8_t *op;
	u8 _opt[15 * 4 - sizeof(_tcph)];
	unsigned int i, optlen;

	/* If we don't have the whole header, drop packet. */
	th = skb_header_pointer(skb, par->thoff, sizeof(_tcph), &_tcph);
	if (th == NULL)
		goto dropit;

	/* Malformed. */
	if (th->doff*4 < sizeof(*th))
		goto dropit;

	optlen = th->doff*4 - sizeof(*th);
	if (!optlen)
		goto out;

	/* Truncated options. */
	op = skb_header_pointer(skb, par->thoff + sizeof(*th), optlen, _opt);
	if (op == NULL)
		goto dropit;

	for (i = 0; i < optlen; ) {
		if (op[i] == TCPOPT_MSS
		    && (optlen - i) >= TCPOLEN_MSS
		    && op[i+1] == TCPOLEN_MSS) {
			u_int16_t mssval;

			mssval = (op[i+2] << 8) | op[i+3];

			return (mssval >= info->mss_min &&
				mssval <= info->mss_max) ^ info->invert;
		}
		if (op[i] < 2 || i == optlen - 1)
			i++;
		else
			i += op[i+1] ? : 1;
	}
out:
	return info->invert;

dropit:
	par->hotdrop = true;
	return false;
}


