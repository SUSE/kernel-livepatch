/*
 * livepatch_bsc1213584
 *
 * Fix for CVE-2023-3610, bsc#1213584
 *
 *  Upstream commit:
 *  4bedf9eee016 ("netfilter: nf_tables: fix chain binding transaction logic")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  12da4f7bc831e172e5a82401918f27857e4dfaf4
 *  ecae123e54d7869241bcfe6c94d7e136dd528db3
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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




#include "livepatch_bsc1213584.h"
int livepatch_bsc1213584_init(void)
{
	int ret;

	ret = bsc1213584_net_netfilter_nf_tables_api_init();
	if (ret)
		return ret;
	return bsc1213584_net_netfilter_nft_immediate_init();
}

void livepatch_bsc1213584_cleanup(void)
{
	bsc1213584_net_netfilter_nf_tables_api_cleanup();
	bsc1213584_net_netfilter_nft_immediate_cleanup();
}
