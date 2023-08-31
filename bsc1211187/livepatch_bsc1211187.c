/*
 * livepatch_bsc1211187
 *
 * Fix for CVE-2023-32233, bsc#1211187
 *
 *  Upstream commit:
 *  c1592a89942e ("netfilter: nf_tables: deactivate anonymous set from preparation phase")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  8d253dca150b74ed75200ae88c9b1ba20ccdedd0
 *
 *  SLE15-SP4 and -SP5 commit:
 *  a0bdb5881cab1c4be558de5e3595f5a155851038
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#include "livepatch_bsc1211187.h"
int livepatch_bsc1211187_init(void)
{
	return bsc1211187_net_netfilter_nf_tables_api_init();
}

void livepatch_bsc1211187_cleanup(void)
{
	bsc1211187_net_netfilter_nf_tables_api_cleanup();
}
