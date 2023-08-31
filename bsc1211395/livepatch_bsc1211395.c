/*
 * livepatch_bsc1211395
 *
 * Fix for CVE-2023-2156, bsc#1211395
 *
 *  Upstream commit:
 *  4e006c7a6dac ("net: rpl: fix rpl header size calculation")
 *  a2f4c143d76b ("ipv6: rpl: Fix Route of Death.")
 *
 *  SLE12-SP5, SLE15-SP1 and -SP2 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  884cd150671de4ac3ebfe4313762074df22e33e8
 *  5601bfa509d6145f887513f07bb8cdc614152857
 *
 *  SLE15-SP4 and -SP5 commit:
 *  c308d834c6e6432315236add3121669ce763f368
 *  c2f8329a79699ffcbf510db4ab1238f8c778a187
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

#include "livepatch_bsc1211395.h"

int livepatch_bsc1211395_init(void)
{
	return bsc1211395_net_ipv6_exthdrs_init();
}
