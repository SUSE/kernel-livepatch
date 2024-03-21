/*
 * livepatch_bsc1208911
 *
 * Fix for CVE-2023-0461, bsc#1208911
 *
 *  Upstream commit:
 *  2c02d41d71f9 ("net/ulp: prevent ULP without clone op from entering the LISTEN status")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  None yet
 *
 *  SLE15-SP2 and -SP3 commit:
 *  66ad1fdf712ea43429b486add9bb69f48672c826
 *
 *  SLE15-SP4 commit:
 *  b5c2842334a421e953ddb3a20949a1d201db43fe
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



#include <linux/kernel.h>
#include "livepatch_bsc1208911.h"
#include "../kallsyms_relocs.h"

int livepatch_bsc1208911_init(void)
{
	int ret;

	ret = bsc1208911_net_ipv4_inet_connection_sock_init();
	if (ret)
		return ret;

	return bsc1208911_net_ipv4_tcp_ulp_init();
}

