/*
 * livepatch_bsc1240744
 *
 * Fix for CVE-2025-21791, bsc#1240744
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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

#include "livepatch_bsc1240744.h"

int livepatch_bsc1240744_init(void)
{
	int ret = 0;
	ret = bsc1240744_net_ipv6_ip6_output_init();
	if (ret)
		return ret;
	ret = bsc1240744_net_ipv6_raw_init();
	if (ret)
		return ret;
	return 0;
}

void livepatch_bsc1240744_cleanup(void)
{
}

