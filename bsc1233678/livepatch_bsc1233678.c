/*
 * livepatch_bsc1233678
 *
 * Fix for CVE-2024-53042, bsc#1233678
 *
 *  Upstream commit:
 *  ad4a3ca6a8e8 ("ipv4: ip_tunnel: Fix suspicious RCU usage warning in ip_tunnel_init_flow()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  6649f1028f25d9e6863c6d6132e9d2c613bb93c7
 *
 *  SLE MICRO-6-0 commit:
 *  6649f1028f25d9e6863c6d6132e9d2c613bb93c7
 *
 *  Copyright (c) 2025 SUSE
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

#include "livepatch_bsc1233678.h"

int livepatch_bsc1233678_init(void)
{
	return 0;
}

void livepatch_bsc1233678_cleanup(void)
{
}

