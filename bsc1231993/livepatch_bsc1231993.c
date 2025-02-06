/*
 * livepatch_bsc1231993
 *
 * Fix for CVE-2024-47684, bsc#1231993
 *
 *  Upstream commit:
 *  c8770db2d544 ("tcp: check skb is non-NULL in tcp_rto_delta_us()")
 *
 *  SLE12-SP5 commit:
 *  35606099a23deebde857b43482da6e280949d6be
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b050ae283562a7211160ca7e937f652648e5037b
 *
 *  SLE15-SP4 and -SP5 commit:
 *  569d85685d31f73b596515198169d6ca6b2bced9
 *
 *  SLE15-SP6 commit:
 *  e27a5c2a64bc5790a49cc7dc399e4ad864bf05b9
 *
 *  SLE MICRO-6-0 commit:
 *  e27a5c2a64bc5790a49cc7dc399e4ad864bf05b9
 *
 *  Copyright (c) 2025 SUSE
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

#include "livepatch_bsc1231993.h"

int livepatch_bsc1231993_init(void)
{
	return 0;
}

void livepatch_bsc1231993_cleanup(void)
{
}

