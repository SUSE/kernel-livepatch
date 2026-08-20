/*
 * livepatch_bsc1270023
 *
 * Fix for CVE-2026-53224, bsc#1270023
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

#include "livepatch_bsc1270023.h"

int livepatch_bsc1270023_init(void)
{

	int ret;

	ret = bsc1270023_net_sctp_sm_make_chunk_init();
	if (ret)
		return ret;

	ret = bsc1270023_net_sctp_bind_addr_init();
	if (ret)
		return ret;

	return 0;
}

void livepatch_bsc1270023_cleanup(void)
{
	bsc1270023_net_sctp_sm_make_chunk_cleanup();

	bsc1270023_net_sctp_bind_addr_cleanup();

}

