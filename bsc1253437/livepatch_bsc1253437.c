/*
 * livepatch_bsc1253437
 *
 * Fix for CVE-2025-40204, bsc#1253437
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

#include "livepatch_bsc1253437.h"

int livepatch_bsc1253437_init(void)
{

	int ret;

	ret = bsc1253437_net_sctp_sm_make_chunk_init();
	if (ret)
		return ret;

	ret = bsc1253437_net_sctp_sm_statefuns_init();
	if (ret) {
		bsc1253437_net_sctp_sm_make_chunk_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1253437_cleanup(void)
{
	bsc1253437_net_sctp_sm_make_chunk_cleanup();

	bsc1253437_net_sctp_sm_statefuns_cleanup();

}

