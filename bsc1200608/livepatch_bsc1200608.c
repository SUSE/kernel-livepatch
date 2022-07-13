/*
 * livepatch_bsc1200608
 *
 * Fix for CVE-2022-20154, bsc#1200608
 *
 *  Upstream commit:
 *  5ec7d18d1813 ("sctp: use call_rcu to free endpoint")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  3cb182dccadbba1119de54f5047a7c30b3d037a0
 *
 *  SLE15-SP2 and -SP3 commit:
 *  44ec44bfdd924468eb987eecc1f4335a6d671036
 *
 *  SLE15-SP4 commit:
 *  7c734e095a0739278582e6e424b5872eaae606e3
 *
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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
#include "livepatch_bsc1200608.h"
#include "bsc1200608_common.h"

int livepatch_bsc1200608_init(void)
{
	int ret;

	ret = livepatch_bsc1200608_sctp_diag_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1200608_sctp_endpointola_init();
	if (ret) {
		livepatch_bsc1200608_sctp_diag_cleanup();
		return ret;
	}

	ret = livepatch_bsc1200608_sctp_socket_init();
	if (ret) {
		livepatch_bsc1200608_sctp_endpointola_cleanup();
		livepatch_bsc1200608_sctp_diag_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1200608_cleanup(void)
{
	livepatch_bsc1200608_sctp_socket_cleanup();
	livepatch_bsc1200608_sctp_endpointola_cleanup();
	livepatch_bsc1200608_sctp_diag_cleanup();
}
