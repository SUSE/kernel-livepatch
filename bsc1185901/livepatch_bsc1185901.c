/*
 * livepatch_bsc1185901
 *
 * Fix for CVE-2021-23133, bsc#1185901
 *
 *  Upstream commits:
 *  b166a20b0738 ("net/sctp: fix race condition in sctp_destroy_sock")
 *  01bfe5e8e428 ("Revert "net/sctp: fix race condition in sctp_destroy_sock")
 *  34e5b0118685 ("sctp: delay auto_asconf init until binding the first addr")
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  c06b5aa2485957a820dbffe3bbd2c1365c082625
 *
 *  SLE15-SP2 and -SP3 commit:
 *  cb84c72139e9053b3218e5e413c75a073acbeabe
 *
 *
 *  Copyright (c) 2021 SUSE
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
#include <linux/module.h>
#include "livepatch_bsc1185901.h"

#include "bsc1185901_common.h"

int livepatch_bsc1185901_init(void)
{
	int ret;

	ret = livepatch_bsc1185901_af_inet_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1185901_af_inet6_init();
	if (ret) {
		livepatch_bsc1185901_af_inet_cleanup();
		return ret;
	}

	ret = livepatch_bsc1185901_sctp_socket_init();
	if (ret) {
		livepatch_bsc1185901_af_inet6_cleanup();
		livepatch_bsc1185901_af_inet_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1185901_cleanup(void)
{
	livepatch_bsc1185901_sctp_socket_cleanup();
	livepatch_bsc1185901_af_inet6_cleanup();
	livepatch_bsc1185901_af_inet_cleanup();
}
