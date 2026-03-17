/*
 * livepatch_bsc1255402
 *
 * Fix for CVE-2025-68285, bsc#1255402
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

#include "livepatch_bsc1255402.h"

int livepatch_bsc1255402_init(void)
{
	int ret;

	ret = bsc1255402_net_ceph_ceph_common_init();
	if (ret)
		return ret;

	ret = bsc1255402_net_ceph_debugfs_init();
	if (ret) {
		bsc1255402_net_ceph_ceph_common_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1255402_cleanup(void)
{
	bsc1255402_net_ceph_debugfs_cleanup();
	bsc1255402_net_ceph_ceph_common_cleanup();
}
