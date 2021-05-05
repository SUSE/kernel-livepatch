/*
 * livepatch_bsc1184952
 *
 * Fix for CVE-2020-36322, bsc#1184952
 *
 *  Upstream commits:
 *  5d069dbe8aaf ("fuse: fix bad inode")
 *  775c5033a0d1 ("fuse: fix live lock in fuse_iget()")
 *
 *  SLE12-SP3 commits:
 *  b67593cbb31b22f354799700cb0e3060d91d5b7f
 *  98e06ce756cabef9a759375edf8388e80819f903
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  2748563da3794bce6b4fb75d399d4fb0b54bc2ae
 *  920863f3f3015b9f218218a5c1d7a3555e7c3b8e
 *
 *  SLE15-SP2 commits:
 *  68a2872392d192b6b92e344906f46665f3636af3
 *  8283ce10828d7049cf14a9edd7f84918912aa3ff
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

#include "bsc1184952_common.h"
#include "livepatch_bsc1184952.h"

int livepatch_bsc1184952_init(void)
{
	int ret;

	ret = livepatch_bsc1184952_fuse_acl_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1184952_fuse_dir_init();
	if (ret) {
		livepatch_bsc1184952_fuse_acl_cleanup();
		return ret;
	}

	ret = livepatch_bsc1184952_fuse_file_init();
	if (ret) {
		livepatch_bsc1184952_fuse_dir_cleanup();
		livepatch_bsc1184952_fuse_acl_cleanup();
		return ret;
	}

	ret = livepatch_bsc1184952_fuse_inode_init();
	if (ret) {
		livepatch_bsc1184952_fuse_file_cleanup();
		livepatch_bsc1184952_fuse_dir_cleanup();
		livepatch_bsc1184952_fuse_acl_cleanup();
		return ret;
	}

	ret = livepatch_bsc1184952_fuse_xattr_init();
	if (ret) {
		livepatch_bsc1184952_fuse_inode_cleanup();
		livepatch_bsc1184952_fuse_file_cleanup();
		livepatch_bsc1184952_fuse_dir_cleanup();
		livepatch_bsc1184952_fuse_acl_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1184952_cleanup(void)
{
	livepatch_bsc1184952_fuse_xattr_cleanup();
	livepatch_bsc1184952_fuse_inode_cleanup();
	livepatch_bsc1184952_fuse_file_cleanup();
	livepatch_bsc1184952_fuse_dir_cleanup();
	livepatch_bsc1184952_fuse_acl_cleanup();
}
