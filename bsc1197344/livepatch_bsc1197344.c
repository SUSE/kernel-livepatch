/*
 * livepatch_bsc1197344
 *
 * Fix for CVE-2022-1011, bsc#1197344
 *
 *  Upstream commit:
 *  0c4bcfdecb1a ("fuse: fix pipe buffer lifetime for direct_io")
 *
 *  SLE12-SP3 commits:
 *  4b7a8537c9173f8546f51d5583018d29f316dbef
 *  680c1130e1c129f6e7f82433f237b8af7a7a07bc
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  2010d5f616d5b0bbe4e101b9466c02f99fec7c52
 *  e67cd7e310e17be5dd9812fffa22da128e183c82
 *
 *  SLE15-SP2 commits:
 *  769342d09dc8b0c0b41ec652917a1b3b7e024451
 *  5920a5896e0806ab0a3654ba59c670f25f710eee
 *
 *  SLE15-SP3 commits:
 *  dc8ab5873f958b4c90e1d0992ff21050d1c76b11
 *  112493c714c593fbd84dff2cf4fa9bb9014cc3e6
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

#if !IS_MODULE(CONFIG_FUSE_FS)
#error "Live patch supports only CONFIG_FUSE_FS=m"
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include "bsc1197344_common.h"
#include "livepatch_bsc1197344.h"

int livepatch_bsc1197344_init(void)
{
	int ret;

	ret = livepatch_bsc1197344_fuse_dev_init();
	if (ret)
		return ret;

	ret = livepatch_bsc1197344_fuse_file_init();
	if (ret) {
		livepatch_bsc1197344_fuse_dev_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1197344_cleanup(void)
{
	livepatch_bsc1197344_fuse_file_cleanup();
	livepatch_bsc1197344_fuse_dev_cleanup();
}
