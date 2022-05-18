/*
 * livepatch_bsc1198590
 *
 * Fix for CVE-2022-1280, bsc#1198590
 *
 *  Upstream commits:
 *  869e76f7a918 ("drm: avoid circular locks in drm_mode_getconnector")
 *  5eff9585de22 ("drm: avoid blocking in drm_clients_info's rcu section")
 *  1f7ef07cfa14 ("drm: add a locked version of drm_is_current_master")
 *  0b0860a3cf5e ("drm: serialize drm_file.master with a new spinlock")
 *  56f0729a510f ("drm: protect drm_master pointers in drm_lease.c")
 *  28be2405fb75 ("drm: use the lookup lock in drm_is_current_master")
 *
 *  SLE12-SP3 commit:
 *  Not affected
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE12-SP5 commits:
 *  3095d7b2e6f0f67718f4aab263017161e9dcc474
 *  4f97fa9204c6a6298b014719f8f29a5ad9e6fee0
 *  16fea17c857feea5c62220fe571004ad946fab98
 *  4b9807ba7b0dbb9108b7df4bfa5ac24eb42e8ca9
 *
 *  SLE15-SP2 commits:
 *  cb6322a7d6cfd5a1b29353818ab06ff5dd563702
 *  a42efa862001c7a8051dd6a2d36dc1ccd81e4187
 *  cd36b1c933630df271fd5297cdb74c573bcd88d6
 *  f800e5380a3b19bd843d3e9166f5e2e4d999998f
 *  82a498ae7f940156157ba6f50140a8fe61a40635
 *
 *  SLE15-SP3 commits:
 *  cb6322a7d6cfd5a1b29353818ab06ff5dd563702
 *  195575e704a4442e30a3afe22b84a01da9e4fdcd
 *  81bf8e60f8221875ea950a6c05327ea0ab896ef5
 *  d3c944d8574354746dd8a23531722b0bf099cc91
 *  05fda16d52b2fcea21717f3d2364427eb58b1a50
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

#if !IS_MODULE(CONFIG_DRM)
#error "Live patch supports only CONFIG=m"
#endif

#include <linux/kernel.h>
#include "livepatch_bsc1198590.h"
#include "bsc1198590_common.h"

int livepatch_bsc1198590_init(void)
{
	int ret;

	ret = bsc1198590_drm_auth_init();
	if (ret)
		return ret;

	ret = bsc1198590_drm_lease_init();
	if (ret) {
		bsc1198590_drm_auth_cleanup();
		return ret;
	}

	return 0;
}

void livepatch_bsc1198590_cleanup(void)
{
	bsc1198590_drm_lease_cleanup();
	bsc1198590_drm_auth_cleanup();
}
