/*
 * livepatch_bsc1217116
 *
 * Fix for CVE-2023-39198, bsc#1217116
 *
 *  Upstream commit:
 *  c611589b4259 ("drm/qxl: fix UAF on handle creation")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  9ba677b99c98d4aed1e31dadca42ce3c96abd9a1
 *
 *  SLE15-SP2 and -SP3 commit:
 *  a0819bc48e9ff3744cf758718e0dd68e1776937c
 *
 *  SLE15-SP4 and -SP5 commit:
 *  d6014b64e9c47e3645dbfdb60171704ebb74ec60
 *  15cc5bbbc8ad16fa5ab384f99fa4199d6feb6919
 *
 *  Copyright (c) 2024 SUSE
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

#if IS_ENABLED(CONFIG_DRM_QXL)

#include "livepatch_bsc1217116.h"

int livepatch_bsc1217116_init(void)
{
	int ret;

	ret = bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_init();
	if (ret)
		return ret;

	ret = bsc1217116_drivers_gpu_drm_qxl_qxl_gem_init();
	if (ret)
		goto out_dumb;

	ret = bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_init();
	if (ret)
		goto out_gem;

	return 0;

out_gem:
	bsc1217116_drivers_gpu_drm_qxl_qxl_gem_cleanup();

out_dumb:
	bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_cleanup();

	return ret;
}

void livepatch_bsc1217116_cleanup(void)
{
	bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_cleanup();
	bsc1217116_drivers_gpu_drm_qxl_qxl_gem_cleanup();
	bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_cleanup();
}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */
