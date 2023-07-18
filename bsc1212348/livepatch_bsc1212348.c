/*
 * livepatch_bsc1212348
 *
 * Fix for CVE-2023-33952, bsc#1212348
 *
 *  Upstream commit:
 *  a950b989ea29 ("drm/vmwgfx: Do not drop the reference to the handle too soon")
 *
 *  SLE12-SP5, SLE15-SP1, SLE15-SP2, -SP3 and -SP4 commit:
 *  Not affected
 *
 *  SLE15-SP5 commit:
 *  f408f067b15126d054fa93efe2a6962e7be1d6d6
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_DRM_VMWGFX)

#include "livepatch_bsc1212348.h"

int livepatch_bsc1212348_init(void)
{
	int ret;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_init();
	if (ret)
		return ret;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_init();
	if (ret)
		goto out_bo;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_init();
	if (ret)
		goto out_execbuf;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_kms_init();
	if (ret)
		goto out_gem;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_overlay_init();
	if (ret)
		goto out_kms;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_init();
	if (ret)
		goto out_overlay;

	ret = bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface_init();
	if (ret)
		goto out_shader;

	return 0;

out_shader:
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_cleanup();
out_overlay:
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_overlay_cleanup();
out_kms:
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_kms_cleanup();
out_gem:
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_cleanup();
out_execbuf:
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_cleanup();
out_bo:
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_cleanup();
	return ret;
}

void livepatch_bsc1212348_cleanup(void)
{
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface_cleanup();
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_cleanup();
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_overlay_cleanup();
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_kms_cleanup();
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_cleanup();
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_cleanup();
	bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_cleanup();
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
