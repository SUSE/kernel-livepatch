/*
 * bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl
 *
 * Fix for CVE-2023-39198, bsc#1217116
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

#if !IS_MODULE(CONFIG_DRM_QXL)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <linux/dma-fence.h>
#include <linux/workqueue.h>
#include <linux/firmware.h>
#include <linux/platform_device.h>
#include <drm/drm_crtc.h>
#include <drm/drm_gem.h>

/* klp-ccp: from include/drm/drm_print.h */
static void (*klpe_drm_err)(const char *, ...);

#define KLPR_DRM_ERROR(fmt, ...) \
	(*klpe_drm_err)(fmt, ##__VA_ARGS__)

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drmP.h>

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/ttm/ttm_module.h>
#include <drm/ttm/ttm_placement.h>
#include <drm/qxl_drm.h>
/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dev.h */
#include <linux/types.h>

#include "livepatch_bsc1217116.h"

typedef uint64_t QXLPHYSICAL;

struct qxl_surface {
	uint32_t format;
	uint32_t width;
	uint32_t height;
	int32_t stride;
	QXLPHYSICAL data;
};

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
struct qxl_device;

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_ioctl.c */
int klpp_qxl_alloc_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv)
{
	struct qxl_device *qdev = dev->dev_private;
	struct drm_qxl_alloc *qxl_alloc = data;
	int ret;
	uint32_t handle;
	u32 domain = QXL_GEM_DOMAIN_VRAM;

	if (qxl_alloc->size == 0) {
		KLPR_DRM_ERROR("invalid size %d\n",qxl_alloc->size);
		return -EINVAL;
	}
	ret = klpp_qxl_gem_object_create_with_handle(qdev, file_priv,
						domain,
						qxl_alloc->size,
						NULL,
						NULL, &handle);
	if (ret) {
		KLPR_DRM_ERROR("%s: failed to create gem ret=%d\n",__func__, ret);
		return -ENOMEM;
	}
	qxl_alloc->handle = handle;
	return 0;
}

int klpp_qxl_alloc_surf_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file)
{
	struct qxl_device *qdev = dev->dev_private;
	struct drm_qxl_alloc_surf *param = data;
	int handle;
	int ret;
	int size, actual_stride;
	struct qxl_surface surf;

	/* work out size allocate bo with handle */
	actual_stride = param->stride < 0 ? -param->stride : param->stride;
	size = actual_stride * param->height + actual_stride;

	surf.format = param->format;
	surf.width = param->width;
	surf.height = param->height;
	surf.stride = param->stride;
	surf.data = 0;

	ret = klpp_qxl_gem_object_create_with_handle(qdev, file,
						QXL_GEM_DOMAIN_SURFACE,
						size,
						&surf,
						NULL, &handle);
	if (ret) {
		KLPR_DRM_ERROR("%s: failed to create gem ret=%d\n",__func__, ret);
		return -ENOMEM;
	} else
		param->handle = handle;
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "qxl"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_err", (void *)&klpe_drm_err, "drm" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */
