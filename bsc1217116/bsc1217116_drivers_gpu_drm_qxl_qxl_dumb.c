/*
 * bsc1217116_drivers_gpu_drm_qxl_qxl_dumb
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

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_put)(struct drm_gem_object *obj);

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drmP.h>
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <drm/ttm/ttm_module.h>
#include <drm/ttm/ttm_placement.h>

/* klp-ccp: from include/uapi/drm/qxl_drm.h */
#define QXL_GEM_DOMAIN_VRAM 1

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dev.h */
#include <linux/types.h>

#include "livepatch_bsc1217116.h"

enum SpiceSurfaceFmt {
	SPICE_SURFACE_FMT_INVALID,
	SPICE_SURFACE_FMT_1_A,
	SPICE_SURFACE_FMT_8_A = 8,
	SPICE_SURFACE_FMT_16_555 = 16,
	SPICE_SURFACE_FMT_32_xRGB = 32,
	SPICE_SURFACE_FMT_16_565 = 80,
	SPICE_SURFACE_FMT_32_ARGB = 96,

	SPICE_SURFACE_FMT_ENUM_END
};

typedef uint64_t QXLPHYSICAL;

struct qxl_surface {
	uint32_t format;
	uint32_t width;
	uint32_t height;
	int32_t stride;
	QXLPHYSICAL data;
};

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
struct qxl_bo {
	/* Protected by gem.mutex */
	struct list_head		list;
	/* Protected by tbo.reserved */
	struct ttm_place		placements[3];
	struct ttm_placement		placement;
	struct ttm_buffer_object	tbo;
	struct ttm_bo_kmap_obj		kmap;
	unsigned			pin_count;
	void				*kptr;
	int                             type;

	/* Constant after initialization */
	struct drm_gem_object		gem_base;
	bool is_primary; /* is this now a primary surface */
	bool is_dumb;
	struct qxl_bo *shadow;
	bool hw_surf_alloc;
	struct qxl_surface surf;
	uint32_t surface_id;
	struct qxl_release *surf_create;
};
#define gem_to_qxl_bo(gobj) container_of((gobj), struct qxl_bo, gem_base)

struct qxl_device;

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dumb.c */
int klpp_qxl_mode_dumb_create(struct drm_file *file_priv,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args)
{
	struct qxl_device *qdev = dev->dev_private;
	struct qxl_bo *qobj;
	struct drm_gem_object *gobj;
	uint32_t handle;
	int r;
	struct qxl_surface surf;
	uint32_t pitch, format;
	pitch = args->width * ((args->bpp + 1) / 8);
	args->size = pitch * args->height;
	args->size = ALIGN(args->size, PAGE_SIZE);

	switch (args->bpp) {
	case 16:
		format = SPICE_SURFACE_FMT_16_565;
		break;
	case 32:
		format = SPICE_SURFACE_FMT_32_xRGB;
		break;
	default:
		return -EINVAL;
	}

	surf.width = args->width;
	surf.height = args->height;
	surf.stride = pitch;
	surf.format = format;
	surf.data = 0;

	r = klpp_qxl_gem_object_create_with_handle(qdev, file_priv,
					      QXL_GEM_DOMAIN_VRAM,
					      args->size, &surf, &gobj,
					      &handle);
	if (r)
		return r;
	qobj = gem_to_qxl_bo(gobj);
	qobj->is_dumb = true;
	(*klpe_drm_gem_object_put)(gobj);
	args->pitch = pitch;
	args->handle = handle;
	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "qxl"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_gem_object_put", (void *)&klpe_drm_gem_object_put, "drm" },
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

int bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_init(void)
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

void bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */
