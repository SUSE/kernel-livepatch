/*
 * bsc1217116_drivers_gpu_drm_qxl_qxl_gem
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

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_gem.c */
#include <drm/drmP.h>
#include <drm/drm.h>
/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <linux/dma-fence.h>
#include <linux/workqueue.h>
#include <linux/platform_device.h>
#include <drm/drm_crtc.h>

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_put_unlocked)(struct drm_gem_object *obj);

static inline void
klpr_drm_gem_object_unreference_unlocked(struct drm_gem_object *obj)
{
	(*klpe_drm_gem_object_put_unlocked)(obj);
}

static int (*klpe_drm_gem_handle_create)(struct drm_file *file_priv,
			  struct drm_gem_object *obj,
			  u32 *handlep);

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/drmP.h>

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
#include <drm/ttm/ttm_module.h>
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/qxl/qxl_dev.h */
#include <linux/types.h>

struct qxl_surface;

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_drv.h */
struct qxl_device;

/* klp-ccp: from drivers/gpu/drm/qxl/qxl_gem.c */
static int (*klpe_qxl_gem_object_create)(struct qxl_device *qdev, int size,
			  int alignment, int initial_domain,
			  bool discardable, bool kernel,
			  struct qxl_surface *surf,
			  struct drm_gem_object **obj);

int klpp_qxl_gem_object_create_with_handle(struct qxl_device *qdev,
				      struct drm_file *file_priv,
				      u32 domain,
				      size_t size,
				      struct qxl_surface *surf,
				      struct drm_gem_object **gobj,
				      uint32_t *handle)
{
	int r;
	struct drm_gem_object *local_gobj;

	BUG_ON(!handle);

	r = (*klpe_qxl_gem_object_create)(qdev, size, 0,
				  domain,
				  false, false, surf,
				  &local_gobj);
	if (r)
		return -ENOMEM;
	r = (*klpe_drm_gem_handle_create)(file_priv, local_gobj, handle);
	if (r)
		return r;

	if (gobj)
		*gobj = local_gobj;
	else
		/* drop reference from allocate - handle holds it now */
		klpr_drm_gem_object_unreference_unlocked(local_gobj);

	return 0;
}



#include "livepatch_bsc1217116.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "qxl"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_gem_handle_create", (void *)&klpe_drm_gem_handle_create,
	  "drm" },
	{ "drm_gem_object_put_unlocked",
	  (void *)&klpe_drm_gem_object_put_unlocked, "drm" },
	{ "qxl_gem_object_create", (void *)&klpe_qxl_gem_object_create,
	  "qxl" },
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

int bsc1217116_drivers_gpu_drm_qxl_qxl_gem_init(void)
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

void bsc1217116_drivers_gpu_drm_qxl_qxl_gem_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */
