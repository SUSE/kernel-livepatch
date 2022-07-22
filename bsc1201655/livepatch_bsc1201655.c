/*
 * livepatch_bsc1201655
 *
 * Fix for CVE-2022-1419, bsc#1201655
 *
 *  Upstream commit:
 *  4b848f20eda5 ("drm/vgem: Close use-after-free race in vgem_gem_create")
 *
 *  SLE12-SP4, SLE15 and SLE15-SP1 commit:
 *  c2b5f0e82022b73dc6f601946deb49d258d05572
 *
 *  SLE12-SP5 commit:
 *  f3d608f5f2656c3fe0c3417484531ab0d337dd70
 *
 *  SLE15-SP2 and -SP3 commit:
 *  65490f21a92a28cde98155b342c2e935ba38cae8
 *
 *  SLE15-SP4 commit:
 *  not affected
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

#if IS_ENABLED(CONFIG_DRM_VGEM)

#if !IS_MODULE(CONFIG_DRM_VGEM)
#error "Live patch supports only CONFIG_DRM_VGEM=m"
#endif

/* klp-ccp: from drivers/gpu/drm/vgem/vgem_drv.c */
#include <linux/module.h>
#include <linux/shmem_fs.h>
#include <linux/dma-buf.h>
/* klp-ccp: from drivers/gpu/drm/vgem/vgem_drv.h */
#include <drm/drmP.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(2, 3)
void (*klpe_drm_dbg)(unsigned int category, const char *format, ...);

#define KLPR_DRM_DEBUG_DRIVER(fmt, ...)					\
	(*klpe_drm_dbg)(DRM_UT_DRIVER, fmt, ##__VA_ARGS__)


/* klp-ccp: from drivers/gpu/drm/vgem/vgem_drv.h */
#include <drm/drm_gem.h>

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_put_unlocked)(struct drm_gem_object *obj);

static int (*klpe_drm_gem_handle_create)(struct drm_file *file_priv,
			  struct drm_gem_object *obj,
			  u32 *handlep);

/* klp-ccp: from drivers/gpu/drm/vgem/vgem_drv.h */
struct drm_vgem_gem_object {
	struct drm_gem_object base;

	struct page **pages;
	unsigned int pages_pin_count;
	struct mutex pages_lock;

	struct sg_table *table;
};

/* klp-ccp: from drivers/gpu/drm/vgem/vgem_drv.c */
static struct drm_vgem_gem_object *(*klpe___vgem_gem_create)(struct drm_device *dev,
						unsigned long size);

static struct drm_gem_object *klpp_vgem_gem_create(struct drm_device *dev,
					      struct drm_file *file,
					      unsigned int *handle,
					      unsigned long size)
{
	struct drm_vgem_gem_object *obj;
	int ret;

	obj = (*klpe___vgem_gem_create)(dev, size);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	ret = (*klpe_drm_gem_handle_create)(file, &obj->base, handle);
	/*
	 * Fix CVE-2022-1419
	 *  -3 lines, +4 lines
	 */
	if (ret) {
		(*klpe_drm_gem_object_put_unlocked)(&obj->base);
		return ERR_PTR(ret);
	}

	return &obj->base;
}

int klpp_vgem_gem_dumb_create(struct drm_file *file, struct drm_device *dev,
				struct drm_mode_create_dumb *args)
{
	struct drm_gem_object *gem_object;
	u64 pitch, size;

	pitch = args->width * DIV_ROUND_UP(args->bpp, 8);
	size = args->height * pitch;
	if (size == 0)
		return -EINVAL;

	gem_object = klpp_vgem_gem_create(dev, file, &args->handle, size);
	if (IS_ERR(gem_object))
		return PTR_ERR(gem_object);

	args->size = gem_object->size;
	args->pitch = pitch;

	/*
	 * Fix CVE-2022-1419
	 *  -1 line, +3 lines
	 */
	(*klpe_drm_gem_object_put_unlocked)(gem_object);

	KLPR_DRM_DEBUG_DRIVER("Created object of size %llu\n", args->size);

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1201655.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "vgem"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_dbg", (void *)&klpe_drm_dbg, "drm" },
	{ "drm_gem_handle_create", (void *)&klpe_drm_gem_handle_create, "drm" },
	{ "drm_gem_object_put_unlocked",
	  (void *)&klpe_drm_gem_object_put_unlocked, "drm" },
	{ "__vgem_gem_create", (void *)&klpe___vgem_gem_create, "vgem" },
};

static int livepatch_bsc1201655_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1201655_module_nb = {
	.notifier_call = livepatch_bsc1201655_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1201655_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1201655_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1201655_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1201655_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VGEM) */
