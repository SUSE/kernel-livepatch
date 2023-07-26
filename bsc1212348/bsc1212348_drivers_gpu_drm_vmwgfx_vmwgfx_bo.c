/*
 * bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo
 *
 * Fix for CVE-2023-33952, bsc#1212348
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

#if !IS_MODULE(CONFIG_DRM_VMWGFX)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1212348.h"

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_bo.c */
#include <drm/ttm/ttm_placement.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <linux/suspend.h>
#include <linux/sync_file.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo_driver.h>

/* klp-ccp: from include/drm/drm_print.h */
static __printf(1, 2)
void (*klpe___drm_err)(const char *format, ...);

/* klp-ccp: from include/drm/drm_gem.h */
static void (*klpe_drm_gem_object_free)(struct kref *kref);

__attribute__((nonnull))
static inline void
klpr___drm_gem_object_put(struct drm_gem_object *obj)
{
	kref_put(&obj->refcount, (*klpe_drm_gem_object_free));
}

inline void
klpr_drm_gem_object_put(struct drm_gem_object *obj)
{
	if (obj)
		klpr___drm_gem_object_put(obj);
}

static struct drm_gem_object *(*klpe_drm_gem_object_lookup)(struct drm_file *filp, u32 handle);

/* klp-ccp: from include/drm/ttm/ttm_bo_api.h */
static int (*klpe_ttm_bo_wait)(struct ttm_buffer_object *bo, bool interruptible, bool no_wait);

static void (*klpe_ttm_bo_put)(struct ttm_buffer_object *bo);

static void (*klpe_ttm_bo_move_to_lru_tail)(struct ttm_buffer_object *bo);

/* klp-ccp: from include/drm/ttm/ttm_bo_driver.h */
static inline void
klpr_ttm_bo_move_to_lru_tail_unlocked(struct ttm_buffer_object *bo)
{
	spin_lock(&bo->bdev->lru_lock);
	(*klpe_ttm_bo_move_to_lru_tail)(bo);
	spin_unlock(&bo->bdev->lru_lock);
}

static inline void klpr_ttm_bo_unreserve(struct ttm_buffer_object *bo)
{
	klpr_ttm_bo_move_to_lru_tail_unlocked(bo);
	dma_resv_unlock(bo->base.resv);
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_hashtab.h */
#include <linux/list.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_fence.h */
#ifndef _VMWGFX_FENCE_H_

#include <linux/dma-fence.h>
#include <linux/dma-fence-array.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _VMWGFX_FENCE_H_ */

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_reg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vm_basic_types.h */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/page.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_validation.h */
#include <linux/list.h>
#include <linux/ww_mutex.h>
#include <drm/ttm/ttm_execbuf_util.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/vmwgfx_drm.h>

struct vmw_buffer_object {
	struct ttm_buffer_object base;
	struct rb_root res_tree;
	/* For KMS atomic helpers: ttm bo mapping count */
	atomic_t base_mapped_count;

	atomic_t cpu_writers;
	/* Not ref-counted.  Protected by binding_mutex */
	struct vmw_resource *dx_query_ctx;
	/* Protected by reservation */
	struct ttm_bo_kmap_obj map;
	u32 res_prios[TTM_MAX_BO_PRIORITY];
	struct vmw_bo_dirty *dirty;
};

static inline struct vmw_buffer_object *gem_to_vmw_bo(struct drm_gem_object *gobj)
{
	return container_of((gobj), struct vmw_buffer_object, base.base);
}

static inline struct vmw_private *vmw_priv(struct drm_device *dev)
{
	return (struct vmw_private *)dev->dev_private;
}

static int (*klpe_vmw_gem_object_create_with_handle)(struct vmw_private *dev_priv,
					     struct drm_file *filp,
					     uint32_t size,
					     uint32_t *handle,
					     struct vmw_buffer_object **p_vbo);

static inline void klpr_vmw_bo_unreference(struct vmw_buffer_object **buf)
{
	struct vmw_buffer_object *tmp_buf = *buf;

	*buf = NULL;
	if (tmp_buf != NULL)
		(*klpe_ttm_bo_put)(&tmp_buf->base);
}

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_bo.c */
static int klpr_vmw_user_bo_synccpu_grab(struct vmw_buffer_object *vmw_bo,
				    uint32_t flags)
{
	bool nonblock = !!(flags & drm_vmw_synccpu_dontblock);
	struct ttm_buffer_object *bo = &vmw_bo->base;
	int ret;

	if (flags & drm_vmw_synccpu_allow_cs) {
		long lret;

		lret = dma_resv_wait_timeout(bo->base.resv, DMA_RESV_USAGE_READ,
					     true, nonblock ? 0 :
					     MAX_SCHEDULE_TIMEOUT);
		if (!lret)
			return -EBUSY;
		else if (lret < 0)
			return lret;
		return 0;
	}

	ret = ttm_bo_reserve(bo, true, nonblock, NULL);
	if (unlikely(ret != 0))
		return ret;

	ret = (*klpe_ttm_bo_wait)(bo, true, nonblock);
	if (likely(ret == 0))
		atomic_inc(&vmw_bo->cpu_writers);

	klpr_ttm_bo_unreserve(bo);
	if (unlikely(ret != 0))
		return ret;

	return ret;
}

static int klpp_vmw_user_bo_synccpu_release(struct drm_file *filp,
				       uint32_t handle,
				       uint32_t flags)
{
	struct vmw_buffer_object *vmw_bo;
	int ret = klpp_vmw_user_bo_lookup(filp, handle, &vmw_bo);

	if (!ret) {
		if (!(flags & drm_vmw_synccpu_allow_cs)) {
			atomic_dec(&vmw_bo->cpu_writers);
		}
		(*klpe_ttm_bo_put)(&vmw_bo->base);
	}

	klpr_drm_gem_object_put(&vmw_bo->base.base);
	return ret;
}

int klpp_vmw_user_bo_synccpu_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv)
{
	struct drm_vmw_synccpu_arg *arg =
		(struct drm_vmw_synccpu_arg *) data;
	struct vmw_buffer_object *vbo;
	int ret;

	if ((arg->flags & (drm_vmw_synccpu_read | drm_vmw_synccpu_write)) == 0
	    || (arg->flags & ~(drm_vmw_synccpu_read | drm_vmw_synccpu_write |
			       drm_vmw_synccpu_dontblock |
			       drm_vmw_synccpu_allow_cs)) != 0) {
		(*klpe___drm_err)("Illegal synccpu flags.\n");
		return -EINVAL;
	}

	switch (arg->op) {
	case drm_vmw_synccpu_grab:
		ret = klpp_vmw_user_bo_lookup(file_priv, arg->handle, &vbo);
		if (unlikely(ret != 0))
			return ret;

		ret = klpr_vmw_user_bo_synccpu_grab(vbo, arg->flags);
		klpr_vmw_bo_unreference(&vbo);
		klpr_drm_gem_object_put(&vbo->base.base);
		if (unlikely(ret != 0)) {
			if (ret == -ERESTARTSYS || ret == -EBUSY)
				return -EBUSY;
			(*klpe___drm_err)("Failed synccpu grab on handle 0x%08x.\n",(unsigned int) arg->handle);
			return ret;
		}
		break;
	case drm_vmw_synccpu_release:
		ret = klpp_vmw_user_bo_synccpu_release(file_priv,
						  arg->handle,
						  arg->flags);
		if (unlikely(ret != 0)) {
			(*klpe___drm_err)("Failed synccpu release on handle 0x%08x.\n",(unsigned int) arg->handle);
			return ret;
		}
		break;
	default:
		(*klpe___drm_err)("Invalid synccpu operation.\n");
		return -EINVAL;
	}

	return 0;
}

int klpp_vmw_user_bo_lookup(struct drm_file *filp,
		       uint32_t handle,
		       struct vmw_buffer_object **out)
{
	struct drm_gem_object *gobj;

	gobj = (*klpe_drm_gem_object_lookup)(filp, handle);
	if (!gobj) {
		(*klpe___drm_err)("Invalid buffer object handle 0x%08lx.\n",(unsigned long)handle);
		return -ESRCH;
	}

	*out = gem_to_vmw_bo(gobj);
	ttm_bo_get(&(*out)->base);

	return 0;
}

int klpp_vmw_dumb_create(struct drm_file *file_priv,
		    struct drm_device *dev,
		    struct drm_mode_create_dumb *args)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	struct vmw_buffer_object *vbo;
	int ret;

	args->pitch = args->width * ((args->bpp + 7) / 8);
	args->size = ALIGN(args->pitch * args->height, PAGE_SIZE);

	ret = (*klpe_vmw_gem_object_create_with_handle)(dev_priv, file_priv,
						args->size, &args->handle,
						&vbo);

	/* drop reference from allocate - handle holds it now */
	klpr_drm_gem_object_put(&vbo->base.base);
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vmwgfx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__drm_err", (void *)&klpe___drm_err, "drm" },
	{ "drm_gem_object_free", (void *)&klpe_drm_gem_object_free, "drm" },
	{ "drm_gem_object_lookup", (void *)&klpe_drm_gem_object_lookup,
	  "drm" },
	{ "ttm_bo_move_to_lru_tail", (void *)&klpe_ttm_bo_move_to_lru_tail,
	  "ttm" },
	{ "ttm_bo_put", (void *)&klpe_ttm_bo_put, "ttm" },
	{ "ttm_bo_wait", (void *)&klpe_ttm_bo_wait, "ttm" },
	{ "vmw_gem_object_create_with_handle",
	  (void *)&klpe_vmw_gem_object_create_with_handle, "vmwgfx" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
