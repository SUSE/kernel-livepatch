/*
 * bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem
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

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <linux/suspend.h>
#include <linux/sync_file.h>

struct drm_lock_data;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drm_device.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo_driver.h>

static int (*klpe_drm_gem_handle_create)(struct drm_file *file_priv,
			  struct drm_gem_object *obj,
			  u32 *handlep);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_hashtab.h */
#include <linux/list.h>

struct vmwgfx_open_hash {
	struct hlist_head *table;
	u8 order;
};

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

typedef u32 uint32;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_validation.h */
#include <linux/list.h>
#include <linux/ww_mutex.h>
#include <drm/ttm/ttm_execbuf_util.h>
/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/vmwgfx_drm.h>

#define VMWGFX_MAX_NUM_IRQS 6

#define MKSSTAT_CAPACITY_LOG2 5U
#define MKSSTAT_CAPACITY (1U << MKSSTAT_CAPACITY_LOG2)

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

enum vmw_res_type {
	vmw_res_context,
	vmw_res_surface,
	vmw_res_stream,
	vmw_res_shader,
	vmw_res_dx_context,
	vmw_res_cotable,
	vmw_res_view,
	vmw_res_streamoutput,
	vmw_res_max
};

struct vmw_res_cache_entry {
	uint32_t handle;
	struct vmw_resource *res;
	void *private;
	unsigned short valid_handle;
	unsigned short valid;
};

enum vmw_dma_map_mode {
	vmw_dma_alloc_coherent, /* Use TTM coherent pages */
	vmw_dma_map_populate,   /* Unmap from DMA just after unpopulate */
	vmw_dma_map_bind,       /* Unmap from DMA just before unbind */
	vmw_dma_map_max
};

enum vmw_display_unit_type {
	vmw_du_invalid = 0,
	vmw_du_legacy,
	vmw_du_screen_object,
	vmw_du_screen_target,
	vmw_du_max
};

struct vmw_sw_context{
	struct vmwgfx_open_hash res_ht;
	bool res_ht_initialized;
	bool kernel;
	struct vmw_fpriv *fp;
	struct drm_file *filp;
	uint32_t *cmd_bounce;
	uint32_t cmd_bounce_size;
	struct vmw_buffer_object *cur_query_bo;
	struct list_head bo_relocations;
	struct list_head res_relocations;
	uint32_t *buf_start;
	struct vmw_res_cache_entry res_cache[vmw_res_max];
	struct vmw_resource *last_query_ctx;
	bool needs_post_query_barrier;
	struct vmw_ctx_binding_state *staged_bindings;
	bool staged_bindings_inuse;
	struct list_head staged_cmd_res;
	struct list_head ctx_list;
	struct vmw_ctx_validation_info *dx_ctx_node;
	struct vmw_buffer_object *dx_query_mob;
	struct vmw_resource *dx_query_ctx;
	struct vmw_cmdbuf_res_manager *man;
	struct vmw_validation_context *ctx;
};

struct vmw_otable_batch {
	unsigned num_otables;
	struct vmw_otable *otables;
	struct vmw_resource *context;
	struct ttm_buffer_object *otable_bo;
};

enum {
	VMW_IRQTHREAD_FENCE,
	VMW_IRQTHREAD_CMDBUF,
	VMW_IRQTHREAD_MAX
};

enum vmw_sm_type {
	VMW_SM_LEGACY = 0,
	VMW_SM_4,
	VMW_SM_4_1,
	VMW_SM_5,
	VMW_SM_5_1X,
	VMW_SM_MAX
};

struct vmw_private {
	struct drm_device drm;
	struct ttm_device bdev;

	struct drm_vma_offset_manager vma_manager;
	u32 pci_id;
	resource_size_t io_start;
	resource_size_t vram_start;
	resource_size_t vram_size;
	resource_size_t max_primary_mem;
	u32 __iomem *rmmio;
	u32 *fifo_mem;
	resource_size_t fifo_mem_size;
	uint32_t fb_max_width;
	uint32_t fb_max_height;
	uint32_t texture_max_width;
	uint32_t texture_max_height;
	uint32_t stdu_max_width;
	uint32_t stdu_max_height;
	uint32_t initial_width;
	uint32_t initial_height;
	uint32_t capabilities;
	uint32_t capabilities2;
	uint32_t max_gmr_ids;
	uint32_t max_gmr_pages;
	uint32_t max_mob_pages;
	uint32_t max_mob_size;
	uint32_t memory_size;
	bool has_gmr;
	bool has_mob;
	spinlock_t hw_lock;
	bool assume_16bpp;
	u32 irqs[VMWGFX_MAX_NUM_IRQS];
	u32 num_irq_vectors;

	enum vmw_sm_type sm_type;

	/*
	 * Framebuffer info.
	 */

	void *fb_info;
	enum vmw_display_unit_type active_display_unit;
	struct vmw_legacy_display *ldu_priv;
	struct vmw_overlay *overlay_priv;
	struct drm_property *hotplug_mode_update_property;
	struct drm_property *implicit_placement_property;
	spinlock_t cursor_lock;
	struct drm_atomic_state *suspend_state;

	/*
	 * Context and surface management.
	 */

	spinlock_t resource_lock;
	struct idr res_idr[vmw_res_max];

	/*
	 * A resource manager for kernel-only surfaces and
	 * contexts.
	 */

	struct ttm_object_device *tdev;

	/*
	 * Fencing and IRQs.
	 */

	atomic_t marker_seq;
	wait_queue_head_t fence_queue;
	wait_queue_head_t fifo_queue;
	spinlock_t waiter_lock;
	int fence_queue_waiters; /* Protected by waiter_lock */
	int goal_queue_waiters; /* Protected by waiter_lock */
	int cmdbuf_waiters; /* Protected by waiter_lock */
	int error_waiters; /* Protected by waiter_lock */
	int fifo_queue_waiters; /* Protected by waiter_lock */
	uint32_t last_read_seqno;
	struct vmw_fence_manager *fman;
	uint32_t irq_mask; /* Updates protected by waiter_lock */

	/*
	 * Device state
	 */

	uint32_t traces_state;
	uint32_t enable_state;
	uint32_t config_done_state;

	/**
	 * Execbuf
	 */
	/**
	 * Protected by the cmdbuf mutex.
	 */

	struct vmw_sw_context ctx;
	struct mutex cmdbuf_mutex;
	struct mutex binding_mutex;

	bool enable_fb;

	/**
	 * PM management.
	 */
	struct notifier_block pm_nb;
	bool refuse_hibernation;
	bool suspend_locked;

	atomic_t num_fifo_resources;

	/*
	 * Query processing. These members
	 * are protected by the cmdbuf mutex.
	 */

	struct vmw_buffer_object *dummy_query_bo;
	struct vmw_buffer_object *pinned_bo;
	uint32_t query_cid;
	uint32_t query_cid_valid;
	bool dummy_query_bo_pinned;

	/*
	 * Surface swapping. The "surface_lru" list is protected by the
	 * resource lock in order to be able to destroy a surface and take
	 * it off the lru atomically. "used_memory_size" is currently
	 * protected by the cmdbuf mutex for simplicity.
	 */

	struct list_head res_lru[vmw_res_max];
	uint32_t used_memory_size;

	/*
	 * DMA mapping stuff.
	 */
	enum vmw_dma_map_mode map_mode;

	/*
	 * Guest Backed stuff
	 */
	struct vmw_otable_batch otable_batch;

	struct vmw_fifo_state *fifo;
	struct vmw_cmdbuf_man *cman;
	DECLARE_BITMAP(irqthread_pending, VMW_IRQTHREAD_MAX);

	uint32 *devcaps;

	/*
	 * mksGuestStat instance-descriptor and pid arrays
	 */
	struct page *mksstat_user_pages[MKSSTAT_CAPACITY];
	atomic_t mksstat_user_pids[MKSSTAT_CAPACITY];

#if IS_ENABLED(CONFIG_DRM_VMWGFX_MKSSTATS)
#error "klp-ccp: non-taken branch"
#endif
};

static inline struct vmw_private *vmw_priv(struct drm_device *dev)
{
	return (struct vmw_private *)dev->dev_private;
}

static int (*klpe_vmw_bo_create)(struct vmw_private *dev_priv,
			 size_t size, struct ttm_placement *placement,
			 bool interruptible, bool pin,
			 void (*bo_free)(struct ttm_buffer_object *bo),
			 struct vmw_buffer_object **p_bo);

static void (*klpe_vmw_gem_destroy)(struct ttm_buffer_object *bo);

static struct ttm_placement (*klpe_vmw_vram_sys_placement);

static struct ttm_placement (*klpe_vmw_sys_placement);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_gem.c */
#include "drm/drm_prime.h"

static const struct drm_gem_object_funcs (*klpe_vmw_gem_object_funcs);

int klpp_vmw_gem_object_create_with_handle(struct vmw_private *dev_priv,
				      struct drm_file *filp,
				      uint32_t size,
				      uint32_t *handle,
				      struct vmw_buffer_object **p_vbo)
{
	int ret;

	ret = (*klpe_vmw_bo_create)(dev_priv, size,
			    (dev_priv->has_mob) ?
				    &(*klpe_vmw_sys_placement) :
				    &(*klpe_vmw_vram_sys_placement),
			    true, false, &(*klpe_vmw_gem_destroy), p_vbo);

	(*p_vbo)->base.base.funcs = &(*klpe_vmw_gem_object_funcs);
	if (ret != 0)
		goto out_no_bo;

	ret = (*klpe_drm_gem_handle_create)(filp, &(*p_vbo)->base.base, handle);
out_no_bo:
	return ret;
}

int klpp_vmw_gem_object_create_ioctl(struct drm_device *dev, void *data,
				struct drm_file *filp)
{
	struct vmw_private *dev_priv = vmw_priv(dev);
	union drm_vmw_alloc_dmabuf_arg *arg =
	    (union drm_vmw_alloc_dmabuf_arg *)data;
	struct drm_vmw_alloc_dmabuf_req *req = &arg->req;
	struct drm_vmw_dmabuf_rep *rep = &arg->rep;
	struct vmw_buffer_object *vbo;
	uint32_t handle;
	int ret;

	ret = klpp_vmw_gem_object_create_with_handle(dev_priv, filp,
						req->size, &handle, &vbo);
	if (ret)
		goto out_no_bo;

	rep->handle = handle;
	rep->map_handle = drm_vma_node_offset_addr(&vbo->base.base.vma_node);
	rep->cur_gmr_id = handle;
	rep->cur_gmr_offset = 0;
	/* drop reference from allocate - handle holds it now */
	klpr_drm_gem_object_put(&vbo->base.base);
out_no_bo:
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vmwgfx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "drm_gem_handle_create", (void *)&klpe_drm_gem_handle_create,
	  "drm" },
	{ "vmw_bo_create", (void *)&klpe_vmw_bo_create, "vmwgfx" },
	{ "vmw_gem_destroy", (void *)&klpe_vmw_gem_destroy, "vmwgfx" },
	{ "vmw_gem_object_funcs", (void *)&klpe_vmw_gem_object_funcs,
	  "vmwgfx" },
	{ "vmw_sys_placement", (void *)&klpe_vmw_sys_placement, "vmwgfx" },
	{ "vmw_vram_sys_placement", (void *)&klpe_vmw_vram_sys_placement,
	  "vmwgfx" },
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

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_init(void)
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

void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
