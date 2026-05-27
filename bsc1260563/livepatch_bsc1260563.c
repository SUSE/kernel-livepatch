/*
 * livepatch_bsc1260563
 *
 * Fix for CVE-2026-23317, bsc#1260563
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_binding.h */
#include <linux/list.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/vm_basic_types.h */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <asm/page.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_bo.h */
#include <drm/ttm/ttm_bo.h>
#include <drm/ttm/ttm_placement.h>

#include <linux/rbtree_types.h>
#include <linux/types.h>
#include <linux/xarray.h>

#include "livepatch_bsc1260563.h"

enum vmw_bo_domain {
	VMW_BO_DOMAIN_SYS           = BIT(0),
	VMW_BO_DOMAIN_WAITABLE_SYS  = BIT(1),
	VMW_BO_DOMAIN_VRAM          = BIT(2),
	VMW_BO_DOMAIN_GMR           = BIT(3),
	VMW_BO_DOMAIN_MOB           = BIT(4),
};

struct vmw_bo {
	struct ttm_buffer_object tbo;

	struct ttm_placement placement;
	struct ttm_place places[5];
	struct ttm_place busy_places[5];

	/* Protected by reservation */
	struct ttm_bo_kmap_obj map;

	struct rb_root res_tree;
	u32 res_prios[TTM_MAX_BO_PRIORITY];
	struct xarray detached_resources;

	atomic_t map_count;
	atomic_t cpu_writers;
	/* Not ref-counted.  Protected by binding_mutex */
	struct vmw_resource *dx_query_ctx;
	struct vmw_bo_dirty *dirty;

	bool is_dumb;
	struct vmw_surface *dumb_surface;
};

void vmw_bo_placement_set(struct vmw_bo *bo, u32 domain, u32 busy_domain);

int vmw_user_bo_lookup(struct drm_file *filp,
		       u32 handle,
		       struct vmw_bo **out);

static inline void vmw_user_bo_unref(struct vmw_bo **buf)
{
	struct vmw_bo *tmp_buf = *buf;

	*buf = NULL;
	if (tmp_buf)
		drm_gem_object_put(&tmp_buf->tbo.base);
}

/* klp-ccp: from include/linux/sync_file.h */
#define _LINUX_SYNC_FILE_H

/* klp-ccp: from include/linux/dma-fence-array.h */
#define __LINUX_DMA_FENCE_ARRAY_H

/* klp-ccp: from include/linux/hashtable.h */
#define _LINUX_HASHTABLE_H

#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/drm_device.h>

/* klp-ccp: from include/drm/ttm/ttm_execbuf_util.h */
#define _TTM_EXECBUF_UTIL_H_

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#include <drm/ttm/ttm_placement.h>
#include <drm/ttm/ttm_bo.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/ttm_object.h */
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/rcupdate.h>

#include <drm/ttm/ttm_bo.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_fence.h */
#ifndef _VMWGFX_FENCE_H_

#include <linux/dma-fence.h>
#include <linux/dma-fence-array.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _VMWGFX_FENCE_H_ */

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_reg.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_validation.h */
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/ww_mutex.h>

#include <drm/ttm/ttm_execbuf_util.h>

struct vmw_validation_context;

int vmw_validation_add_bo(struct vmw_validation_context *ctx,
			  struct vmw_bo *vbo);

void *vmw_validation_mem_alloc(struct vmw_validation_context *ctx,
			       unsigned int size);
int vmw_validation_preload_bo(struct vmw_validation_context *ctx);

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_drv.h */
#define VMWGFX_MAX_NUM_IRQS 6

#define VMW_RES_HT_ORDER 12

#define MKSSTAT_CAPACITY_LOG2 5U
#define MKSSTAT_CAPACITY (1U << MKSSTAT_CAPACITY_LOG2)

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
	DECLARE_HASHTABLE(res_ht, VMW_RES_HT_ORDER);
	bool kernel;
	struct vmw_fpriv *fp;
	struct drm_file *filp;
	uint32_t *cmd_bounce;
	uint32_t cmd_bounce_size;
	struct vmw_bo *cur_query_bo;
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
	struct vmw_bo *dx_query_mob;
	struct vmw_resource *dx_query_ctx;
	struct vmw_cmdbuf_res_manager *man;
	struct vmw_validation_context *ctx;
};

struct vmw_otable_batch {
	unsigned num_otables;
	struct vmw_otable *otables;
	struct vmw_resource *context;
	struct vmw_bo *otable_bo;
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

	struct vmw_bo *dummy_query_bo;
	struct vmw_bo *pinned_bo;
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

	bool vkms_enabled;
	struct workqueue_struct *crc_workq;

	/*
	 * mksGuestStat instance-descriptor and pid arrays
	 */
	struct page *mksstat_user_pages[MKSSTAT_CAPACITY];
	atomic_t mksstat_user_pids[MKSSTAT_CAPACITY];

#if IS_ENABLED(CONFIG_DRM_VMWGFX_MKSSTATS)
#error "klp-ccp: non-taken branch"
#endif
};

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_mksstat.h */
#include <asm/page.h>
#include <linux/kconfig.h>

/* klp-ccp: from drivers/gpu/drm/vmwgfx/vmwgfx_execbuf.c */
#include <drm/ttm/ttm_bo.h>
#include <drm/ttm/ttm_placement.h>

#include <linux/sync_file.h>
#include <linux/hashtable.h>
#include <linux/vmalloc.h>

struct vmw_relocation {
	struct list_head head;
	struct vmw_bo *vbo;
	union {
		SVGAMobId *mob_loc;
		SVGAGuestPtr *location;
	};
};

int klpp_vmw_translate_mob_ptr(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGAMobId *id,
				 struct vmw_bo **vmw_bo_p)
{
	struct vmw_bo *vmw_bo, *tmp_bo;
	uint32_t handle = *id;
	struct vmw_relocation *reloc;
	int ret;

	vmw_validation_preload_bo(sw_context->ctx);
	ret = vmw_user_bo_lookup(sw_context->filp, handle, &vmw_bo);
	if (ret != 0) {
		drm_dbg(&dev_priv->drm, "Could not find or use MOB buffer.\n");
		return ret;
	}
	vmw_bo_placement_set(vmw_bo, VMW_BO_DOMAIN_MOB, VMW_BO_DOMAIN_MOB);
	ret = vmw_validation_add_bo(sw_context->ctx, vmw_bo);
	tmp_bo = vmw_bo;
	vmw_user_bo_unref(&tmp_bo);
	if (unlikely(ret != 0))
		return ret;

	reloc = vmw_validation_mem_alloc(sw_context->ctx, sizeof(*reloc));
	if (!reloc)
		return -ENOMEM;

	reloc->mob_loc = id;
	reloc->vbo = vmw_bo;

	*vmw_bo_p = vmw_bo;
	list_add_tail(&reloc->head, &sw_context->bo_relocations);

	return 0;
}

int klpp_vmw_translate_guest_ptr(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   SVGAGuestPtr *ptr,
				   struct vmw_bo **vmw_bo_p)
{
	struct vmw_bo *vmw_bo, *tmp_bo;
	uint32_t handle = ptr->gmrId;
	struct vmw_relocation *reloc;
	int ret;

	vmw_validation_preload_bo(sw_context->ctx);
	ret = vmw_user_bo_lookup(sw_context->filp, handle, &vmw_bo);
	if (ret != 0) {
		drm_dbg(&dev_priv->drm, "Could not find or use GMR region.\n");
		return ret;
	}
	vmw_bo_placement_set(vmw_bo, VMW_BO_DOMAIN_GMR | VMW_BO_DOMAIN_VRAM,
			     VMW_BO_DOMAIN_GMR | VMW_BO_DOMAIN_VRAM);
	ret = vmw_validation_add_bo(sw_context->ctx, vmw_bo);
	tmp_bo = vmw_bo;
	vmw_user_bo_unref(&tmp_bo);
	if (unlikely(ret != 0))
		return ret;

	reloc = vmw_validation_mem_alloc(sw_context->ctx, sizeof(*reloc));
	if (!reloc)
		return -ENOMEM;

	reloc->location = ptr;
	reloc->vbo = vmw_bo;
	*vmw_bo_p = vmw_bo;
	list_add_tail(&reloc->head, &sw_context->bo_relocations);

	return 0;
}



#include <linux/livepatch.h>

extern typeof(vmw_bo_placement_set) vmw_bo_placement_set
	 KLP_RELOC_SYMBOL(vmwgfx, vmwgfx, vmw_bo_placement_set);
extern typeof(vmw_user_bo_lookup) vmw_user_bo_lookup
	 KLP_RELOC_SYMBOL(vmwgfx, vmwgfx, vmw_user_bo_lookup);
extern typeof(vmw_validation_add_bo) vmw_validation_add_bo
	 KLP_RELOC_SYMBOL(vmwgfx, vmwgfx, vmw_validation_add_bo);
extern typeof(vmw_validation_mem_alloc) vmw_validation_mem_alloc
	 KLP_RELOC_SYMBOL(vmwgfx, vmwgfx, vmw_validation_mem_alloc);
extern typeof(vmw_validation_preload_bo) vmw_validation_preload_bo
	 KLP_RELOC_SYMBOL(vmwgfx, vmwgfx, vmw_validation_preload_bo);

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
