/*
 * livepatch_bsc1225313
 *
 * Fix for CVE-2024-35817, bsc#1225313
 *
 *  Upstream commit:
 *  6c6064cbe58b ("drm/amdgpu: amdgpu_ttm_gart_bind set gtt bound flag")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  3fd949ad1bc29032a3f4f6cb80c6c1c731ed9abc
 *
 *  SLE15-SP6 commit:
 *  eec66e2dbe7d9bb592a2c51f4e8f465e886313e2
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_DRM_AMDGPU)

#if !IS_MODULE(CONFIG_DRM_AMDGPU)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.c */
#include <linux/dma-mapping.h>
#include <linux/pagemap.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/dma-buf.h>
#include <linux/sizes.h>
#include <linux/module.h>
#include <drm/drm_drv.h>
#include <linux/agp_backend.h>
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <drm/ttm/ttm_placement.h>

/* klp-ccp: from include/uapi/drm/amdgpu_drm.h */
#define __AMDGPU_DRM_H__

#define AMDGPU_GEM_CREATE_CP_MQD_GFX9		(1 << 8)

#define AMDGPU_GEM_CREATE_ENCRYPTED		(1 << 10)

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.c */
#include <drm/drm_drv.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.h */
#include <linux/ktime.h>
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ring.h */
#include <drm/amdgpu_drm.h>
#include <drm/drm_print.h>

struct amdgpu_device;

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/rbtree.h>

/* klp-ccp: from include/linux/hashtable.h */
#define _LINUX_HASHTABLE_H

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#include <linux/dma-fence.h>
#include <drm/ttm/ttm_bo_api.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <drm/ttm/ttm_placement.h>
#include <drm/amdgpu_drm.h>
#include <drm/drm_gem.h>
/* klp-ccp: from drivers/gpu/drm/amd/include/kgd_kfd_interface.h */
#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/dma-fence.h>
/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <asm/byteorder.h>
#include <drm/drm_print.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mode.h */
#include <drm/display/drm_dp_helper.h>
#include <linux/i2c.h>
#include <linux/hrtimer.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_irq.h */
#include <linux/irqdomain.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.h */
#include <linux/dma-direction.h>
#include <drm/gpu_scheduler.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_sync.h */
#include <linux/hashtable.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#include <linux/idr.h>
#include <linux/rbtree.h>
#include <drm/gpu_scheduler.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ids.h */
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/dma-fence.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#define AMDGPU_PTE_TMZ		(1ULL << 3)

#define AMDGPU_PTE_MTYPE_VG10(a)	((uint64_t)(a) << 57)
#define AMDGPU_PTE_MTYPE_VG10_MASK	AMDGPU_PTE_MTYPE_VG10(3ULL)

#define AMDGPU_MTYPE_NC 0

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ras.h */
#include <linux/debugfs.h>
#include <linux/list.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ras_eeprom.h */
#include <linux/i2c.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mn.h */
#include <linux/types.h>
#include <linux/rwsem.h>
#include <linux/workqueue.h>
#include <linux/interval_tree.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gmc.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h */
#include <drm/display/drm_dp_mst_helper.h>
#include <drm/drm_atomic.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_plane.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gart.h */
#include <linux/types.h>

static void (*klpe_amdgpu_gart_bind)(struct amdgpu_device *adev, uint64_t offset,
		      int pages, dma_addr_t *dma_addr, uint64_t flags);

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_job.h */
#include <drm/gpu_scheduler.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_bo_list.h */
#include <drm/ttm/ttm_execbuf_util.h>
#include <drm/amdgpu_drm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gem.h */
#include <drm/amdgpu_drm.h>
#include <drm/drm_gem.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd.h */
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <drm/ttm/ttm_execbuf_util.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mes.h */
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_fdinfo.h */
#include <linux/idr.h>
#include <linux/kfifo.h>
#include <linux/rbtree.h>
#include <drm/gpu_scheduler.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo_driver.h>
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_object.h */
#include <drm/amdgpu_drm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_res_cursor.h */
#include <drm/drm_mm.h>
#include <drm/ttm/ttm_resource.h>
#include <drm/ttm/ttm_range_manager.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_object.h */
#ifdef CONFIG_MMU_NOTIFIER
#include <linux/mmu_notifier.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define AMDGPU_BO_MAX_PLACEMENTS	3

struct amdgpu_bo {
	/* Protected by tbo.reserved */
	u32				preferred_domains;
	u32				allowed_domains;
	struct ttm_place		placements[AMDGPU_BO_MAX_PLACEMENTS];
	struct ttm_placement		placement;
	struct ttm_buffer_object	tbo;
	struct ttm_bo_kmap_obj		kmap;
	u64				flags;
	/* per VM structure for page tables and with virtual addresses */
	struct amdgpu_vm_bo_base	*vm_bo;
	/* Constant after initialization */
	struct amdgpu_bo		*parent;

#ifdef CONFIG_MMU_NOTIFIER
	struct mmu_interval_notifier	notifier;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct kgd_mem                  *kfd_bo;
};

static inline struct amdgpu_bo *ttm_to_amdgpu_bo(struct ttm_buffer_object *tbo)
{
	return container_of(tbo, struct amdgpu_bo, tbo);
}

static inline bool amdgpu_bo_encrypted(struct amdgpu_bo *bo)
{
	return bo->flags & AMDGPU_GEM_CREATE_ENCRYPTED;
}

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_trace.h */
#if !defined(_AMDGPU_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/stringify.h>
#include <linux/types.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#include <trace/define_trace.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.c */
struct amdgpu_ttm_tt {
	struct ttm_tt	ttm;
	struct drm_gem_object	*gobj;
	u64			offset;
	uint64_t		userptr;
	struct task_struct	*usertask;
	uint32_t		userflags;
	bool			bound;
};

#define ttm_to_amdgpu_ttm_tt(ptr)	container_of(ptr, struct amdgpu_ttm_tt, ttm)

void klpp_amdgpu_ttm_gart_bind(struct amdgpu_device *adev,
				 struct ttm_buffer_object *tbo,
				 uint64_t flags)
{
	struct amdgpu_bo *abo = ttm_to_amdgpu_bo(tbo);
	struct ttm_tt *ttm = tbo->ttm;
	struct amdgpu_ttm_tt *gtt = ttm_to_amdgpu_ttm_tt(ttm);

	if (amdgpu_bo_encrypted(abo))
		flags |= AMDGPU_PTE_TMZ;

	if (abo->flags & AMDGPU_GEM_CREATE_CP_MQD_GFX9) {
		uint64_t page_idx = 1;

		(*klpe_amdgpu_gart_bind)(adev, gtt->offset, page_idx,
				 gtt->ttm.dma_address, flags);

		/* The memory type of the first page defaults to UC. Now
		 * modify the memory type to NC from the second page of
		 * the BO onward.
		 */
		flags &= ~AMDGPU_PTE_MTYPE_VG10_MASK;
		flags |= AMDGPU_PTE_MTYPE_VG10(AMDGPU_MTYPE_NC);

		(*klpe_amdgpu_gart_bind)(adev, gtt->offset + (page_idx << PAGE_SHIFT),
				 ttm->num_pages - page_idx,
				 &(gtt->ttm.dma_address[page_idx]), flags);
	} else {
		(*klpe_amdgpu_gart_bind)(adev, gtt->offset, ttm->num_pages,
				 gtt->ttm.dma_address, flags);
	}
	gtt->bound = true;
}


#include "livepatch_bsc1225313.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "amdgpu"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "amdgpu_gart_bind", (void *)&klpe_amdgpu_gart_bind, "amdgpu" },
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

int livepatch_bsc1225313_init(void)
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

void livepatch_bsc1225313_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */
