/*
 * livepatch_bsc1266668
 *
 * Fix for CVE-2026-43206, bsc#1266668
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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

#include "livepatch_bsc1266668.h"


#define CC_USING_FENTRY 1
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/../amdkfd/kfd_events.c */
#include <linux/mm_types.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/uaccess.h>
#include <linux/mman.h>
#include <linux/memory.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_priv.h */
#include <linux/hashtable.h>
#include <linux/mmu_notifier.h>
#include <linux/memremap.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/kfd_ioctl.h>
#include <linux/idr.h>
#include <linux/kfifo.h>
#include <linux/seq_file.h>
#include <linux/kref.h>
#include <linux/sysfs.h>
#include <linux/device_cgroup.h>
#include <drm/drm_file.h>
#include <drm/drm_drv.h>
#include <drm/drm_device.h>
#include <drm/drm_ioctl.h>
/* klp-ccp: from drivers/gpu/drm/amd/include/kgd_kfd_interface.h */
#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/dma-fence.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_irq.h */
#include <linux/irqdomain.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ring.h */
#include <drm/amdgpu_drm.h>
#include <drm/gpu_scheduler.h>
#include <drm/drm_print.h>
#include <drm/drm_suballoc.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ras.h */
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/kfifo.h>
#include <linux/radix-tree.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ras_eeprom.h */
#include <linux/i2c.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_aca.h */
#include <linux/list.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ring_mux.h */
#include <linux/timer.h>
#include <linux/spinlock.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_xcp.h */
#include <linux/pci.h>
#include <linux/xarray.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ctx.h */
#include <linux/ktime.h>
#include <linux/types.h>

/* klp-ccp: from drivers/gpu/drm/amd/include/kgd_kfd_interface.h */
struct kgd_mem;

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_priv.h */
#include <linux/swap.h>
/* klp-ccp: from drivers/gpu/drm/amd/include/amd_shared.h */
#include <drm/amd_asic_type.h>
#include <drm/drm_print.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#undef pr_fmt
#define pr_fmt(fmt) "amdgpu: " fmt

#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/kref.h>
#include <linux/rbtree.h>
#include <linux/hashtable.h>
#include <linux/dma-fence.h>
#include <linux/pci.h>
#include <drm/ttm/ttm_bo.h>
#include <drm/ttm/ttm_placement.h>
#include <drm/amdgpu_drm.h>
#include <drm/drm_gem.h>
#include <drm/drm_ioctl.h>
/* klp-ccp: from drivers/gpu/drm/amd/display/dc/os_types.h */
#include <linux/slab.h>
#include <linux/kgdb.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/byteorder.h>
#include <drm/display/drm_dp_helper.h>
#include <drm/drm_device.h>
#include <drm/drm_print.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mode.h */
#include <drm/display/drm_dp_helper.h>
#include <drm/drm_crtc.h>
#include <drm/drm_encoder.h>
#include <drm/drm_fixed.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_probe_helper.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>
#include <linux/hrtimer.h>
#include <drm/display/drm_dp_mst_helper.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ttm.h */
#include <linux/dma-direction.h>
#include <drm/gpu_scheduler.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vram_mgr.h */
#include <drm/drm_buddy.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_sync.h */
#include <linux/hashtable.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_vm.h */
#include <linux/idr.h>
#include <linux/kfifo.h>
#include <linux/rbtree.h>
#include <drm/gpu_scheduler.h>
#include <drm/drm_file.h>
#include <drm/ttm/ttm_bo.h>
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_ids.h */
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/dma-fence.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_acp.h */
#include <linux/mfd/core.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gmc.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/amd/display/amdgpu_dm/amdgpu_dm.h */
#include <drm/display/drm_dp_mst_helper.h>
#include <drm/drm_atomic.h>
#include <drm/drm_connector.h>
#include <drm/drm_crtc.h>
#include <drm/drm_plane.h>
#include <drm/drm_writeback.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gart.h */
#include <linux/types.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_job.h */
#include <drm/gpu_scheduler.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_bo_list.h */
#include <drm/amdgpu_drm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_gem.h */
#include <drm/amdgpu_drm.h>
#include <drm/drm_gem.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_amdkfd.h */
#include <linux/list.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/mmu_notifier.h>
#include <linux/memremap.h>
#include <drm/drm_client.h>

int amdgpu_amdkfd_gpuvm_map_gtt_bo_to_kernel(struct kgd_mem *mem,
					     void **kptr, uint64_t *size);
void amdgpu_amdkfd_gpuvm_unmap_gtt_bo_from_kernel(struct kgd_mem *mem);

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_mes.h */
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu_fdinfo.h */
#include <linux/idr.h>
#include <linux/kfifo.h>
#include <linux/rbtree.h>
#include <drm/gpu_scheduler.h>
#include <drm/drm_file.h>
#include <linux/sched/mm.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/amdgpu.h */
#define MAX_GPU_INSTANCE		64

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

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_priv.h */
struct process_queue_manager {
	/* data */
	struct kfd_process	*process;
	struct list_head	queues;
	unsigned long		*queue_slot_bitmap;
};

struct qcm_process_device {
	/* The Device Queue Manager that owns this data */
	struct device_queue_manager *dqm;
	struct process_queue_manager *pqm;
	/* Queues list */
	struct list_head queues_list;
	struct list_head priv_queue_list;

	unsigned int queue_count;
	unsigned int vmid;
	bool is_debug;
	unsigned int evicted; /* eviction counter, 0=active */

	/* This flag tells if we should reset all wavefronts on
	 * process termination
	 */
	bool reset_wavefronts;

	/* This flag tells us if this process has a GWS-capable
	 * queue that will be mapped into the runlist. It's
	 * possible to request a GWS BO, but not have the queue
	 * currently mapped, and this changes how the MAP_PROCESS
	 * PM4 packet is configured.
	 */
	bool mapped_gws_queue;

	/* All the memory management data should be here too */
	uint64_t gds_context_area;
	/* Contains page table flags such as AMDGPU_PTE_VALID since gfx9 */
	uint64_t page_table_base;
	uint32_t sh_mem_config;
	uint32_t sh_mem_bases;
	uint32_t sh_mem_ape1_base;
	uint32_t sh_mem_ape1_limit;
	uint32_t gds_size;
	uint32_t num_gws;
	uint32_t num_oac;
	uint32_t sh_hidden_private_base;

	/* CWSR memory */
	struct kgd_mem *cwsr_mem;
	void *cwsr_kaddr;
	uint64_t cwsr_base;
	uint64_t tba_addr;
	uint64_t tma_addr;

	/* IB memory */
	struct kgd_mem *ib_mem;
	uint64_t ib_base;
	void *ib_kaddr;

	/* doorbells for kfd process */
	struct amdgpu_bo *proc_doorbells;

	/* bitmap for dynamic doorbell allocation from the bo */
	unsigned long *doorbell_bitmap;
};

#define GET_GPU_ID(handle) (handle >> 32)
#define GET_IDR_HANDLE(handle) (handle & 0xFFFFFFFF)

enum kfd_pdd_bound {
	PDD_UNBOUND = 0,
	PDD_BOUND,
	PDD_BOUND_SUSPENDED,
};

#define MAX_SYSFS_FILENAME_LEN 15

struct kfd_process_device {
	/* The device that owns this data. */
	struct kfd_node *dev;

	/* The process that owns this kfd_process_device. */
	struct kfd_process *process;

	/* per-process-per device QCM data structure */
	struct qcm_process_device qpd;

	/*Apertures*/
	uint64_t lds_base;
	uint64_t lds_limit;
	uint64_t gpuvm_base;
	uint64_t gpuvm_limit;
	uint64_t scratch_base;
	uint64_t scratch_limit;

	/* VM context for GPUVM allocations */
	struct file *drm_file;
	void *drm_priv;

	/* GPUVM allocations storage */
	struct idr alloc_idr;

	/* Flag used to tell the pdd has dequeued from the dqm.
	 * This is used to prevent dev->dqm->ops.process_termination() from
	 * being called twice when it is already called in IOMMU callback
	 * function.
	 */
	bool already_dequeued;
	bool runtime_inuse;

	/* Is this process/pasid bound to this device? (amd_iommu_bind_pasid) */
	enum kfd_pdd_bound bound;

	/* VRAM usage */
	atomic64_t vram_usage;
	struct attribute attr_vram;
	char vram_filename[MAX_SYSFS_FILENAME_LEN];

	/* SDMA activity tracking */
	uint64_t sdma_past_activity_counter;
	struct attribute attr_sdma;
	char sdma_filename[MAX_SYSFS_FILENAME_LEN];

	/* Eviction activity tracking */
	uint64_t last_evict_timestamp;
	atomic64_t evict_duration_counter;
	struct attribute attr_evict;

	struct kobject *kobj_stats;

	/*
	 * @cu_occupancy: Reports occupancy of Compute Units (CU) of a process
	 * that is associated with device encoded by "this" struct instance. The
	 * value reflects CU usage by all of the waves launched by this process
	 * on this device. A very important property of occupancy parameter is
	 * that its value is a snapshot of current use.
	 *
	 * Following is to be noted regarding how this parameter is reported:
	 *
	 *  The number of waves that a CU can launch is limited by couple of
	 *  parameters. These are encoded by struct amdgpu_cu_info instance
	 *  that is part of every device definition. For GFX9 devices this
	 *  translates to 40 waves (simd_per_cu * max_waves_per_simd) when waves
	 *  do not use scratch memory and 32 waves (max_scratch_slots_per_cu)
	 *  when they do use scratch memory. This could change for future
	 *  devices and therefore this example should be considered as a guide.
	 *
	 *  All CU's of a device are available for the process. This may not be true
	 *  under certain conditions - e.g. CU masking.
	 *
	 *  Finally number of CU's that are occupied by a process is affected by both
	 *  number of CU's a device has along with number of other competing processes
	 */
	struct attribute attr_cu_occupancy;

	/* sysfs counters for GPU retry fault and page migration tracking */
	struct kobject *kobj_counters;
	struct attribute attr_faults;
	struct attribute attr_page_in;
	struct attribute attr_page_out;
	uint64_t faults;
	uint64_t page_in;
	uint64_t page_out;

	/* Exception code status*/
	uint64_t exception_status;
	void *vm_fault_exc_data;
	size_t vm_fault_exc_data_size;

	/* Tracks debug per-vmid request settings */
	uint32_t spi_dbg_override;
	uint32_t spi_dbg_launch_mode;
	uint32_t watch_points[4];
	uint32_t alloc_watch_ids;

	/*
	 * If this process has been checkpointed before, then the user
	 * application will use the original gpu_id on the
	 * checkpointed node to refer to this device.
	 */
	uint32_t user_gpu_id;

	void *proc_ctx_bo;
	uint64_t proc_ctx_gpu_addr;
	void *proc_ctx_cpu_ptr;

	/* Tracks queue reset status */
	bool has_reset_queue;
};

struct svm_range_list {
	struct mutex			lock;
	struct rb_root_cached		objects;
	struct list_head		list;
	struct work_struct		deferred_list_work;
	struct list_head		deferred_range_list;
	struct list_head                criu_svm_metadata_list;
	spinlock_t			deferred_list_lock;
	atomic_t			evicted_ranges;
	atomic_t			drain_pagefaults;
	struct delayed_work		restore_work;
	DECLARE_BITMAP(bitmap_supported, MAX_GPU_INSTANCE);
	struct task_struct		*faulting_task;
	/* check point ts decides if page fault recovery need be dropped */
	uint64_t			checkpoint_ts[MAX_GPU_INSTANCE];

	/* Default granularity to use in buffer migration
	 * and restoration of backing memory while handling
	 * recoverable page faults
	 */
	uint8_t default_granularity;
};

struct kfd_process {
	/*
	 * kfd_process are stored in an mm_struct*->kfd_process*
	 * hash table (kfd_processes in kfd_process.c)
	 */
	struct hlist_node kfd_processes;

	/*
	 * Opaque pointer to mm_struct. We don't hold a reference to
	 * it so it should never be dereferenced from here. This is
	 * only used for looking up processes by their mm.
	 */
	void *mm;

	struct kref ref;
	struct work_struct release_work;

	struct mutex mutex;

	/*
	 * In any process, the thread that started main() is the lead
	 * thread and outlives the rest.
	 * It is here because amd_iommu_bind_pasid wants a task_struct.
	 * It can also be used for safely getting a reference to the
	 * mm_struct of the process.
	 */
	struct task_struct *lead_thread;

	/* We want to receive a notification when the mm_struct is destroyed */
	struct mmu_notifier mmu_notifier;

	u32 pasid;

	/*
	 * Array of kfd_process_device pointers,
	 * one for each device the process is using.
	 */
	struct kfd_process_device *pdds[MAX_GPU_INSTANCE];
	uint32_t n_pdds;

	struct process_queue_manager pqm;

	/*Is the user space process 32 bit?*/
	bool is_32bit_user_mode;

	/* Event-related data */
	struct mutex event_mutex;
	/* Event ID allocator and lookup */
	struct idr event_idr;
	/* Event page */
	u64 signal_handle;
	struct kfd_signal_page *signal_page;
	size_t signal_mapped_size;
	size_t signal_event_count;
	bool signal_event_limit_reached;

	/* Information used for memory eviction */
	void *kgd_process_info;
	/* Eviction fence that is attached to all the BOs of this process. The
	 * fence will be triggered during eviction and new one will be created
	 * during restore
	 */
	struct dma_fence __rcu *ef;

	/* Work items for evicting and restoring BOs */
	struct delayed_work eviction_work;
	struct delayed_work restore_work;
	/* seqno of the last scheduled eviction */
	unsigned int last_eviction_seqno;
	/* Approx. the last timestamp (in jiffies) when the process was
	 * restored after an eviction
	 */
	unsigned long last_restore_timestamp;

	/* Indicates device process is debug attached with reserved vmid. */
	bool debug_trap_enabled;

	/* per-process-per device debug event fd file */
	struct file *dbg_ev_file;

	/* If the process is a kfd debugger, we need to know so we can clean
	 * up at exit time.  If a process enables debugging on itself, it does
	 * its own clean-up, so we don't set the flag here.  We track this by
	 * counting the number of processes this process is debugging.
	 */
	atomic_t debugged_process_count;

	/* If the process is a debugged, this is the debugger process */
	struct kfd_process *debugger_process;

	/* Kobj for our procfs */
	struct kobject *kobj;
	struct kobject *kobj_queues;
	struct attribute attr_pasid;

	/* Keep track cwsr init */
	bool has_cwsr;

	/* Exception code enable mask and status */
	uint64_t exception_enable_mask;
	uint64_t exception_status;

	/* Used to drain stale interrupts */
	wait_queue_head_t wait_irq_drain;
	bool irq_drain_is_open;

	/* shared virtual memory registered by this process */
	struct svm_range_list svms;

	bool xnack_enabled;

	/* Work area for debugger event writer worker. */
	struct work_struct debug_event_workarea;

	/* Tracks debug per-vmid request for debug flags */
	u32 dbg_flags;

	atomic_t poison;
	/* Queues are in paused stated because we are in the process of doing a CRIU checkpoint */
	bool queues_paused;

	/* Tracks runtime enable status */
	struct semaphore runtime_enable_sema;
	bool is_runtime_retry;
	struct kfd_runtime_info runtime_info;
};

struct kfd_process_device *kfd_process_device_data_by_id(struct kfd_process *process,
							 uint32_t gpu_id);

struct kfd_process_device *kfd_bind_process_to_device(struct kfd_node *dev,
						struct kfd_process *p);

void *kfd_process_device_translate_handle(struct kfd_process_device *p,
					int handle);

int klpp_kfd_kmap_event_page(struct kfd_process *p, uint64_t event_page_offset);

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_events.h */
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <uapi/linux/kfd_ioctl.h>

#define UNSIGNALED_EVENT_SLOT ((uint64_t)-1)

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_device_queue_manager.h */
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/sched/mm.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdgpu/../amdkfd/kfd_events.c */
#include <linux/device.h>

struct kfd_signal_page {
	uint64_t *kernel_address;
	uint64_t __user *user_address;
	bool need_to_free_pages;
};

static int klpp_kfd_event_page_set(struct kfd_process *p, void *kernel_address,
		       uint64_t size, uint64_t user_handle)
{
	struct kfd_signal_page *page;

	if (p->signal_page)
		return -EBUSY;

	if (size < KFD_SIGNAL_EVENT_LIMIT * 8) {
		pr_err("Event page size %llu is too small, need at least %lu bytes\n",
				size, (unsigned long)(KFD_SIGNAL_EVENT_LIMIT * 8));
		return -EINVAL;
	}

	page = kzalloc(sizeof(*page), GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	/* Initialize all events to unsignaled */
	memset(kernel_address, (uint8_t) UNSIGNALED_EVENT_SLOT,
	       KFD_SIGNAL_EVENT_LIMIT * 8);

	page->kernel_address = kernel_address;

	p->signal_page = page;
	p->signal_mapped_size = size;
	p->signal_handle = user_handle;
	return 0;
}

int klpp_kfd_kmap_event_page(struct kfd_process *p, uint64_t event_page_offset)
{
	struct kfd_node *kfd;
	struct kfd_process_device *pdd;
	void *mem, *kern_addr;
	uint64_t size;
	int err = 0;

	if (p->signal_page) {
		pr_err("Event page is already set\n");
		return -EINVAL;
	}

	pdd = kfd_process_device_data_by_id(p, GET_GPU_ID(event_page_offset));
	if (!pdd) {
		pr_err("Getting device by id failed in %s\n", __func__);
		return -EINVAL;
	}
	kfd = pdd->dev;

	pdd = kfd_bind_process_to_device(kfd, p);
	if (IS_ERR(pdd))
		return PTR_ERR(pdd);

	mem = kfd_process_device_translate_handle(pdd,
			GET_IDR_HANDLE(event_page_offset));
	if (!mem) {
		pr_err("Can't find BO, offset is 0x%llx\n", event_page_offset);
		return -EINVAL;
	}

	err = amdgpu_amdkfd_gpuvm_map_gtt_bo_to_kernel(mem, &kern_addr, &size);
	if (err) {
		pr_err("Failed to map event page to kernel\n");
		return err;
	}

	err = klpp_kfd_event_page_set(p, kern_addr, size, event_page_offset);
	if (err) {
		pr_err("Failed to set event page\n");
		amdgpu_amdkfd_gpuvm_unmap_gtt_bo_from_kernel(mem);
		return err;
	}
	return err;
}


#include <linux/livepatch.h>

extern typeof(amdgpu_amdkfd_gpuvm_map_gtt_bo_to_kernel)
	 amdgpu_amdkfd_gpuvm_map_gtt_bo_to_kernel
	 KLP_RELOC_SYMBOL(amdgpu, amdgpu, amdgpu_amdkfd_gpuvm_map_gtt_bo_to_kernel);
extern typeof(amdgpu_amdkfd_gpuvm_unmap_gtt_bo_from_kernel)
	 amdgpu_amdkfd_gpuvm_unmap_gtt_bo_from_kernel
	 KLP_RELOC_SYMBOL(amdgpu, amdgpu, amdgpu_amdkfd_gpuvm_unmap_gtt_bo_from_kernel);
extern typeof(kfd_bind_process_to_device) kfd_bind_process_to_device
	 KLP_RELOC_SYMBOL(amdgpu, amdgpu, kfd_bind_process_to_device);
extern typeof(kfd_process_device_data_by_id) kfd_process_device_data_by_id
	 KLP_RELOC_SYMBOL(amdgpu, amdgpu, kfd_process_device_data_by_id);
extern typeof(kfd_process_device_translate_handle)
	 kfd_process_device_translate_handle
	 KLP_RELOC_SYMBOL(amdgpu, amdgpu, kfd_process_device_translate_handle);

#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */
