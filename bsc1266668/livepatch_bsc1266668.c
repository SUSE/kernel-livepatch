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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_events.c */
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
/* klp-ccp: from drivers/gpu/drm/amd/include/kgd_kfd_interface.h */
#include <linux/types.h>
#include <linux/bitmap.h>
#include <linux/dma-fence.h>
/* klp-ccp: from drivers/gpu/drm/amd/include/amd_shared.h */
#include <drm/amd_asic_type.h>

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_priv.h */
struct process_queue_manager {
	/* data */
	struct kfd_process	*process;
	struct list_head	queues;
	unsigned long		*queue_slot_bitmap;
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

	/* Use for delayed freeing of kfd_process structure */
	struct rcu_head	rcu;

	unsigned int pasid;
	unsigned int doorbell_index;

	/*
	 * List of kfd_process_device structures,
	 * one for each device the process is using.
	 */
	struct list_head per_device_data;

	struct process_queue_manager pqm;

	/*Is the user space process 32 bit?*/
	bool is_32bit_user_mode;

	/* Event-related data */
	struct mutex event_mutex;
	/* Event ID allocator and lookup */
	struct idr event_idr;
	/* Event page */
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
	struct dma_fence *ef;

	/* Work items for evicting and restoring BOs */
	struct delayed_work eviction_work;
	struct delayed_work restore_work;
	/* seqno of the last scheduled eviction */
	unsigned int last_eviction_seqno;
	/* Approx. the last timestamp (in jiffies) when the process was
	 * restored after an eviction
	 */
	unsigned long last_restore_timestamp;
};

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_events.h */
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <uapi/linux/kfd_ioctl.h>

#define UNSIGNALED_EVENT_SLOT ((uint64_t)-1)

/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_iommu.h */
#include <linux/kconfig.h>
/* klp-ccp: from drivers/gpu/drm/amd/amdkfd/kfd_events.c */
#include <linux/device.h>

struct kfd_signal_page {
	uint64_t *kernel_address;
	uint64_t __user *user_address;
	bool need_to_free_pages;
};

int klpp_kfd_event_page_set(struct kfd_process *p, void *kernel_address,
		       uint64_t size)
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

	return 0;
}



#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */
