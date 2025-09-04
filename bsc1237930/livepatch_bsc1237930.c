/*
 * livepatch_bsc1237930
 *
 * Fix for CVE-2022-49053, bsc#1237930
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_TCM_USER2)

#if !IS_MODULE(CONFIG_TCM_USER2)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/target/target_core_user.c */
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/timer.h>

#include <linux/vmalloc.h>
#include <linux/uio_driver.h>
#include <linux/radix-tree.h>
#include <linux/stringify.h>
#include <linux/bitops.h>
#include <linux/highmem.h>
#include <linux/configfs.h>
#include <linux/mutex.h>
#include <linux/workqueue.h>
#include <net/genetlink.h>

/* klp-ccp: from include/scsi/scsi_proto.h */
#define _SCSI_PROTO_H_

/* klp-ccp: from drivers/target/target_core_user.c */
#include <scsi/scsi_proto.h>
#include <target/target_core_base.h>

#define DATA_BLOCK_SIZE PAGE_SIZE

#define TCMU_CONFIG_LEN 256

struct tcmu_nl_cmd {
	/* wake up thread waiting for reply */
	struct completion complete;
	struct list_head nl_list;
	struct tcmu_dev *udev;
	int cmd;
	int status;
};

struct tcmu_dev {
	struct list_head node;
	struct kref kref;

	struct se_device se_dev;

	char *name;
	struct se_hba *hba;

	unsigned long flags;

	struct uio_info uio_info;

	struct inode *inode;

	struct tcmu_mailbox *mb_addr;
	size_t dev_size;
	u32 cmdr_size;
	u32 cmdr_last_cleaned;
	/* Offset of data area from start of mb */
	/* Must add data_off and mb_addr to get the address */
	size_t data_off;
	size_t data_size;
	uint32_t max_blocks;
	size_t ring_size;

	struct mutex cmdr_lock;
	struct list_head cmdr_queue;

	uint32_t dbi_max;
	uint32_t dbi_thresh;
	unsigned long *data_bitmap;
	struct radix_tree_root data_blocks;

	struct idr commands;

	struct timer_list cmd_timer;
	unsigned int cmd_time_out;

	struct timer_list qfull_timer;
	int qfull_time_out;

	struct list_head timedout_entry;

	struct tcmu_nl_cmd curr_nl_cmd;

	char dev_config[TCMU_CONFIG_LEN];

	int nl_reply_supported;
};

static inline struct page *
tcmu_get_block_page(struct tcmu_dev *udev, uint32_t dbi)
{
	return radix_tree_lookup(&udev->data_blocks, dbi);
}

static int tcmu_find_mem_index(struct vm_area_struct *vma)
{
	struct tcmu_dev *udev = vma->vm_private_data;
	struct uio_info *info = &udev->uio_info;

	if (vma->vm_pgoff < MAX_UIO_MAPS) {
		if (info->mem[vma->vm_pgoff].size == 0)
			return -1;
		return (int)vma->vm_pgoff;
	}
	return -1;
}

static struct page *klpp_tcmu_try_get_block_page(struct tcmu_dev *udev, uint32_t dbi)
{
	struct page *page;

	mutex_lock(&udev->cmdr_lock);
	page = tcmu_get_block_page(udev, dbi);
	if (likely(page)) {
		get_page(page);
		mutex_unlock(&udev->cmdr_lock);
		return page;
	}

	/*
	 * Userspace messed up and passed in a address not in the
	 * data iov passed to it.
	 */
	pr_err("Invalid addr to data block mapping  (dbi %u) on device %s\n",
	       dbi, udev->name);
	page = NULL;
	mutex_unlock(&udev->cmdr_lock);

	return page;
}

int klpp_tcmu_vma_fault(struct vm_fault *vmf)
{
	struct tcmu_dev *udev = vmf->vma->vm_private_data;
	struct uio_info *info = &udev->uio_info;
	struct page *page;
	unsigned long offset;
	void *addr;

	int mi = tcmu_find_mem_index(vmf->vma);
	if (mi < 0)
		return VM_FAULT_SIGBUS;

	/*
	 * We need to subtract mi because userspace uses offset = N*PAGE_SIZE
	 * to use mem[N].
	 */
	offset = (vmf->pgoff - mi) << PAGE_SHIFT;

	if (offset < udev->data_off) {
		/* For the vmalloc()ed cmd area pages */
		addr = (void *)(unsigned long)info->mem[mi].addr + offset;
		page = vmalloc_to_page(addr);
		get_page(page);
	} else {
		uint32_t dbi;

		/* For the dynamically growing data area pages */
		dbi = (offset - udev->data_off) / DATA_BLOCK_SIZE;
		page = klpp_tcmu_try_get_block_page(udev, dbi);
		if (!page)
			return VM_FAULT_SIGBUS;
	}

	vmf->page = page;
	return 0;
}


#include "livepatch_bsc1237930.h"


#endif /* IS_ENABLED(CONFIG_TCM_USER2) */
