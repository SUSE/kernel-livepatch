/*
 * livepatch_bsc1228585
 *
 * Fix for CVE-2024-40956, bsc#1228585
 *
 *  Upstream commit:
 *  e3215deca452 ("dmaengine: idxd: Fix possible Use-After-Free in irq_process_work_list")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  26f1077906e5901a4dc6aa055864b2810237fba1
 *
 *  SLE15-SP4 and -SP5 commit:
 *  3632d87c54841cfe0e62cead09f2efaeab96f60b
 *
 *  SLE15-SP6 commit:
 *  36cedd66a94c171cc3001ffa27aa1372ddb85ed1
 *
 *  SLE MICRO-6-0 commit:
 *  36cedd66a94c171cc3001ffa27aa1372ddb85ed1
 *
 *  Copyright (c) 2025 SUSE
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

#if IS_ENABLED(CONFIG_INTEL_IDXD)

#if !IS_MODULE(CONFIG_INTEL_IDXD)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/dma/idxd/irq.c */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#include <linux/dmaengine.h>

#include <linux/iommu.h>
#include <linux/sched/mm.h>
#include <uapi/linux/idxd.h>

/* klp-ccp: from drivers/dma/dmaengine.h */
#include <linux/bug.h>
#include <linux/dmaengine.h>

/* klp-ccp: from drivers/dma/idxd/idxd.h */
#include <linux/sbitmap.h>
#include <linux/dmaengine.h>
#include <linux/percpu-rwsem.h>
#include <linux/wait.h>

#include <linux/idr.h>
#include <linux/pci.h>
#include <linux/bitmap.h>

#include <linux/iommu.h>

#include <uapi/linux/idxd.h>

/* klp-ccp: from drivers/dma/idxd/registers.h */
#include <uapi/linux/idxd.h>

/* klp-ccp: from drivers/dma/idxd/idxd.h */
enum idxd_dev_type {
	IDXD_DEV_NONE = -1,
	IDXD_DEV_DSA = 0,
	IDXD_DEV_IAX,
	IDXD_DEV_WQ,
	IDXD_DEV_GROUP,
	IDXD_DEV_ENGINE,
	IDXD_DEV_CDEV,
	IDXD_DEV_CDEV_FILE,
	IDXD_DEV_MAX_TYPE,
};

struct idxd_dev {
	struct device conf_dev;
	enum idxd_dev_type type;
};

enum idxd_complete_type {
	IDXD_COMPLETE_NORMAL = 0,
	IDXD_COMPLETE_ABORT,
	IDXD_COMPLETE_DEV_FAIL,
};

struct idxd_desc;

struct idxd_device_driver {
	const char *name;
	enum idxd_dev_type *type;
	int (*probe)(struct idxd_dev *idxd_dev);
	void (*remove)(struct idxd_dev *idxd_dev);
	void (*desc_complete)(struct idxd_desc *desc,
			      enum idxd_complete_type comp_type,
			      bool free_desc,
			      void *ctx, u32 *status);
	struct device_driver drv;
};

struct idxd_irq_entry {
	int id;
	int vector;
	struct llist_head pending_llist;
	struct list_head work_list;
	/*
	 * Lock to protect access between irq thread process descriptor
	 * and irq thread processing error descriptor.
	 */
	spinlock_t list_lock;
	int int_handle;
	ioasid_t pasid;
};

enum idxd_wq_state {
	IDXD_WQ_DISABLED = 0,
	IDXD_WQ_ENABLED,
};

enum idxd_wq_type {
	IDXD_WQT_NONE = 0,
	IDXD_WQT_KERNEL,
	IDXD_WQT_USER,
};

#define DRIVER_NAME_SIZE		128

#define WQ_NAME_SIZE   1024

struct idxd_wq {
	void __iomem *portal;
	u32 portal_offset;
	unsigned int enqcmds_retries;
	struct percpu_ref wq_active;
	struct completion wq_dead;
	struct completion wq_resurrect;
	struct idxd_dev idxd_dev;
	struct idxd_cdev *idxd_cdev;
	struct wait_queue_head err_queue;
	struct workqueue_struct *wq;
	struct idxd_device *idxd;
	int id;
	struct idxd_irq_entry ie;
	enum idxd_wq_type type;
	struct idxd_group *group;
	int client_count;
	struct mutex wq_lock;	/* mutex for workqueue */
	u32 size;
	u32 threshold;
	u32 priority;
	enum idxd_wq_state state;
	unsigned long flags;
	union wqcfg *wqcfg;
	unsigned long *opcap_bmap;

	struct dsa_hw_desc **hw_descs;
	int num_descs;
	union {
		struct dsa_completion_record *compls;
		struct iax_completion_record *iax_compls;
	};
	dma_addr_t compls_addr;
	int compls_size;
	struct idxd_desc **descs;
	struct sbitmap_queue sbq;
	struct idxd_dma_chan *idxd_chan;
	char name[WQ_NAME_SIZE + 1];
	u64 max_xfer_bytes;
	u32 max_batch_size;

	/* Lock to protect upasid_xa access. */
	struct mutex uc_lock;
	struct xarray upasid_xa;

	char driver_name[DRIVER_NAME_SIZE + 1];
};

struct crypto_ctx {
	struct acomp_req *req;
	struct crypto_tfm *tfm;
	dma_addr_t src_addr;
	dma_addr_t dst_addr;
	bool compress;
};

struct idxd_desc {
	union {
		struct dsa_hw_desc *hw;
		struct iax_hw_desc *iax_hw;
	};
	dma_addr_t desc_dma;
	union {
		struct dsa_completion_record *completion;
		struct iax_completion_record *iax_completion;
	};
	dma_addr_t compl_dma;
	union {
		struct dma_async_tx_descriptor txd;
		struct crypto_ctx crypto;
	};
	struct llist_node llnode;
	struct list_head list;
	int id;
	int cpu;
	struct idxd_wq *wq;
};

enum idxd_completion_status {
	IDXD_COMP_DESC_ABORT = 0xff,
};

#define wq_confdev(wq) &wq->idxd_dev.conf_dev

static inline struct idxd_device_driver *wq_to_idxd_drv(struct idxd_wq *wq)
{
	struct device *dev = wq_confdev(wq);
	struct idxd_device_driver *idxd_drv =
		container_of(dev->driver, struct idxd_device_driver, drv);

	return idxd_drv;
}

static inline void idxd_desc_complete(struct idxd_desc *desc,
				      enum idxd_complete_type comp_type,
				      bool free_desc)
{
	struct idxd_device_driver *drv;
	u32 status;

	drv = wq_to_idxd_drv(desc->wq);
	if (drv->desc_complete)
		drv->desc_complete(desc, comp_type, free_desc,
				   &desc->txd, &status);
}

/* klp-ccp: from drivers/dma/idxd/irq.c */
static void irq_process_pending_llist(struct idxd_irq_entry *irq_entry)
{
	struct idxd_desc *desc, *t;
	struct llist_node *head;

	head = llist_del_all(&irq_entry->pending_llist);
	if (!head)
		return;

	llist_for_each_entry_safe(desc, t, head, llnode) {
		u8 status = desc->completion->status & DSA_COMP_STATUS_MASK;

		if (status) {
			/*
			 * Check against the original status as ABORT is software defined
			 * and 0xff, which DSA_COMP_STATUS_MASK can mask out.
			 */
			if (unlikely(desc->completion->status == IDXD_COMP_DESC_ABORT)) {
				idxd_desc_complete(desc, IDXD_COMPLETE_ABORT, true);
				continue;
			}

			idxd_desc_complete(desc, IDXD_COMPLETE_NORMAL, true);
		} else {
			spin_lock(&irq_entry->list_lock);
			list_add_tail(&desc->list,
				      &irq_entry->work_list);
			spin_unlock(&irq_entry->list_lock);
		}
	}
}

void klpp_irq_process_work_list(struct idxd_irq_entry *irq_entry)
{
	LIST_HEAD(flist);
	struct idxd_desc *desc, *n;

	/*
	 * This lock protects list corruption from access of list outside of the irq handler
	 * thread.
	 */
	spin_lock(&irq_entry->list_lock);
	if (list_empty(&irq_entry->work_list)) {
		spin_unlock(&irq_entry->list_lock);
		return;
	}

	list_for_each_entry_safe(desc, n, &irq_entry->work_list, list) {
		if (desc->completion->status) {
			list_move_tail(&desc->list, &flist);
		}
	}

	spin_unlock(&irq_entry->list_lock);

	list_for_each_entry_safe(desc, n, &flist, list) {
		/*
		 * Check against the original status as ABORT is software defined
		 * and 0xff, which DSA_COMP_STATUS_MASK can mask out.
		 */
		list_del(&desc->list);

		if (unlikely(desc->completion->status == IDXD_COMP_DESC_ABORT)) {
			idxd_desc_complete(desc, IDXD_COMPLETE_ABORT, true);
			continue;
		}

		idxd_desc_complete(desc, IDXD_COMPLETE_NORMAL, true);
	}
}

irqreturn_t klpp_idxd_wq_thread(int irq, void *data)
{
	struct idxd_irq_entry *irq_entry = data;

	/*
	 * There are two lists we are processing. The pending_llist is where
	 * submmiter adds all the submitted descriptor after sending it to
	 * the workqueue. It's a lockless singly linked list. The work_list
	 * is the common linux double linked list. We are in a scenario of
	 * multiple producers and a single consumer. The producers are all
	 * the kernel submitters of descriptors, and the consumer is the
	 * kernel irq handler thread for the msix vector when using threaded
	 * irq. To work with the restrictions of llist to remain lockless,
	 * we are doing the following steps:
	 * 1. Iterate through the work_list and process any completed
	 *    descriptor. Delete the completed entries during iteration.
	 * 2. llist_del_all() from the pending list.
	 * 3. Iterate through the llist that was deleted from the pending list
	 *    and process the completed entries.
	 * 4. If the entry is still waiting on hardware, list_add_tail() to
	 *    the work_list.
	 */
	klpp_irq_process_work_list(irq_entry);
	irq_process_pending_llist(irq_entry);

	return IRQ_HANDLED;
}


#include "livepatch_bsc1228585.h"


#endif /* IS_ENABLED(CONFIG_INTEL_IDXD) */
