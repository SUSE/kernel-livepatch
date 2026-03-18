/*
 * livepatch_bsc1256217
 *
 * Fix for CVE-2022-50756, bsc#1256217
 *
 *  Copyright (c) 2026 SUSE
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

#include "livepatch_bsc1256217.h"

/* klp-ccp: from drivers/nvme/host/pci.c */
#include <linux/aer.h>
#include <linux/async.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/blk-mq-pci.h>
#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/once.h>
#include <linux/pci.h>
#include <linux/t10-pi.h>
#include <linux/types.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/sed-opal.h>
#include <linux/msi.h>

/* klp-ccp: from drivers/nvme/host/nvme.h */
#include <linux/nvme.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/kref.h>
#include <linux/blk-mq.h>
#include <linux/lightnvm.h>
#include <linux/sed-opal.h>
#include <linux/fault-inject.h>
#include <linux/rcupdate.h>

static unsigned int (*klpe_nvme_io_timeout);

static unsigned int (*klpe_admin_timeout);

static struct workqueue_struct *(*klpe_nvme_wq);

enum nvme_quirks {
	/*
	 * Prefers I/O aligned to a stripe size specified in a vendor
	 * specific Identify field.
	 */
	NVME_QUIRK_STRIPE_SIZE			= (1 << 0),

	/*
	 * The controller doesn't handle Identify value others than 0 or 1
	 * correctly.
	 */
	NVME_QUIRK_IDENTIFY_CNS			= (1 << 1),

	/*
	 * The controller deterministically returns O's on reads to
	 * logical blocks that deallocate was called on.
	 */
	NVME_QUIRK_DEALLOCATE_ZEROES		= (1 << 2),

	/*
	 * The controller needs a delay before starts checking the device
	 * readiness, which is done by reading the NVME_CSTS_RDY bit.
	 */
	NVME_QUIRK_DELAY_BEFORE_CHK_RDY		= (1 << 3),

	/*
	 * APST should not be used.
	 */
	NVME_QUIRK_NO_APST			= (1 << 4),

	/*
	 * The deepest sleep state should not be used.
	 */
	NVME_QUIRK_NO_DEEPEST_PS		= (1 << 5),

	/*
	 * Supports the LighNVM command set if indicated in vs[1].
	 */
	NVME_QUIRK_LIGHTNVM			= (1 << 6),

	/*
	 * Set MEDIUM priority on SQ creation
	 */
	NVME_QUIRK_MEDIUM_PRIO_SQ		= (1 << 7),

	/*
	 * Ignore device provided subnqn.
	 */
	NVME_QUIRK_IGNORE_DEV_SUBNQN		= (1 << 8),

	/*
	 * The controller doesn't handle the Identify Namespace
	 * Identification Descriptor list subcommand despite claiming
	 * NVMe 1.3 compliance.
	 */
	NVME_QUIRK_NO_NS_DESC_LIST              = (1 << 15),
};

struct nvme_request {
	struct nvme_command	*cmd;
	union nvme_result	result;
	u8			retries;
	u8			flags;
	u16			status;
	struct nvme_ctrl	*ctrl;
};

enum nvme_ctrl_state {
	NVME_CTRL_NEW,
	NVME_CTRL_LIVE,
	NVME_CTRL_ADMIN_ONLY,    /* Only admin queue live */
	NVME_CTRL_RESETTING,
	NVME_CTRL_CONNECTING,
	NVME_CTRL_DELETING,
	NVME_CTRL_DEAD,
};

struct nvme_ctrl {
	bool comp_seen;
	enum nvme_ctrl_state state;
	bool identified;
	spinlock_t lock;
	struct mutex scan_lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct device *dev;
	int instance;
	int numa_node;
	struct blk_mq_tag_set *tagset;
	struct blk_mq_tag_set *admin_tagset;
	struct list_head namespaces;
	struct rw_semaphore namespaces_rwsem;
	struct device ctrl_device;
	struct device *device;	/* char device */
	struct cdev cdev;
	struct work_struct reset_work;
	struct work_struct delete_work;

	struct nvme_subsystem *subsys;
	struct list_head subsys_entry;

	struct opal_dev *opal_dev;

	char name[12];
	u16 cntlid;

	u32 ctrl_config;
	u16 mtfa;
	u32 queue_count;

	u64 cap;
	u32 page_size;
	u32 max_hw_sectors;
	u32 max_segments;
	u16 crdt[3];
	u16 oncs;
	u16 oacs;
	u16 nssa;
	u16 nr_streams;
	u32 max_namespaces;
	atomic_t abort_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	u8 npss;
	u8 apsta;
	u32 oaes;
	u32 aen_result;
	u32 ctratt;
	unsigned int shutdown_timeout;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	struct nvme_id_power_state psd[32];
	struct nvme_effects_log *effects;
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;
	struct nvme_command ka_cmd;
	struct work_struct fw_act_work;
	unsigned long events;

#ifdef CONFIG_NVME_MULTIPATH
	u8 anacap;
	u8 anatt;
	u32 anagrpmax;
	u32 nanagrpid;
	struct mutex ana_lock;
	struct nvme_ana_rsp_hdr *ana_log_buf;
	size_t ana_log_size;
	struct timer_list anatt_timer;
	struct work_struct ana_work;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u64 ps_max_latency_us;
	bool apst_enabled;

	/* PCIe only: */
	u32 hmpre;
	u32 hmmin;
	u32 hmminds;
	u16 hmmaxd;

	/* Fabrics only */
	u16 sqsize;
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	int nr_reconnects;
	struct nvmf_ctrl_options *opts;
#ifndef __GENKSYMS__
	struct request_queue *fabrics_q;
	struct delayed_work failfast_work;
	unsigned long flags;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct nvme_ctrl_ops {
	const char *name;
	struct module *module;
	unsigned int flags;
	int (*reg_read32)(struct nvme_ctrl *ctrl, u32 off, u32 *val);
	int (*reg_write32)(struct nvme_ctrl *ctrl, u32 off, u32 val);
	int (*reg_read64)(struct nvme_ctrl *ctrl, u32 off, u64 *val);
	void (*free_ctrl)(struct nvme_ctrl *ctrl);
	void (*submit_async_event)(struct nvme_ctrl *ctrl);
	void (*delete_ctrl)(struct nvme_ctrl *ctrl);
	int (*get_address)(struct nvme_ctrl *ctrl, char *buf, int size);
	void (*stop_ctrl)(struct nvme_ctrl *ctrl);
};

static inline void nvme_get_ctrl(struct nvme_ctrl *ctrl)
{
	get_device(ctrl->device);
}

static inline void nvme_put_ctrl(struct nvme_ctrl *ctrl)
{
	put_device(ctrl->device);
}

static bool (*klpe_nvme_change_ctrl_state)(struct nvme_ctrl *ctrl,
		enum nvme_ctrl_state new_state);
static int (*klpe_nvme_disable_ctrl)(struct nvme_ctrl *ctrl, u64 cap);
static int (*klpe_nvme_enable_ctrl)(struct nvme_ctrl *ctrl, u64 cap);

static int (*klpe_nvme_init_ctrl)(struct nvme_ctrl *ctrl, struct device *dev,
		const struct nvme_ctrl_ops *ops, unsigned long quirks);

static void (*klpe_nvme_start_ctrl)(struct nvme_ctrl *ctrl);

void nvme_put_ctrl(struct nvme_ctrl *ctrl);
static int (*klpe_nvme_init_identify)(struct nvme_ctrl *ctrl);

static void (*klpe_nvme_remove_namespaces)(struct nvme_ctrl *ctrl);

static int (*klpe_nvme_sec_submit)(void *data, u16 spsp, u8 secp, void *buffer, size_t len,
		bool send);

static void (*klpe_nvme_start_queues)(struct nvme_ctrl *ctrl);
static void (*klpe_nvme_kill_queues)(struct nvme_ctrl *ctrl);
static void (*klpe_nvme_sync_queues)(struct nvme_ctrl *ctrl);

static void (*klpe_nvme_unfreeze)(struct nvme_ctrl *ctrl);
static void (*klpe_nvme_wait_freeze)(struct nvme_ctrl *ctrl);

static int (*klpe_nvme_submit_sync_cmd)(struct request_queue *q, struct nvme_command *cmd,
		void *buf, unsigned bufflen);

static int (*klpe_nvme_set_queue_count)(struct nvme_ctrl *ctrl, int *count);

/* klp-ccp: from drivers/nvme/host/pci.c */
#define SQ_SIZE(depth)		(depth * sizeof(struct nvme_command))
#define CQ_SIZE(depth)		(depth * sizeof(struct nvme_completion))

#define NVME_MAX_KB_SZ	4096
#define NVME_MAX_SEGS	127

static bool (*klpe_use_cmb_sqes);

static unsigned int (*klpe_max_host_mem_size_mb);

static unsigned int (*klpe_sgl_threshold);

static int (*klpe_io_queue_depth);

struct nvme_dev;

static void (*klpe_nvme_dev_disable)(struct nvme_dev *dev, bool shutdown);

struct nvme_dev {
	struct nvme_queue *queues;
	struct blk_mq_tag_set tagset;
	struct blk_mq_tag_set admin_tagset;
	u32 __iomem *dbs;
	struct device *dev;
	struct dma_pool *prp_page_pool;
	struct dma_pool *prp_small_pool;
	unsigned online_queues;
	unsigned max_qid;
	unsigned int num_vecs;
	int q_depth;
	u32 db_stride;
	void __iomem *bar;
	unsigned long bar_mapped_size;
	struct work_struct remove_work;
	struct mutex shutdown_lock;
	bool subsystem;
	void __iomem *cmb;
	pci_bus_addr_t cmb_bus_addr;
	u64 cmb_size;
	u32 cmbsz;
	u32 cmbloc;
	struct nvme_ctrl ctrl;
	struct completion ioq_wait;

	mempool_t *iod_mempool;

	/* shadow doorbell buffer support: */
	__le32 *dbbuf_dbs;
	dma_addr_t dbbuf_dbs_dma_addr;
	__le32 *dbbuf_eis;
	dma_addr_t dbbuf_eis_dma_addr;

	/* host memory buffer support: */
	u64 host_mem_size;
	u32 nr_host_mem_descs;
	u32 host_mem_descs_size;
	dma_addr_t host_mem_descs_dma;
	struct nvme_host_mem_buf_desc *host_mem_descs;
	void **host_mem_desc_bufs;
};

struct nvme_queue {
	struct device *q_dmadev;
	struct nvme_dev *dev;
	spinlock_t sq_lock;
	struct nvme_command *sq_cmds;
	struct nvme_command __iomem *sq_cmds_io;
	spinlock_t cq_lock ____cacheline_aligned_in_smp;
	volatile struct nvme_completion *cqes;
	struct blk_mq_tags **tags;
	dma_addr_t sq_dma_addr;
	dma_addr_t cq_dma_addr;
	u32 __iomem *q_db;
	u16 q_depth;
	s16 cq_vector;
	u16 sq_tail;
	u16 cq_head;
	u16 last_cq_head;
	u16 qid;
	u8 cq_phase;
	__le32 *dbbuf_sq_db;
	__le32 *dbbuf_cq_db;
	__le32 *dbbuf_sq_ei;
	__le32 *dbbuf_cq_ei;
};

struct nvme_iod {
	struct nvme_request req;
	struct nvme_queue *nvmeq;
	bool use_sgl;
	int aborted;
	int npages;		/* In the PRP list. 0 means small pool in use */
	int nents;		/* Used in scatterlist */
	int length;		/* Of data, in bytes */
	dma_addr_t first_dma;
	struct scatterlist meta_sg; /* metadata requires single contiguous buffer */
	struct scatterlist *sg;
	struct scatterlist inline_sg[0];
};

static inline unsigned int nvme_dbbuf_size(u32 stride)
{
	return ((num_possible_cpus() + 1) * 8 * stride);
}

static int nvme_dbbuf_dma_alloc(struct nvme_dev *dev)
{
	unsigned int mem_size = nvme_dbbuf_size(dev->db_stride);

	if (dev->dbbuf_dbs)
		return 0;

	dev->dbbuf_dbs = dma_alloc_coherent(dev->dev, mem_size,
					    &dev->dbbuf_dbs_dma_addr,
					    GFP_KERNEL);
	if (!dev->dbbuf_dbs)
		return -ENOMEM;
	dev->dbbuf_eis = dma_alloc_coherent(dev->dev, mem_size,
					    &dev->dbbuf_eis_dma_addr,
					    GFP_KERNEL);
	if (!dev->dbbuf_eis) {
		dma_free_coherent(dev->dev, mem_size,
				  dev->dbbuf_dbs, dev->dbbuf_dbs_dma_addr);
		dev->dbbuf_dbs = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void (*klpe_nvme_dbbuf_dma_free)(struct nvme_dev *dev);

static void nvme_dbbuf_free(struct nvme_queue *nvmeq)
{
	if (!nvmeq->qid)
		return;

	nvmeq->dbbuf_sq_db = NULL;
	nvmeq->dbbuf_cq_db = NULL;
	nvmeq->dbbuf_sq_ei = NULL;
	nvmeq->dbbuf_cq_ei = NULL;
}

static void klpr_nvme_dbbuf_set(struct nvme_dev *dev)
{
	struct nvme_command c;
	unsigned int i;

	if (!dev->dbbuf_dbs)
		return;

	memset(&c, 0, sizeof(c));
	c.dbbuf.opcode = nvme_admin_dbbuf;
	c.dbbuf.prp1 = cpu_to_le64(dev->dbbuf_dbs_dma_addr);
	c.dbbuf.prp2 = cpu_to_le64(dev->dbbuf_eis_dma_addr);

	if ((*klpe_nvme_submit_sync_cmd)(dev->ctrl.admin_q, &c, NULL, 0)) {
		dev_warn(dev->ctrl.device, "unable to set dbbuf\n");
		/* Free memory and continue on */
		(*klpe_nvme_dbbuf_dma_free)(dev);

		for (i = 1; i <= dev->online_queues; i++)
			nvme_dbbuf_free(&dev->queues[i]);
	}
}

#define NVME_INT_PAGES		2
#define NVME_INT_BYTES(dev)	(NVME_INT_PAGES * (dev)->ctrl.page_size)

static int nvme_npages(unsigned size, struct nvme_dev *dev)
{
	unsigned nprps = DIV_ROUND_UP(size + dev->ctrl.page_size,
				      dev->ctrl.page_size);
	return DIV_ROUND_UP(8 * nprps, PAGE_SIZE - 8);
}

static int nvme_pci_npages_sgl(unsigned int num_seg)
{
	return DIV_ROUND_UP(num_seg * sizeof(struct nvme_sgl_desc), PAGE_SIZE);
}

static unsigned int nvme_pci_iod_alloc_size(struct nvme_dev *dev,
		unsigned int size, unsigned int nseg, bool use_sgl)
{
	size_t alloc_size;

	if (use_sgl)
		alloc_size = sizeof(__le64 *) * nvme_pci_npages_sgl(nseg);
	else
		alloc_size = sizeof(__le64 *) * nvme_npages(size, dev);

	return alloc_size + sizeof(struct scatterlist) * nseg;
}

static unsigned int klpp_nvme_pci_cmd_size(struct nvme_dev *dev, bool use_sgl)
{
	unsigned int alloc_size = nvme_pci_iod_alloc_size(dev,
				    NVME_INT_BYTES(dev) * 512, NVME_INT_PAGES,
				    use_sgl);

	return sizeof(struct nvme_iod) + alloc_size;
}

static int klpr_adapter_delete_queue(struct nvme_dev *dev, u8 opcode, u16 id)
{
	struct nvme_command c;

	memset(&c, 0, sizeof(c));
	c.delete_queue.opcode = opcode;
	c.delete_queue.qid = cpu_to_le16(id);

	return (*klpe_nvme_submit_sync_cmd)(dev->ctrl.admin_q, &c, NULL, 0);
}

static int klpr_adapter_alloc_cq(struct nvme_dev *dev, u16 qid,
		struct nvme_queue *nvmeq, s16 vector)
{
	struct nvme_command c;
	int flags = NVME_QUEUE_PHYS_CONTIG | NVME_CQ_IRQ_ENABLED;

	/*
	 * Note: we (ab)use the fact that the prp fields survive if no data
	 * is attached to the request.
	 */
	memset(&c, 0, sizeof(c));
	c.create_cq.opcode = nvme_admin_create_cq;
	c.create_cq.prp1 = cpu_to_le64(nvmeq->cq_dma_addr);
	c.create_cq.cqid = cpu_to_le16(qid);
	c.create_cq.qsize = cpu_to_le16(nvmeq->q_depth - 1);
	c.create_cq.cq_flags = cpu_to_le16(flags);
	c.create_cq.irq_vector = cpu_to_le16(vector);

	return (*klpe_nvme_submit_sync_cmd)(dev->ctrl.admin_q, &c, NULL, 0);
}

static int klpr_adapter_alloc_sq(struct nvme_dev *dev, u16 qid,
						struct nvme_queue *nvmeq)
{
	struct nvme_ctrl *ctrl = &dev->ctrl;
	struct nvme_command c;
	int flags = NVME_QUEUE_PHYS_CONTIG;

	/*
	 * Some drives have a bug that auto-enables WRRU if MEDIUM isn't
	 * set. Since URGENT priority is zeroes, it makes all queues
	 * URGENT.
	 */
	if (ctrl->quirks & NVME_QUIRK_MEDIUM_PRIO_SQ)
		flags |= NVME_SQ_PRIO_MEDIUM;

	/*
	 * Note: we (ab)use the fact that the prp fields survive if no data
	 * is attached to the request.
	 */
	memset(&c, 0, sizeof(c));
	c.create_sq.opcode = nvme_admin_create_sq;
	c.create_sq.prp1 = cpu_to_le64(nvmeq->sq_dma_addr);
	c.create_sq.sqid = cpu_to_le16(qid);
	c.create_sq.qsize = cpu_to_le16(nvmeq->q_depth - 1);
	c.create_sq.sq_flags = cpu_to_le16(flags);
	c.create_sq.cqid = cpu_to_le16(qid);

	return (*klpe_nvme_submit_sync_cmd)(dev->ctrl.admin_q, &c, NULL, 0);
}

static int klpr_adapter_delete_cq(struct nvme_dev *dev, u16 cqid)
{
	return klpr_adapter_delete_queue(dev, nvme_admin_delete_cq, cqid);
}

static int klpr_adapter_delete_sq(struct nvme_dev *dev, u16 sqid)
{
	return klpr_adapter_delete_queue(dev, nvme_admin_delete_sq, sqid);
}

static void nvme_free_queue(struct nvme_queue *nvmeq)
{
	dma_free_coherent(nvmeq->q_dmadev, CQ_SIZE(nvmeq->q_depth),
				(void *)nvmeq->cqes, nvmeq->cq_dma_addr);
	if (nvmeq->sq_cmds)
		dma_free_coherent(nvmeq->q_dmadev, SQ_SIZE(nvmeq->q_depth),
					nvmeq->sq_cmds, nvmeq->sq_dma_addr);
}

static void nvme_free_queues(struct nvme_dev *dev, int lowest)
{
	int i;

	for (i = dev->ctrl.queue_count - 1; i >= lowest; i--) {
		dev->ctrl.queue_count--;
		nvme_free_queue(&dev->queues[i]);
	}
}

static int nvme_cmb_qdepth(struct nvme_dev *dev, int nr_io_queues,
				int entry_size)
{
	int q_depth = dev->q_depth;
	unsigned q_size_aligned = roundup(q_depth * entry_size,
					  dev->ctrl.page_size);

	if (q_size_aligned * nr_io_queues > dev->cmb_size) {
		u64 mem_per_q = div_u64(dev->cmb_size, nr_io_queues);
		mem_per_q = round_down(mem_per_q, dev->ctrl.page_size);
		q_depth = div_u64(mem_per_q, entry_size);

		/*
		 * Ensure the reduced q_depth is above some threshold where it
		 * would be better to map queues in system memory with the
		 * original depth
		 */
		if (q_depth < 64)
			return -ENOMEM;
	}

	return q_depth;
}

static int (*klpe_nvme_alloc_queue)(struct nvme_dev *dev, int qid, int depth);

static int (*klpe_queue_request_irq)(struct nvme_queue *nvmeq);

static void (*klpe_nvme_init_queue)(struct nvme_queue *nvmeq, u16 qid);

static int klpr_nvme_create_queue(struct nvme_queue *nvmeq, int qid)
{
	struct nvme_dev *dev = nvmeq->dev;
	int result;
	s16 vector;

	if (dev->cmb && (*klpe_use_cmb_sqes) && (dev->cmbsz & NVME_CMBSZ_SQS)) {
		unsigned offset = (qid - 1) * roundup(SQ_SIZE(nvmeq->q_depth),
						      dev->ctrl.page_size);
		nvmeq->sq_dma_addr = dev->cmb_bus_addr + offset;
		nvmeq->sq_cmds_io = dev->cmb + offset;
	}

	/*
	 * A queue's vector matches the queue identifier unless the controller
	 * has only one vector available.
	 */
	vector = dev->num_vecs == 1 ? 0 : qid;
	result = klpr_adapter_alloc_cq(dev, qid, nvmeq, vector);
	if (result)
		return result;

	result = klpr_adapter_alloc_sq(dev, qid, nvmeq);
	if (result < 0)
		return result;
	else if (result)
		goto release_cq;

	/*
	 * Set cq_vector after alloc cq/sq, otherwise nvme_suspend_queue will
	 * invoke free_irq for it and cause a 'Trying to free already-free IRQ
	 * xxx' warning if the create CQ/SQ command times out.
	 */
	nvmeq->cq_vector = vector;
	(*klpe_nvme_init_queue)(nvmeq, qid);
	result = (*klpe_queue_request_irq)(nvmeq);
	if (result < 0)
		goto release_sq;

	return result;

release_sq:
	nvmeq->cq_vector = -1;
	dev->online_queues--;
	klpr_adapter_delete_sq(dev, qid);
release_cq:
	klpr_adapter_delete_cq(dev, qid);
	return result;
}

static const struct blk_mq_ops (*klpe_nvme_mq_admin_ops);

static const struct blk_mq_ops (*klpe_nvme_mq_ops);

static void (*klpe_nvme_dev_remove_admin)(struct nvme_dev *dev);

static int klpr_nvme_alloc_admin_tags(struct nvme_dev *dev)
{
	if (!dev->ctrl.admin_q) {
		dev->admin_tagset.ops = &(*klpe_nvme_mq_admin_ops);
		dev->admin_tagset.nr_hw_queues = 1;

		dev->admin_tagset.queue_depth = NVME_AQ_MQ_TAG_DEPTH;
		dev->admin_tagset.timeout = ((*klpe_admin_timeout) * 250);
		dev->admin_tagset.numa_node = dev_to_node(dev->dev);
		dev->admin_tagset.cmd_size = klpp_nvme_pci_cmd_size(dev, false);
		dev->admin_tagset.flags = BLK_MQ_F_NO_SCHED;
		dev->admin_tagset.driver_data = dev;

		if (blk_mq_alloc_tag_set(&dev->admin_tagset))
			return -ENOMEM;
		dev->ctrl.admin_tagset = &dev->admin_tagset;

		dev->ctrl.admin_q = blk_mq_init_queue(&dev->admin_tagset);
		if (IS_ERR(dev->ctrl.admin_q)) {
			blk_mq_free_tag_set(&dev->admin_tagset);
			dev->ctrl.admin_q = NULL;
			return -ENOMEM;
		}
		if (!blk_get_queue(dev->ctrl.admin_q)) {
			(*klpe_nvme_dev_remove_admin)(dev);
			dev->ctrl.admin_q = NULL;
			return -ENODEV;
		}
	} else
		blk_mq_unquiesce_queue(dev->ctrl.admin_q);

	return 0;
}

static unsigned long db_bar_size(struct nvme_dev *dev, unsigned nr_io_queues)
{
	return NVME_REG_DBS + ((nr_io_queues + 1) * 8 * dev->db_stride);
}

static int (*klpe_nvme_remap_bar)(struct nvme_dev *dev, unsigned long size);

static int klpr_nvme_pci_configure_admin_queue(struct nvme_dev *dev)
{
	int result;
	u32 aqa;
	struct nvme_queue *nvmeq;

	result = (*klpe_nvme_remap_bar)(dev, db_bar_size(dev, 0));
	if (result < 0)
		return result;

	dev->subsystem = readl(dev->bar + NVME_REG_VS) >= NVME_VS(1, 1, 0) ?
				NVME_CAP_NSSRC(dev->ctrl.cap) : 0;

	if (dev->subsystem &&
	    (readl(dev->bar + NVME_REG_CSTS) & NVME_CSTS_NSSRO))
		writel(NVME_CSTS_NSSRO, dev->bar + NVME_REG_CSTS);

	result = (*klpe_nvme_disable_ctrl)(&dev->ctrl, dev->ctrl.cap);
	if (result < 0)
		return result;

	result = (*klpe_nvme_alloc_queue)(dev, 0, NVME_AQ_DEPTH);
	if (result)
		return result;

	dev->ctrl.numa_node = dev_to_node(dev->dev);

	nvmeq = &dev->queues[0];
	aqa = nvmeq->q_depth - 1;
	aqa |= aqa << 16;

	writel(aqa, dev->bar + NVME_REG_AQA);
	lo_hi_writeq(nvmeq->sq_dma_addr, dev->bar + NVME_REG_ASQ);
	lo_hi_writeq(nvmeq->cq_dma_addr, dev->bar + NVME_REG_ACQ);

	result = (*klpe_nvme_enable_ctrl)(&dev->ctrl, dev->ctrl.cap);
	if (result)
		return result;

	nvmeq->cq_vector = 0;
	(*klpe_nvme_init_queue)(nvmeq, 0);
	result = (*klpe_queue_request_irq)(nvmeq);
	if (result) {
		nvmeq->cq_vector = -1;
		return result;
	}

	return result;
}

static int klpr_nvme_create_io_queues(struct nvme_dev *dev)
{
	unsigned i, max;
	int ret = 0;

	for (i = dev->ctrl.queue_count; i <= dev->max_qid; i++) {
		if ((*klpe_nvme_alloc_queue)(dev, i, dev->q_depth)) {
			ret = -ENOMEM;
			break;
		}
	}

	max = min(dev->max_qid, dev->ctrl.queue_count - 1);
	for (i = dev->online_queues; i <= max; i++) {
		ret = klpr_nvme_create_queue(&dev->queues[i], i);
		if (ret)
			break;
	}

	/*
	 * Ignore failing Create SQ/CQ commands, we can continue with less
	 * than the desired amount of queues, and even a controller without
	 * I/O queues can still be used to issue admin commands.  This might
	 * be useful to upgrade a buggy firmware for example.
	 */
	return ret >= 0 ? 0 : ret;
}

static struct device_attribute (*klpe_dev_attr_cmb);

static u64 nvme_cmb_size_unit(struct nvme_dev *dev)
{
	u8 szu = (dev->cmbsz >> NVME_CMBSZ_SZU_SHIFT) & NVME_CMBSZ_SZU_MASK;

	return 1ULL << (12 + 4 * szu);
}

static u32 nvme_cmb_size(struct nvme_dev *dev)
{
	return (dev->cmbsz >> NVME_CMBSZ_SZ_SHIFT) & NVME_CMBSZ_SZ_MASK;
}

static void klpr_nvme_map_cmb(struct nvme_dev *dev)
{
	u64 size, offset;
	resource_size_t bar_size;
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	int bar;

	dev->cmbsz = readl(dev->bar + NVME_REG_CMBSZ);
	if (!dev->cmbsz)
		return;
	dev->cmbloc = readl(dev->bar + NVME_REG_CMBLOC);

	if (!(*klpe_use_cmb_sqes))
		return;

	size = nvme_cmb_size_unit(dev) * nvme_cmb_size(dev);
	offset = nvme_cmb_size_unit(dev) * NVME_CMB_OFST(dev->cmbloc);
	bar = NVME_CMB_BIR(dev->cmbloc);
	bar_size = pci_resource_len(pdev, bar);

	if (offset > bar_size)
		return;

	/*
	 * Controllers may support a CMB size larger than their BAR,
	 * for example, due to being behind a bridge. Reduce the CMB to
	 * the reported size of the BAR
	 */
	if (size > bar_size - offset)
		size = bar_size - offset;

	dev->cmb = ioremap_wc(pci_resource_start(pdev, bar) + offset, size);
	if (!dev->cmb)
		return;
	dev->cmb_bus_addr = pci_bus_address(pdev, bar) + offset;
	dev->cmb_size = size;

	if (sysfs_add_file_to_group(&dev->ctrl.device->kobj,
				    &(*klpe_dev_attr_cmb).attr, NULL))
		dev_warn(dev->ctrl.device,
			 "failed to add sysfs attribute for CMB\n");
}

static inline void klpr_nvme_release_cmb(struct nvme_dev *dev)
{
	if (dev->cmb) {
		iounmap(dev->cmb);
		dev->cmb = NULL;
		sysfs_remove_file_from_group(&dev->ctrl.device->kobj,
					     &(*klpe_dev_attr_cmb).attr, NULL);
		dev->cmbsz = 0;
	}
}

static int klpr_nvme_set_host_mem(struct nvme_dev *dev, u32 bits)
{
	u64 dma_addr = dev->host_mem_descs_dma;
	struct nvme_command c;
	int ret;

	memset(&c, 0, sizeof(c));
	c.features.opcode	= nvme_admin_set_features;
	c.features.fid		= cpu_to_le32(NVME_FEAT_HOST_MEM_BUF);
	c.features.dword11	= cpu_to_le32(bits);
	c.features.dword12	= cpu_to_le32(dev->host_mem_size >>
					      ilog2(dev->ctrl.page_size));
	c.features.dword13	= cpu_to_le32(lower_32_bits(dma_addr));
	c.features.dword14	= cpu_to_le32(upper_32_bits(dma_addr));
	c.features.dword15	= cpu_to_le32(dev->nr_host_mem_descs);

	ret = (*klpe_nvme_submit_sync_cmd)(dev->ctrl.admin_q, &c, NULL, 0);
	if (ret) {
		dev_warn(dev->ctrl.device,
			 "failed to set host mem (err %d, flags %#x).\n",
			 ret, bits);
	}
	return ret;
}

static void (*klpe_nvme_free_host_mem)(struct nvme_dev *dev);

static int __nvme_alloc_host_mem(struct nvme_dev *dev, u64 preferred,
		u32 chunk_size)
{
	struct nvme_host_mem_buf_desc *descs;
	u32 max_entries, len, descs_size;
	dma_addr_t descs_dma;
	int i = 0;
	void **bufs;
	u64 size, tmp;

	tmp = (preferred + chunk_size - 1);
	do_div(tmp, chunk_size);
	max_entries = tmp;

	if (dev->ctrl.hmmaxd && dev->ctrl.hmmaxd < max_entries)
		max_entries = dev->ctrl.hmmaxd;

	descs_size = max_entries * sizeof(*descs);
	descs = dma_alloc_coherent(dev->dev, descs_size, &descs_dma,
			GFP_KERNEL);
	if (!descs)
		goto out;

	bufs = kcalloc(max_entries, sizeof(*bufs), GFP_KERNEL);
	if (!bufs)
		goto out_free_descs;

	for (size = 0; size < preferred && i < max_entries; size += len) {
		dma_addr_t dma_addr;

		len = min_t(u64, chunk_size, preferred - size);
		bufs[i] = dma_alloc_attrs(dev->dev, len, &dma_addr, GFP_KERNEL,
				DMA_ATTR_NO_KERNEL_MAPPING | DMA_ATTR_NO_WARN);
		if (!bufs[i])
			break;

		descs[i].addr = cpu_to_le64(dma_addr);
		descs[i].size = cpu_to_le32(len / dev->ctrl.page_size);
		i++;
	}

	if (!size)
		goto out_free_bufs;

	dev->nr_host_mem_descs = i;
	dev->host_mem_size = size;
	dev->host_mem_descs = descs;
	dev->host_mem_descs_dma = descs_dma;
	dev->host_mem_descs_size = descs_size;
	dev->host_mem_desc_bufs = bufs;
	return 0;

out_free_bufs:
	while (--i >= 0) {
		size_t size = le32_to_cpu(descs[i].size) * dev->ctrl.page_size;

		dma_free_attrs(dev->dev, size, bufs[i],
			       le64_to_cpu(descs[i].addr),
			       DMA_ATTR_NO_KERNEL_MAPPING | DMA_ATTR_NO_WARN);
	}

	kfree(bufs);
out_free_descs:
	dma_free_coherent(dev->dev, descs_size, descs, descs_dma);
out:
	dev->host_mem_descs = NULL;
	return -ENOMEM;
}

static int klpr_nvme_alloc_host_mem(struct nvme_dev *dev, u64 min, u64 preferred)
{
	u32 chunk_size;

	/* start big and work our way down */
	for (chunk_size = min_t(u64, preferred, PAGE_SIZE * MAX_ORDER_NR_PAGES);
	     chunk_size >= max_t(u32, dev->ctrl.hmminds * 4096, PAGE_SIZE * 2);
	     chunk_size /= 2) {
		if (!__nvme_alloc_host_mem(dev, preferred, chunk_size)) {
			if (!min || dev->host_mem_size >= min)
				return 0;
			(*klpe_nvme_free_host_mem)(dev);
		}
	}

	return -ENOMEM;
}

static int klpr_nvme_setup_host_mem(struct nvme_dev *dev)
{
	u64 max = (u64)(*klpe_max_host_mem_size_mb) * SZ_1M;
	u64 preferred = (u64)dev->ctrl.hmpre * 4096;
	u64 min = (u64)dev->ctrl.hmmin * 4096;
	u32 enable_bits = NVME_HOST_MEM_ENABLE;
	int ret;

	preferred = min(preferred, max);
	if (min > max) {
		dev_warn(dev->ctrl.device,
			"min host memory (%lld MiB) above limit (%d MiB).\n",
			min >> ilog2(SZ_1M), (*klpe_max_host_mem_size_mb));
		(*klpe_nvme_free_host_mem)(dev);
		return 0;
	}

	/*
	 * If we already have a buffer allocated check if we can reuse it.
	 */
	if (dev->host_mem_descs) {
		if (dev->host_mem_size >= min)
			enable_bits |= NVME_HOST_MEM_RETURN;
		else
			(*klpe_nvme_free_host_mem)(dev);
	}

	if (!dev->host_mem_descs) {
		if (klpr_nvme_alloc_host_mem(dev, min, preferred)) {
			dev_warn(dev->ctrl.device,
				"failed to allocate host memory buffer.\n");
			return 0; /* controller must work without HMB */
		}

		dev_info(dev->ctrl.device,
			"allocated %lld MiB host memory buffer.\n",
			dev->host_mem_size >> ilog2(SZ_1M));
	}

	ret = klpr_nvme_set_host_mem(dev, enable_bits);
	if (ret)
		(*klpe_nvme_free_host_mem)(dev);
	return ret;
}

static int klpr_nvme_setup_io_queues(struct nvme_dev *dev)
{
	struct nvme_queue *adminq = &dev->queues[0];
	struct pci_dev *pdev = to_pci_dev(dev->dev);
	int result, nr_io_queues;
	unsigned long size;

	struct irq_affinity affd = {
		.pre_vectors = 1
	};

	nr_io_queues = num_possible_cpus();
	result = (*klpe_nvme_set_queue_count)(&dev->ctrl, &nr_io_queues);
	if (result < 0)
		return result;

	if (nr_io_queues == 0)
		return 0;

	if (dev->cmb && (dev->cmbsz & NVME_CMBSZ_SQS)) {
		result = nvme_cmb_qdepth(dev, nr_io_queues,
				sizeof(struct nvme_command));
		if (result > 0)
			dev->q_depth = result;
		else
			klpr_nvme_release_cmb(dev);
	}

	do {
		size = db_bar_size(dev, nr_io_queues);
		result = (*klpe_nvme_remap_bar)(dev, size);
		if (!result)
			break;
		if (!--nr_io_queues)
			return -ENOMEM;
	} while (1);
	adminq->q_db = dev->dbs;

	/* Deregister the admin queue's interrupt */
	pci_free_irq(pdev, 0, adminq);

	/*
	 * If we enable msix early due to not intx, disable it again before
	 * setting up the full range we need.
	 */
	pci_free_irq_vectors(pdev);
	result = pci_alloc_irq_vectors_affinity(pdev, 1, nr_io_queues + 1,
			PCI_IRQ_ALL_TYPES | PCI_IRQ_AFFINITY, &affd);
	if (result <= 0)
		return -EIO;
	dev->num_vecs = result;
	dev->max_qid = max(result - 1, 1);

#ifdef CONFIG_GENERIC_MSI_IRQ
	suse_msi_set_irq_unmanaged(dev->dev);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	result = (*klpe_queue_request_irq)(adminq);
	if (result) {
		adminq->cq_vector = -1;
		return result;
	}
	return klpr_nvme_create_io_queues(dev);
}

static int klpr_nvme_dev_add(struct nvme_dev *dev)
{
	int ret;

	if (!dev->ctrl.tagset) {
		dev->tagset.ops = &(*klpe_nvme_mq_ops);
		dev->tagset.nr_hw_queues = dev->online_queues - 1;
		dev->tagset.timeout = ((*klpe_nvme_io_timeout) * 250);
		dev->tagset.numa_node = dev_to_node(dev->dev);
		dev->tagset.queue_depth =
				min_t(int, dev->q_depth, BLK_MQ_MAX_DEPTH) - 1;
		dev->tagset.cmd_size = klpp_nvme_pci_cmd_size(dev, false);
		if ((dev->ctrl.sgls & ((1 << 0) | (1 << 1))) && (*klpe_sgl_threshold)) {
			dev->tagset.cmd_size = max(dev->tagset.cmd_size,
					klpp_nvme_pci_cmd_size(dev, true));
		}
		dev->tagset.flags = BLK_MQ_F_SHOULD_MERGE;
		dev->tagset.driver_data = dev;

		ret = blk_mq_alloc_tag_set(&dev->tagset);
		if (ret) {
			dev_warn(dev->ctrl.device,
				"IO queues tagset allocation failed %d\n", ret);
			return ret;
		}
		dev->ctrl.tagset = &dev->tagset;

		klpr_nvme_dbbuf_set(dev);
	} else {
		/* Give up if we are racing with nvme_dev_disable() */
		if (!mutex_trylock(&dev->shutdown_lock))
			return -EAGAIN;

		/* Check if nvme_dev_disable() has been executed already */
		if (!dev->online_queues) {
			mutex_unlock(&dev->shutdown_lock);
			return -EAGAIN;
		}
		blk_mq_update_nr_hw_queues(&dev->tagset, dev->online_queues - 1);

		/* Free previously allocated queues that are no longer usable */
		nvme_free_queues(dev, dev->online_queues);
		mutex_unlock(&dev->shutdown_lock);
	}

	return 0;
}

static int klpr_nvme_pci_enable(struct nvme_dev *dev)
{
	int result = -ENOMEM;
	struct pci_dev *pdev = to_pci_dev(dev->dev);

	if (pci_enable_device_mem(pdev))
		return result;

	pci_set_master(pdev);

	if (dma_set_mask_and_coherent(dev->dev, DMA_BIT_MASK(64)) &&
	    dma_set_mask_and_coherent(dev->dev, DMA_BIT_MASK(32)))
		goto disable;

	if (readl(dev->bar + NVME_REG_CSTS) == -1) {
		result = -ENODEV;
		goto disable;
	}

	/*
	 * Some devices and/or platforms don't advertise or work with INTx
	 * interrupts. Pre-enable a single MSIX or MSI vec for setup. We'll
	 * adjust this later.
	 */
	result = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	if (result < 0)
		return result;

	dev->ctrl.cap = lo_hi_readq(dev->bar + NVME_REG_CAP);

	dev->q_depth = min_t(int, NVME_CAP_MQES(dev->ctrl.cap) + 1,
				(*klpe_io_queue_depth));
	dev->db_stride = 1 << NVME_CAP_STRIDE(dev->ctrl.cap);
	dev->dbs = dev->bar + 4096;

	/*
	 * Temporary fix for the Apple controller found in the MacBook8,1 and
	 * some MacBook7,1 to avoid controller resets and data loss.
	 */
	if (pdev->vendor == PCI_VENDOR_ID_APPLE && pdev->device == 0x2001) {
		dev->q_depth = 2;
		dev_warn(dev->ctrl.device, "detected Apple NVMe controller, "
			"set queue depth=%u to work around controller resets\n",
			dev->q_depth);
	} else if (pdev->vendor == PCI_VENDOR_ID_SAMSUNG &&
		   (pdev->device == 0xa821 || pdev->device == 0xa822) &&
		   NVME_CAP_MQES(dev->ctrl.cap) == 0) {
		dev->q_depth = 64;
		dev_err(dev->ctrl.device, "detected PM1725 NVMe controller, "
                        "set queue depth=%u\n", dev->q_depth);
	}

	klpr_nvme_map_cmb(dev);

	pci_enable_pcie_error_reporting(pdev);
	pci_save_state(pdev);
	return 0;

 disable:
	pci_disable_device(pdev);
	return result;
}

static void nvme_dev_unmap(struct nvme_dev *dev)
{
	if (dev->bar)
		iounmap(dev->bar);
	pci_release_mem_regions(to_pci_dev(dev->dev));
}

static void (*klpe_nvme_dev_disable)(struct nvme_dev *dev, bool shutdown);

static int nvme_setup_prp_pools(struct nvme_dev *dev)
{
	dev->prp_page_pool = dma_pool_create("prp list page", dev->dev,
						PAGE_SIZE, PAGE_SIZE, 0);
	if (!dev->prp_page_pool)
		return -ENOMEM;

	/* Optimisation for I/Os between 4k and 128k */
	dev->prp_small_pool = dma_pool_create("prp list 256", dev->dev,
						256, 256, 0);
	if (!dev->prp_small_pool) {
		dma_pool_destroy(dev->prp_page_pool);
		return -ENOMEM;
	}
	return 0;
}

static void nvme_release_prp_pools(struct nvme_dev *dev)
{
	dma_pool_destroy(dev->prp_page_pool);
	dma_pool_destroy(dev->prp_small_pool);
}

static void klpr_nvme_remove_dead_ctrl(struct nvme_dev *dev, int status)
{
	dev_warn(dev->ctrl.device, "Removing after probe failure status: %d\n", status);

	nvme_get_ctrl(&dev->ctrl);
	(*klpe_nvme_dev_disable)(dev, false);
	(*klpe_nvme_kill_queues)(&dev->ctrl);
	if (!queue_work((*klpe_nvme_wq), &dev->remove_work))
		nvme_put_ctrl(&dev->ctrl);
}

static void (*klpe_nvme_reset_work)(struct work_struct *work);

void klpp_nvme_reset_work(struct work_struct *work)
{
	struct nvme_dev *dev =
		container_of(work, struct nvme_dev, ctrl.reset_work);
	bool was_suspend = !!(dev->ctrl.ctrl_config & NVME_CC_SHN_NORMAL);
	int result = -ENODEV;
	enum nvme_ctrl_state new_state = NVME_CTRL_LIVE;

	if (dev->ctrl.state != NVME_CTRL_RESETTING) {
		dev_warn(dev->ctrl.device, "ctrl state %d is not RESETTING\n",
			 dev->ctrl.state);
		goto out;
	}

	/*
	 * If we're called to reset a live controller first shut it down before
	 * moving on.
	 */
	if (dev->ctrl.ctrl_config & NVME_CC_ENABLE)
		(*klpe_nvme_dev_disable)(dev, false);
	(*klpe_nvme_sync_queues)(&dev->ctrl);

	/*
	 * Introduce CONNECTING state from nvme-fc/rdma transports to mark the
	 * initializing procedure here.
	 */
	if (!(*klpe_nvme_change_ctrl_state)(&dev->ctrl, NVME_CTRL_CONNECTING)) {
		dev_warn(dev->ctrl.device,
			"failed to mark controller CONNECTING\n");
		goto out;
	}

	result = klpr_nvme_pci_enable(dev);
	if (result)
		goto out;

	result = klpr_nvme_pci_configure_admin_queue(dev);
	if (result)
		goto out;

	result = klpr_nvme_alloc_admin_tags(dev);
	if (result)
		goto out;

	/*
	 * Limit the max command size to prevent iod->sg allocations going
	 * over a single page.
	 */
	dev->ctrl.max_hw_sectors = NVME_MAX_KB_SZ << 1;
	dev->ctrl.max_segments = NVME_MAX_SEGS;

	result = (*klpe_nvme_init_identify)(&dev->ctrl);
	if (result)
		goto out;

	if (dev->ctrl.oacs & NVME_CTRL_OACS_SEC_SUPP) {
		if (!dev->ctrl.opal_dev)
			dev->ctrl.opal_dev =
				init_opal_dev(&dev->ctrl, &(*klpe_nvme_sec_submit));
		else if (was_suspend)
			opal_unlock_from_suspend(dev->ctrl.opal_dev);
	} else {
		free_opal_dev(dev->ctrl.opal_dev);
		dev->ctrl.opal_dev = NULL;
	}

	if (dev->ctrl.oacs & NVME_CTRL_OACS_DBBUF_SUPP) {
		result = nvme_dbbuf_dma_alloc(dev);
		if (result)
			dev_warn(dev->dev,
				 "unable to allocate dma for dbbuf\n");
	}

	if (dev->ctrl.hmpre) {
		result = klpr_nvme_setup_host_mem(dev);
		if (result < 0)
			goto out;
	}

	result = klpr_nvme_setup_io_queues(dev);
	if (result)
		goto out;

	/*
	 * Keep the controller around but remove all namespaces if we don't have
	 * any working I/O queue.
	 */
	if (dev->online_queues < 2) {
		dev_warn(dev->ctrl.device, "IO queues not created\n");
		(*klpe_nvme_kill_queues)(&dev->ctrl);
		(*klpe_nvme_remove_namespaces)(&dev->ctrl);
		new_state = NVME_CTRL_ADMIN_ONLY;
	} else {
		(*klpe_nvme_start_queues)(&dev->ctrl);
		(*klpe_nvme_wait_freeze)(&dev->ctrl);
		/* hit this only when allocate tagset fails */
		if (klpr_nvme_dev_add(dev))
			new_state = NVME_CTRL_ADMIN_ONLY;
		(*klpe_nvme_unfreeze)(&dev->ctrl);
	}

	/*
	 * If only admin queue live, keep it to do further investigation or
	 * recovery.
	 */
	if (!(*klpe_nvme_change_ctrl_state)(&dev->ctrl, new_state)) {
		dev_warn(dev->ctrl.device,
			"failed to mark controller state %d\n", new_state);
		goto out;
	}

	(*klpe_nvme_start_ctrl)(&dev->ctrl);
	return;

 out:
	klpr_nvme_remove_dead_ctrl(dev, result);
}

static void (*klpe_nvme_remove_dead_ctrl_work)(struct work_struct *work);

static const struct nvme_ctrl_ops (*klpe_nvme_pci_ctrl_ops);

static int klpr_nvme_dev_map(struct nvme_dev *dev)
{
	struct pci_dev *pdev = to_pci_dev(dev->dev);

	if (pci_request_mem_regions(pdev, "nvme"))
		return -ENODEV;

	if ((*klpe_nvme_remap_bar)(dev, NVME_REG_DBS + 4096))
		goto release;

	return 0;
  release:
	pci_release_mem_regions(pdev);
	return -ENODEV;
}

static unsigned long check_vendor_combination_bug(struct pci_dev *pdev)
{
	if (pdev->vendor == 0x144d && pdev->device == 0xa802) {
		/*
		 * Several Samsung devices seem to drop off the PCIe bus
		 * randomly when APST is on and uses the deepest sleep state.
		 * This has been observed on a Samsung "SM951 NVMe SAMSUNG
		 * 256GB", a "PM951 NVMe SAMSUNG 512GB", and a "Samsung SSD
		 * 950 PRO 256GB", but it seems to be restricted to two Dell
		 * laptops.
		 */
		if (dmi_match(DMI_SYS_VENDOR, "Dell Inc.") &&
		    (dmi_match(DMI_PRODUCT_NAME, "XPS 15 9550") ||
		     dmi_match(DMI_PRODUCT_NAME, "Precision 5510")))
			return NVME_QUIRK_NO_DEEPEST_PS;
	} else if (pdev->vendor == 0x144d && pdev->device == 0xa804) {
		/*
		 * Samsung SSD 960 EVO drops off the PCIe bus after system
		 * suspend on a Ryzen board, ASUS PRIME B350M-A, as well as
		 * within few minutes after bootup on a Coffee Lake board -
		 * ASUS PRIME Z370-A
		 */
		if (dmi_match(DMI_BOARD_VENDOR, "ASUSTeK COMPUTER INC.") &&
		    (dmi_match(DMI_BOARD_NAME, "PRIME B350M-A") ||
		     dmi_match(DMI_BOARD_NAME, "PRIME Z370-A")))
			return NVME_QUIRK_NO_APST;
	}

	return 0;
}

static void (*klpe_nvme_async_probe)(void *data, async_cookie_t cookie);

int klpp_nvme_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int node, result = -ENOMEM;
	struct nvme_dev *dev;
	unsigned long quirks = id->driver_data;
	size_t alloc_size;

	node = dev_to_node(&pdev->dev);
	if (node == NUMA_NO_NODE)
		set_dev_node(&pdev->dev, first_memory_node);

	dev = kzalloc_node(sizeof(*dev), GFP_KERNEL, node);
	if (!dev)
		return -ENOMEM;

	dev->queues = kzalloc_node((num_possible_cpus() + 1) *
			sizeof(struct nvme_queue), GFP_KERNEL, node);
	if (!dev->queues)
		goto free;

	dev->dev = get_device(&pdev->dev);
	pci_set_drvdata(pdev, dev);

	result = klpr_nvme_dev_map(dev);
	if (result)
		goto put_pci;

	INIT_WORK(&dev->ctrl.reset_work, (*klpe_nvme_reset_work));
	INIT_WORK(&dev->remove_work, (*klpe_nvme_remove_dead_ctrl_work));
	mutex_init(&dev->shutdown_lock);
	init_completion(&dev->ioq_wait);

	result = nvme_setup_prp_pools(dev);
	if (result)
		goto unmap;

	quirks |= check_vendor_combination_bug(pdev);

	/*
	 * Double check that our mempool alloc size will cover the biggest
	 * command we support.
	 */
	alloc_size = nvme_pci_iod_alloc_size(dev, NVME_MAX_KB_SZ * 1024,
						NVME_MAX_SEGS, true);
	WARN_ON_ONCE(alloc_size > PAGE_SIZE);

	dev->iod_mempool = mempool_create_node(1, mempool_kmalloc,
						mempool_kfree,
						(void *) alloc_size,
						GFP_KERNEL, node);
	if (!dev->iod_mempool) {
		result = -ENOMEM;
		goto release_pools;
	}

	result = (*klpe_nvme_init_ctrl)(&dev->ctrl, &pdev->dev, &(*klpe_nvme_pci_ctrl_ops),
			quirks);
	if (result)
		goto release_mempool;

	dev_info(dev->ctrl.device, "pci function %s\n", dev_name(&pdev->dev));

	async_schedule((*klpe_nvme_async_probe), dev);

	return 0;

 release_mempool:
	mempool_destroy(dev->iod_mempool);
 release_pools:
	nvme_release_prp_pools(dev);
 unmap:
	nvme_dev_unmap(dev);
 put_pci:
	put_device(dev->dev);
 free:
	kfree(dev->queues);
	kfree(dev);
	return result;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nvme"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "admin_timeout", (void *)&klpe_admin_timeout, "nvme_core" },
	{ "nvme_change_ctrl_state", (void *)&klpe_nvme_change_ctrl_state,
	  "nvme_core" },
	{ "nvme_disable_ctrl", (void *)&klpe_nvme_disable_ctrl, "nvme_core" },
	{ "nvme_enable_ctrl", (void *)&klpe_nvme_enable_ctrl, "nvme_core" },
	{ "nvme_init_ctrl", (void *)&klpe_nvme_init_ctrl, "nvme_core" },
	{ "nvme_init_identify", (void *)&klpe_nvme_init_identify,
	  "nvme_core" },
	{ "nvme_io_timeout", (void *)&klpe_nvme_io_timeout, "nvme_core" },
	{ "nvme_kill_queues", (void *)&klpe_nvme_kill_queues, "nvme_core" },
	{ "nvme_remove_namespaces", (void *)&klpe_nvme_remove_namespaces,
	  "nvme_core" },
	{ "nvme_sec_submit", (void *)&klpe_nvme_sec_submit, "nvme_core" },
	{ "nvme_set_queue_count", (void *)&klpe_nvme_set_queue_count,
	  "nvme_core" },
	{ "nvme_start_ctrl", (void *)&klpe_nvme_start_ctrl, "nvme_core" },
	{ "nvme_start_queues", (void *)&klpe_nvme_start_queues, "nvme_core" },
	{ "nvme_submit_sync_cmd", (void *)&klpe_nvme_submit_sync_cmd,
	  "nvme_core" },
	{ "nvme_sync_queues", (void *)&klpe_nvme_sync_queues, "nvme_core" },
	{ "nvme_unfreeze", (void *)&klpe_nvme_unfreeze, "nvme_core" },
	{ "nvme_wait_freeze", (void *)&klpe_nvme_wait_freeze, "nvme_core" },
	{ "nvme_wq", (void *)&klpe_nvme_wq, "nvme_core" },
	{ "dev_attr_cmb", (void *)&klpe_dev_attr_cmb, "nvme" },
	{ "io_queue_depth", (void *)&klpe_io_queue_depth, "nvme" },
	{ "max_host_mem_size_mb", (void *)&klpe_max_host_mem_size_mb, "nvme" },
	{ "nvme_alloc_queue", (void *)&klpe_nvme_alloc_queue, "nvme" },
	{ "nvme_async_probe", (void *)&klpe_nvme_async_probe, "nvme" },
	{ "nvme_dbbuf_dma_free", (void *)&klpe_nvme_dbbuf_dma_free, "nvme" },
	{ "nvme_dev_disable", (void *)&klpe_nvme_dev_disable, "nvme" },
	{ "nvme_dev_remove_admin", (void *)&klpe_nvme_dev_remove_admin,
	  "nvme" },
	{ "nvme_free_host_mem", (void *)&klpe_nvme_free_host_mem, "nvme" },
	{ "nvme_init_queue", (void *)&klpe_nvme_init_queue, "nvme" },
	{ "nvme_mq_admin_ops", (void *)&klpe_nvme_mq_admin_ops, "nvme" },
	{ "nvme_mq_ops", (void *)&klpe_nvme_mq_ops, "nvme" },
	{ "nvme_pci_ctrl_ops", (void *)&klpe_nvme_pci_ctrl_ops, "nvme" },
	{ "nvme_remap_bar", (void *)&klpe_nvme_remap_bar, "nvme" },
	{ "nvme_remove_dead_ctrl_work",
	  (void *)&klpe_nvme_remove_dead_ctrl_work, "nvme" },
	{ "nvme_reset_work", (void *)&klpe_nvme_reset_work, "nvme" },
	{ "queue_request_irq", (void *)&klpe_queue_request_irq, "nvme" },
	{ "sgl_threshold", (void *)&klpe_sgl_threshold, "nvme" },
	{ "use_cmb_sqes", (void *)&klpe_use_cmb_sqes, "nvme" },
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

int livepatch_bsc1256217_init(void)
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

void livepatch_bsc1256217_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
