/*
 * livepatch_bsc1228755
 *
 * Fix for CVE-2024-42159, bsc#1228755
 *
 *  Upstream commit:
 *  3668651def2c ("scsi: mpi3mr: Sanitise num_phys")
 *  9f365cb8bbd0 ("scsi: mpi3mr: Use proper format specifier in mpi3mr_sas_port_add()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  6986cfdb065dd07ecfdf6e7bcf286e887f034fd6
 *  e024eb0f3efe41906c56d2146548c1c1e841441f
 *
 *  SLE MICRO-6-0 commit:
 *  6986cfdb065dd07ecfdf6e7bcf286e887f034fd6
 *  e024eb0f3efe41906c56d2146548c1c1e841441f
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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


/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr.h */
#include <linux/blkdev.h>
#include <linux/blk-mq.h>

/* klp-ccp: from include/linux/dmapool.h */
#define	LINUX_DMAPOOL_H

/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr.h */
#include <linux/errno.h>
#include <linux/init.h>

/* klp-ccp: from include/linux/io.h */
#define _LINUX_IO_H

/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr.h */
#include <linux/interrupt.h>
#include <linux/kernel.h>

#include <linux/module.h>
#include <linux/pci.h>

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include <linux/workqueue.h>

/* klp-ccp: from include/scsi/scsi_device.h */
#define _SCSI_SCSI_DEVICE_H

struct scsi_device;

/* klp-ccp: from include/scsi/scsi_cmnd.h */
struct Scsi_Host;

/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr.h */
#include <scsi/scsi_device.h>

#include <uapi/scsi/scsi_bsg_mpi3mr.h>
#include <scsi/scsi_transport_sas.h>

/* klp-ccp: from drivers/scsi/mpi3mr/mpi/mpi30_transport.h */
struct mpi3_sge_common {
	__le64             address;
	__le32             length;
	u8                 reserved0c[3];
	u8                 flags;
};

#define MPI3_SGE_FLAGS_ELEMENT_TYPE_SIMPLE      (0x00)

#define MPI3_SGE_FLAGS_END_OF_LIST              (0x08)

#define MPI3_SGE_FLAGS_DLAS_SYSTEM              (0x00)

#define MPI3_FUNCTION_SMP_PASSTHROUGH               (0x22)

#define MPI3_IOCSTATUS_STATUS_MASK                  (0x7fff)
#define MPI3_IOCSTATUS_SUCCESS                      (0x0000)

/* klp-ccp: from drivers/scsi/mpi3mr/mpi/mpi30_ioc.h */
#define MPI3_EVENT_NOTIFY_EVENTMASK_WORDS           (4)

/* klp-ccp: from drivers/scsi/mpi3mr/mpi/mpi30_sas.h */
struct mpi3_smp_passthrough_request {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     change_count;
	u8                         reserved0a;
	u8                         io_unit_port;
	__le32                     reserved0c[3];
	__le64                     sas_address;
	struct mpi3_sge_common         request_sge;
	struct mpi3_sge_common         response_sge;
};

struct mpi3_smp_passthrough_reply {
	__le16                     host_tag;
	u8                         ioc_use_only02;
	u8                         function;
	__le16                     ioc_use_only04;
	u8                         ioc_use_only06;
	u8                         msg_flags;
	__le16                     ioc_use_only08;
	__le16                     ioc_status;
	__le32                     ioc_log_info;
	__le16                     response_data_length;
	__le16                     reserved12;
};

/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr_debug.h */
#define MPI3_DEBUG_TRANSPORT_ERROR	0x00000200

#define MPI3_DEBUG_CFG_INFO		0x00040000
#define MPI3_DEBUG_TRANSPORT_INFO	0x00080000

#define ioc_err(ioc, fmt, ...) \
	pr_err("%s: " fmt, (ioc)->name, ##__VA_ARGS__)

#define ioc_warn(ioc, fmt, ...) \
	pr_warn("%s: " fmt, (ioc)->name, ##__VA_ARGS__)
#define ioc_info(ioc, fmt, ...) \
	pr_info("%s: " fmt, (ioc)->name, ##__VA_ARGS__)

#define dprint_cfg_info(ioc, fmt, ...) \
	do { \
		if (ioc->logging_level & MPI3_DEBUG_CFG_INFO) \
			pr_info("%s: " fmt, (ioc)->name, ##__VA_ARGS__); \
	} while (0)

#define dprint_transport_info(ioc, fmt, ...) \
	do { \
		if (ioc->logging_level & MPI3_DEBUG_TRANSPORT_INFO) \
			pr_info("%s: " fmt, (ioc)->name, ##__VA_ARGS__); \
	} while (0)

#define dprint_transport_err(ioc, fmt, ...) \
	do { \
		if (ioc->logging_level & MPI3_DEBUG_TRANSPORT_ERROR) \
			pr_info("%s: " fmt, (ioc)->name, ##__VA_ARGS__); \
	} while (0)

static inline void
dprint_dump(void *req, int sz, const char *name_string)
{
	int i;
	__le32 *mfp = (__le32 *)req;

	sz = sz/4;
	if (name_string)
		pr_info("%s:\n\t", name_string);
	else
		pr_info("request:\n\t");
	for (i = 0; i < sz; i++) {
		if (i && ((i % 8) == 0))
			pr_info("\n\t");
		pr_info("%08x ", le32_to_cpu(mfp[i]));
	}
	pr_info("\n");
}

/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr.h */
#define MPI3MR_NAME_LENGTH	32

#define MPI3MR_HOSTTAG_TRANSPORT_CMDS	7

#define MPI3MR_NUM_DEVRMCMD		16

#define MPI3MR_NUM_EVTACKCMD		4

#define MPI3MR_INTADMCMD_TIMEOUT		60

#define MPI3MR_CMD_NOTUSED	0x8000
#define MPI3MR_CMD_COMPLETE	0x0001
#define MPI3MR_CMD_PENDING	0x0002
#define MPI3MR_CMD_REPLY_VALID	0x0004

#define MPI3MR_SGEFLAGS_SYSTEM_SIMPLE_END_OF_LIST \
	(MPI3_SGE_FLAGS_ELEMENT_TYPE_SIMPLE | MPI3_SGE_FLAGS_DLAS_SYSTEM | \
	MPI3_SGE_FLAGS_END_OF_LIST)

enum mpi3mr_reset_reason {
	MPI3MR_RESET_FROM_BRINGUP = 1,
	MPI3MR_RESET_FROM_FAULT_WATCH = 2,
	MPI3MR_RESET_FROM_APP = 3,
	MPI3MR_RESET_FROM_EH_HOS = 4,
	MPI3MR_RESET_FROM_TM_TIMEOUT = 5,
	MPI3MR_RESET_FROM_APP_TIMEOUT = 6,
	MPI3MR_RESET_FROM_MUR_FAILURE = 7,
	MPI3MR_RESET_FROM_CTLR_CLEANUP = 8,
	MPI3MR_RESET_FROM_CIACTIV_FAULT = 9,
	MPI3MR_RESET_FROM_PE_TIMEOUT = 10,
	MPI3MR_RESET_FROM_TSU_TIMEOUT = 11,
	MPI3MR_RESET_FROM_DELREQQ_TIMEOUT = 12,
	MPI3MR_RESET_FROM_DELREPQ_TIMEOUT = 13,
	MPI3MR_RESET_FROM_CREATEREPQ_TIMEOUT = 14,
	MPI3MR_RESET_FROM_CREATEREQQ_TIMEOUT = 15,
	MPI3MR_RESET_FROM_IOCFACTS_TIMEOUT = 16,
	MPI3MR_RESET_FROM_IOCINIT_TIMEOUT = 17,
	MPI3MR_RESET_FROM_EVTNOTIFY_TIMEOUT = 18,
	MPI3MR_RESET_FROM_EVTACK_TIMEOUT = 19,
	MPI3MR_RESET_FROM_CIACTVRST_TIMER = 20,
	MPI3MR_RESET_FROM_GETPKGVER_TIMEOUT = 21,
	MPI3MR_RESET_FROM_PELABORT_TIMEOUT = 22,
	MPI3MR_RESET_FROM_SYSFS = 23,
	MPI3MR_RESET_FROM_SYSFS_TIMEOUT = 24,
	MPI3MR_RESET_FROM_FIRMWARE = 27,
	MPI3MR_RESET_FROM_CFG_REQ_TIMEOUT = 29,
	MPI3MR_RESET_FROM_SAS_TRANSPORT_TIMEOUT = 30,
};

struct mpi3mr_compimg_ver {
	u16 build_num;
	u16 cust_id;
	u8 ph_minor;
	u8 ph_major;
	u8 gen_minor;
	u8 gen_major;
};

struct mpi3mr_ioc_facts {
	u32 ioc_capabilities;
	struct mpi3mr_compimg_ver fw_ver;
	u32 mpi_version;
	u16 max_reqs;
	u16 product_id;
	u16 op_req_sz;
	u16 reply_sz;
	u16 exceptions;
	u16 max_perids;
	u16 max_pds;
	u16 max_sasexpanders;
	u32 max_data_length;
	u16 max_sasinitiators;
	u16 max_enclosures;
	u16 max_pcie_switches;
	u16 max_nvme;
	u16 max_vds;
	u16 max_hpds;
	u16 max_advhpds;
	u16 max_raid_pds;
	u16 min_devhandle;
	u16 max_devhandle;
	u16 max_op_req_q;
	u16 max_op_reply_q;
	u16 shutdown_timeout;
	u8 ioc_num;
	u8 who_init;
	u16 max_msix_vectors;
	u8 personality;
	u8 dma_mask;
	u8 protocol_flags;
	u8 sge_mod_mask;
	u8 sge_mod_value;
	u8 sge_mod_shift;
	u8 max_dev_per_tg;
	u16 max_io_throttle_group;
	u16 io_throttle_data_length;
	u16 io_throttle_low;
	u16 io_throttle_high;

};

struct mpi3mr_intr_info {
	struct mpi3mr_ioc *mrioc;
	int os_irq;
	u16 msix_index;
	struct op_reply_qinfo *op_reply_q;
	char name[MPI3MR_NAME_LENGTH];
};

#define MPI3MR_NUM_IOCTL_SGE		256

struct mpi3mr_hba_port {
	struct list_head list;
	u8 port_id;
	u8 flags;
};

struct mpi3mr_sas_port {
	struct list_head port_list;
	u8 num_phys;
	u8 marked_responding;
	int lowest_phy;
	u64 phy_mask;
	struct mpi3mr_hba_port *hba_port;
	struct sas_identify remote_identify;
	struct sas_rphy *rphy;
	struct sas_port *port;
	struct list_head phy_list;
};

struct mpi3mr_sas_phy {
	struct list_head port_siblings;
	struct sas_identify identify;
	struct sas_identify remote_identify;
	struct sas_phy *phy;
	u8 phy_id;
	u16 handle;
	u16 attached_handle;
	u8 phy_belongs_to_port;
	struct mpi3mr_hba_port *hba_port;
};

struct mpi3mr_sas_node {
	struct list_head list;
	struct device *parent_dev;
	u8 num_phys;
	u64 sas_address;
	u16 handle;
	u64 sas_address_parent;
	u16 enclosure_handle;
	u64 enclosure_logical_id;
	u8 non_responding;
	u8 host_node;
	struct mpi3mr_hba_port *hba_port;
	struct mpi3mr_sas_phy *phy;
	struct list_head sas_port_list;
	struct sas_rphy *rphy;
};

struct tgt_dev_sas_sata {
	u64 sas_address;
	u64 sas_address_parent;
	u16 dev_info;
	u8 phy_id;
	u8 attached_phy_id;
	u8 sas_transport_attached;
	u8 pend_sas_rphy_add;
	struct mpi3mr_hba_port *hba_port;
	struct sas_rphy *rphy;
};

struct tgt_dev_pcie {
	u32 mdts;
	u16 capb;
	u8 pgsz;
	u8 abort_to;
	u8 reset_to;
	u16 dev_info;
};

struct tgt_dev_vd {
	u8 state;
	u8 tg_qd_reduction;
	u16 tg_id;
	u32 tg_high;
	u32 tg_low;
	struct mpi3mr_throttle_group_info *tg;
};

union _form_spec_inf {
	struct tgt_dev_sas_sata sas_sata_inf;
	struct tgt_dev_pcie pcie_inf;
	struct tgt_dev_vd vd_inf;
};

enum mpi3mr_dev_state {
	MPI3MR_DEV_CREATED = 1,
	MPI3MR_DEV_REMOVE_HS_STARTED = 2,
	MPI3MR_DEV_DELETED = 3,
};

struct mpi3mr_tgt_dev {
	struct list_head list;
	struct scsi_target *starget;
	u16 dev_handle;
	u16 parent_handle;
	u16 slot;
	u16 encl_handle;
	u16 perst_id;
	u16 devpg0_flag;
	u8 dev_type;
	u8 is_hidden;
	u8 host_exposed;
	u8 io_unit_port;
	u8 non_stl;
	u8 io_throttle_enabled;
	u16 wslen;
	u16 q_depth;
	u64 wwid;
	u64 enclosure_logical_id;
	union _form_spec_inf dev_spec;
	struct kref ref_count;
	enum mpi3mr_dev_state state;
};

static inline void mpi3mr_free_tgtdev(struct kref *r)
{
	kfree(container_of(r, struct mpi3mr_tgt_dev, ref_count));
}

static inline void mpi3mr_tgtdev_put(struct mpi3mr_tgt_dev *s)
{
	kref_put(&s->ref_count, mpi3mr_free_tgtdev);
}

struct mpi3mr_drv_cmd {
	struct mutex mutex;
	struct completion done;
	void *reply;
	u8 *sensebuf;
	u8 iou_rc;
	u16 state;
	u16 dev_handle;
	u16 ioc_status;
	u32 ioc_loginfo;
	u8 is_waiting;
	u8 is_sense;
	u8 retry_count;
	u16 host_tag;

	void (*callback)(struct mpi3mr_ioc *mrioc,
	    struct mpi3mr_drv_cmd *drv_cmd);
};

struct dma_memory_desc {
	u32 size;
	void *addr;
	dma_addr_t dma_addr;
};

struct mpi3mr_ioc {
	struct list_head list;
	struct pci_dev *pdev;
	struct Scsi_Host *shost;
	u8 id;
	int cpu_count;
	bool enable_segqueue;
	u32 irqpoll_sleep;

	char name[MPI3MR_NAME_LENGTH];
	char driver_name[MPI3MR_NAME_LENGTH];

	volatile struct mpi3_sysif_registers __iomem *sysif_regs;
	resource_size_t sysif_regs_phys;
	int bars;
	u64 dma_mask;

	u16 msix_count;
	u8 intr_enabled;

	u16 num_admin_req;
	u32 admin_req_q_sz;
	u16 admin_req_pi;
	u16 admin_req_ci;
	void *admin_req_base;
	dma_addr_t admin_req_dma;
	spinlock_t admin_req_lock;

	u16 num_admin_replies;
	u32 admin_reply_q_sz;
	u16 admin_reply_ci;
	u8 admin_reply_ephase;
	void *admin_reply_base;
	dma_addr_t admin_reply_dma;
	atomic_t admin_reply_q_in_use;

	u32 ready_timeout;

	struct mpi3mr_intr_info *intr_info;
	u16 intr_info_count;
	bool is_intr_info_set;

	u16 num_queues;
	u16 num_op_req_q;
	struct op_req_qinfo *req_qinfo;

	u16 num_op_reply_q;
	struct op_reply_qinfo *op_reply_qinfo;

	struct mpi3mr_drv_cmd init_cmds;
	struct mpi3mr_drv_cmd cfg_cmds;
	struct mpi3mr_ioc_facts facts;
	u16 op_reply_desc_sz;

	u32 num_reply_bufs;
	struct dma_pool *reply_buf_pool;
	u8 *reply_buf;
	dma_addr_t reply_buf_dma;
	dma_addr_t reply_buf_dma_max_address;

	u16 reply_free_qsz;
	u16 reply_sz;
	struct dma_pool *reply_free_q_pool;
	__le64 *reply_free_q;
	dma_addr_t reply_free_q_dma;
	spinlock_t reply_free_queue_lock;
	u32 reply_free_queue_host_index;

	u32 num_sense_bufs;
	struct dma_pool *sense_buf_pool;
	u8 *sense_buf;
	dma_addr_t sense_buf_dma;

	u16 sense_buf_q_sz;
	struct dma_pool *sense_buf_q_pool;
	__le64 *sense_buf_q;
	dma_addr_t sense_buf_q_dma;
	spinlock_t sbq_lock;
	u32 sbq_host_index;
	u32 event_masks[MPI3_EVENT_NOTIFY_EVENTMASK_WORDS];

	char fwevt_worker_name[MPI3MR_NAME_LENGTH];
	struct workqueue_struct	*fwevt_worker_thread;
	spinlock_t fwevt_lock;
	struct list_head fwevt_list;

	char watchdog_work_q_name[20];
	struct workqueue_struct *watchdog_work_q;
	struct delayed_work watchdog_work;
	spinlock_t watchdog_lock;

	u8 is_driver_loading;
	u8 scan_started;
	u16 scan_failed;
	u8 stop_drv_processing;
	u8 device_refresh_on;

	u16 max_host_ios;
	spinlock_t tgtdev_lock;
	struct list_head tgtdev_list;
	u16 max_sgl_entries;

	u32 chain_buf_count;
	struct dma_pool *chain_buf_pool;
	struct chain_element *chain_sgl_list;
	unsigned long *chain_bitmap;
	spinlock_t chain_buf_lock;

	struct mpi3mr_drv_cmd bsg_cmds;
	struct mpi3mr_drv_cmd host_tm_cmds;
	struct mpi3mr_drv_cmd dev_rmhs_cmds[MPI3MR_NUM_DEVRMCMD];
	struct mpi3mr_drv_cmd evtack_cmds[MPI3MR_NUM_EVTACKCMD];
	unsigned long *devrem_bitmap;
	u16 dev_handle_bitmap_bits;
	unsigned long *removepend_bitmap;
	struct list_head delayed_rmhs_list;
	unsigned long *evtack_cmds_bitmap;
	struct list_head delayed_evtack_cmds_list;

	u32 ts_update_counter;
	u8 reset_in_progress;
	u8 unrecoverable;
	int prev_reset_result;
	struct mutex reset_mutex;
	wait_queue_head_t reset_waitq;

	u8 prepare_for_reset;
	u16 prepare_for_reset_timeout_counter;

	void *prp_list_virt;
	dma_addr_t prp_list_dma;
	u32 prp_sz;

	u16 diagsave_timeout;
	int logging_level;
	u16 flush_io_count;

	struct mpi3mr_fwevt *current_event;
	struct mpi3_driver_info_layout driver_info;
	u16 change_count;

	u8 pel_enabled;
	u8 pel_abort_requested;
	u8 pel_class;
	u16 pel_locale;
	struct mpi3mr_drv_cmd pel_cmds;
	struct mpi3mr_drv_cmd pel_abort_cmd;

	u32 pel_newest_seqnum;
	void *pel_seqnum_virt;
	dma_addr_t pel_seqnum_dma;
	u32 pel_seqnum_sz;

	u16 op_reply_q_offset;
	u16 default_qcount;
	u16 active_poll_qcount;
	u16 requested_poll_qcount;

	struct device bsg_dev;
	struct request_queue *bsg_queue;
	u8 stop_bsgs;
	u8 *logdata_buf;
	u16 logdata_buf_idx;
	u16 logdata_entry_sz;

	atomic_t pend_large_data_sz;
	u32 io_throttle_data_length;
	u32 io_throttle_high;
	u32 io_throttle_low;
	u16 num_io_throttle_group;
	struct mpi3mr_throttle_group_info *throttle_groups;

	void *cfg_page;
	dma_addr_t cfg_page_dma;
	u16 cfg_page_sz;

	u8 sas_transport_enabled;
	u8 scsi_device_channel;
	struct mpi3mr_drv_cmd transport_cmds;
	struct mpi3mr_sas_node sas_hba;
	struct list_head sas_expander_list;
	spinlock_t sas_node_lock;
	struct list_head hba_port_table_list;
	struct list_head enclosure_list;

	struct dma_pool *ioctl_dma_pool;
	struct dma_memory_desc ioctl_sge[MPI3MR_NUM_IOCTL_SGE];
	struct dma_memory_desc ioctl_chain_sge;
	struct dma_memory_desc ioctl_resp_sge;
	bool ioctl_sges_allocated;
};

struct mpi3mr_fwevt {
	struct list_head list;
	struct work_struct work;
	struct mpi3mr_ioc *mrioc;
	u16 event_id;
	bool send_ack;
	bool process_evt;
	u32 evt_ctx;
	u16 event_data_size;
	bool pending_at_sml;
	bool discard;
	struct kref ref_count;
	char event_data[] __aligned(4);
};

int mpi3mr_admin_request_post(struct mpi3mr_ioc *mrioc, void *admin_req,
u16 admin_req_sz, u8 ignore_reset);

void mpi3mr_add_sg_single(void *paddr, u8 flags, u32 length,
			  dma_addr_t dma_addr);

void mpi3mr_check_rh_fault_ioc(struct mpi3mr_ioc *mrioc, u32 reason_code);

void mpi3mr_check_rh_fault_ioc(struct mpi3mr_ioc *mrioc, u32 reason_code);

void mpi3mr_expander_remove(struct mpi3mr_ioc *mrioc, u64 sas_address,
	struct mpi3mr_hba_port *hba_port);

void mpi3mr_remove_tgtdev_from_host(struct mpi3mr_ioc *mrioc,
	struct mpi3mr_tgt_dev *tgtdev);

void mpi3mr_print_device_event_notice(struct mpi3mr_ioc *mrioc,
	bool device_add);

/* klp-ccp: from drivers/scsi/mpi3mr/mpi3mr_transport.c */
static int mpi3mr_post_transport_req(struct mpi3mr_ioc *mrioc, void *request,
	u16 request_sz, void *reply, u16 reply_sz, int timeout,
	u16 *ioc_status)
{
	int retval = 0;

	mutex_lock(&mrioc->transport_cmds.mutex);
	if (mrioc->transport_cmds.state & MPI3MR_CMD_PENDING) {
		retval = -1;
		ioc_err(mrioc, "sending transport request failed due to command in use\n");
		mutex_unlock(&mrioc->transport_cmds.mutex);
		goto out;
	}
	mrioc->transport_cmds.state = MPI3MR_CMD_PENDING;
	mrioc->transport_cmds.is_waiting = 1;
	mrioc->transport_cmds.callback = NULL;
	mrioc->transport_cmds.ioc_status = 0;
	mrioc->transport_cmds.ioc_loginfo = 0;

	init_completion(&mrioc->transport_cmds.done);
	dprint_cfg_info(mrioc, "posting transport request\n");
	if (mrioc->logging_level & MPI3_DEBUG_TRANSPORT_INFO)
		dprint_dump(request, request_sz, "transport_req");
	retval = mpi3mr_admin_request_post(mrioc, request, request_sz, 1);
	if (retval) {
		ioc_err(mrioc, "posting transport request failed\n");
		goto out_unlock;
	}
	wait_for_completion_timeout(&mrioc->transport_cmds.done,
	    (timeout * HZ));
	if (!(mrioc->transport_cmds.state & MPI3MR_CMD_COMPLETE)) {
		mpi3mr_check_rh_fault_ioc(mrioc,
		    MPI3MR_RESET_FROM_SAS_TRANSPORT_TIMEOUT);
		ioc_err(mrioc, "transport request timed out\n");
		retval = -1;
		goto out_unlock;
	}
	*ioc_status = mrioc->transport_cmds.ioc_status &
		MPI3_IOCSTATUS_STATUS_MASK;
	if ((*ioc_status) != MPI3_IOCSTATUS_SUCCESS)
		dprint_transport_err(mrioc,
		    "transport request returned with ioc_status(0x%04x), log_info(0x%08x)\n",
		    *ioc_status, mrioc->transport_cmds.ioc_loginfo);

	if ((reply) && (mrioc->transport_cmds.state & MPI3MR_CMD_REPLY_VALID))
		memcpy((u8 *)reply, mrioc->transport_cmds.reply, reply_sz);

out_unlock:
	mrioc->transport_cmds.state = MPI3MR_CMD_NOTUSED;
	mutex_unlock(&mrioc->transport_cmds.mutex);

out:
	return retval;
}

struct rep_manu_request {
	u8 smp_frame_type;
	u8 function;
	u8 reserved;
	u8 request_length;
};

struct rep_manu_reply {
	u8 smp_frame_type; /* 0x41 */
	u8 function; /* 0x01 */
	u8 function_result;
	u8 response_length;
	u16 expander_change_count;
	u8 reserved0[2];
	u8 sas_format;
	u8 reserved2[3];
	u8 vendor_id[SAS_EXPANDER_VENDOR_ID_LEN];
	u8 product_id[SAS_EXPANDER_PRODUCT_ID_LEN];
	u8 product_rev[SAS_EXPANDER_PRODUCT_REV_LEN];
	u8 component_vendor_id[SAS_EXPANDER_COMPONENT_VENDOR_ID_LEN];
	u16 component_id;
	u8 component_revision_id;
	u8 reserved3;
	u8 vendor_specific[8];
};

static int mpi3mr_report_manufacture(struct mpi3mr_ioc *mrioc,
	u64 sas_address, struct sas_expander_device *edev, u8 port_id)
{
	struct mpi3_smp_passthrough_request mpi_request;
	struct mpi3_smp_passthrough_reply mpi_reply;
	struct rep_manu_reply *manufacture_reply;
	struct rep_manu_request *manufacture_request;
	int rc = 0;
	void *psge;
	void *data_out = NULL;
	dma_addr_t data_out_dma;
	dma_addr_t data_in_dma;
	size_t data_in_sz;
	size_t data_out_sz;
	u8 sgl_flags = MPI3MR_SGEFLAGS_SYSTEM_SIMPLE_END_OF_LIST;
	u16 request_sz = sizeof(struct mpi3_smp_passthrough_request);
	u16 reply_sz = sizeof(struct mpi3_smp_passthrough_reply);
	u16 ioc_status;
	u8 *tmp;

	if (mrioc->reset_in_progress) {
		ioc_err(mrioc, "%s: host reset in progress!\n", __func__);
		return -EFAULT;
	}

	data_out_sz = sizeof(struct rep_manu_request);
	data_in_sz = sizeof(struct rep_manu_reply);
	data_out = dma_alloc_coherent(&mrioc->pdev->dev,
	    data_out_sz + data_in_sz, &data_out_dma, GFP_KERNEL);
	if (!data_out) {
		rc = -ENOMEM;
		goto out;
	}

	data_in_dma = data_out_dma + data_out_sz;
	manufacture_reply = data_out + data_out_sz;

	manufacture_request = data_out;
	manufacture_request->smp_frame_type = 0x40;
	manufacture_request->function = 1;
	manufacture_request->reserved = 0;
	manufacture_request->request_length = 0;

	memset(&mpi_request, 0, request_sz);
	memset(&mpi_reply, 0, reply_sz);
	mpi_request.host_tag = cpu_to_le16(MPI3MR_HOSTTAG_TRANSPORT_CMDS);
	mpi_request.function = MPI3_FUNCTION_SMP_PASSTHROUGH;
	mpi_request.io_unit_port = (u8) port_id;
	mpi_request.sas_address = cpu_to_le64(sas_address);

	psge = &mpi_request.request_sge;
	mpi3mr_add_sg_single(psge, sgl_flags, data_out_sz, data_out_dma);

	psge = &mpi_request.response_sge;
	mpi3mr_add_sg_single(psge, sgl_flags, data_in_sz, data_in_dma);

	dprint_transport_info(mrioc,
	    "sending report manufacturer SMP request to sas_address(0x%016llx), port(%d)\n",
	    (unsigned long long)sas_address, port_id);

	rc = mpi3mr_post_transport_req(mrioc, &mpi_request, request_sz,
				       &mpi_reply, reply_sz,
				       MPI3MR_INTADMCMD_TIMEOUT, &ioc_status);
	if (rc)
		goto out;

	dprint_transport_info(mrioc,
	    "report manufacturer SMP request completed with ioc_status(0x%04x)\n",
	    ioc_status);

	if (ioc_status != MPI3_IOCSTATUS_SUCCESS) {
		rc = -EINVAL;
		goto out;
	}

	dprint_transport_info(mrioc,
	    "report manufacturer - reply data transfer size(%d)\n",
	    le16_to_cpu(mpi_reply.response_data_length));

	if (le16_to_cpu(mpi_reply.response_data_length) !=
	    sizeof(struct rep_manu_reply)) {
		rc = -EINVAL;
		goto out;
	}

	strscpy(edev->vendor_id, manufacture_reply->vendor_id,
	     SAS_EXPANDER_VENDOR_ID_LEN);
	strscpy(edev->product_id, manufacture_reply->product_id,
	     SAS_EXPANDER_PRODUCT_ID_LEN);
	strscpy(edev->product_rev, manufacture_reply->product_rev,
	     SAS_EXPANDER_PRODUCT_REV_LEN);
	edev->level = manufacture_reply->sas_format & 1;
	if (edev->level) {
		strscpy(edev->component_vendor_id,
		    manufacture_reply->component_vendor_id,
		     SAS_EXPANDER_COMPONENT_VENDOR_ID_LEN);
		tmp = (u8 *)&manufacture_reply->component_id;
		edev->component_id = tmp[0] << 8 | tmp[1];
		edev->component_revision_id =
		    manufacture_reply->component_revision_id;
	}

out:
	if (data_out)
		dma_free_coherent(&mrioc->pdev->dev, data_out_sz + data_in_sz,
		    data_out, data_out_dma);

	return rc;
}

extern struct mpi3mr_tgt_dev *__mpi3mr_get_tgtdev_by_addr(struct mpi3mr_ioc *mrioc,
	u64 sas_address, struct mpi3mr_hba_port *hba_port);

static struct mpi3mr_tgt_dev *mpi3mr_get_tgtdev_by_addr(struct mpi3mr_ioc *mrioc,
	u64 sas_address, struct mpi3mr_hba_port *hba_port)
{
	struct mpi3mr_tgt_dev *tgtdev = NULL;
	unsigned long flags;

	if (!hba_port)
		goto out;

	spin_lock_irqsave(&mrioc->tgtdev_lock, flags);
	tgtdev = __mpi3mr_get_tgtdev_by_addr(mrioc, sas_address, hba_port);
	spin_unlock_irqrestore(&mrioc->tgtdev_lock, flags);

out:
	return tgtdev;
}

static void mpi3mr_remove_device_by_sas_address(struct mpi3mr_ioc *mrioc,
	u64 sas_address, struct mpi3mr_hba_port *hba_port)
{
	struct mpi3mr_tgt_dev *tgtdev = NULL;
	unsigned long flags;
	u8 was_on_tgtdev_list = 0;

	if (!hba_port)
		return;

	spin_lock_irqsave(&mrioc->tgtdev_lock, flags);
	tgtdev = __mpi3mr_get_tgtdev_by_addr(mrioc,
			 sas_address, hba_port);
	if (tgtdev) {
		if (!list_empty(&tgtdev->list)) {
			list_del_init(&tgtdev->list);
			was_on_tgtdev_list = 1;
			mpi3mr_tgtdev_put(tgtdev);
		}
	}
	spin_unlock_irqrestore(&mrioc->tgtdev_lock, flags);
	if (was_on_tgtdev_list) {
		if (tgtdev->host_exposed)
			mpi3mr_remove_tgtdev_from_host(mrioc, tgtdev);
		mpi3mr_tgtdev_put(tgtdev);
	}
}

static struct mpi3mr_sas_node *mpi3mr_expander_find_by_sas_address(
	struct mpi3mr_ioc *mrioc, u64 sas_address,
	struct mpi3mr_hba_port *hba_port)
{
	struct mpi3mr_sas_node *sas_expander, *r = NULL;

	if (!hba_port)
		goto out;

	list_for_each_entry(sas_expander, &mrioc->sas_expander_list, list) {
		if ((sas_expander->sas_address != sas_address) ||
					 (sas_expander->hba_port != hba_port))
			continue;
		r = sas_expander;
		goto out;
	}
out:
	return r;
}

static struct mpi3mr_sas_node *__mpi3mr_sas_node_find_by_sas_address(
	struct mpi3mr_ioc *mrioc, u64 sas_address,
	struct mpi3mr_hba_port *hba_port)
{

	if (mrioc->sas_hba.sas_address == sas_address)
		return &mrioc->sas_hba;
	return mpi3mr_expander_find_by_sas_address(mrioc, sas_address,
	    hba_port);
}

static void mpi3mr_delete_sas_phy(struct mpi3mr_ioc *mrioc,
	struct mpi3mr_sas_port *mr_sas_port,
	struct mpi3mr_sas_phy *mr_sas_phy)
{
	u64 sas_address = mr_sas_port->remote_identify.sas_address;

	dev_info(&mr_sas_phy->phy->dev,
	    "remove: sas_address(0x%016llx), phy(%d)\n",
	    (unsigned long long) sas_address, mr_sas_phy->phy_id);

	list_del(&mr_sas_phy->port_siblings);
	mr_sas_port->num_phys--;
	mr_sas_port->phy_mask &= ~(1 << mr_sas_phy->phy_id);
	if (mr_sas_port->lowest_phy == mr_sas_phy->phy_id)
		mr_sas_port->lowest_phy = ffs(mr_sas_port->phy_mask) - 1;
	sas_port_delete_phy(mr_sas_port->port, mr_sas_phy->phy);
	mr_sas_phy->phy_belongs_to_port = 0;
}

static void  mpi3mr_delete_sas_port(struct mpi3mr_ioc *mrioc,
	struct mpi3mr_sas_port *mr_sas_port)
{
	u64 sas_address = mr_sas_port->remote_identify.sas_address;
	struct mpi3mr_hba_port *hba_port = mr_sas_port->hba_port;
	enum sas_device_type device_type =
	    mr_sas_port->remote_identify.device_type;

	dev_info(&mr_sas_port->port->dev,
	    "remove: sas_address(0x%016llx)\n",
	    (unsigned long long) sas_address);

	if (device_type == SAS_END_DEVICE)
		mpi3mr_remove_device_by_sas_address(mrioc, sas_address,
		    hba_port);

	else if (device_type == SAS_EDGE_EXPANDER_DEVICE ||
	    device_type == SAS_FANOUT_EXPANDER_DEVICE)
		mpi3mr_expander_remove(mrioc, sas_address, hba_port);
}

static void mpi3mr_del_phy_from_an_existing_port(struct mpi3mr_ioc *mrioc,
	struct mpi3mr_sas_node *mr_sas_node, struct mpi3mr_sas_phy *mr_sas_phy)
{
	struct mpi3mr_sas_port *mr_sas_port, *next;
	struct mpi3mr_sas_phy *srch_phy;

	if (mr_sas_phy->phy_belongs_to_port == 0)
		return;

	list_for_each_entry_safe(mr_sas_port, next, &mr_sas_node->sas_port_list,
	    port_list) {
		list_for_each_entry(srch_phy, &mr_sas_port->phy_list,
		    port_siblings) {
			if (srch_phy != mr_sas_phy)
				continue;
			if ((mr_sas_port->num_phys == 1) &&
			    !mrioc->reset_in_progress)
				mpi3mr_delete_sas_port(mrioc, mr_sas_port);
			else
				mpi3mr_delete_sas_phy(mrioc, mr_sas_port,
				    mr_sas_phy);
			return;
		}
	}
}

static void mpi3mr_sas_port_sanity_check(struct mpi3mr_ioc *mrioc,
	struct mpi3mr_sas_node *mr_sas_node, u64 sas_address,
	struct mpi3mr_hba_port *hba_port)
{
	int i;

	for (i = 0; i < mr_sas_node->num_phys; i++) {
		if ((mr_sas_node->phy[i].remote_identify.sas_address !=
		    sas_address) || (mr_sas_node->phy[i].hba_port != hba_port))
			continue;
		if (mr_sas_node->phy[i].phy_belongs_to_port == 1)
			mpi3mr_del_phy_from_an_existing_port(mrioc,
			    mr_sas_node, &mr_sas_node->phy[i]);
	}
}

extern int mpi3mr_set_identify(struct mpi3mr_ioc *mrioc, u16 handle,
	struct sas_identify *identify);

struct mpi3mr_sas_port *klpp_mpi3mr_sas_port_add(struct mpi3mr_ioc *mrioc,
	u16 handle, u64 sas_address_parent, struct mpi3mr_hba_port *hba_port)
{
	struct mpi3mr_sas_phy *mr_sas_phy, *next;
	struct mpi3mr_sas_port *mr_sas_port;
	unsigned long flags;
	struct mpi3mr_sas_node *mr_sas_node;
	struct sas_rphy *rphy;
	struct mpi3mr_tgt_dev *tgtdev = NULL;
	int i;
	struct sas_port *port;

	if (!hba_port) {
		ioc_err(mrioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		return NULL;
	}

	mr_sas_port = kzalloc(sizeof(struct mpi3mr_sas_port), GFP_KERNEL);
	if (!mr_sas_port)
		return NULL;

	INIT_LIST_HEAD(&mr_sas_port->port_list);
	INIT_LIST_HEAD(&mr_sas_port->phy_list);
	spin_lock_irqsave(&mrioc->sas_node_lock, flags);
	mr_sas_node = __mpi3mr_sas_node_find_by_sas_address(mrioc,
	    sas_address_parent, hba_port);
	spin_unlock_irqrestore(&mrioc->sas_node_lock, flags);

	if (!mr_sas_node) {
		ioc_err(mrioc, "%s:could not find parent sas_address(0x%016llx)!\n",
		    __func__, (unsigned long long)sas_address_parent);
		goto out_fail;
	}

	if ((mpi3mr_set_identify(mrioc, handle,
	    &mr_sas_port->remote_identify))) {
		ioc_err(mrioc,  "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		goto out_fail;
	}

	if (mr_sas_port->remote_identify.device_type == SAS_PHY_UNUSED) {
		ioc_err(mrioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		goto out_fail;
	}

	mr_sas_port->hba_port = hba_port;
	mpi3mr_sas_port_sanity_check(mrioc, mr_sas_node,
	    mr_sas_port->remote_identify.sas_address, hba_port);

	if (mr_sas_node->num_phys >= sizeof(mr_sas_port->phy_mask) * 8)
		ioc_info(mrioc, "max port count %u could be too high\n",
		    mr_sas_node->num_phys);

	for (i = 0; i < mr_sas_node->num_phys; i++) {
		if ((mr_sas_node->phy[i].remote_identify.sas_address !=
		    mr_sas_port->remote_identify.sas_address) ||
		    (mr_sas_node->phy[i].hba_port != hba_port))
			continue;

		if (i >= sizeof(mr_sas_port->phy_mask) * 8) {
			ioc_warn(mrioc, "skipping port %u, max allowed value is %zu\n",
			    i, sizeof(mr_sas_port->phy_mask) * 8);
			goto out_fail;
		}
		list_add_tail(&mr_sas_node->phy[i].port_siblings,
		    &mr_sas_port->phy_list);
		mr_sas_port->num_phys++;
		mr_sas_port->phy_mask |= (1 << i);
	}

	if (!mr_sas_port->num_phys) {
		ioc_err(mrioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		goto out_fail;
	}

	mr_sas_port->lowest_phy = ffs(mr_sas_port->phy_mask) - 1;

	if (mr_sas_port->remote_identify.device_type == SAS_END_DEVICE) {
		tgtdev = mpi3mr_get_tgtdev_by_addr(mrioc,
		    mr_sas_port->remote_identify.sas_address,
		    mr_sas_port->hba_port);

		if (!tgtdev) {
			ioc_err(mrioc, "failure at %s:%d/%s()!\n",
			    __FILE__, __LINE__, __func__);
			goto out_fail;
		}
		tgtdev->dev_spec.sas_sata_inf.pend_sas_rphy_add = 1;
	}

	if (!mr_sas_node->parent_dev) {
		ioc_err(mrioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		goto out_fail;
	}

	port = sas_port_alloc_num(mr_sas_node->parent_dev);
	if ((sas_port_add(port))) {
		ioc_err(mrioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
		goto out_fail;
	}

	list_for_each_entry(mr_sas_phy, &mr_sas_port->phy_list,
	    port_siblings) {
		if ((mrioc->logging_level & MPI3_DEBUG_TRANSPORT_INFO))
			dev_info(&port->dev,
			    "add: handle(0x%04x), sas_address(0x%016llx), phy(%d)\n",
			    handle, (unsigned long long)
			    mr_sas_port->remote_identify.sas_address,
			    mr_sas_phy->phy_id);
		sas_port_add_phy(port, mr_sas_phy->phy);
		mr_sas_phy->phy_belongs_to_port = 1;
		mr_sas_phy->hba_port = hba_port;
	}

	mr_sas_port->port = port;
	if (mr_sas_port->remote_identify.device_type == SAS_END_DEVICE) {
		rphy = sas_end_device_alloc(port);
		tgtdev->dev_spec.sas_sata_inf.rphy = rphy;
	} else {
		rphy = sas_expander_alloc(port,
		    mr_sas_port->remote_identify.device_type);
	}
	rphy->identify = mr_sas_port->remote_identify;

	if (mrioc->current_event)
		mrioc->current_event->pending_at_sml = 1;

	if ((sas_rphy_add(rphy))) {
		ioc_err(mrioc, "failure at %s:%d/%s()!\n",
		    __FILE__, __LINE__, __func__);
	}
	if (mr_sas_port->remote_identify.device_type == SAS_END_DEVICE) {
		tgtdev->dev_spec.sas_sata_inf.pend_sas_rphy_add = 0;
		tgtdev->dev_spec.sas_sata_inf.sas_transport_attached = 1;
		mpi3mr_tgtdev_put(tgtdev);
	}

	dev_info(&rphy->dev,
	    "%s: added: handle(0x%04x), sas_address(0x%016llx)\n",
	    __func__, handle, (unsigned long long)
	    mr_sas_port->remote_identify.sas_address);

	mr_sas_port->rphy = rphy;
	spin_lock_irqsave(&mrioc->sas_node_lock, flags);
	list_add_tail(&mr_sas_port->port_list, &mr_sas_node->sas_port_list);
	spin_unlock_irqrestore(&mrioc->sas_node_lock, flags);

	if (mrioc->current_event) {
		mrioc->current_event->pending_at_sml = 0;
		if (mrioc->current_event->discard)
			mpi3mr_print_device_event_notice(mrioc, true);
	}

	/* fill in report manufacture */
	if (mr_sas_port->remote_identify.device_type ==
	    SAS_EDGE_EXPANDER_DEVICE ||
	    mr_sas_port->remote_identify.device_type ==
	    SAS_FANOUT_EXPANDER_DEVICE)
		mpi3mr_report_manufacture(mrioc,
		    mr_sas_port->remote_identify.sas_address,
		    rphy_to_expander_device(rphy), hba_port->port_id);

	return mr_sas_port;

 out_fail:
	list_for_each_entry_safe(mr_sas_phy, next, &mr_sas_port->phy_list,
	    port_siblings)
		list_del(&mr_sas_phy->port_siblings);
	kfree(mr_sas_port);
	return NULL;
}

void mpi3mr_expander_remove(struct mpi3mr_ioc *mrioc, u64 sas_address,
	struct mpi3mr_hba_port *hba_port);


#include "livepatch_bsc1228755.h"

#include <linux/livepatch.h>

extern typeof(__mpi3mr_get_tgtdev_by_addr) __mpi3mr_get_tgtdev_by_addr
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, __mpi3mr_get_tgtdev_by_addr);
extern typeof(mpi3mr_add_sg_single) mpi3mr_add_sg_single
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_add_sg_single);
extern typeof(mpi3mr_admin_request_post) mpi3mr_admin_request_post
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_admin_request_post);
extern typeof(mpi3mr_check_rh_fault_ioc) mpi3mr_check_rh_fault_ioc
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_check_rh_fault_ioc);
extern typeof(mpi3mr_expander_remove) mpi3mr_expander_remove
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_expander_remove);
extern typeof(mpi3mr_print_device_event_notice) mpi3mr_print_device_event_notice
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_print_device_event_notice);
extern typeof(mpi3mr_remove_tgtdev_from_host) mpi3mr_remove_tgtdev_from_host
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_remove_tgtdev_from_host);
extern typeof(mpi3mr_set_identify) mpi3mr_set_identify
	 KLP_RELOC_SYMBOL(mpi3mr, mpi3mr, mpi3mr_set_identify);
extern typeof(sas_end_device_alloc) sas_end_device_alloc
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_end_device_alloc);
extern typeof(sas_expander_alloc) sas_expander_alloc
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_expander_alloc);
extern typeof(sas_port_add) sas_port_add
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_port_add);
extern typeof(sas_port_add_phy) sas_port_add_phy
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_port_add_phy);
extern typeof(sas_port_alloc_num) sas_port_alloc_num
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_port_alloc_num);
extern typeof(sas_port_delete_phy) sas_port_delete_phy
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_port_delete_phy);
extern typeof(sas_rphy_add) sas_rphy_add
	 KLP_RELOC_SYMBOL(mpi3mr, scsi_transport_sas, sas_rphy_add);
