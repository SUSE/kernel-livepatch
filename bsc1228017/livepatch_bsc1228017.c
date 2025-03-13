/*
 * livepatch_bsc1228017
 *
 * Fix for CVE-2022-48792, bsc#1228017
 *
 *  Upstream commit:
 *  df7abcaa1246 ("scsi: pm8001: Fix use-after-free for aborted SSP/STP sas_task")
 *
 *  SLE12-SP5 commit:
 *  fba83b8990c4bf9c71a78bf61caca2eaca45811a
 *
 *  SLE15-SP3 commit:
 *  e1a6b294b4bf9511f314fb1ccb7a3cb895e57872
 *
 *  SLE15-SP4 and -SP5 commit:
 *  3239ab52ee70f66c53aa3e950507ef5d70c7ef23
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
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

#if IS_ENABLED(CONFIG_SCSI_PM8001)

#if !IS_MODULE(CONFIG_SCSI_PM8001)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/scsi/pm8001/pm80xx_hwi.c */
#include <linux/slab.h>

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.h */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/types.h>

/* klp-ccp: from include/linux/ctype.h */
#define _LINUX_CTYPE_H

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.h */
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <scsi/libsas.h>

/* klp-ccp: from include/scsi/libsas.h */
static void (*klpe_sas_free_task)(struct sas_task *task);

static void (*klpe_sas_ssp_task_response)(struct device *dev, struct sas_task *task,
				  struct ssp_response_iu *iu);

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.h */
#include <linux/atomic.h>

/* klp-ccp: from drivers/scsi/pm8001/pm8001_defs.h */
#define	PM8001_MAX_SPCV_INB_NUM		1
#define	PM8001_MAX_SPCV_OUTB_NUM	4

#define	PM8001_MAX_PHYS		 16	/* max. possible phys */

#define	PM8001_MAX_MSIX_VEC	 64	/* max msi-x int for spcv/ve */

#define USI_MAX_MEMCNT_BASE	5
#define IB			(USI_MAX_MEMCNT_BASE + 1)
#define CI			(IB + PM8001_MAX_SPCV_INB_NUM)
#define OB			(CI + PM8001_MAX_SPCV_INB_NUM)
#define PI			(OB + PM8001_MAX_SPCV_OUTB_NUM)
#define USI_MAX_MEMCNT		(PI + PM8001_MAX_SPCV_OUTB_NUM)
#define PM8001_MAX_DMA_SG	SG_ALL

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.h */
#define PM8001_FAIL_LOGGING	0x01 /* Error message logging */

#define PM8001_IO_LOGGING	0x08 /* I/O path logging */

#define pm8001_printk(format, arg...)	printk(KERN_INFO "pm80xx %s %d:" \
			format, __func__, __LINE__, ## arg)
#define PM8001_CHECK_LOGGING(HBA, LEVEL, CMD)	\
do {						\
	if (unlikely(HBA->logging_level & LEVEL))	\
		do {					\
			CMD;				\
		} while (0);				\
} while (0);

#define PM8001_IO_DBG(HBA, CMD)		\
	PM8001_CHECK_LOGGING(HBA, PM8001_IO_LOGGING, CMD)

#define PM8001_FAIL_DBG(HBA, CMD)		\
	PM8001_CHECK_LOGGING(HBA, PM8001_FAIL_LOGGING, CMD)

#define PM8001_USE_TASKLET
#define PM8001_USE_MSIX

#define DEV_IS_EXPANDER(type)	((type == SAS_EDGE_EXPANDER_DEVICE) || (type == SAS_FANOUT_EXPANDER_DEVICE))

#define PM8001_NAME_LENGTH		32/* generic length of strings */

struct forensic_data {
	u32  data_type;
	union {
		struct {
			u32  direct_len;
			u32  direct_offset;
			void  *direct_data;
		} gsm_buf;
		struct {
			u16  queue_type;
			u16  queue_index;
			u32  direct_len;
			void  *direct_data;
		} queue_buf;
		struct {
			u32  direct_len;
			u32  direct_offset;
			u32  read_len;
			void  *direct_data;
		} data_buf;
	};
};

struct pm8001_port {
	struct asd_sas_port	sas_port;
	u8			port_attached;
	u16			wide_port_phymap;
	u8			port_state;
	struct list_head	list;
};

struct pm8001_phy {
	struct pm8001_hba_info	*pm8001_ha;
	struct pm8001_port	*port;
	struct asd_sas_phy	sas_phy;
	struct sas_identify	identify;
	struct scsi_device	*sdev;
	u64			dev_sas_addr;
	u32			phy_type;
	struct completion	*enable_completion;
	u32			frame_rcvd_size;
	u8			frame_rcvd[32];
	u8			phy_attached;
	u8			phy_state;
	enum sas_linkrate	minimum_linkrate;
	enum sas_linkrate	maximum_linkrate;
	struct completion	*reset_completion;
	bool			port_reset_status;
	bool			reset_success;
};

struct pm8001_device {
	enum sas_device_type	dev_type;
	struct domain_device	*sas_device;
	u32			attached_phy;
	u32			id;
	struct completion	*dcompletion;
	struct completion	*setds_completion;
	u32			device_id;
	u32			running_req;
};

struct pm8001_prd_imt {
	__le32			len;
	__le32			e;
};

struct pm8001_prd {
	__le64			addr;		/* 64-bit buffer address */
	struct pm8001_prd_imt	im_len;		/* 64-bit length */
} __attribute__ ((packed));

struct pm8001_ccb_info {
	struct list_head	entry;
	struct sas_task		*task;
	u32			n_elem;
	u32			ccb_tag;
	dma_addr_t		ccb_dma_handle;
	struct pm8001_device	*device;
	struct pm8001_prd	buf_prd[PM8001_MAX_DMA_SG];
	struct fw_control_ex	*fw_control_context;
	u8			open_retry;
};

struct mpi_mem {
	void			*virt_ptr;
	dma_addr_t		phys_addr;
	u32			phys_addr_hi;
	u32			phys_addr_lo;
	u32			total_len;
	u32			num_elements;
	u32			element_size;
	u32			alignment;
};

struct mpi_mem_req {
	/* The number of element in the  mpiMemory array */
	u32			count;
	/* The array of structures that define memroy regions*/
	struct mpi_mem		region[USI_MAX_MEMCNT];
};

struct encrypt {
	u32	cipher_mode;
	u32	sec_mode;
	u32	status;
	u32	flag;
};

struct sas_phy_attribute_table {
	u32	phystart1_16[16];
	u32	outbound_hw_event_pid1_16[16];
};

union main_cfg_table {
	struct {
	u32			signature;
	u32			interface_rev;
	u32			firmware_rev;
	u32			max_out_io;
	u32			max_sgl;
	u32			ctrl_cap_flag;
	u32			gst_offset;
	u32			inbound_queue_offset;
	u32			outbound_queue_offset;
	u32			inbound_q_nppd_hppd;
	u32			outbound_hw_event_pid0_3;
	u32			outbound_hw_event_pid4_7;
	u32			outbound_ncq_event_pid0_3;
	u32			outbound_ncq_event_pid4_7;
	u32			outbound_tgt_ITNexus_event_pid0_3;
	u32			outbound_tgt_ITNexus_event_pid4_7;
	u32			outbound_tgt_ssp_event_pid0_3;
	u32			outbound_tgt_ssp_event_pid4_7;
	u32			outbound_tgt_smp_event_pid0_3;
	u32			outbound_tgt_smp_event_pid4_7;
	u32			upper_event_log_addr;
	u32			lower_event_log_addr;
	u32			event_log_size;
	u32			event_log_option;
	u32			upper_iop_event_log_addr;
	u32			lower_iop_event_log_addr;
	u32			iop_event_log_size;
	u32			iop_event_log_option;
	u32			fatal_err_interrupt;
	u32			fatal_err_dump_offset0;
	u32			fatal_err_dump_length0;
	u32			fatal_err_dump_offset1;
	u32			fatal_err_dump_length1;
	u32			hda_mode_flag;
	u32			anolog_setup_table_offset;
	u32			rsvd[4];
	} pm8001_tbl;

	struct {
	u32			signature;
	u32			interface_rev;
	u32			firmware_rev;
	u32			max_out_io;
	u32			max_sgl;
	u32			ctrl_cap_flag;
	u32			gst_offset;
	u32			inbound_queue_offset;
	u32			outbound_queue_offset;
	u32			inbound_q_nppd_hppd;
	u32			rsvd[8];
	u32			crc_core_dump;
	u32			rsvd1;
	u32			upper_event_log_addr;
	u32			lower_event_log_addr;
	u32			event_log_size;
	u32			event_log_severity;
	u32			upper_pcs_event_log_addr;
	u32			lower_pcs_event_log_addr;
	u32			pcs_event_log_size;
	u32			pcs_event_log_severity;
	u32			fatal_err_interrupt;
	u32			fatal_err_dump_offset0;
	u32			fatal_err_dump_length0;
	u32			fatal_err_dump_offset1;
	u32			fatal_err_dump_length1;
	u32			gpio_led_mapping;
	u32			analog_setup_table_offset;
	u32			int_vec_table_offset;
	u32			phy_attr_table_offset;
	u32			port_recovery_timer;
	u32			interrupt_reassertion_delay;
	u32			fatal_n_non_fatal_dump;	        /* 0x28 */
	u32			ila_version;
	u32			inc_fw_version;
	} pm80xx_tbl;
};

union general_status_table {
	struct {
	u32			gst_len_mpistate;
	u32			iq_freeze_state0;
	u32			iq_freeze_state1;
	u32			msgu_tcnt;
	u32			iop_tcnt;
	u32			rsvd;
	u32			phy_state[8];
	u32			gpio_input_val;
	u32			rsvd1[2];
	u32			recover_err_info[8];
	} pm8001_tbl;
	struct {
	u32			gst_len_mpistate;
	u32			iq_freeze_state0;
	u32			iq_freeze_state1;
	u32			msgu_tcnt;
	u32			iop_tcnt;
	u32			rsvd[9];
	u32			gpio_input_val;
	u32			rsvd1[2];
	u32			recover_err_info[8];
	} pm80xx_tbl;
};
struct inbound_queue_table {
	u32			element_pri_size_cnt;
	u32			upper_base_addr;
	u32			lower_base_addr;
	u32			ci_upper_base_addr;
	u32			ci_lower_base_addr;
	u32			pi_pci_bar;
	u32			pi_offset;
	u32			total_length;
	void			*base_virt;
	void			*ci_virt;
	u32			reserved;
	__le32			consumer_index;
	u32			producer_idx;
};
struct outbound_queue_table {
	u32			element_size_cnt;
	u32			upper_base_addr;
	u32			lower_base_addr;
	void			*base_virt;
	u32			pi_upper_base_addr;
	u32			pi_lower_base_addr;
	u32			ci_pci_bar;
	u32			ci_offset;
	u32			total_length;
	void			*pi_virt;
	u32			interrup_vec_cnt_delay;
	u32			dinterrup_to_pci_offset;
	__le32			producer_index;
	u32			consumer_idx;
};
struct pm8001_hba_memspace {
	void __iomem  		*memvirtaddr;
	u64			membase;
	u32			memsize;
};
struct isr_param {
	struct pm8001_hba_info *drv_inst;
	u32 irq_id;
};
struct pm8001_hba_info {
	char			name[PM8001_NAME_LENGTH];
	struct list_head	list;
	unsigned long		flags;
	spinlock_t		lock;/* host-wide lock */
	spinlock_t		bitmap_lock;
	struct pci_dev		*pdev;/* our device */
	struct device		*dev;
	struct pm8001_hba_memspace io_mem[6];
	struct mpi_mem_req	memoryMap;
	struct encrypt		encrypt_info; /* support encryption */
	struct forensic_data	forensic_info;
	u32			fatal_bar_loc;
	u32			forensic_last_offset;
	u32			fatal_forensic_shift_offset;
	u32			forensic_fatal_step;
	u32			evtlog_ib_offset;
	u32			evtlog_ob_offset;
	void __iomem	*msg_unit_tbl_addr;/*Message Unit Table Addr*/
	void __iomem	*main_cfg_tbl_addr;/*Main Config Table Addr*/
	void __iomem	*general_stat_tbl_addr;/*General Status Table Addr*/
	void __iomem	*inbnd_q_tbl_addr;/*Inbound Queue Config Table Addr*/
	void __iomem	*outbnd_q_tbl_addr;/*Outbound Queue Config Table Addr*/
	void __iomem	*pspa_q_tbl_addr;
			/*MPI SAS PHY attributes Queue Config Table Addr*/
	void __iomem	*ivt_tbl_addr; /*MPI IVT Table Addr */
	void __iomem	*fatal_tbl_addr; /*MPI IVT Table Addr */
	union main_cfg_table	main_cfg_tbl;
	union general_status_table	gs_tbl;
	struct inbound_queue_table	inbnd_q_tbl[PM8001_MAX_SPCV_INB_NUM];
	struct outbound_queue_table	outbnd_q_tbl[PM8001_MAX_SPCV_OUTB_NUM];
	struct sas_phy_attribute_table	phy_attr_table;
					/* MPI SAS PHY attributes */
	u8			sas_addr[SAS_ADDR_SIZE];
	struct sas_ha_struct	*sas;/* SCSI/SAS glue */
	struct Scsi_Host	*shost;
	u32			chip_id;
	const struct pm8001_chip_info	*chip;
	struct completion	*nvmd_completion;
	int			tags_num;
	unsigned long		*tags;
	struct pm8001_phy	phy[PM8001_MAX_PHYS];
	struct pm8001_port	port[PM8001_MAX_PHYS];
	u32			id;
	u32			irq;
	u32			iomb_size; /* SPC and SPCV IOMB size */
	struct pm8001_device	*devices;
	struct pm8001_ccb_info	*ccb_info;
#ifdef PM8001_USE_MSIX
	int			number_of_intr;/*will be used in remove()*/
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef PM8001_USE_TASKLET
	struct tasklet_struct	tasklet[PM8001_MAX_MSIX_VEC];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u32			logging_level;
	u32			fw_status;
	u32			smp_exp_mode;
	bool			controller_fatal_error;
	const struct firmware 	*fw_image;
	struct isr_param irq_vector[PM8001_MAX_MSIX_VEC];
	u32			reset_in_progress;
};

#define	NCQ_READ_LOG_FLAG			0x80000000
#define	NCQ_ABORT_ALL_FLAG			0x40000000

static void (*klpe_pm8001_ccb_task_free)(struct pm8001_hba_info *pm8001_ha,
	struct sas_task *task, struct pm8001_ccb_info *ccb, u32 ccb_idx);

static int (*klpe_pm8001_handle_event)(struct pm8001_hba_info *pm8001_ha,
					void *data, int handler);

static void (*klpe_pm8001_tag_free)(struct pm8001_hba_info *pm8001_ha, u32 tag);

static inline void
klpr_pm8001_ccb_task_free_done(struct pm8001_hba_info *pm8001_ha,
			struct sas_task *task, struct pm8001_ccb_info *ccb,
			u32 ccb_idx)
{
	(*klpe_pm8001_ccb_task_free)(pm8001_ha, task, ccb, ccb_idx);
	smp_mb(); /*in order to force CPU ordering*/
	spin_unlock(&pm8001_ha->lock);
	task->task_done(task);
	spin_lock(&pm8001_ha->lock);
}

/* klp-ccp: from drivers/scsi/pm8001/pm80xx_hwi.h */
#include <linux/types.h>
#include <scsi/libsas.h>

struct set_dev_bits_fis {
	u8	fis_type;	/* 0xA1*/
	u8	n_i_pmport;
	/* b7 : n Bit. Notification bit. If set device needs attention. */
	/* b6 : i Bit. Interrupt Bit */
	/* b5-b4: reserved2 */
	/* b3-b0: PM Port */
	u8	status;
	u8	error;
	u32	_r_a;
} __attribute__ ((packed));

struct pio_setup_fis {
	u8	fis_type;	/* 0x5f */
	u8	i_d_pmPort;
	/* b7 : reserved */
	/* b6 : i bit. Interrupt bit */
	/* b5 : d bit. data transfer direction. set to 1 for device to host
	xfer */
	/* b4 : reserved */
	/* b3-b0: PM Port */
	u8	status;
	u8	error;
	u8	lbal;
	u8	lbam;
	u8	lbah;
	u8	device;
	u8	lbal_exp;
	u8	lbam_exp;
	u8	lbah_exp;
	u8	_r_a;
	u8	sector_count;
	u8	sector_count_exp;
	u8	_r_b;
	u8	e_status;
	u8	_r_c[2];
	u8	transfer_count;
} __attribute__ ((packed));

struct sata_completion_resp {
	__le32	tag;
	__le32	status;
	__le32	param;
	u32	sata_resp[12];
} __attribute__((packed, aligned(4)));

struct ssp_completion_resp {
	__le32	tag;
	__le32	status;
	__le32	param;
	__le32	ssptag_rescv_rescpad;
	struct ssp_response_iu ssp_resp_iu;
	__le32	residual_count;
} __attribute__((packed, aligned(4)));

#define IO_SUCCESS				0x00
#define IO_ABORTED				0x01
#define IO_OVERFLOW				0x02
#define IO_UNDERFLOW				0x03

#define IO_NO_DEVICE				0x07

#define IO_XFER_ERROR_BREAK			0x0E
#define IO_XFER_ERROR_PHY_NOT_READY		0x0F
#define IO_OPEN_CNX_ERROR_PROTOCOL_NOT_SUPPORTED	0x10
#define IO_OPEN_CNX_ERROR_ZONE_VIOLATION		0x11
#define IO_OPEN_CNX_ERROR_BREAK				0x12
#define IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS			0x13
#define IO_OPEN_CNX_ERROR_BAD_DESTINATION		0x14
#define IO_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED	0x15
#define IO_OPEN_CNX_ERROR_STP_RESOURCES_BUSY		0x16
#define IO_OPEN_CNX_ERROR_WRONG_DESTINATION		0x17

#define IO_XFER_ERROR_NAK_RECEIVED			0x19
#define IO_XFER_ERROR_ACK_NAK_TIMEOUT			0x1A

#define IO_XFER_ERROR_DMA				0x1D

#define IO_XFER_ERROR_SATA_LINK_TIMEOUT			0x1F

#define IO_XFER_ERROR_REJECTED_NCQ_MODE			0x21

#define IO_XFER_OPEN_RETRY_TIMEOUT			0x24

#define IO_XFER_ERROR_OFFSET_MISMATCH			0x34

#define IO_PORT_IN_RESET				0x38
#define IO_DS_NON_OPERATIONAL				0x39
#define IO_DS_IN_RECOVERY				0x3A
#define IO_TM_TAG_NOT_FOUND				0x3B

#define IO_SSP_EXT_IU_ZERO_LEN_ERROR			0x3D
#define IO_DS_IN_ERROR					0x3E
#define IO_OPEN_CNX_ERROR_HW_RESOURCE_BUSY		0x3F

#define IO_XFER_OPEN_RETRY_BACKOFF_THRESHOLD_REACHED	0x44
#define IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_OPEN_TMO	0x45
#define IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_NO_DEST		0x46
#define IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_OPEN_COLLIDE	0x47
#define IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_PATHWAY_BLOCKED	0x48

#define IO_XFER_ERROR_INVALID_SSP_RSP_FRAME	0x57

/* klp-ccp: from drivers/scsi/pm8001/pm80xx_hwi.c */
static void (*klpe_pm80xx_send_abort_all)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_device *pm8001_ha_dev);

void
klpp_mpi_ssp_completion(struct pm8001_hba_info *pm8001_ha , void *piomb)
{
	struct sas_task *t;
	struct pm8001_ccb_info *ccb;
	unsigned long flags;
	u32 status;
	u32 param;
	u32 tag;
	struct ssp_completion_resp *psspPayload;
	struct task_status_struct *ts;
	struct ssp_response_iu *iu;
	struct pm8001_device *pm8001_dev;
	psspPayload = (struct ssp_completion_resp *)(piomb + 4);
	status = le32_to_cpu(psspPayload->status);
	tag = le32_to_cpu(psspPayload->tag);
	ccb = &pm8001_ha->ccb_info[tag];
	if ((status == IO_ABORTED) && ccb->open_retry) {
		/* Being completed by another */
		ccb->open_retry = 0;
		return;
	}
	pm8001_dev = ccb->device;
	param = le32_to_cpu(psspPayload->param);
	t = ccb->task;

	if (status && status != IO_UNDERFLOW)
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("sas IO status 0x%x\n", status));
	if (unlikely(!t || !t->lldd_task || !t->dev))
		return;
	ts = &t->task_status;
	/* Print sas address of IO failed device */
	if ((status != IO_SUCCESS) && (status != IO_OVERFLOW) &&
		(status != IO_UNDERFLOW))
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("SAS Address of IO Failure Drive"
			":%016llx", SAS_ADDR(t->dev->sas_addr)));

	switch (status) {
	case IO_SUCCESS:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_SUCCESS ,param = 0x%x\n",
				param));
		if (param == 0) {
			ts->resp = SAS_TASK_COMPLETE;
			ts->stat = SAM_STAT_GOOD;
		} else {
			ts->resp = SAS_TASK_COMPLETE;
			ts->stat = SAS_PROTO_RESPONSE;
			ts->residual = param;
			iu = &psspPayload->ssp_resp_iu;
			(*klpe_sas_ssp_task_response)(pm8001_ha->dev, t, iu);
		}
		if (pm8001_dev)
			pm8001_dev->running_req--;
		break;
	case IO_ABORTED:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_ABORTED IOMB Tag\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_ABORTED_TASK;
		break;
	case IO_UNDERFLOW:
		/* SSP Completion with error */
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_UNDERFLOW ,param = 0x%x\n",
				param));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DATA_UNDERRUN;
		ts->residual = param;
		if (pm8001_dev)
			pm8001_dev->running_req--;
		break;
	case IO_NO_DEVICE:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_NO_DEVICE\n"));
		ts->resp = SAS_TASK_UNDELIVERED;
		ts->stat = SAS_PHY_DOWN;
		break;
	case IO_XFER_ERROR_BREAK:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_BREAK\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		/* Force the midlayer to retry */
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_XFER_ERROR_PHY_NOT_READY:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_PHY_NOT_READY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_XFER_ERROR_INVALID_SSP_RSP_FRAME:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_INVALID_SSP_RSP_FRAME\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_OPEN_CNX_ERROR_PROTOCOL_NOT_SUPPORTED:
		PM8001_IO_DBG(pm8001_ha,
		pm8001_printk("IO_OPEN_CNX_ERROR_PROTOCOL_NOT_SUPPORTED\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_EPROTO;
		break;
	case IO_OPEN_CNX_ERROR_ZONE_VIOLATION:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_ZONE_VIOLATION\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_UNKNOWN;
		break;
	case IO_OPEN_CNX_ERROR_BREAK:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_BREAK\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS:
	case IO_XFER_OPEN_RETRY_BACKOFF_THRESHOLD_REACHED:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_OPEN_TMO:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_NO_DEST:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_OPEN_COLLIDE:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_PATHWAY_BLOCKED:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_UNKNOWN;
		if (!t->uldd_task)
			(*klpe_pm8001_handle_event)(pm8001_ha,
				pm8001_dev,
				IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS);
		break;
	case IO_OPEN_CNX_ERROR_BAD_DESTINATION:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_BAD_DESTINATION\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_BAD_DEST;
		break;
	case IO_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED:
		PM8001_IO_DBG(pm8001_ha, pm8001_printk(
			"IO_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_CONN_RATE;
		break;
	case IO_OPEN_CNX_ERROR_WRONG_DESTINATION:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_WRONG_DESTINATION\n"));
		ts->resp = SAS_TASK_UNDELIVERED;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_WRONG_DEST;
		break;
	case IO_XFER_ERROR_NAK_RECEIVED:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_NAK_RECEIVED\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_XFER_ERROR_ACK_NAK_TIMEOUT:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_ACK_NAK_TIMEOUT\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_NAK_R_ERR;
		break;
	case IO_XFER_ERROR_DMA:
		PM8001_IO_DBG(pm8001_ha,
		pm8001_printk("IO_XFER_ERROR_DMA\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	case IO_XFER_OPEN_RETRY_TIMEOUT:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_OPEN_RETRY_TIMEOUT\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_XFER_ERROR_OFFSET_MISMATCH:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_OFFSET_MISMATCH\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	case IO_PORT_IN_RESET:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_PORT_IN_RESET\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	case IO_DS_NON_OPERATIONAL:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_DS_NON_OPERATIONAL\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		if (!t->uldd_task)
			(*klpe_pm8001_handle_event)(pm8001_ha,
				pm8001_dev,
				IO_DS_NON_OPERATIONAL);
		break;
	case IO_DS_IN_RECOVERY:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_DS_IN_RECOVERY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	case IO_TM_TAG_NOT_FOUND:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_TM_TAG_NOT_FOUND\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	case IO_SSP_EXT_IU_ZERO_LEN_ERROR:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_SSP_EXT_IU_ZERO_LEN_ERROR\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	case IO_OPEN_CNX_ERROR_HW_RESOURCE_BUSY:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_HW_RESOURCE_BUSY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	default:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("Unknown status 0x%x\n", status));
		/* not allowed case. Therefore, return failed status */
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		break;
	}
	PM8001_IO_DBG(pm8001_ha,
		pm8001_printk("scsi_status = 0x%x\n ",
		psspPayload->ssp_resp_iu.status));
	spin_lock_irqsave(&t->task_state_lock, flags);
	t->task_state_flags &= ~SAS_TASK_STATE_PENDING;
	t->task_state_flags &= ~SAS_TASK_AT_INITIATOR;
	t->task_state_flags |= SAS_TASK_STATE_DONE;
	if (unlikely((t->task_state_flags & SAS_TASK_STATE_ABORTED))) {
		spin_unlock_irqrestore(&t->task_state_lock, flags);
		PM8001_FAIL_DBG(pm8001_ha, pm8001_printk(
			"task 0x%p done with io_status 0x%x resp 0x%x "
			"stat 0x%x but aborted by upper layer!\n",
			t, status, ts->resp, ts->stat));
		(*klpe_pm8001_ccb_task_free)(pm8001_ha, t, ccb, tag);
		if (t->slow_task)
			complete(&t->slow_task->completion);
	} else {
		spin_unlock_irqrestore(&t->task_state_lock, flags);
		(*klpe_pm8001_ccb_task_free)(pm8001_ha, t, ccb, tag);
		mb();/* in order to force CPU ordering */
		t->task_done(t);
	}
}

void
klpp_mpi_sata_completion(struct pm8001_hba_info *pm8001_ha, void *piomb)
{
	struct sas_task *t;
	struct pm8001_ccb_info *ccb;
	u32 param;
	u32 status;
	u32 tag;
	int i, j;
	u8 sata_addr_low[4];
	u32 temp_sata_addr_low, temp_sata_addr_hi;
	u8 sata_addr_hi[4];
	struct sata_completion_resp *psataPayload;
	struct task_status_struct *ts;
	struct ata_task_resp *resp ;
	u32 *sata_resp;
	struct pm8001_device *pm8001_dev;
	unsigned long flags;

	psataPayload = (struct sata_completion_resp *)(piomb + 4);
	status = le32_to_cpu(psataPayload->status);
	tag = le32_to_cpu(psataPayload->tag);

	if (!tag) {
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("tag null\n"));
		return;
	}
	ccb = &pm8001_ha->ccb_info[tag];
	param = le32_to_cpu(psataPayload->param);
	if (ccb) {
		t = ccb->task;
		pm8001_dev = ccb->device;
	} else {
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("ccb null\n"));
		return;
	}

	if (t) {
		if (t->dev && (t->dev->lldd_dev))
			pm8001_dev = t->dev->lldd_dev;
	} else {
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("task null\n"));
		return;
	}

	if ((pm8001_dev && !(pm8001_dev->id & NCQ_READ_LOG_FLAG))
		&& unlikely(!t || !t->lldd_task || !t->dev)) {
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("task or dev null\n"));
		return;
	}

	ts = &t->task_status;
	if (!ts) {
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("ts null\n"));
		return;
	}
	/* Print sas address of IO failed device */
	if ((status != IO_SUCCESS) && (status != IO_OVERFLOW) &&
		(status != IO_UNDERFLOW)) {
		if (!((t->dev->parent) &&
			(DEV_IS_EXPANDER(t->dev->parent->dev_type)))) {
			for (i = 0 , j = 4; i <= 3 && j <= 7; i++ , j++)
				sata_addr_low[i] = pm8001_ha->sas_addr[j];
			for (i = 0 , j = 0; i <= 3 && j <= 3; i++ , j++)
				sata_addr_hi[i] = pm8001_ha->sas_addr[j];
			memcpy(&temp_sata_addr_low, sata_addr_low,
				sizeof(sata_addr_low));
			memcpy(&temp_sata_addr_hi, sata_addr_hi,
				sizeof(sata_addr_hi));
			temp_sata_addr_hi = (((temp_sata_addr_hi >> 24) & 0xff)
						|((temp_sata_addr_hi << 8) &
						0xff0000) |
						((temp_sata_addr_hi >> 8)
						& 0xff00) |
						((temp_sata_addr_hi << 24) &
						0xff000000));
			temp_sata_addr_low = ((((temp_sata_addr_low >> 24)
						& 0xff) |
						((temp_sata_addr_low << 8)
						& 0xff0000) |
						((temp_sata_addr_low >> 8)
						& 0xff00) |
						((temp_sata_addr_low << 24)
						& 0xff000000)) +
						pm8001_dev->attached_phy +
						0x10);
			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("SAS Address of IO Failure Drive:"
				"%08x%08x", temp_sata_addr_hi,
					temp_sata_addr_low));

		} else {
			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("SAS Address of IO Failure Drive:"
				"%016llx", SAS_ADDR(t->dev->sas_addr)));
		}
	}
	switch (status) {
	case IO_SUCCESS:
		PM8001_IO_DBG(pm8001_ha, pm8001_printk("IO_SUCCESS\n"));
		if (param == 0) {
			ts->resp = SAS_TASK_COMPLETE;
			ts->stat = SAM_STAT_GOOD;
			/* check if response is for SEND READ LOG */
			if (pm8001_dev &&
				(pm8001_dev->id & NCQ_READ_LOG_FLAG)) {
				/* set new bit for abort_all */
				pm8001_dev->id |= NCQ_ABORT_ALL_FLAG;
				/* clear bit for read log */
				pm8001_dev->id = pm8001_dev->id & 0x7FFFFFFF;
				(*klpe_pm80xx_send_abort_all)(pm8001_ha, pm8001_dev);
				/* Free the tag */
				(*klpe_pm8001_tag_free)(pm8001_ha, tag);
				(*klpe_sas_free_task)(t);
				return;
			}
		} else {
			u8 len;
			ts->resp = SAS_TASK_COMPLETE;
			ts->stat = SAS_PROTO_RESPONSE;
			ts->residual = param;
			PM8001_IO_DBG(pm8001_ha,
				pm8001_printk("SAS_PROTO_RESPONSE len = %d\n",
				param));
			sata_resp = &psataPayload->sata_resp[0];
			resp = (struct ata_task_resp *)ts->buf;
			if (t->ata_task.dma_xfer == 0 &&
			t->data_dir == PCI_DMA_FROMDEVICE) {
				len = sizeof(struct pio_setup_fis);
				PM8001_IO_DBG(pm8001_ha,
				pm8001_printk("PIO read len = %d\n", len));
			} else if (t->ata_task.use_ncq &&
				   t->data_dir != PCI_DMA_NONE) {
				len = sizeof(struct set_dev_bits_fis);
				PM8001_IO_DBG(pm8001_ha,
					pm8001_printk("FPDMA len = %d\n", len));
			} else {
				len = sizeof(struct dev_to_host_fis);
				PM8001_IO_DBG(pm8001_ha,
				pm8001_printk("other len = %d\n", len));
			}
			if (SAS_STATUS_BUF_SIZE >= sizeof(*resp)) {
				resp->frame_len = len;
				memcpy(&resp->ending_fis[0], sata_resp, len);
				ts->buf_valid_size = sizeof(*resp);
			} else
				PM8001_IO_DBG(pm8001_ha,
					pm8001_printk("response to large\n"));
		}
		if (pm8001_dev)
			pm8001_dev->running_req--;
		break;
	case IO_ABORTED:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_ABORTED IOMB Tag\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_ABORTED_TASK;
		if (pm8001_dev)
			pm8001_dev->running_req--;
		break;
		/* following cases are to do cases */
	case IO_UNDERFLOW:
		/* SATA Completion with error */
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_UNDERFLOW param = %d\n", param));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DATA_UNDERRUN;
		ts->residual = param;
		if (pm8001_dev)
			pm8001_dev->running_req--;
		break;
	case IO_NO_DEVICE:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_NO_DEVICE\n"));
		ts->resp = SAS_TASK_UNDELIVERED;
		ts->stat = SAS_PHY_DOWN;
		break;
	case IO_XFER_ERROR_BREAK:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_BREAK\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_INTERRUPTED;
		break;
	case IO_XFER_ERROR_PHY_NOT_READY:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_PHY_NOT_READY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	case IO_OPEN_CNX_ERROR_PROTOCOL_NOT_SUPPORTED:
		PM8001_IO_DBG(pm8001_ha, pm8001_printk(
			"IO_OPEN_CNX_ERROR_PROTOCOL_NOT_SUPPORTED\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_EPROTO;
		break;
	case IO_OPEN_CNX_ERROR_ZONE_VIOLATION:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_ZONE_VIOLATION\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_UNKNOWN;
		break;
	case IO_OPEN_CNX_ERROR_BREAK:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_BREAK\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_CONT0;
		break;
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS:
	case IO_XFER_OPEN_RETRY_BACKOFF_THRESHOLD_REACHED:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_OPEN_TMO:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_NO_DEST:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_OPEN_COLLIDE:
	case IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS_PATHWAY_BLOCKED:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		if (!t->uldd_task) {
			(*klpe_pm8001_handle_event)(pm8001_ha,
				pm8001_dev,
				IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS);
			ts->resp = SAS_TASK_UNDELIVERED;
			ts->stat = SAS_QUEUE_FULL;
			klpr_pm8001_ccb_task_free_done(pm8001_ha, t, ccb, tag);
			return;
		}
		break;
	case IO_OPEN_CNX_ERROR_BAD_DESTINATION:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_BAD_DESTINATION\n"));
		ts->resp = SAS_TASK_UNDELIVERED;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_BAD_DEST;
		if (!t->uldd_task) {
			(*klpe_pm8001_handle_event)(pm8001_ha,
				pm8001_dev,
				IO_OPEN_CNX_ERROR_IT_NEXUS_LOSS);
			ts->resp = SAS_TASK_UNDELIVERED;
			ts->stat = SAS_QUEUE_FULL;
			klpr_pm8001_ccb_task_free_done(pm8001_ha, t, ccb, tag);
			return;
		}
		break;
	case IO_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED:
		PM8001_IO_DBG(pm8001_ha, pm8001_printk(
			"IO_OPEN_CNX_ERROR_CONNECTION_RATE_NOT_SUPPORTED\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_CONN_RATE;
		break;
	case IO_OPEN_CNX_ERROR_STP_RESOURCES_BUSY:
		PM8001_IO_DBG(pm8001_ha, pm8001_printk(
			"IO_OPEN_CNX_ERROR_STP_RESOURCES_BUSY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		if (!t->uldd_task) {
			(*klpe_pm8001_handle_event)(pm8001_ha,
				pm8001_dev,
				IO_OPEN_CNX_ERROR_STP_RESOURCES_BUSY);
			ts->resp = SAS_TASK_UNDELIVERED;
			ts->stat = SAS_QUEUE_FULL;
			klpr_pm8001_ccb_task_free_done(pm8001_ha, t, ccb, tag);
			return;
		}
		break;
	case IO_OPEN_CNX_ERROR_WRONG_DESTINATION:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_WRONG_DESTINATION\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_WRONG_DEST;
		break;
	case IO_XFER_ERROR_NAK_RECEIVED:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_NAK_RECEIVED\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_NAK_R_ERR;
		break;
	case IO_XFER_ERROR_ACK_NAK_TIMEOUT:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_ACK_NAK_TIMEOUT\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_NAK_R_ERR;
		break;
	case IO_XFER_ERROR_DMA:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_DMA\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_ABORTED_TASK;
		break;
	case IO_XFER_ERROR_SATA_LINK_TIMEOUT:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_SATA_LINK_TIMEOUT\n"));
		ts->resp = SAS_TASK_UNDELIVERED;
		ts->stat = SAS_DEV_NO_RESPONSE;
		break;
	case IO_XFER_ERROR_REJECTED_NCQ_MODE:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_ERROR_REJECTED_NCQ_MODE\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DATA_UNDERRUN;
		break;
	case IO_XFER_OPEN_RETRY_TIMEOUT:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_XFER_OPEN_RETRY_TIMEOUT\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_TO;
		break;
	case IO_PORT_IN_RESET:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_PORT_IN_RESET\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		break;
	case IO_DS_NON_OPERATIONAL:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_DS_NON_OPERATIONAL\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		if (!t->uldd_task) {
			(*klpe_pm8001_handle_event)(pm8001_ha, pm8001_dev,
					IO_DS_NON_OPERATIONAL);
			ts->resp = SAS_TASK_UNDELIVERED;
			ts->stat = SAS_QUEUE_FULL;
			klpr_pm8001_ccb_task_free_done(pm8001_ha, t, ccb, tag);
			return;
		}
		break;
	case IO_DS_IN_RECOVERY:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_DS_IN_RECOVERY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		break;
	case IO_DS_IN_ERROR:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_DS_IN_ERROR\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		if (!t->uldd_task) {
			(*klpe_pm8001_handle_event)(pm8001_ha, pm8001_dev,
					IO_DS_IN_ERROR);
			ts->resp = SAS_TASK_UNDELIVERED;
			ts->stat = SAS_QUEUE_FULL;
			klpr_pm8001_ccb_task_free_done(pm8001_ha, t, ccb, tag);
			return;
		}
		break;
	case IO_OPEN_CNX_ERROR_HW_RESOURCE_BUSY:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("IO_OPEN_CNX_ERROR_HW_RESOURCE_BUSY\n"));
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		break;
	default:
		PM8001_IO_DBG(pm8001_ha,
			pm8001_printk("Unknown status 0x%x\n", status));
		/* not allowed case. Therefore, return failed status */
		ts->resp = SAS_TASK_COMPLETE;
		ts->stat = SAS_DEV_NO_RESPONSE;
		break;
	}
	spin_lock_irqsave(&t->task_state_lock, flags);
	t->task_state_flags &= ~SAS_TASK_STATE_PENDING;
	t->task_state_flags &= ~SAS_TASK_AT_INITIATOR;
	t->task_state_flags |= SAS_TASK_STATE_DONE;
	if (unlikely((t->task_state_flags & SAS_TASK_STATE_ABORTED))) {
		spin_unlock_irqrestore(&t->task_state_lock, flags);
		PM8001_FAIL_DBG(pm8001_ha,
			pm8001_printk("task 0x%p done with io_status 0x%x"
			" resp 0x%x stat 0x%x but aborted by upper layer!\n",
			t, status, ts->resp, ts->stat));
		(*klpe_pm8001_ccb_task_free)(pm8001_ha, t, ccb, tag);
		if (t->slow_task)
			complete(&t->slow_task->completion);
	} else {
		spin_unlock_irqrestore(&t->task_state_lock, flags);
		klpr_pm8001_ccb_task_free_done(pm8001_ha, t, ccb, tag);
	}
}


#include "livepatch_bsc1228017.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "pm80xx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "pm8001_ccb_task_free", (void *)&klpe_pm8001_ccb_task_free,
	  "pm80xx" },
	{ "pm8001_handle_event", (void *)&klpe_pm8001_handle_event, "pm80xx" },
	{ "pm8001_tag_free", (void *)&klpe_pm8001_tag_free, "pm80xx" },
	{ "pm80xx_send_abort_all", (void *)&klpe_pm80xx_send_abort_all,
	  "pm80xx" },
	{ "sas_free_task", (void *)&klpe_sas_free_task, "libsas" },
	{ "sas_ssp_task_response", (void *)&klpe_sas_ssp_task_response,
	  "libsas" },
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

int livepatch_bsc1228017_init(void)
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

void livepatch_bsc1228017_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SCSI_PM8001) */
