/*
 * livepatch_bsc1228012
 *
 * Fix for CVE-2022-48791, bsc#1228012
 *
 *  Upstream commit:
 *  d712d3fb484b ("scsi: pm80xx: Fix TMF task completion race condition")
 *  61f162aa4381 ("scsi: pm8001: Fix use-after-free for aborted TMF sas_task")
 *
 *  SLE12-SP5 commit:
 *  47ce1348d07dfef37d2f2369f2711ff446c380e5
 *  0f736ca0a8695458bd229e5fc9f89fd570476e3e
 *
 *  SLE15-SP3 commit:
 *  cec204a20d7d7bea3fa15af529676a9642e55e28
 *
 *  SLE15-SP4 and -SP5 commit:
 *  da02c91148e0cdebfd487a9735bbfdfaf7647806
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

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.c */
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
static struct sas_task *(*klpe_sas_alloc_slow_task)(gfp_t flags);
static void (*klpe_sas_free_task)(struct sas_task *task);

static int (*klpe_sas_phy_reset)(struct sas_phy *phy, int hard_reset);

static struct sas_phy *(*klpe_sas_get_local_phy)(struct domain_device *dev);

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.h */
#include <scsi/sas_ata.h>
#include <linux/atomic.h>

/* klp-ccp: from drivers/scsi/pm8001/pm8001_defs.h */
enum chip_flavors {
	chip_8001,
	chip_8008,
	chip_8009,
	chip_8018,
	chip_8019,
	chip_8074,
	chip_8076,
	chip_8077,
	chip_8006,
	chip_8070,
	chip_8072
};

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

enum phy_control_type {
	PHY_LINK_RESET = 0x01,
	PHY_HARD_RESET = 0x02,
	PHY_NOTIFY_ENABLE_SPINUP = 0x10,
};

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.h */
#define PM8001_FAIL_LOGGING	0x01 /* Error message logging */

#define PM8001_IO_LOGGING	0x08 /* I/O path logging */
#define PM8001_EH_LOGGING	0x10 /* libsas EH function logging*/

#define PM8001_MSG_LOGGING	0x40 /* misc message logging */
#define pm8001_printk(format, arg...)	printk(KERN_INFO "pm80xx %s %d:" \
			format, __func__, __LINE__, ## arg)
#define PM8001_CHECK_LOGGING(HBA, LEVEL, CMD)	\
do {						\
	if (unlikely(HBA->logging_level & LEVEL))	\
		do {					\
			CMD;				\
		} while (0);				\
} while (0);

#define PM8001_EH_DBG(HBA, CMD)			\
	PM8001_CHECK_LOGGING(HBA, PM8001_EH_LOGGING, CMD)

#define PM8001_IO_DBG(HBA, CMD)		\
	PM8001_CHECK_LOGGING(HBA, PM8001_IO_LOGGING, CMD)

#define PM8001_FAIL_DBG(HBA, CMD)		\
	PM8001_CHECK_LOGGING(HBA, PM8001_FAIL_LOGGING, CMD)

#define PM8001_MSG_DBG(HBA, CMD)		\
	PM8001_CHECK_LOGGING(HBA, PM8001_MSG_LOGGING, CMD)

#define PM8001_USE_TASKLET
#define PM8001_USE_MSIX

#define PM8001_NAME_LENGTH		32/* generic length of strings */

struct pm8001_hba_info;
struct pm8001_ccb_info;
struct pm8001_device;

struct pm8001_tmf_task {
	u8	tmf;
	u32	tag_of_task_to_be_managed;
};

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

struct pm8001_dispatch {
	char *name;
	int (*chip_init)(struct pm8001_hba_info *pm8001_ha);
	int (*chip_soft_rst)(struct pm8001_hba_info *pm8001_ha);
	void (*chip_rst)(struct pm8001_hba_info *pm8001_ha);
	int (*chip_ioremap)(struct pm8001_hba_info *pm8001_ha);
	void (*chip_iounmap)(struct pm8001_hba_info *pm8001_ha);
	irqreturn_t (*isr)(struct pm8001_hba_info *pm8001_ha, u8 vec);
	u32 (*is_our_interupt)(struct pm8001_hba_info *pm8001_ha);
	int (*isr_process_oq)(struct pm8001_hba_info *pm8001_ha, u8 vec);
	void (*interrupt_enable)(struct pm8001_hba_info *pm8001_ha, u8 vec);
	void (*interrupt_disable)(struct pm8001_hba_info *pm8001_ha, u8 vec);
	void (*make_prd)(struct scatterlist *scatter, int nr, void *prd);
	int (*smp_req)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_ccb_info *ccb);
	int (*ssp_io_req)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_ccb_info *ccb);
	int (*sata_req)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_ccb_info *ccb);
	int (*phy_start_req)(struct pm8001_hba_info *pm8001_ha,	u8 phy_id);
	int (*phy_stop_req)(struct pm8001_hba_info *pm8001_ha, u8 phy_id);
	int (*reg_dev_req)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_device *pm8001_dev, u32 flag);
	int (*dereg_dev_req)(struct pm8001_hba_info *pm8001_ha, u32 device_id);
	int (*phy_ctl_req)(struct pm8001_hba_info *pm8001_ha,
		u32 phy_id, u32 phy_op);
	int (*task_abort)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_device *pm8001_dev, u8 flag, u32 task_tag,
		u32 cmd_tag);
	int (*ssp_tm_req)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_ccb_info *ccb, struct pm8001_tmf_task *tmf);
	int (*get_nvmd_req)(struct pm8001_hba_info *pm8001_ha, void *payload);
	int (*set_nvmd_req)(struct pm8001_hba_info *pm8001_ha, void *payload);
	int (*fw_flash_update_req)(struct pm8001_hba_info *pm8001_ha,
		void *payload);
	int (*set_dev_state_req)(struct pm8001_hba_info *pm8001_ha,
		struct pm8001_device *pm8001_dev, u32 state);
	int (*sas_diag_start_end_req)(struct pm8001_hba_info *pm8001_ha,
		u32 state);
	int (*sas_diag_execute_req)(struct pm8001_hba_info *pm8001_ha,
		u32 state);
	int (*sas_re_init_req)(struct pm8001_hba_info *pm8001_ha);
};

struct pm8001_chip_info {
	u32     encrypt;
	u32	n_phy;
	const struct pm8001_dispatch	*dispatch;
};
#define PM8001_CHIP_DISP	(pm8001_ha->chip->dispatch)

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

static int (*klpe_pm8001_tag_alloc)(struct pm8001_hba_info *pm8001_ha, u32 *tag_out);

int klpp_pm8001_abort_task(struct sas_task *task);
int klpp_pm8001_abort_task_set(struct domain_device *dev, u8 *lun);
int klpp_pm8001_clear_aca(struct domain_device *dev, u8 *lun);
int klpp_pm8001_clear_task_set(struct domain_device *dev, u8 *lun);
int klpp_pm8001_lu_reset(struct domain_device *dev, u8 *lun);
int klpp_pm8001_query_task(struct sas_task *task);

static void (*klpe_pm8001_task_done)(struct sas_task *task);
void klpp_pm8001_task_done(struct sas_task *task);

static void (*klpe_pm8001_tag_free)(struct pm8001_hba_info *pm8001_ha, u32 tag);

/* klp-ccp: from drivers/scsi/pm8001/pm8001_sas.c */
static int pm8001_find_tag(struct sas_task *task, u32 *tag)
{
	if (task->lldd_task) {
		struct pm8001_ccb_info *ccb;
		ccb = task->lldd_task;
		*tag = ccb->ccb_tag;
		return 1;
	}
	return 0;
}


static
struct pm8001_hba_info *pm8001_find_ha_by_dev(struct domain_device *dev)
{
	struct sas_ha_struct *sha = dev->port->ha;
	struct pm8001_hba_info *pm8001_ha = sha->lldd_ha;
	return pm8001_ha;
}

static int pm8001_task_prep_smp(struct pm8001_hba_info *pm8001_ha,
	struct pm8001_ccb_info *ccb)
{
	return PM8001_CHIP_DISP->smp_req(pm8001_ha, ccb);
}

static int pm8001_task_prep_ata(struct pm8001_hba_info *pm8001_ha,
	struct pm8001_ccb_info *ccb)
{
	return PM8001_CHIP_DISP->sata_req(pm8001_ha, ccb);
}

static int pm8001_task_prep_ssp_tm(struct pm8001_hba_info *pm8001_ha,
	struct pm8001_ccb_info *ccb, struct pm8001_tmf_task *tmf)
{
	return PM8001_CHIP_DISP->ssp_tm_req(pm8001_ha, ccb, tmf);
}

static int pm8001_task_prep_ssp(struct pm8001_hba_info *pm8001_ha,
	struct pm8001_ccb_info *ccb)
{
	return PM8001_CHIP_DISP->ssp_io_req(pm8001_ha, ccb);
}

static int sas_find_local_port_id(struct domain_device *dev)
{
	struct domain_device *pdev = dev->parent;

	/* Directly attached device */
	if (!pdev)
		return dev->port->id;
	while (pdev) {
		struct domain_device *pdev_p = pdev->parent;
		if (!pdev_p)
			return pdev->port->id;
		pdev = pdev->parent;
	}
	return 0;
}

#define DEV_IS_GONE(pm8001_dev)	\
	((!pm8001_dev || (pm8001_dev->dev_type == SAS_PHY_UNUSED)))
static int klpr_pm8001_task_exec(struct sas_task *task,
	gfp_t gfp_flags, int is_tmf, struct pm8001_tmf_task *tmf)
{
	struct domain_device *dev = task->dev;
	struct pm8001_hba_info *pm8001_ha;
	struct pm8001_device *pm8001_dev;
	struct pm8001_port *port = NULL;
	struct sas_task *t = task;
	struct pm8001_ccb_info *ccb;
	u32 tag = 0xdeadbeef, rc, n_elem = 0;
	unsigned long flags = 0;

	if (!dev->port) {
		struct task_status_struct *tsm = &t->task_status;
		tsm->resp = SAS_TASK_UNDELIVERED;
		tsm->stat = SAS_PHY_DOWN;
		if (dev->dev_type != SAS_SATA_DEV)
			t->task_done(t);
		return 0;
	}
	pm8001_ha = pm8001_find_ha_by_dev(task->dev);
	if (pm8001_ha->controller_fatal_error) {
		struct task_status_struct *ts = &t->task_status;

		ts->resp = SAS_TASK_UNDELIVERED;
		t->task_done(t);
		return 0;
	}
	PM8001_IO_DBG(pm8001_ha, pm8001_printk("pm8001_task_exec device \n "));
	spin_lock_irqsave(&pm8001_ha->lock, flags);
	do {
		dev = t->dev;
		pm8001_dev = dev->lldd_dev;
		port = &pm8001_ha->port[sas_find_local_port_id(dev)];
		if (DEV_IS_GONE(pm8001_dev) || !port->port_attached) {
			if (sas_protocol_ata(t->task_proto)) {
				struct task_status_struct *ts = &t->task_status;
				ts->resp = SAS_TASK_UNDELIVERED;
				ts->stat = SAS_PHY_DOWN;

				spin_unlock_irqrestore(&pm8001_ha->lock, flags);
				t->task_done(t);
				spin_lock_irqsave(&pm8001_ha->lock, flags);
				continue;
			} else {
				struct task_status_struct *ts = &t->task_status;
				ts->resp = SAS_TASK_UNDELIVERED;
				ts->stat = SAS_PHY_DOWN;
				t->task_done(t);
				continue;
			}
		}
		rc = (*klpe_pm8001_tag_alloc)(pm8001_ha, &tag);
		if (rc)
			goto err_out;
		ccb = &pm8001_ha->ccb_info[tag];

		if (!sas_protocol_ata(t->task_proto)) {
			if (t->num_scatter) {
				n_elem = dma_map_sg(pm8001_ha->dev,
					t->scatter,
					t->num_scatter,
					t->data_dir);
				if (!n_elem) {
					rc = -ENOMEM;
					goto err_out_tag;
				}
			}
		} else {
			n_elem = t->num_scatter;
		}

		t->lldd_task = ccb;
		ccb->n_elem = n_elem;
		ccb->ccb_tag = tag;
		ccb->task = t;
		ccb->device = pm8001_dev;
		switch (t->task_proto) {
		case SAS_PROTOCOL_SMP:
			rc = pm8001_task_prep_smp(pm8001_ha, ccb);
			break;
		case SAS_PROTOCOL_SSP:
			if (is_tmf)
				rc = pm8001_task_prep_ssp_tm(pm8001_ha,
					ccb, tmf);
			else
				rc = pm8001_task_prep_ssp(pm8001_ha, ccb);
			break;
		case SAS_PROTOCOL_SATA:
		case SAS_PROTOCOL_STP:
			rc = pm8001_task_prep_ata(pm8001_ha, ccb);
			break;
		default:
			dev_printk(KERN_ERR, pm8001_ha->dev,
				"unknown sas_task proto: 0x%x\n",
				t->task_proto);
			rc = -EINVAL;
			break;
		}

		if (rc) {
			PM8001_IO_DBG(pm8001_ha,
				pm8001_printk("rc is %x\n", rc));
			goto err_out_tag;
		}
		/* TODO: select normal or high priority */
		spin_lock(&t->task_state_lock);
		t->task_state_flags |= SAS_TASK_AT_INITIATOR;
		spin_unlock(&t->task_state_lock);
		pm8001_dev->running_req++;
	} while (0);
	rc = 0;
	goto out_done;

err_out_tag:
	(*klpe_pm8001_tag_free)(pm8001_ha, tag);
err_out:
	dev_printk(KERN_ERR, pm8001_ha->dev, "pm8001 exec failed[%d]!\n", rc);
	if (!sas_protocol_ata(t->task_proto))
		if (n_elem)
			dma_unmap_sg(pm8001_ha->dev, t->scatter, t->num_scatter,
				t->data_dir);
out_done:
	spin_unlock_irqrestore(&pm8001_ha->lock, flags);
	return rc;
}

void klpp_pm8001_task_done(struct sas_task *task)
{
	del_timer(&task->slow_task->timer);
	complete(&task->slow_task->completion);
}

static void (*klpe_pm8001_tmf_timedout)(struct timer_list *t);

void klpp_pm8001_tmf_timedout(struct timer_list *t)
{
	struct sas_task_slow *slow = from_timer(slow, t, timer);
	struct sas_task *task = slow->task;
	unsigned long flags;

	spin_lock_irqsave(&task->task_state_lock, flags);
	if (!(task->task_state_flags & SAS_TASK_STATE_DONE)) {
		task->task_state_flags |= SAS_TASK_STATE_ABORTED;
		complete(&task->slow_task->completion);
	}
	spin_unlock_irqrestore(&task->task_state_lock, flags);
}

#define PM8001_TASK_TIMEOUT 20

static int klpr_pm8001_exec_internal_tmf_task(struct domain_device *dev,
	void *parameter, u32 para_len, struct pm8001_tmf_task *tmf)
{
	int res, retry;
	struct sas_task *task = NULL;
	struct pm8001_hba_info *pm8001_ha = pm8001_find_ha_by_dev(dev);
	struct pm8001_device *pm8001_dev = dev->lldd_dev;
	DECLARE_COMPLETION_ONSTACK(completion_setstate);

	for (retry = 0; retry < 3; retry++) {
		task = (*klpe_sas_alloc_slow_task)(GFP_KERNEL);
		if (!task)
			return -ENOMEM;

		task->dev = dev;
		task->task_proto = dev->tproto;
		memcpy(&task->ssp_task, parameter, para_len);
		task->task_done = (*klpe_pm8001_task_done);
		task->slow_task->timer.function = (TIMER_FUNC_TYPE)(*klpe_pm8001_tmf_timedout);
		task->slow_task->timer.expires = jiffies + PM8001_TASK_TIMEOUT*HZ;
		add_timer(&task->slow_task->timer);

		res = klpr_pm8001_task_exec(task, GFP_KERNEL, 1, tmf);

		if (res) {
			del_timer(&task->slow_task->timer);
			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("Executing internal task "
				"failed\n"));
			goto ex_err;
		}
		wait_for_completion(&task->slow_task->completion);
		if (pm8001_ha->chip_id != chip_8001) {
			pm8001_dev->setds_completion = &completion_setstate;
				PM8001_CHIP_DISP->set_dev_state_req(pm8001_ha,
					pm8001_dev, 0x01);
			wait_for_completion(&completion_setstate);
		}
		res = -TMF_RESP_FUNC_FAILED;
		/* Even TMF timed out, return direct. */
		if (task->task_state_flags & SAS_TASK_STATE_ABORTED) {
			struct pm8001_ccb_info *ccb = task->lldd_task;

			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("TMF task[%x]timeout.\n", tmf->tmf));
				goto ex_err;

			if (ccb)
				ccb->task = NULL;
			goto ex_err;
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
			task->task_status.stat == SAM_STAT_GOOD) {
			res = TMF_RESP_FUNC_COMPLETE;
			break;
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
		task->task_status.stat == SAS_DATA_UNDERRUN) {
			/* no error, but return the number of bytes of
			* underrun */
			res = task->task_status.residual;
			break;
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
			task->task_status.stat == SAS_DATA_OVERRUN) {
			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("Blocked task error.\n"));
			res = -EMSGSIZE;
			break;
		} else {
			PM8001_EH_DBG(pm8001_ha,
				pm8001_printk(" Task to dev %016llx response:"
				"0x%x status 0x%x\n",
				SAS_ADDR(dev->sas_addr),
				task->task_status.resp,
				task->task_status.stat));
			(*klpe_sas_free_task)(task);
			task = NULL;
		}
	}
ex_err:
	BUG_ON(retry == 3 && task != NULL);
	(*klpe_sas_free_task)(task);
	return res;
}

int
klpp_pm8001_exec_internal_task_abort(struct pm8001_hba_info *pm8001_ha,
	struct pm8001_device *pm8001_dev, struct domain_device *dev, u32 flag,
	u32 task_tag)
{
	int res, retry;
	u32 ccb_tag;
	struct pm8001_ccb_info *ccb;
	struct sas_task *task = NULL;

	for (retry = 0; retry < 3; retry++) {
		task = (*klpe_sas_alloc_slow_task)(GFP_KERNEL);
		if (!task)
			return -ENOMEM;

		task->dev = dev;
		task->task_proto = dev->tproto;
		task->task_done = (*klpe_pm8001_task_done);
		task->slow_task->timer.function = (TIMER_FUNC_TYPE)(*klpe_pm8001_tmf_timedout);
		task->slow_task->timer.expires = jiffies + PM8001_TASK_TIMEOUT * HZ;
		add_timer(&task->slow_task->timer);

		res = (*klpe_pm8001_tag_alloc)(pm8001_ha, &ccb_tag);
		if (res)
			goto ex_err;
		ccb = &pm8001_ha->ccb_info[ccb_tag];
		ccb->device = pm8001_dev;
		ccb->ccb_tag = ccb_tag;
		ccb->task = task;
		ccb->n_elem = 0;

		res = PM8001_CHIP_DISP->task_abort(pm8001_ha,
			pm8001_dev, flag, task_tag, ccb_tag);

		if (res) {
			del_timer(&task->slow_task->timer);
			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("Executing internal task "
				"failed\n"));
			goto ex_err;
		}
		wait_for_completion(&task->slow_task->completion);
		res = TMF_RESP_FUNC_FAILED;
		/* Even TMF timed out, return direct. */
		if (task->task_state_flags & SAS_TASK_STATE_ABORTED) {
			PM8001_FAIL_DBG(pm8001_ha,
				pm8001_printk("TMF task timeout.\n"));
			goto ex_err;
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
			task->task_status.stat == SAM_STAT_GOOD) {
			res = TMF_RESP_FUNC_COMPLETE;
			break;

		} else {
			PM8001_EH_DBG(pm8001_ha,
				pm8001_printk(" Task to dev %016llx response: "
					"0x%x status 0x%x\n",
				SAS_ADDR(dev->sas_addr),
				task->task_status.resp,
				task->task_status.stat));
			(*klpe_sas_free_task)(task);
			task = NULL;
		}
	}
ex_err:
	BUG_ON(retry == 3 && task != NULL);
	(*klpe_sas_free_task)(task);
	return res;
}

static int klpr_pm8001_issue_ssp_tmf(struct domain_device *dev,
	u8 *lun, struct pm8001_tmf_task *tmf)
{
	struct sas_ssp_task ssp_task;
	if (!(dev->tproto & SAS_PROTOCOL_SSP))
		return TMF_RESP_FUNC_ESUPP;

	strncpy((u8 *)&ssp_task.LUN, lun, 8);
	return klpr_pm8001_exec_internal_tmf_task(dev, &ssp_task, sizeof(ssp_task),
		tmf);
}

int klpp_pm8001_lu_reset(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct pm8001_tmf_task tmf_task;
	struct pm8001_device *pm8001_dev = dev->lldd_dev;
	struct pm8001_hba_info *pm8001_ha = pm8001_find_ha_by_dev(dev);
	DECLARE_COMPLETION_ONSTACK(completion_setstate);
	if (dev_is_sata(dev)) {
		struct sas_phy *phy = (*klpe_sas_get_local_phy)(dev);
		rc = klpp_pm8001_exec_internal_task_abort(pm8001_ha, pm8001_dev ,
			dev, 1, 0);
		rc = (*klpe_sas_phy_reset)(phy, 1);
		sas_put_local_phy(phy);
		pm8001_dev->setds_completion = &completion_setstate;
		rc = PM8001_CHIP_DISP->set_dev_state_req(pm8001_ha,
			pm8001_dev, 0x01);
		wait_for_completion(&completion_setstate);
	} else {
		tmf_task.tmf = TMF_LU_RESET;
		rc = klpr_pm8001_issue_ssp_tmf(dev, lun, &tmf_task);
	}
	/* If failed, fall-through I_T_Nexus reset */
	PM8001_EH_DBG(pm8001_ha, pm8001_printk("for device[%x]:rc=%d\n",
		pm8001_dev->device_id, rc));
	return rc;
}

int klpp_pm8001_query_task(struct sas_task *task)
{
	u32 tag = 0xdeadbeef;
	int i = 0;
	struct scsi_lun lun;
	struct pm8001_tmf_task tmf_task;
	int rc = TMF_RESP_FUNC_FAILED;
	if (unlikely(!task || !task->lldd_task || !task->dev))
		return rc;

	if (task->task_proto & SAS_PROTOCOL_SSP) {
		struct scsi_cmnd *cmnd = task->uldd_task;
		struct domain_device *dev = task->dev;
		struct pm8001_hba_info *pm8001_ha =
			pm8001_find_ha_by_dev(dev);

		int_to_scsilun(cmnd->device->lun, &lun);
		rc = pm8001_find_tag(task, &tag);
		if (rc == 0) {
			rc = TMF_RESP_FUNC_FAILED;
			return rc;
		}
		PM8001_EH_DBG(pm8001_ha, pm8001_printk("Query:["));
		for (i = 0; i < 16; i++)
			printk(KERN_INFO "%02x ", cmnd->cmnd[i]);
		printk(KERN_INFO "]\n");
		tmf_task.tmf = 	TMF_QUERY_TASK;
		tmf_task.tag_of_task_to_be_managed = tag;

		rc = klpr_pm8001_issue_ssp_tmf(dev, lun.scsi_lun, &tmf_task);
		switch (rc) {
		/* The task is still in Lun, release it then */
		case TMF_RESP_FUNC_SUCC:
			PM8001_EH_DBG(pm8001_ha,
				pm8001_printk("The task is still in Lun\n"));
			break;
		/* The task is not in Lun or failed, reset the phy */
		case TMF_RESP_FUNC_FAILED:
		case TMF_RESP_FUNC_COMPLETE:
			PM8001_EH_DBG(pm8001_ha,
			pm8001_printk("The task is not in Lun or failed,"
			" reset the phy\n"));
			break;
		}
	}
	pm8001_printk(":rc= %d\n", rc);
	return rc;
}

int klpp_pm8001_abort_task(struct sas_task *task)
{
	unsigned long flags;
	u32 tag;
	u32 device_id;
	struct domain_device *dev ;
	struct pm8001_hba_info *pm8001_ha;
	struct scsi_lun lun;
	struct pm8001_device *pm8001_dev;
	struct pm8001_tmf_task tmf_task;
	int rc = TMF_RESP_FUNC_FAILED, ret;
	u32 phy_id;
	struct sas_task_slow slow_task;
	if (unlikely(!task || !task->lldd_task || !task->dev))
		return TMF_RESP_FUNC_FAILED;
	dev = task->dev;
	pm8001_dev = dev->lldd_dev;
	pm8001_ha = pm8001_find_ha_by_dev(dev);
	device_id = pm8001_dev->device_id;
	phy_id = pm8001_dev->attached_phy;
	rc = pm8001_find_tag(task, &tag);
	if (rc == 0) {
		pm8001_printk("no tag for task:%p\n", task);
		return TMF_RESP_FUNC_FAILED;
	}
	spin_lock_irqsave(&task->task_state_lock, flags);
	if (task->task_state_flags & SAS_TASK_STATE_DONE) {
		spin_unlock_irqrestore(&task->task_state_lock, flags);
		return TMF_RESP_FUNC_COMPLETE;
	}
	task->task_state_flags |= SAS_TASK_STATE_ABORTED;
	if (task->slow_task == NULL) {
		init_completion(&slow_task.completion);
		task->slow_task = &slow_task;
	}
	spin_unlock_irqrestore(&task->task_state_lock, flags);
	if (task->task_proto & SAS_PROTOCOL_SSP) {
		struct scsi_cmnd *cmnd = task->uldd_task;
		int_to_scsilun(cmnd->device->lun, &lun);
		tmf_task.tmf = TMF_ABORT_TASK;
		tmf_task.tag_of_task_to_be_managed = tag;
		rc = klpr_pm8001_issue_ssp_tmf(dev, lun.scsi_lun, &tmf_task);
		klpp_pm8001_exec_internal_task_abort(pm8001_ha, pm8001_dev,
			pm8001_dev->sas_device, 0, tag);
	} else if (task->task_proto & SAS_PROTOCOL_SATA ||
		task->task_proto & SAS_PROTOCOL_STP) {
		if (pm8001_ha->chip_id == chip_8006) {
			DECLARE_COMPLETION_ONSTACK(completion_reset);
			DECLARE_COMPLETION_ONSTACK(completion);
			struct pm8001_phy *phy = pm8001_ha->phy + phy_id;

			/* 1. Set Device state as Recovery */
			pm8001_dev->setds_completion = &completion;
			PM8001_CHIP_DISP->set_dev_state_req(pm8001_ha,
				pm8001_dev, 0x03);
			wait_for_completion(&completion);

			/* 2. Send Phy Control Hard Reset */
			reinit_completion(&completion);
			phy->reset_success = false;
			phy->enable_completion = &completion;
			phy->reset_completion = &completion_reset;
			ret = PM8001_CHIP_DISP->phy_ctl_req(pm8001_ha, phy_id,
				PHY_HARD_RESET);
			if (ret)
				goto out;
			PM8001_MSG_DBG(pm8001_ha,
				pm8001_printk("Waiting for local phy ctl\n"));
			wait_for_completion(&completion);
			if (!phy->reset_success)
				goto out;

			/* 3. Wait for Port Reset complete / Port reset TMO */
			PM8001_MSG_DBG(pm8001_ha,
				pm8001_printk("Waiting for Port reset\n"));
			wait_for_completion(&completion_reset);
			if (phy->port_reset_status)
				goto out;

			/*
			 * 4. SATA Abort ALL
			 * we wait for the task to be aborted so that the task
			 * is removed from the ccb. on success the caller is
			 * going to free the task.
			 */
			ret = klpp_pm8001_exec_internal_task_abort(pm8001_ha,
				pm8001_dev, pm8001_dev->sas_device, 1, tag);
			if (ret)
				goto out;
			ret = wait_for_completion_timeout(
				&task->slow_task->completion,
				PM8001_TASK_TIMEOUT * HZ);
			if (!ret)
				goto out;

			/* 5. Set Device State as Operational */
			reinit_completion(&completion);
			pm8001_dev->setds_completion = &completion;
			PM8001_CHIP_DISP->set_dev_state_req(pm8001_ha,
				pm8001_dev, 0x01);
			wait_for_completion(&completion);
		} else {
			rc = klpp_pm8001_exec_internal_task_abort(pm8001_ha,
				pm8001_dev, pm8001_dev->sas_device, 0, tag);
		}
		rc = TMF_RESP_FUNC_COMPLETE;
	} else if (task->task_proto & SAS_PROTOCOL_SMP) {
		/* SMP */
		rc = klpp_pm8001_exec_internal_task_abort(pm8001_ha, pm8001_dev,
			pm8001_dev->sas_device, 0, tag);

	}
out:
	spin_lock_irqsave(&task->task_state_lock, flags);
	if (task->slow_task == &slow_task)
		task->slow_task = NULL;
	spin_unlock_irqrestore(&task->task_state_lock, flags);
	if (rc != TMF_RESP_FUNC_COMPLETE)
		pm8001_printk("rc= %d\n", rc);
	return rc;
}

int klpp_pm8001_abort_task_set(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct pm8001_tmf_task tmf_task;

	tmf_task.tmf = TMF_ABORT_TASK_SET;
	rc = klpr_pm8001_issue_ssp_tmf(dev, lun, &tmf_task);
	return rc;
}

int klpp_pm8001_clear_aca(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct pm8001_tmf_task tmf_task;

	tmf_task.tmf = TMF_CLEAR_ACA;
	rc = klpr_pm8001_issue_ssp_tmf(dev, lun, &tmf_task);

	return rc;
}

int klpp_pm8001_clear_task_set(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct pm8001_tmf_task tmf_task;
	struct pm8001_device *pm8001_dev = dev->lldd_dev;
	struct pm8001_hba_info *pm8001_ha = pm8001_find_ha_by_dev(dev);

	PM8001_EH_DBG(pm8001_ha,
		pm8001_printk("I_T_L_Q clear task set[%x]\n",
		pm8001_dev->device_id));
	tmf_task.tmf = TMF_CLEAR_TASK_SET;
	rc = klpr_pm8001_issue_ssp_tmf(dev, lun, &tmf_task);
	return rc;
}


#include "livepatch_bsc1228012.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "pm80xx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "pm8001_tag_alloc", (void *)&klpe_pm8001_tag_alloc, "pm80xx" },
	{ "pm8001_tag_free", (void *)&klpe_pm8001_tag_free, "pm80xx" },
	{ "pm8001_task_done", (void *)&klpe_pm8001_task_done, "pm80xx" },
	{ "pm8001_tmf_timedout", (void *)&klpe_pm8001_tmf_timedout, "pm80xx" },
	{ "sas_alloc_slow_task", (void *)&klpe_sas_alloc_slow_task, "libsas" },
	{ "sas_free_task", (void *)&klpe_sas_free_task, "libsas" },
	{ "sas_get_local_phy", (void *)&klpe_sas_get_local_phy, "libsas" },
	{ "sas_phy_reset", (void *)&klpe_sas_phy_reset, "libsas" },
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

int livepatch_bsc1228012_init(void)
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

void livepatch_bsc1228012_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SCSI_PM8001) */
