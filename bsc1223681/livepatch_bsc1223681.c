/*
 * livepatch_bsc1223681
 *
 * Fix for CVE-2024-26930, bsc#1223681
 *
 *  Upstream commit:
 *  e288285d4778 ("scsi: qla2xxx: Fix double free of the ha->vp_map pointer")
 *
 *  SLE12-SP5 commit:
 *  1bab65d134dc5623231f15214f30f0020fa5bdd5
 *  e55f751b7cdb060415ac38c3ca09cd9316fef923
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  dba3cc608d85afc01a3366af734cb60fb8e2cf01
 *
 *  Copyright (c) 2024 SUSE
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

#if IS_ENABLED(CONFIG_SCSI_QLA_FC)

#if !IS_MODULE(CONFIG_SCSI_QLA_FC)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/scsi/qla2xxx/qla_def.h */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/dmapool.h>
#include <linux/mempool.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/btree.h>

/* klp-ccp: from include/scsi/scsi.h */
#define _SCSI_SCSI_H

/* klp-ccp: from include/scsi/scsi_transport_fc.h */
#define SCSI_TRANSPORT_FC_H

/* klp-ccp: from drivers/scsi/qla2xxx/qla_def.h */
#include <uapi/scsi/fc/fc_els.h>

typedef struct {
	uint8_t domain;
	uint8_t area;
	uint8_t al_pa;
} be_id_t;

typedef union {
	uint32_t b24 : 24;
	struct {
#ifdef __BIG_ENDIAN
#error "klp-ccp: non-taken branch"
#elif defined(__LITTLE_ENDIAN)
		uint8_t al_pa;
		uint8_t area;
		uint8_t domain;
#else
#error "klp-ccp: non-taken branch"
#endif
		uint8_t rsvd_1;
	} b;
} port_id_t;

/* klp-ccp: from drivers/scsi/qla2xxx/qla_edif_bsg.h */
#define	ELS_MAX_PAYLOAD		2112

#define WWN_SIZE		8

/* klp-ccp: from drivers/scsi/qla2xxx/qla_dsd.h */
#include <asm/unaligned.h>

struct dsd64 {
	__le64 address;
	__le32 length;
} __packed;

/* klp-ccp: from drivers/scsi/qla2xxx/qla_nx.h */
#include <scsi/scsi.h>

struct qla82xx_legacy_intr_set {
	uint32_t	int_vec_bit;
	uint32_t	tgt_status_reg;
	uint32_t	tgt_mask_reg;
	uint32_t	pci_int_reg;
};

struct device_reg_82xx {
	__le32	req_q_out[64];		/* Request Queue out-Pointer (64 * 4) */
	__le32	rsp_q_in[64];		/* Response Queue In-Pointer. */
	__le32	rsp_q_out[64];		/* Response Queue Out-Pointer. */

	__le16	mailbox_in[32];		/* Mailbox In registers */
	__le16	unused_1[32];
	__le32	hint;			/* Host interrupt register */
	__le16	unused_2[62];
	__le16	mailbox_out[32];	/* Mailbox Out registers */
	__le32	unused_3[48];

	__le32	host_status;		/* host status */
	__le32	host_int;		/* Interrupt status. */
};

struct dsd_dma {
	struct list_head list;
	dma_addr_t dsd_list_dma;
	void *dsd_addr;
};

struct ct6_dsd {
	uint16_t fcp_cmnd_len;
	dma_addr_t fcp_cmnd_dma;
	struct fcp_cmnd *fcp_cmnd;
	int dsd_use_cnt;
	struct list_head dsd_list;
};

/* klp-ccp: from drivers/scsi/qla2xxx/qla_nvme.h */
#include <uapi/scsi/fc/fc_els.h>

/* klp-ccp: from drivers/scsi/qla2xxx/qla_def.h */
#define QLA2XXX_DRIVER_NAME	"qla2xxx"

#define MAILBOX_REGISTER_COUNT		32

#define BIT_0	0x1
#define BIT_1	0x2

#define BIT_13	0x2000
#define BIT_14	0x4000
#define BIT_15	0x8000
#define BIT_16	0x10000
#define BIT_17	0x20000
#define BIT_18	0x40000
#define BIT_19	0x80000
#define BIT_20	0x100000
#define BIT_21	0x200000

#define BIT_23	0x800000

#define BIT_25	0x2000000
#define BIT_26	0x4000000
#define BIT_27	0x8000000

#define MSD(x)	((uint32_t)((((uint64_t)(x)) >> 16) >> 16))

#define MAX_FIBRE_DEVICES_2100	512
#define MAX_FIBRE_DEVICES_2400	2048

#define MAX_FIBRE_DEVICES_MAX	MAX_FIBRE_DEVICES_2400
#define LOOPID_MAP_SIZE		(ha->max_fibre_devices)

#define SNS_FIRST_LOOP_ID	0x81
#define MANAGEMENT_SERVER	0xfe
#define BROADCAST		0xff

#define MAX_CMDSZ	16		/* SCSI maximum CDB size. */

/* klp-ccp: from drivers/scsi/qla2xxx/qla_fw.h */
struct device_reg_24xx {
	__le32	flash_addr;		/* Flash/NVRAM BIOS address. */



					/*
					 * RISC code begins at offset 512KB
					 * within flash. Consisting of two
					 * contiguous RISC code segments.
					 */



/*
 * Flash Error Log Event Codes.
 */

	__le32	flash_data;		/* Flash/NVRAM BIOS data. */

	__le32	ctrl_status;		/* Control/Status. */
					/* PCI-X Bus Mode. */
					/* Max Write Burst byte count. */


	__le32	ictrl;			/* Interrupt control. */

	__le32	istatus;		/* Interrupt status. */

	__le32	unused_1[2];		/* Gap. */

					/* Request Queue. */
	__le32	req_q_in;		/*  In-Pointer. */
	__le32	req_q_out;		/*  Out-Pointer. */
					/* Response Queue. */
	__le32	rsp_q_in;		/*  In-Pointer. */
	__le32	rsp_q_out;		/*  Out-Pointer. */
					/* Priority Request Queue. */
	__le32	preq_q_in;		/*  In-Pointer. */
	__le32	preq_q_out;		/*  Out-Pointer. */

	__le32	unused_2[2];		/* Gap. */

					/* ATIO Queue. */
	__le32	atio_q_in;		/*  In-Pointer. */
	__le32	atio_q_out;		/*  Out-Pointer. */

	__le32	host_status;

	__le32	hccr;			/* Host command & control register. */
					/* HCCR statuses. */
					/* HCCR commands. */
					/* NOOP. */
					/* Set RISC Reset. */
					/* Clear RISC Reset. */
					/* Set RISC Pause. */
					/* Releases RISC Pause. */
					/* Set HOST to RISC interrupt. */
					/* Clear HOST to RISC interrupt. */
					/* Clear RISC to PCI interrupt. */

	__le32	gpiod;			/* GPIO Data register. */

					/* LED update mask. */
					/* Data update mask. */
					/* Data update mask. */
					/* LED control mask. */
					/* LED bit values. Color names as
					 * referenced in fw spec.
					 */
					/* Data in/out. */

	__le32	gpioe;			/* GPIO Enable register. */
					/* Enable update mask. */
					/* Enable update mask. */
					/* Enable. */

	__le32	iobase_addr;		/* I/O Bus Base Address register. */

	__le32	unused_3[10];		/* Gap. */

	__le16	mailbox0;
	__le16	mailbox1;
	__le16	mailbox2;
	__le16	mailbox3;
	__le16	mailbox4;
	__le16	mailbox5;
	__le16	mailbox6;
	__le16	mailbox7;
	__le16	mailbox8;
	__le16	mailbox9;
	__le16	mailbox10;
	__le16	mailbox11;
	__le16	mailbox12;
	__le16	mailbox13;
	__le16	mailbox14;
	__le16	mailbox15;
	__le16	mailbox16;
	__le16	mailbox17;
	__le16	mailbox18;
	__le16	mailbox19;
	__le16	mailbox20;
	__le16	mailbox21;
	__le16	mailbox22;
	__le16	mailbox23;
	__le16	mailbox24;
	__le16	mailbox25;
	__le16	mailbox26;
	__le16	mailbox27;
	__le16	mailbox28;
	__le16	mailbox29;
	__le16	mailbox30;
	__le16	mailbox31;

	__le32	iobase_window;
	__le32	iobase_c4;
	__le32	iobase_c8;
	__le32	unused_4_1[6];		/* Gap. */
	__le32	iobase_q;
	__le32	unused_5[2];		/* Gap. */
	__le32	iobase_select;
	__le32	unused_6[2];		/* Gap. */
	__le32	iobase_sdata;
};

#define MAX_MULTI_ID_FABRIC	256	/* ... */

struct qla_flt_region {
	__le16	code;
	uint8_t attribute;
	uint8_t reserved;
	__le32 size;
	__le32 start;
	__le32 end;
};

struct qla_flt_header {
	__le16	version;
	__le16	length;
	__le16	checksum;
	__le16	unused;
	struct qla_flt_region region[0];
};

#define FLT_REGION_SIZE		16
#define FLT_MAX_REGIONS		0xFF
#define FLT_REGIONS_SIZE	(FLT_REGION_SIZE * FLT_MAX_REGIONS)

struct qla_npiv_entry {
	__le16	flags;
	__le16	vf_id;
	uint8_t q_qos;
	uint8_t f_qos;
	__le16	unused1;
	uint8_t port_name[WWN_SIZE];
	uint8_t node_name[WWN_SIZE];
};

/* klp-ccp: from drivers/scsi/qla2xxx/qla_def.h */
struct els_reject {
	struct fc_els_ls_rjt *c;
	dma_addr_t  cdma;
	u16 size;
};

typedef struct srb srb_t;

struct device_reg_2xxx {
	__le16	flash_address; 	/* Flash BIOS address */
	__le16	flash_data;		/* Flash BIOS data */
	__le16	unused_1[1];		/* Gap */
	__le16	ctrl_status;		/* Control/Status */

	__le16	ictrl;			/* Interrupt control */

	__le16	istatus;		/* Interrupt status */

	__le16	semaphore;		/* Semaphore */
	__le16	nvram;			/* NVRAM register. */


	union {
		struct {
			__le16	mailbox0;
			__le16	mailbox1;
			__le16	mailbox2;
			__le16	mailbox3;
			__le16	mailbox4;
			__le16	mailbox5;
			__le16	mailbox6;
			__le16	mailbox7;
			__le16	unused_2[59];	/* Gap */
		} __attribute__((packed)) isp2100;
		struct {
						/* Request Queue */
			__le16	req_q_in;	/*  In-Pointer */
			__le16	req_q_out;	/*  Out-Pointer */
						/* Response Queue */
			__le16	rsp_q_in;	/*  In-Pointer */
			__le16	rsp_q_out;	/*  Out-Pointer */

						/* RISC to Host Status */
			__le32	host_status;

					/* Host to Host Semaphore */
			__le16	host_semaphore;
			__le16	unused_3[17];	/* Gap */
			__le16	mailbox0;
			__le16	mailbox1;
			__le16	mailbox2;
			__le16	mailbox3;
			__le16	mailbox4;
			__le16	mailbox5;
			__le16	mailbox6;
			__le16	mailbox7;
			__le16	mailbox8;
			__le16	mailbox9;
			__le16	mailbox10;
			__le16	mailbox11;
			__le16	mailbox12;
			__le16	mailbox13;
			__le16	mailbox14;
			__le16	mailbox15;
			__le16	mailbox16;
			__le16	mailbox17;
			__le16	mailbox18;
			__le16	mailbox19;
			__le16	mailbox20;
			__le16	mailbox21;
			__le16	mailbox22;
			__le16	mailbox23;
			__le16	mailbox24;
			__le16	mailbox25;
			__le16	mailbox26;
			__le16	mailbox27;
			__le16	mailbox28;
			__le16	mailbox29;
			__le16	mailbox30;
			__le16	mailbox31;
			__le16	fb_cmd;
			__le16	unused_4[10];	/* Gap */
		} __attribute__((packed)) isp2300;
	} u;

	__le16	fpm_diag_config;
	__le16	unused_5[0x4];		/* Gap */
	__le16	risc_hw;
	__le16	unused_5_1;		/* Gap */
	__le16	pcr;			/* Processor Control Register. */
	__le16	unused_6[0x5];		/* Gap */
	__le16	mctr;			/* Memory Configuration and Timing. */
	__le16	unused_7[0x3];		/* Gap */
	__le16	fb_cmd_2100;		/* Unused on 23XX */
	__le16	unused_8[0x3];		/* Gap */
	__le16	hccr;			/* Host command & control register. */
					/* HCCR commands */

	__le16	unused_9[5];		/* Gap */
	__le16	gpiod;			/* GPIO Data register. */
	__le16	gpioe;			/* GPIO Enable register. */

	union {
		struct {
			__le16	unused_10[8];	/* Gap */
			__le16	mailbox8;
			__le16	mailbox9;
			__le16	mailbox10;
			__le16	mailbox11;
			__le16	mailbox12;
			__le16	mailbox13;
			__le16	mailbox14;
			__le16	mailbox15;
			__le16	mailbox16;
			__le16	mailbox17;
			__le16	mailbox18;
			__le16	mailbox19;
			__le16	mailbox20;
			__le16	mailbox21;
			__le16	mailbox22;
			__le16	mailbox23;	/* Also probe reg. */
		} __attribute__((packed)) isp2200;
	} u_end;
};

struct device_reg_25xxmq {
	__le32	req_q_in;
	__le32	req_q_out;
	__le32	rsp_q_in;
	__le32	rsp_q_out;
	__le32	atio_q_in;
	__le32	atio_q_out;
};

struct device_reg_fx00 {
	__le32	mailbox0;		/* 00 */
	__le32	mailbox1;		/* 04 */
	__le32	mailbox2;		/* 08 */
	__le32	mailbox3;		/* 0C */
	__le32	mailbox4;		/* 10 */
	__le32	mailbox5;		/* 14 */
	__le32	mailbox6;		/* 18 */
	__le32	mailbox7;		/* 1C */
	__le32	mailbox8;		/* 20 */
	__le32	mailbox9;		/* 24 */
	__le32	mailbox10;		/* 28 */
	__le32	mailbox11;
	__le32	mailbox12;
	__le32	mailbox13;
	__le32	mailbox14;
	__le32	mailbox15;
	__le32	mailbox16;
	__le32	mailbox17;
	__le32	mailbox18;
	__le32	mailbox19;
	__le32	mailbox20;
	__le32	mailbox21;
	__le32	mailbox22;
	__le32	mailbox23;
	__le32	mailbox24;
	__le32	mailbox25;
	__le32	mailbox26;
	__le32	mailbox27;
	__le32	mailbox28;
	__le32	mailbox29;
	__le32	mailbox30;
	__le32	mailbox31;
	__le32	aenmailbox0;
	__le32	aenmailbox1;
	__le32	aenmailbox2;
	__le32	aenmailbox3;
	__le32	aenmailbox4;
	__le32	aenmailbox5;
	__le32	aenmailbox6;
	__le32	aenmailbox7;
	/* Request Queue. */
	__le32	req_q_in;		/* A0 - Request Queue In-Pointer */
	__le32	req_q_out;		/* A4 - Request Queue Out-Pointer */
	/* Response Queue. */
	__le32	rsp_q_in;		/* A8 - Response Queue In-Pointer */
	__le32	rsp_q_out;		/* AC - Response Queue Out-Pointer */
	/* Init values shadowed on FW Up Event */
	__le32	initval0;		/* B0 */
	__le32	initval1;		/* B4 */
	__le32	initval2;		/* B8 */
	__le32	initval3;		/* BC */
	__le32	initval4;		/* C0 */
	__le32	initval5;		/* C4 */
	__le32	initval6;		/* C8 */
	__le32	initval7;		/* CC */
	__le32	fwheartbeat;		/* D0 */
	__le32	pseudoaen;		/* D4 */
};

typedef union {
		struct device_reg_2xxx isp;
		struct device_reg_24xx isp24;
		struct device_reg_25xxmq isp25mq;
		struct device_reg_82xx isp82;
		struct device_reg_fx00 ispfx00;
} __iomem device_reg_t;

typedef struct {
	uint32_t	out_mb;		/* outbound from driver */
	uint32_t	in_mb;			/* Incoming from RISC */
	uint16_t	mb[MAILBOX_REGISTER_COUNT];
	long		buf_size;
	void		*bufp;
	uint32_t	tov;
	uint8_t		flags;
} mbx_cmd_t;

typedef struct {
	uint8_t  version;
	uint8_t  reserved_1;

	/*
	 * LSB BIT 0  = Enable Hard Loop Id
	 * LSB BIT 1  = Enable Fairness
	 * LSB BIT 2  = Enable Full-Duplex
	 * LSB BIT 3  = Enable Fast Posting
	 * LSB BIT 4  = Enable Target Mode
	 * LSB BIT 5  = Disable Initiator Mode
	 * LSB BIT 6  = Enable ADISC
	 * LSB BIT 7  = Enable Target Inquiry Data
	 *
	 * MSB BIT 0  = Enable PDBC Notify
	 * MSB BIT 1  = Non Participating LIP
	 * MSB BIT 2  = Descending Loop ID Search
	 * MSB BIT 3  = Acquire Loop ID in LIPA
	 * MSB BIT 4  = Stop PortQ on Full Status
	 * MSB BIT 5  = Full Login after LIP
	 * MSB BIT 6  = Node Name Option
	 * MSB BIT 7  = Ext IFWCB enable bit
	 */
	uint8_t  firmware_options[2];

	__le16	frame_payload_size;
	__le16	max_iocb_allocation;
	__le16	execution_throttle;
	uint8_t  retry_count;
	uint8_t	 retry_delay;			/* unused */
	uint8_t	 port_name[WWN_SIZE];		/* Big endian. */
	uint16_t hard_address;
	uint8_t	 inquiry_data;
	uint8_t	 login_timeout;
	uint8_t	 node_name[WWN_SIZE];		/* Big endian. */

	__le16	request_q_outpointer;
	__le16	response_q_inpointer;
	__le16	request_q_length;
	__le16	response_q_length;
	__le64  request_q_address __packed;
	__le64  response_q_address __packed;

	__le16	lun_enables;
	uint8_t  command_resource_count;
	uint8_t  immediate_notify_resource_count;
	__le16	timeout;
	uint8_t  reserved_2[2];

	/*
	 * LSB BIT 0 = Timer Operation mode bit 0
	 * LSB BIT 1 = Timer Operation mode bit 1
	 * LSB BIT 2 = Timer Operation mode bit 2
	 * LSB BIT 3 = Timer Operation mode bit 3
	 * LSB BIT 4 = Init Config Mode bit 0
	 * LSB BIT 5 = Init Config Mode bit 1
	 * LSB BIT 6 = Init Config Mode bit 2
	 * LSB BIT 7 = Enable Non part on LIHA failure
	 *
	 * MSB BIT 0 = Enable class 2
	 * MSB BIT 1 = Enable ACK0
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 = FC Tape Enable
	 * MSB BIT 5 = Enable FC Confirm
	 * MSB BIT 6 = Enable command queuing in target mode
	 * MSB BIT 7 = No Logo On Link Down
	 */
	uint8_t	 add_firmware_options[2];

	uint8_t	 response_accumulation_timer;
	uint8_t	 interrupt_delay_timer;

	/*
	 * LSB BIT 0 = Enable Read xfr_rdy
	 * LSB BIT 1 = Soft ID only
	 * LSB BIT 2 =
	 * LSB BIT 3 =
	 * LSB BIT 4 = FCP RSP Payload [0]
	 * LSB BIT 5 = FCP RSP Payload [1] / Sbus enable - 2200
	 * LSB BIT 6 = Enable Out-of-Order frame handling
	 * LSB BIT 7 = Disable Automatic PLOGI on Local Loop
	 *
	 * MSB BIT 0 = Sbus enable - 2300
	 * MSB BIT 1 =
	 * MSB BIT 2 =
	 * MSB BIT 3 =
	 * MSB BIT 4 = LED mode
	 * MSB BIT 5 = enable 50 ohm termination
	 * MSB BIT 6 = Data Rate (2300 only)
	 * MSB BIT 7 = Data Rate (2300 only)
	 */
	uint8_t	 special_options[2];

	uint8_t  reserved_3[26];
} init_cb_t;

typedef struct {
	uint8_t		entry_type;		/* Entry type. */
	uint8_t		entry_count;		/* Entry count. */
	uint8_t		sys_define;		/* System defined. */
	uint8_t		entry_status;		/* Entry Status. */
	uint32_t	handle;			/* System defined handle */
	uint8_t		data[52];
	uint32_t	signature;
} response_t;

typedef union {
	__le16	extended;
	struct {
		uint8_t reserved;
		uint8_t standard;
	} id;
} target_id_t;

typedef struct {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle. */
	target_id_t target;		/* SCSI ID */
	__le16	lun;			/* SCSI LUN */
	__le16	control_flags;		/* Control flags. */
	uint16_t reserved_1;
	__le16	timeout;		/* Command timeout. */
	__le16	dseg_count;		/* Data segment count. */
	uint8_t scsi_cdb[MAX_CMDSZ];	/* SCSI command words. */
	uint32_t byte_count;		/* Total byte count. */
	struct dsd64 dsd[2];
} request_t;

typedef struct {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t handle_count;		/* Handle count. */
	uint8_t entry_status;		/* Entry Status. */
	uint32_t handle1;		/* System handle. */
	target_id_t loop_id;
	__le16	status;
	__le16	control_flags;		/* Control flags. */
	uint16_t reserved2;
	__le16	timeout;
	__le16	cmd_dsd_count;
	__le16	total_dsd_count;
	uint8_t type;
	uint8_t r_ctl;
	__le16	rx_id;
	uint16_t reserved3;
	uint32_t handle2;
	__le32	rsp_bytecount;
	__le32	req_bytecount;
	struct dsd64 req_dsd;
	struct dsd64 rsp_dsd;
} ms_iocb_entry_t;

#define REQUEST_ENTRY_SIZE	(sizeof(request_t))

#define IOCB_SIZE 64

typedef enum {
	FCT_UNKNOWN,
	FCT_BROADCAST = 0x01,
	FCT_INITIATOR = 0x02,
	FCT_TARGET    = 0x04,
	FCT_NVME_INITIATOR = 0x10,
	FCT_NVME_TARGET = 0x20,
	FCT_NVME_DISCOVERY = 0x40,
	FCT_NVME = 0xf0,
} fc_port_type_t;

enum qlt_plogi_link_t {
	QLT_PLOGI_LINK_SAME_WWN,
	QLT_PLOGI_LINK_CONFLICT,
	QLT_PLOGI_LINK_MAX
};

struct ct_sns_desc {
	struct ct_sns_pkt	*ct_sns;
	dma_addr_t		ct_sns_dma;
};

enum discovery_state {
	DSC_DELETED,
	DSC_GNL,
	DSC_LOGIN_PEND,
	DSC_LOGIN_FAILED,
	DSC_GPDB,
	DSC_UPD_FCPORT,
	DSC_LOGIN_COMPLETE,
	DSC_ADISC,
	DSC_DELETE_PEND,
	DSC_LOGIN_AUTH_PEND,
};

enum login_state {	/* FW control Target side */
	DSC_LS_LLIOCB_SENT = 2,
	DSC_LS_PLOGI_PEND,
	DSC_LS_PLOGI_COMP,
	DSC_LS_PRLI_PEND,
	DSC_LS_PRLI_COMP,
	DSC_LS_PORT_UNAVAIL,
	DSC_LS_PRLO_PEND = 9,
	DSC_LS_LOGO_PEND,
};

typedef struct fc_port {
	struct list_head list;
	struct scsi_qla_host *vha;

	unsigned int conf_compl_supported:1;
	unsigned int deleted:2;
	unsigned int free_pending:1;
	unsigned int local:1;
	unsigned int logout_on_delete:1;
	unsigned int logo_ack_needed:1;
	unsigned int keep_nport_handle:1;
	unsigned int send_els_logo:1;
	unsigned int login_pause:1;
	unsigned int login_succ:1;
	unsigned int query:1;
	unsigned int id_changed:1;
	unsigned int scan_needed:1;
	unsigned int n2n_flag:1;
	unsigned int explicit_logout:1;
	unsigned int prli_pend_timer:1;
	unsigned int do_prli_nvme:1;

	uint8_t nvme_flag;
	uint8_t node_name[WWN_SIZE];
	uint8_t port_name[WWN_SIZE];
	port_id_t d_id;
	uint16_t loop_id;
	uint16_t old_loop_id;

	struct completion nvme_del_done;
	uint32_t nvme_prli_service_param;

	uint32_t nvme_first_burst_size;

	struct fc_port *conflict;
	unsigned char logout_completed;
	int generation;

	struct se_session *se_sess;
	struct list_head sess_cmd_list;
	spinlock_t sess_cmd_lock;
	struct kref sess_kref;
	struct qla_tgt *tgt;
	unsigned long expires;
	struct list_head del_list_entry;
	struct work_struct free_work;
	struct work_struct reg_work;
	uint64_t jiffies_at_registration;
	unsigned long prli_expired;
	struct qlt_plogi_ack_t *plogi_link[QLT_PLOGI_LINK_MAX];

	uint16_t tgt_id;
	uint16_t old_tgt_id;
	uint16_t sec_since_registration;

	uint8_t fcp_prio;

	uint8_t fabric_port_name[WWN_SIZE];
	uint16_t fp_speed;

	fc_port_type_t port_type;

	atomic_t state;
	uint32_t flags;

	int login_retry;

	struct fc_rport *rport;
	u32 supported_classes;

	uint8_t fc4_type;
	uint8_t fc4_features;
	uint8_t scan_state;

	unsigned long last_queue_full;
	unsigned long last_ramp_up;

	uint16_t port_id;

	struct nvme_fc_remote_port *nvme_remote_port;

	unsigned long retry_delay_timestamp;
	struct qla_tgt_sess *tgt_session;
	struct ct_sns_desc ct_desc;
	enum discovery_state disc_state;
	atomic_t shadow_disc_state;
	enum discovery_state next_disc_state;
	enum login_state fw_login_state;
	unsigned long dm_login_expire;
	unsigned long plogi_nack_done_deadline;

	u32 login_gen, last_login_gen;
	u32 rscn_gen, last_rscn_gen;
	u32 chip_reset;
	struct list_head gnl_entry;
	struct work_struct del_work;
	u8 iocb[IOCB_SIZE];
	u8 current_login_state;
	u8 last_login_state;
	u16 n2n_link_reset_cnt;
	u16 n2n_chip_reset;

	struct dentry *dfs_rport_dir;

	u64 tgt_short_link_down_cnt;
	u64 tgt_link_down_time;
	u64 dev_loss_tmo;
	/*
	 * EDIF parameters for encryption.
	 */
	struct {
		uint32_t	enable:1;	/* device is edif enabled/req'd */
		uint32_t	app_stop:2;
		uint32_t	aes_gmac:1;
		uint32_t	app_sess_online:1;
		uint32_t	tx_sa_set:1;
		uint32_t	rx_sa_set:1;
		uint32_t	tx_sa_pending:1;
		uint32_t	rx_sa_pending:1;
		uint32_t	tx_rekey_cnt;
		uint32_t	rx_rekey_cnt;
		uint64_t	tx_bytes;
		uint64_t	rx_bytes;
		uint8_t		sess_down_acked;
		uint8_t		auth_state;
		uint16_t	authok:1;
		uint16_t	rekey_cnt;
		struct list_head edif_indx_list;
		spinlock_t  indx_list_lock;

		struct list_head tx_sa_list;
		struct list_head rx_sa_list;
		spinlock_t	sa_list_lock;
	} edif;
} fc_port_t;

/* klp-ccp: from drivers/scsi/qla2xxx/qla_mr.h */
#define AEN_MAILBOX_REGISTER_COUNT_FX00	8

struct mr_data_fx00 {
	uint8_t	symbolic_name[64];
	uint8_t	serial_num[32];
	uint8_t	hw_version[16];
	uint8_t	fw_version[16];
	uint8_t	uboot_version[16];
	uint8_t	fru_serial_num[32];
	fc_port_t       fcport;		/* fcport used for requests
					 * that are not linked
					 * to a particular target
					 */
	uint8_t fw_hbt_en;
	uint8_t fw_hbt_cnt;
	uint8_t fw_hbt_miss_cnt;
	uint32_t old_fw_hbt_cnt;
	uint16_t fw_reset_timer_tick;
	uint8_t fw_reset_timer_exp;
	uint16_t fw_critemp_timer_tick;
	uint32_t old_aenmbx0_state;
	uint32_t critical_temperature;
	bool extended_io_enabled;
	bool host_info_resend;
	uint8_t hinfo_resend_timer_tick;
};

/* klp-ccp: from drivers/scsi/qla2xxx/qla_def.h */
#define FDMI1_HBA_ATTR_COUNT			10
#define FDMI2_HBA_ATTR_COUNT			17

struct ct_fdmi_hba_attr {
	__be16	type;
	__be16	len;
	union {
		uint8_t node_name[WWN_SIZE];
		uint8_t manufacturer[64];
		uint8_t serial_num[32];
		uint8_t model[16+1];
		uint8_t model_desc[80];
		uint8_t hw_version[32];
		uint8_t driver_version[32];
		uint8_t orom_version[16];
		uint8_t fw_version[32];
		uint8_t os_version[128];
		__be32	 max_ct_len;

		uint8_t sym_name[256];
		__be32	 vendor_specific_info;
		__be32	 num_ports;
		uint8_t fabric_name[WWN_SIZE];
		uint8_t bios_name[32];
		uint8_t vendor_identifier[8];
	} a;
};

struct ct_fdmi1_hba_attributes {
	__be32	count;
	struct ct_fdmi_hba_attr entry[FDMI1_HBA_ATTR_COUNT];
};

struct ct_fdmi2_hba_attributes {
	__be32	count;
	struct ct_fdmi_hba_attr entry[FDMI2_HBA_ATTR_COUNT];
};

#define FDMI2_PORT_ATTR_COUNT		16

struct ct_fdmi_port_attr {
	__be16	type;
	__be16	len;
	union {
		uint8_t fc4_types[32];
		__be32	sup_speed;
		__be32	cur_speed;
		__be32	max_frame_size;
		uint8_t os_dev_name[32];
		uint8_t host_name[256];

		uint8_t node_name[WWN_SIZE];
		uint8_t port_name[WWN_SIZE];
		uint8_t port_sym_name[128];
		__be32	port_type;
		__be32	port_supported_cos;
		uint8_t fabric_name[WWN_SIZE];
		uint8_t port_fc4_type[32];
		__be32	 port_state;
		__be32	 num_ports;
		__be32	 port_id;

		uint8_t smartsan_service[24];
		uint8_t smartsan_guid[16];
		uint8_t smartsan_version[24];
		uint8_t smartsan_prod_name[16];
		__be32	 smartsan_port_info;
		__be32	 smartsan_qos_support;
		__be32	 smartsan_security_support;
	} a;
};

struct ct_fdmi2_port_attributes {
	__be32	count;
	struct ct_fdmi_port_attr entry[FDMI2_PORT_ATTR_COUNT];
};

struct ct_cmd_hdr {
	uint8_t revision;
	uint8_t in_id[3];
	uint8_t gs_type;
	uint8_t gs_subtype;
	uint8_t options;
	uint8_t reserved;
};

struct ct_sns_req {
	struct ct_cmd_hdr header;
	__be16	command;
	__be16	max_rsp_size;
	uint8_t fragment_id;
	uint8_t reserved[3];

	union {
		/* GA_NXT, GPN_ID, GNN_ID, GFT_ID, GFPN_ID */
		struct {
			uint8_t reserved;
			be_id_t port_id;
		} port_id;

		struct {
			uint8_t reserved;
			uint8_t domain;
			uint8_t area;
			uint8_t port_type;
		} gpn_ft;

		struct {
			uint8_t port_type;
			uint8_t domain;
			uint8_t area;
			uint8_t reserved;
		} gid_pt;

		struct {
			uint8_t reserved;
			be_id_t port_id;
			uint8_t fc4_types[32];
		} rft_id;

		struct {
			uint8_t reserved;
			be_id_t port_id;
			uint16_t reserved2;
			uint8_t fc4_feature;
			uint8_t fc4_type;
		} rff_id;

		struct {
			uint8_t reserved;
			be_id_t port_id;
			uint8_t node_name[8];
		} rnn_id;

		struct {
			uint8_t node_name[8];
			uint8_t name_len;
			uint8_t sym_node_name[255];
		} rsnn_nn;

		struct {
			uint8_t hba_identifier[8];
		} ghat;

		struct {
			uint8_t hba_identifier[8];
			__be32	entry_count;
			uint8_t port_name[8];
			struct ct_fdmi2_hba_attributes attrs;
		} rhba;

		struct {
			uint8_t hba_identifier[8];
			struct ct_fdmi1_hba_attributes attrs;
		} rhat;

		struct {
			uint8_t port_name[8];
			struct ct_fdmi2_port_attributes attrs;
		} rpa;

		struct {
			uint8_t hba_identifier[8];
			uint8_t port_name[8];
			struct ct_fdmi2_port_attributes attrs;
		} rprt;

		struct {
			uint8_t port_name[8];
		} dhba;

		struct {
			uint8_t port_name[8];
		} dhat;

		struct {
			uint8_t port_name[8];
		} dprt;

		struct {
			uint8_t port_name[8];
		} dpa;

		struct {
			uint8_t port_name[8];
		} gpsc;

		struct {
			uint8_t reserved;
			uint8_t port_id[3];
		} gff_id;

		struct {
			uint8_t port_name[8];
		} gid_pn;
	} req;
};

struct ct_rsp_hdr {
	struct ct_cmd_hdr header;
	__be16	response;
	uint16_t residual;
	uint8_t fragment_id;
	uint8_t reason_code;
	uint8_t explanation_code;
	uint8_t vendor_unique;
};

struct ct_sns_gid_pt_data {
	uint8_t control_byte;
	be_id_t port_id;
};

struct ct_sns_rsp {
	struct ct_rsp_hdr header;

	union {
		struct {
			uint8_t port_type;
			be_id_t port_id;
			uint8_t port_name[8];
			uint8_t sym_port_name_len;
			uint8_t sym_port_name[255];
			uint8_t node_name[8];
			uint8_t sym_node_name_len;
			uint8_t sym_node_name[255];
			uint8_t init_proc_assoc[8];
			uint8_t node_ip_addr[16];
			uint8_t class_of_service[4];
			uint8_t fc4_types[32];
			uint8_t ip_address[16];
			uint8_t fabric_port_name[8];
			uint8_t reserved;
			uint8_t hard_address[3];
		} ga_nxt;

		struct {
			/* Assume the largest number of targets for the union */
			struct ct_sns_gid_pt_data
			    entries[MAX_FIBRE_DEVICES_MAX];
		} gid_pt;

		struct {
			uint8_t port_name[8];
		} gpn_id;

		struct {
			uint8_t node_name[8];
		} gnn_id;

		struct {
			uint8_t fc4_types[32];
		} gft_id;

		struct {
			uint32_t entry_count;
			uint8_t port_name[8];
			struct ct_fdmi1_hba_attributes attrs;
		} ghat;

		struct {
			uint8_t port_name[8];
		} gfpn_id;

		struct {
			__be16	speeds;
			__be16	speed;
		} gpsc;

		struct {
			uint8_t fc4_features[128];
		} gff_id;
		struct {
			uint8_t reserved;
			uint8_t port_id[3];
		} gid_pn;
	} rsp;
};

struct ct_sns_pkt {
	union {
		struct ct_sns_req req;
		struct ct_sns_rsp rsp;
	} p;
};

#define	RFT_ID_SNS_DATA_SIZE	16

#define	RNN_ID_SNS_DATA_SIZE	16

#define	GA_NXT_SNS_DATA_SIZE	(620 + 16)

#define	GID_PT_SNS_DATA_SIZE	(MAX_FIBRE_DEVICES_2100 * 4 + 16)

#define	GPN_ID_SNS_DATA_SIZE	(8 + 16)

#define	GNN_ID_SNS_DATA_SIZE	(8 + 16)

struct sns_cmd_pkt {
	union {
		struct {
			__le16	buffer_length;
			__le16	reserved_1;
			__le64	buffer_address __packed;
			__le16	subcommand_length;
			__le16	reserved_2;
			__le16	subcommand;
			__le16	size;
			uint32_t reserved_3;
			uint8_t param[36];
		} cmd;

		uint8_t rft_data[RFT_ID_SNS_DATA_SIZE];
		uint8_t rnn_data[RNN_ID_SNS_DATA_SIZE];
		uint8_t gan_data[GA_NXT_SNS_DATA_SIZE];
		uint8_t gid_data[GID_PT_SNS_DATA_SIZE];
		uint8_t gpn_data[GPN_ID_SNS_DATA_SIZE];
		uint8_t gnn_data[GNN_ID_SNS_DATA_SIZE];
	} p;
};

struct gid_list_info {
	uint8_t	al_pa;
	uint8_t	area;
	uint8_t	domain;
	uint8_t	loop_id_2100;	/* ISP2100/ISP2200 -- 4 bytes. */
	__le16	loop_id;	/* ISP23XX         -- 6 bytes. */
	uint16_t reserved_1;	/* ISP24XX         -- 8 bytes. */
};

#define QLA_MAX_QUEUES 256

struct rsp_que {
	dma_addr_t  dma;
	response_t *ring;
	response_t *ring_ptr;
	__le32	__iomem *rsp_q_in;	/* FWI2-capable only. */
	__le32	__iomem *rsp_q_out;
	uint16_t  ring_index;
	uint16_t  out_ptr;
	uint16_t  *in_ptr;		/* queue shadow in index */
	uint16_t  length;
	uint16_t  options;
	uint16_t  rid;
	uint16_t  id;
	uint16_t  vp_idx;
	struct qla_hw_data *hw;
	struct qla_msix_entry *msix;
	struct req_que *req;
	srb_t *status_srb; /* status continuation entry */
	struct qla_qpair *qpair;

	dma_addr_t  dma_fx00;
	response_t *ring_fx00;
	uint16_t  length_fx00;
	uint8_t rsp_pkt[REQUEST_ENTRY_SIZE];
};

struct req_que {
	dma_addr_t  dma;
	request_t *ring;
	request_t *ring_ptr;
	__le32	__iomem *req_q_in;	/* FWI2-capable only. */
	__le32	__iomem *req_q_out;
	uint16_t  ring_index;
	uint16_t  in_ptr;
	uint16_t  *out_ptr;		/* queue shadow out index */
	uint16_t  cnt;
	uint16_t  length;
	uint16_t  options;
	uint16_t  rid;
	uint16_t  id;
	uint16_t  qos;
	uint16_t  vp_idx;
	struct rsp_que *rsp;
	srb_t **outstanding_cmds;
	uint32_t current_outstanding_cmd;
	uint16_t num_outstanding_cmds;
	int max_q_depth;

	dma_addr_t  dma_fx00;
	request_t *ring_fx00;
	uint16_t  length_fx00;
	uint8_t req_pkt[REQUEST_ENTRY_SIZE];
};

struct qla_fw_res {
	u16      iocb_total;
	u16      iocb_limit;
	atomic_t iocb_used;

	u16      exch_total;
	u16      exch_limit;
	atomic_t exch_used;
};

struct qlfc_fw {
	void *fw_buf;
	dma_addr_t fw_dma;
	uint32_t len;
};

struct qlt_hw_data {
	/* Protected by hw lock */
	uint32_t node_name_set:1;

	dma_addr_t atio_dma;	/* Physical address. */
	struct atio *atio_ring;	/* Base virtual address */
	struct atio *atio_ring_ptr;	/* Current address. */
	uint16_t atio_ring_index; /* Current index. */
	uint16_t atio_q_length;
	__le32 __iomem *atio_q_in;
	__le32 __iomem *atio_q_out;

	const struct qla_tgt_func_tmpl *tgt_ops;

	int saved_set;
	__le16	saved_exchange_count;
	__le32	saved_firmware_options_1;
	__le32	saved_firmware_options_2;
	__le32	saved_firmware_options_3;
	uint8_t saved_firmware_options[2];
	uint8_t saved_add_firmware_options[2];

	uint8_t tgt_node_name[WWN_SIZE];

	struct dentry *dfs_tgt_sess;
	struct dentry *dfs_tgt_port_database;
	struct dentry *dfs_naqp;

	struct list_head q_full_list;
	uint32_t num_pend_cmds;
	uint32_t num_qfull_cmds_alloc;
	uint32_t num_qfull_cmds_dropped;
	spinlock_t q_full_lock;
	uint32_t leak_exchg_thresh_hold;
	spinlock_t sess_lock;
	int num_act_qpairs;
	spinlock_t atio_lock ____cacheline_aligned;
};

struct qla_hw_data_stat {
	u32 num_fw_dump;
	u32 num_mpi_reset;
};

typedef enum {
	QLA_PCI_RESUME,
	QLA_PCI_ERR_DETECTED,
	QLA_PCI_MMIO_ENABLED,
	QLA_PCI_SLOT_RESET,
} pci_error_state_t;

struct qla_hw_data {
	struct pci_dev  *pdev;

#define SRB_MIN_REQ     128
	mempool_t       *srb_mempool;
	u8 port_name[WWN_SIZE];

	volatile struct {
		uint32_t	mbox_int		:1;
		uint32_t	mbox_busy		:1;
		uint32_t	disable_risc_code_load	:1;
		uint32_t	enable_64bit_addressing	:1;
		uint32_t	enable_lip_reset	:1;
		uint32_t	enable_target_reset	:1;
		uint32_t	enable_lip_full_login	:1;
		uint32_t	enable_led_scheme	:1;

		uint32_t	msi_enabled		:1;
		uint32_t	msix_enabled		:1;
		uint32_t	disable_serdes		:1;
		uint32_t	gpsc_supported		:1;
		uint32_t	npiv_supported		:1;
		uint32_t	pci_channel_io_perm_failure	:1;
		uint32_t	fce_enabled		:1;
		uint32_t	fac_supported		:1;

		uint32_t	chip_reset_done		:1;
		uint32_t	running_gold_fw		:1;
		uint32_t	eeh_busy		:1;
		uint32_t	disable_msix_handshake	:1;
		uint32_t	fcp_prio_enabled	:1;
		uint32_t	isp82xx_fw_hung:1;
		uint32_t	nic_core_hung:1;

		uint32_t	quiesce_owner:1;
		uint32_t	nic_core_reset_hdlr_active:1;
		uint32_t	nic_core_reset_owner:1;
		uint32_t	isp82xx_no_md_cap:1;
		uint32_t	host_shutting_down:1;
		uint32_t	idc_compl_status:1;
		uint32_t        mr_reset_hdlr_active:1;
		uint32_t        mr_intr_valid:1;

		uint32_t        dport_enabled:1;
		uint32_t	fawwpn_enabled:1;
		uint32_t	exlogins_enabled:1;
		uint32_t	exchoffld_enabled:1;

		uint32_t	lip_ae:1;
		uint32_t	n2n_ae:1;
		uint32_t	fw_started:1;
		uint32_t	fw_init_done:1;

		uint32_t	lr_detected:1;

		uint32_t	rida_fmt2:1;
		uint32_t	purge_mbox:1;
		uint32_t        n2n_bigger:1;
		uint32_t	secure_adapter:1;
		uint32_t	secure_fw:1;
				/* Supported by Adapter */
		uint32_t	scm_supported_a:1;
				/* Supported by Firmware */
		uint32_t	scm_supported_f:1;
				/* Enabled in Driver */
		uint32_t	scm_enabled:1;
		uint32_t	edif_hw:1;
		uint32_t	edif_enabled:1;
		uint32_t	n2n_fw_acc_sec:1;
		uint32_t	plogi_template_valid:1;
		uint32_t	port_isolated:1;
		uint32_t	eeh_flush:2;
	} flags;

	uint16_t max_exchg;
	uint16_t lr_distance;	/* 32G & above */

	/* This spinlock is used to protect "io transactions", you must
	* acquire it before doing any IO to the card, eg with RD_REG*() and
	* WRT_REG*() for the duration of your entire commandtransaction.
	*
	* This spinlock is of lower priority than the io request lock.
	*/

	spinlock_t	hardware_lock ____cacheline_aligned;
	int		bars;
	int		mem_only;
	device_reg_t *iobase;           /* Base I/O address */
	resource_size_t pio_address;

	dma_addr_t		bar0_hdl;

	void __iomem *cregbase;
	dma_addr_t		bar2_hdl;

	uint32_t		rqstq_intr_code;
	uint32_t		mbx_intr_code;
	uint32_t		req_que_len;
	uint32_t		rsp_que_len;
	uint32_t		req_que_off;
	uint32_t		rsp_que_off;
	unsigned long		eeh_jif;

	/* Multi queue data structs */
	device_reg_t *mqiobase;
	device_reg_t *msixbase;
	uint16_t        msix_count;
	uint8_t         mqenable;
	struct req_que **req_q_map;
	struct rsp_que **rsp_q_map;
	struct qla_qpair **queue_pair_map;
	struct qla_qpair **qp_cpu_map;
	unsigned long req_qid_map[(QLA_MAX_QUEUES / 8) / sizeof(unsigned long)];
	unsigned long rsp_qid_map[(QLA_MAX_QUEUES / 8) / sizeof(unsigned long)];
	unsigned long qpair_qid_map[(QLA_MAX_QUEUES / 8)
		/ sizeof(unsigned long)];
	uint8_t 	max_req_queues;
	uint8_t 	max_rsp_queues;
	uint8_t		max_qpairs;
	uint8_t		num_qpairs;
	struct qla_qpair *base_qpair;
	struct qla_npiv_entry *npiv_info;
	uint16_t	nvram_npiv_size;

	uint16_t        switch_cap;

	uint8_t		port_no;		/* Physical port of adapter */
	uint8_t		exch_starvation;

	/* Timeout timers. */
	uint8_t 	loop_down_abort_time;    /* port down timer */
	atomic_t	loop_down_timer;         /* loop down timer */
	uint8_t		link_down_timeout;       /* link down timeout */
	uint16_t	max_loop_id;
	uint16_t	max_fibre_devices;	/* Maximum number of targets */

	uint16_t	fb_rev;
	uint16_t	min_external_loopid;    /* First external loop Id */

	uint16_t	link_data_rate;         /* F/W operating speed */
	uint16_t	set_data_rate;		/* Set by user */

	uint8_t		current_topology;
	uint8_t		prev_topology;

	uint8_t		operating_mode;         /* F/W operating mode */
	uint8_t		interrupts_on;
	uint32_t	isp_abort_cnt;

	uint32_t	isp_type;
#define DT_ISP2100                      BIT_0
#define DT_ISP2200                      BIT_1

#define DT_ISP8001			BIT_13
#define DT_ISP8021			BIT_14
#define DT_ISP2031			BIT_15
#define DT_ISP8031			BIT_16
#define DT_ISPFX00			BIT_17
#define DT_ISP8044			BIT_18
#define DT_ISP2071			BIT_19
#define DT_ISP2271			BIT_20
#define DT_ISP2261			BIT_21

#define DT_ISP2081			BIT_23

#define DT_ISP2281			BIT_25
#define DT_ISP2289			BIT_26
#define DT_ISP_LAST			(DT_ISP2289 << 1)
	uint32_t	device_type;

#define DT_FWI2                         BIT_27

#define DT_MASK(ha)     ((ha)->isp_type & (DT_ISP_LAST - 1))
#define IS_QLA2100(ha)  (DT_MASK(ha) & DT_ISP2100)
#define IS_QLA2200(ha)  (DT_MASK(ha) & DT_ISP2200)

#define IS_QLA8001(ha)	(DT_MASK(ha) & DT_ISP8001)
#define IS_QLA81XX(ha)	(IS_QLA8001(ha))
#define IS_QLA82XX(ha)	(DT_MASK(ha) & DT_ISP8021)
#define IS_QLA8044(ha)  (DT_MASK(ha) & DT_ISP8044)
#define IS_QLA2031(ha)	(DT_MASK(ha) & DT_ISP2031)
#define IS_QLA8031(ha)	(DT_MASK(ha) & DT_ISP8031)
#define IS_QLAFX00(ha)	(DT_MASK(ha) & DT_ISPFX00)
#define IS_QLA2071(ha)	(DT_MASK(ha) & DT_ISP2071)
#define IS_QLA2271(ha)	(DT_MASK(ha) & DT_ISP2271)
#define IS_QLA2261(ha)	(DT_MASK(ha) & DT_ISP2261)
#define IS_QLA2081(ha)	(DT_MASK(ha) & DT_ISP2081)
#define IS_QLA2281(ha)	(DT_MASK(ha) & DT_ISP2281)

#define IS_QLA27XX(ha)  (IS_QLA2071(ha) || IS_QLA2271(ha) || IS_QLA2261(ha))
#define IS_QLA28XX(ha)	(IS_QLA2081(ha) || IS_QLA2281(ha))

#define IS_CNA_CAPABLE(ha)	(IS_QLA81XX(ha) || IS_QLA82XX(ha) || \
				IS_QLA8031(ha) || IS_QLA8044(ha))
#define IS_P3P_TYPE(ha)		(IS_QLA82XX(ha) || IS_QLA8044(ha))

#define IS_FWI2_CAPABLE(ha)     ((ha)->device_type & DT_FWI2)
	uint8_t		serial0;
	uint8_t		serial1;
	uint8_t		serial2;

#define MAX_NVRAM_SIZE  4096
	uint16_t	nvram_size;
	uint16_t	nvram_base;
	void		*nvram;
	uint16_t	vpd_size;
	uint16_t	vpd_base;
	void		*vpd;

	uint16_t	loop_reset_delay;
	uint8_t		retry_count;
	uint8_t		login_timeout;
	uint16_t	r_a_tov;
	int		port_down_retry_count;
	uint8_t		mbx_count;
	uint8_t		aen_mbx_count;
	atomic_t	num_pend_mbx_stage1;
	atomic_t	num_pend_mbx_stage2;
	uint16_t	frame_payload_size;

	uint32_t	login_retry_count;
	/* SNS command interfaces. */
	ms_iocb_entry_t		*ms_iocb;
	dma_addr_t		ms_iocb_dma;
	struct ct_sns_pkt	*ct_sns;
	dma_addr_t		ct_sns_dma;
	/* SNS command interfaces for 2200. */
	struct sns_cmd_pkt	*sns_cmd;
	dma_addr_t		sns_cmd_dma;

#define SFP_DEV_SIZE    512
	void		*sfp_data;
	dma_addr_t	sfp_data_dma;

	struct qla_flt_header *flt;
	dma_addr_t	flt_dma;

	void		*xgmac_data;
	dma_addr_t	xgmac_data_dma;

	void		*dcbx_tlv;
	dma_addr_t	dcbx_tlv_dma;

	struct task_struct	*dpc_thread;
	uint8_t dpc_active;                  /* DPC routine is active */

	dma_addr_t	gid_list_dma;
	struct gid_list_info *gid_list;
	int		gid_list_info_size;

#define DMA_POOL_SIZE   256
	struct dma_pool *s_dma_pool;

	dma_addr_t	init_cb_dma;
	init_cb_t	*init_cb;
	int		init_cb_size;
	dma_addr_t	ex_init_cb_dma;
	struct ex_init_cb_81xx *ex_init_cb;
	dma_addr_t	sf_init_cb_dma;
	struct init_sf_cb *sf_init_cb;

	void		*scm_fpin_els_buff;
	uint64_t	scm_fpin_els_buff_size;
	bool		scm_fpin_valid;
	bool		scm_fpin_payload_size;

	void		*async_pd;
	dma_addr_t	async_pd_dma;


	/* Extended Logins  */
	void		*exlogin_buf;
	dma_addr_t	exlogin_buf_dma;
	uint32_t	exlogin_size;


	/* Exchange Offload */
	void		*exchoffld_buf;
	dma_addr_t	exchoffld_buf_dma;
	int		exchoffld_size;
	int 		exchoffld_count;

	/* n2n */
	struct fc_els_flogi plogi_els_payld;

	void            *swl;

	/* These are used by mailbox operations. */
	uint16_t mailbox_out[MAILBOX_REGISTER_COUNT];
	uint32_t mailbox_out32[MAILBOX_REGISTER_COUNT];
	uint32_t aenmb[AEN_MAILBOX_REGISTER_COUNT_FX00];

	mbx_cmd_t	*mcp;
	struct mbx_cmd_32	*mcp32;

	unsigned long	mbx_cmd_flags;

	struct mutex vport_lock;        /* Virtual port synchronization */
	spinlock_t vport_slock; /* order is hardware_lock, then vport_slock */
	struct mutex mq_lock;        /* multi-queue synchronization */
	struct completion mbx_cmd_comp; /* Serialize mbx access */
	struct completion mbx_intr_comp;  /* Used for completion notification */
	struct completion dcbx_comp;	/* For set port config notification */
	struct completion lb_portup_comp; /* Used to wait for link up during
					   * loopback */

	int notify_dcbx_comp;
	int notify_lb_portup_comp;
	struct mutex selflogin_lock;

	/* Basic firmware related information. */
	uint16_t	fw_major_version;
	uint16_t	fw_minor_version;
	uint16_t	fw_subminor_version;
	uint16_t	fw_attributes;
	uint16_t	fw_attributes_h;

	/* About firmware SCM support */
	/* Brocade fabric attached */
	/* Cisco fabric attached */
	uint16_t	fw_attributes_ext[2];
	uint32_t	fw_memory_size;
	uint32_t	fw_transfer_size;
	uint32_t	fw_srisc_address;

	uint16_t	orig_fw_tgt_xcb_count;
	uint16_t	cur_fw_tgt_xcb_count;
	uint16_t	orig_fw_xcb_count;
	uint16_t	cur_fw_xcb_count;
	uint16_t	orig_fw_iocb_count;
	uint16_t	cur_fw_iocb_count;
	uint16_t	fw_max_fcf_count;

	uint32_t	fw_shared_ram_start;
	uint32_t	fw_shared_ram_end;
	uint32_t	fw_ddr_ram_start;
	uint32_t	fw_ddr_ram_end;

	uint16_t	fw_options[16];         /* slots: 1,2,3,10,11 */
	uint8_t		fw_seriallink_options[4];
	__le16		fw_seriallink_options24[4];

	uint8_t		serdes_version[3];
	uint8_t		mpi_version[3];
	uint32_t	mpi_capabilities;
	uint8_t		phy_version[3];
	uint8_t		pep_version[3];

	/* Firmware dump template */
	struct fwdt {
		void *template;
		ulong length;
		ulong dump_size;
	} fwdt[2];
	struct qla2xxx_fw_dump *fw_dump;
	uint32_t	fw_dump_len;
	u32		fw_dump_alloc_len;
	bool		fw_dumped;
	unsigned long	fw_dump_cap_flags;
	int		fw_dump_reading;
	void		*mpi_fw_dump;
	u32		mpi_fw_dump_len;
	unsigned int	mpi_fw_dump_reading:1;
	unsigned int	mpi_fw_dumped:1;
	int		prev_minidump_failed;
	dma_addr_t	eft_dma;
	void		*eft;
/* Current size of mctp dump is 0x086064 bytes */
	dma_addr_t	mctp_dump_dma;
	void		*mctp_dump;
	int		mctp_dumped;
	int		mctp_dump_reading;
	uint32_t	chain_offset;
	struct dentry *dfs_dir;
	struct dentry *dfs_fce;
	struct dentry *dfs_tgt_counters;
	struct dentry *dfs_fw_resource_cnt;

	dma_addr_t	fce_dma;
	void		*fce;
	uint32_t	fce_bufs;
	uint16_t	fce_mb[8];
	uint64_t	fce_wr, fce_rd;
	struct mutex	fce_mutex;

	uint32_t	pci_attr;
	uint16_t	chip_revision;

	uint16_t	product_id[4];

	uint8_t		model_number[16+1];
	char		model_desc[80];
	uint8_t		adapter_id[16+1];

	/* Option ROM information. */
	char		*optrom_buffer;
	uint32_t	optrom_size;
	int		optrom_state;
	uint32_t	optrom_region_start;
	uint32_t	optrom_region_size;
	struct mutex	optrom_mutex;

/* PCI expansion ROM image information. */
	uint8_t 	bios_revision[2];
	uint8_t 	efi_revision[2];
	uint8_t 	fcode_revision[16];
	uint32_t	fw_revision[4];

	uint32_t	gold_fw_version[4];

	/* Offsets for flash/nvram access (set to ~0 if not used). */
	uint32_t	flash_conf_off;
	uint32_t	flash_data_off;
	uint32_t	nvram_conf_off;
	uint32_t	nvram_data_off;

	uint32_t	fdt_wrt_disable;
	uint32_t	fdt_wrt_enable;
	uint32_t	fdt_erase_cmd;
	uint32_t	fdt_block_size;
	uint32_t	fdt_unprotect_sec_cmd;
	uint32_t	fdt_protect_sec_cmd;
	uint32_t	fdt_wrt_sts_reg_cmd;

	struct {
		uint32_t	flt_region_flt;
		uint32_t	flt_region_fdt;
		uint32_t	flt_region_boot;
		uint32_t	flt_region_boot_sec;
		uint32_t	flt_region_fw;
		uint32_t	flt_region_fw_sec;
		uint32_t	flt_region_vpd_nvram;
		uint32_t	flt_region_vpd_nvram_sec;
		uint32_t	flt_region_vpd;
		uint32_t	flt_region_vpd_sec;
		uint32_t	flt_region_nvram;
		uint32_t	flt_region_nvram_sec;
		uint32_t	flt_region_npiv_conf;
		uint32_t	flt_region_gold_fw;
		uint32_t	flt_region_fcp_prio;
		uint32_t	flt_region_bootload;
		uint32_t	flt_region_img_status_pri;
		uint32_t	flt_region_img_status_sec;
		uint32_t	flt_region_aux_img_status_pri;
		uint32_t	flt_region_aux_img_status_sec;
	};
	uint8_t         active_image;
	uint8_t active_tmf;

	/* Needed for BEACON */
	uint16_t        beacon_blink_led;
	uint8_t         beacon_color_state;
					/* ISP2322: red, green, amber. */
	uint16_t        zio_mode;
	uint16_t        zio_timer;

	struct qla_msix_entry *msix_entries;

	struct list_head tmf_pending;
	struct list_head tmf_active;
	struct list_head        vp_list;        /* list of VP */
	unsigned long   vp_idx_map[(MAX_MULTI_ID_FABRIC / 8) /
			sizeof(unsigned long)];
	uint16_t        num_vhosts;     /* number of vports created */
	uint16_t        num_vsans;      /* number of vsan created */
	uint16_t        max_npiv_vports;        /* 63 or 125 per topoloty */
	int             cur_vport_count;

	struct qla_chip_state_84xx *cs84xx;
	struct isp_operations *isp_ops;
	struct workqueue_struct *wq;
	struct work_struct heartbeat_work;
	struct qlfc_fw fw_buf;
	unsigned long last_heartbeat_run_jiffies;

	/* FCP_CMND priority support */
	struct qla_fcp_prio_cfg *fcp_prio_cfg;

	struct dma_pool *dl_dma_pool;
#define DSD_LIST_DMA_POOL_SIZE  512
	struct dma_pool *fcp_cmnd_dma_pool;
	mempool_t       *ctx_mempool;
#define FCP_CMND_DMA_POOL_SIZE 512
	void __iomem	*nx_pcibase;		/* Base I/O address */
	void __iomem	*nxdb_rd_ptr;		/* Doorbell read pointer */
	void __iomem	*nxdb_wr_ptr;		/* Door bell write pointer */

	uint32_t	crb_win;
	uint32_t	curr_window;
	uint32_t	ddr_mn_window;
	unsigned long	mn_win_crb;
	unsigned long	ms_win_crb;
	int		qdr_sn_window;
	uint32_t	fcoe_dev_init_timeout;
	uint32_t	fcoe_reset_timeout;
	rwlock_t	hw_lock;
	uint16_t	portnum;		/* port number */
	int		link_width;
	struct fw_blob	*hablob;
	struct qla82xx_legacy_intr_set nx_legacy_intr;

	uint8_t fw_type;
	uint32_t file_prd_off;	/* File firmware product offset */

	uint32_t	md_template_size;
	void		*md_tmplt_hdr;
	dma_addr_t      md_tmplt_hdr_dma;
	void            *md_dump;
	uint32_t	md_dump_size;

	void		*loop_id_map;

	/* QLA83XX IDC specific fields */
	uint32_t	idc_audit_ts;
	uint32_t	idc_extend_tmo;

	/* DPC low-priority workqueue */
	struct workqueue_struct *dpc_lp_wq;
	struct work_struct idc_aen;
	/* DPC high-priority workqueue */
	struct workqueue_struct *dpc_hp_wq;
	struct work_struct nic_core_reset;
	struct work_struct idc_state_handler;
	struct work_struct nic_core_unrecoverable;
	struct work_struct board_disable;

	struct mr_data_fx00 mr;
	uint32_t chip_reset;

	struct qlt_hw_data tgt;
	int	allow_cna_fw_dump;
	uint32_t fw_ability_mask;
	uint16_t min_supported_speed;
	uint16_t max_supported_speed;

	/* DMA pool for the DIF bundling buffers */
	struct dma_pool *dif_bundl_pool;
	
#define DIF_BUNDLING_DMA_POOL_SIZE  1024
struct {
		struct {
			struct list_head head;
			uint count;
		} good;
		struct {
			struct list_head head;
			uint count;
		} unusable;
	} pool;

	unsigned long long dif_bundle_crossed_pages;
	unsigned long long dif_bundle_reads;
	unsigned long long dif_bundle_writes;
	unsigned long long dif_bundle_kallocs;
	unsigned long long dif_bundle_dma_allocs;

	atomic_t        nvme_active_aen_cnt;
	uint16_t        nvme_last_rptd_aen;             /* Last recorded aen count */

	uint8_t fc4_type_priority;

	atomic_t zio_threshold;
	uint16_t last_zio_threshold;


	struct qla_hw_data_stat stat;
	pci_error_state_t pci_error_state;
	struct dma_pool *purex_dma_pool;
	struct btree_head32 host_map;

	void *edif_rx_sa_id_map;
	void *edif_tx_sa_id_map;
	spinlock_t sadb_fp_lock;

	struct list_head sadb_tx_index_list;
	struct list_head sadb_rx_index_list;
	spinlock_t sadb_lock;	/* protects list */
	struct els_reject elsrej;
	u8 edif_post_stop_cnt_down;
	struct qla_vp_map *vp_map;
	struct qla_fw_res fwres ____cacheline_aligned;
};

typedef struct scsi_qla_host scsi_qla_host_t;

struct qla_vp_map {
	uint8_t	idx;
	scsi_qla_host_t *vha;
};

/* klp-ccp: from drivers/scsi/qla2xxx/qla_target.h */
static int (*klpe_ql2x_ini_mode);

static int (*klpe_qlt_mem_alloc)(struct qla_hw_data *);
static void (*klpe_qlt_mem_free)(struct qla_hw_data *);

/* klp-ccp: from drivers/scsi/qla2xxx/qla_gbl.h */
#include <linux/interrupt.h>

static struct kmem_cache *(*klpe_srb_cachep);

static int (*klpe_ql2xenabledif);

static int (*klpe_ql2xsecenable);

/* klp-ccp: from drivers/scsi/qla2xxx/qla_dbg.h */
#define ql_log_fatal		0 /* display fatal errors */

static void __attribute__((format (printf, 4, 5)))
(*klpe_ql_dbg_pci)(uint, struct pci_dev *pdev, uint, const char *fmt, ...);

static void __attribute__((format (printf, 4, 5)))
(*klpe_ql_log)(uint, scsi_qla_host_t *vha, uint, const char *fmt, ...);
static void __attribute__((format (printf, 4, 5)))
(*klpe_ql_log_pci)(uint, struct pci_dev *pdev, uint, const char *fmt, ...);

#define ql_dbg_init	0x40000000 /* Init Debug */

/* klp-ccp: from drivers/scsi/qla2xxx/qla_inline.h */
static inline int
qla2x00_gid_list_size(struct qla_hw_data *ha)
{
	if (IS_QLAFX00(ha))
		return sizeof(uint32_t) * 32;
	else
		return sizeof(struct gid_list_info) * ha->max_fibre_devices;
}

/* klp-ccp: from drivers/scsi/qla2xxx/qla_os.c */
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/kobject.h>
#include <linux/slab.h>
#include <linux/refcount.h>
#include <scsi/scsi_transport_fc.h>

static struct kmem_cache *(*klpe_ctx_cachep);

static void qla2x00_set_reserved_loop_ids(struct qla_hw_data *ha)
{
	int i;

	if (IS_FWI2_CAPABLE(ha))
		return;

	for (i = 0; i < SNS_FIRST_LOOP_ID; i++)
		set_bit(i, ha->loop_id_map);
	set_bit(MANAGEMENT_SERVER, ha->loop_id_map);
	set_bit(BROADCAST, ha->loop_id_map);
}

#define QLA2XXX_INI_MODE_ENABLED	2
#define QLA_TGT_MODE_ENABLED() ((*klpe_ql2x_ini_mode) != QLA2XXX_INI_MODE_ENABLED)

#define EDIF_CAP(_ha) ((*klpe_ql2xsecenable) && IS_QLA28XX(_ha))

int
klpp_qla2x00_mem_alloc(struct qla_hw_data *ha, uint16_t req_len, uint16_t rsp_len,
	struct req_que **req, struct rsp_que **rsp)
{
	char	name[16];
	int rc;

	if (QLA_TGT_MODE_ENABLED() || EDIF_CAP(ha)) {
		ha->vp_map = kcalloc(MAX_MULTI_ID_FABRIC, sizeof(struct qla_vp_map), GFP_KERNEL);
		if (!ha->vp_map)
			goto fail;
	}

	ha->init_cb = dma_alloc_coherent(&ha->pdev->dev, ha->init_cb_size,
		&ha->init_cb_dma, GFP_KERNEL);
	if (!ha->init_cb)
		goto fail_free_vp_map;

	rc = btree_init32(&ha->host_map);
	if (rc)
		goto fail_free_init_cb;

	if ((*klpe_qlt_mem_alloc)(ha) < 0)
		goto fail_free_btree;

	ha->gid_list = dma_alloc_coherent(&ha->pdev->dev,
		qla2x00_gid_list_size(ha), &ha->gid_list_dma, GFP_KERNEL);
	if (!ha->gid_list)
		goto fail_free_tgt_mem;

	ha->srb_mempool = mempool_create_slab_pool(SRB_MIN_REQ, (*klpe_srb_cachep));
	if (!ha->srb_mempool)
		goto fail_free_gid_list;

	if (IS_P3P_TYPE(ha) || IS_QLA27XX(ha) || ((*klpe_ql2xsecenable) && IS_QLA28XX(ha))) {
		/* Allocate cache for CT6 Ctx. */
		if (!(*klpe_ctx_cachep)) {
			(*klpe_ctx_cachep) = kmem_cache_create("qla2xxx_ctx",
				sizeof(struct ct6_dsd), 0,
				SLAB_HWCACHE_ALIGN, NULL);
			if (!(*klpe_ctx_cachep))
				goto fail_free_srb_mempool;
		}
		ha->ctx_mempool = mempool_create_slab_pool(SRB_MIN_REQ,
			(*klpe_ctx_cachep));
		if (!ha->ctx_mempool)
			goto fail_free_srb_mempool;
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0021,
		    "ctx_cachep=%p ctx_mempool=%p.\n",
		    (*klpe_ctx_cachep), ha->ctx_mempool);
	}

	/* Get memory for cached NVRAM */
	ha->nvram = kzalloc(MAX_NVRAM_SIZE, GFP_KERNEL);
	if (!ha->nvram)
		goto fail_free_ctx_mempool;

	snprintf(name, sizeof(name), "%s_%d", QLA2XXX_DRIVER_NAME,
		ha->pdev->device);
	ha->s_dma_pool = dma_pool_create(name, &ha->pdev->dev,
		DMA_POOL_SIZE, 8, 0);
	if (!ha->s_dma_pool)
		goto fail_free_nvram;

	(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0022,
	    "init_cb=%p gid_list=%p, srb_mempool=%p s_dma_pool=%p.\n",
	    ha->init_cb, ha->gid_list, ha->srb_mempool, ha->s_dma_pool);

	if (IS_P3P_TYPE(ha) || (*klpe_ql2xenabledif) || (IS_QLA28XX(ha) && (*klpe_ql2xsecenable))) {
		ha->dl_dma_pool = dma_pool_create(name, &ha->pdev->dev,
			DSD_LIST_DMA_POOL_SIZE, 8, 0);
		if (!ha->dl_dma_pool) {
			(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x0023,
			    "Failed to allocate memory for dl_dma_pool.\n");
			goto fail_s_dma_pool;
		}

		ha->fcp_cmnd_dma_pool = dma_pool_create(name, &ha->pdev->dev,
			FCP_CMND_DMA_POOL_SIZE, 8, 0);
		if (!ha->fcp_cmnd_dma_pool) {
			(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x0024,
			    "Failed to allocate memory for fcp_cmnd_dma_pool.\n");
			goto fail_dl_dma_pool;
		}

		if ((*klpe_ql2xenabledif)) {
			u64 bufsize = DIF_BUNDLING_DMA_POOL_SIZE;
			struct dsd_dma *dsd, *nxt;
			uint i;
			/* Creata a DMA pool of buffers for DIF bundling */
			ha->dif_bundl_pool = dma_pool_create(name,
			    &ha->pdev->dev, DIF_BUNDLING_DMA_POOL_SIZE, 8, 0);
			if (!ha->dif_bundl_pool) {
				(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0024,
				    "%s: failed create dif_bundl_pool\n",
				    __func__);
				goto fail_dif_bundl_dma_pool;
			}

			INIT_LIST_HEAD(&ha->pool.good.head);
			INIT_LIST_HEAD(&ha->pool.unusable.head);
			ha->pool.good.count = 0;
			ha->pool.unusable.count = 0;
			for (i = 0; i < 128; i++) {
				dsd = kzalloc(sizeof(*dsd), GFP_ATOMIC);
				if (!dsd) {
					(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev,
					    0xe0ee, "%s: failed alloc dsd\n",
					    __func__);
					return -ENOMEM;
				}
				ha->dif_bundle_kallocs++;

				dsd->dsd_addr = dma_pool_alloc(
				    ha->dif_bundl_pool, GFP_ATOMIC,
				    &dsd->dsd_list_dma);
				if (!dsd->dsd_addr) {
					(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev,
					    0xe0ee,
					    "%s: failed alloc ->dsd_addr\n",
					    __func__);
					kfree(dsd);
					ha->dif_bundle_kallocs--;
					continue;
				}
				ha->dif_bundle_dma_allocs++;

				/*
				 * if DMA buffer crosses 4G boundary,
				 * put it on bad list
				 */
				if (MSD(dsd->dsd_list_dma) ^
				    MSD(dsd->dsd_list_dma + bufsize)) {
					list_add_tail(&dsd->list,
					    &ha->pool.unusable.head);
					ha->pool.unusable.count++;
				} else {
					list_add_tail(&dsd->list,
					    &ha->pool.good.head);
					ha->pool.good.count++;
				}
			}

			/* return the good ones back to the pool */
			list_for_each_entry_safe(dsd, nxt,
			    &ha->pool.good.head, list) {
				list_del(&dsd->list);
				dma_pool_free(ha->dif_bundl_pool,
				    dsd->dsd_addr, dsd->dsd_list_dma);
				ha->dif_bundle_dma_allocs--;
				kfree(dsd);
				ha->dif_bundle_kallocs--;
			}

			(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0024,
			    "%s: dif dma pool (good=%u unusable=%u)\n",
			    __func__, ha->pool.good.count,
			    ha->pool.unusable.count);
		}

		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0025,
		    "dl_dma_pool=%p fcp_cmnd_dma_pool=%p dif_bundl_pool=%p.\n",
		    ha->dl_dma_pool, ha->fcp_cmnd_dma_pool,
		    ha->dif_bundl_pool);
	}

	/* Allocate memory for SNS commands */
	if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
	/* Get consistent memory allocated for SNS commands */
		ha->sns_cmd = dma_alloc_coherent(&ha->pdev->dev,
		sizeof(struct sns_cmd_pkt), &ha->sns_cmd_dma, GFP_KERNEL);
		if (!ha->sns_cmd)
			goto fail_dma_pool;
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0026,
		    "sns_cmd: %p.\n", ha->sns_cmd);
	} else {
	/* Get consistent memory allocated for MS IOCB */
		ha->ms_iocb = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL,
			&ha->ms_iocb_dma);
		if (!ha->ms_iocb)
			goto fail_dma_pool;
	/* Get consistent memory allocated for CT SNS commands */
		ha->ct_sns = dma_alloc_coherent(&ha->pdev->dev,
			sizeof(struct ct_sns_pkt), &ha->ct_sns_dma, GFP_KERNEL);
		if (!ha->ct_sns)
			goto fail_free_ms_iocb;
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0027,
		    "ms_iocb=%p ct_sns=%p.\n",
		    ha->ms_iocb, ha->ct_sns);
	}

	/* Allocate memory for request ring */
	*req = kzalloc(sizeof(struct req_que), GFP_KERNEL);
	if (!*req) {
		(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x0028,
		    "Failed to allocate memory for req.\n");
		goto fail_req;
	}
	(*req)->length = req_len;
	(*req)->ring = dma_alloc_coherent(&ha->pdev->dev,
		((*req)->length + 1) * sizeof(request_t),
		&(*req)->dma, GFP_KERNEL);
	if (!(*req)->ring) {
		(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x0029,
		    "Failed to allocate memory for req_ring.\n");
		goto fail_req_ring;
	}
	/* Allocate memory for response ring */
	*rsp = kzalloc(sizeof(struct rsp_que), GFP_KERNEL);
	if (!*rsp) {
		(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x002a,
		    "Failed to allocate memory for rsp.\n");
		goto fail_rsp;
	}
	(*rsp)->hw = ha;
	(*rsp)->length = rsp_len;
	(*rsp)->ring = dma_alloc_coherent(&ha->pdev->dev,
		((*rsp)->length + 1) * sizeof(response_t),
		&(*rsp)->dma, GFP_KERNEL);
	if (!(*rsp)->ring) {
		(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x002b,
		    "Failed to allocate memory for rsp_ring.\n");
		goto fail_rsp_ring;
	}
	(*req)->rsp = *rsp;
	(*rsp)->req = *req;
	(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x002c,
	    "req=%p req->length=%d req->ring=%p rsp=%p "
	    "rsp->length=%d rsp->ring=%p.\n",
	    *req, (*req)->length, (*req)->ring, *rsp, (*rsp)->length,
	    (*rsp)->ring);
	/* Allocate memory for NVRAM data for vports */
	if (ha->nvram_npiv_size) {
		ha->npiv_info = kzalloc(sizeof(struct qla_npiv_entry) *
		    ha->nvram_npiv_size, GFP_KERNEL);
		if (!ha->npiv_info) {
			(*klpe_ql_log_pci)(ql_log_fatal, ha->pdev, 0x002d,
			    "Failed to allocate memory for npiv_info.\n");
			goto fail_npiv_info;
		}
	} else
		ha->npiv_info = NULL;

	/* Get consistent memory allocated for EX-INIT-CB. */
	if (IS_CNA_CAPABLE(ha) || IS_QLA2031(ha) || IS_QLA27XX(ha) ||
	    IS_QLA28XX(ha)) {
		ha->ex_init_cb = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL,
		    &ha->ex_init_cb_dma);
		if (!ha->ex_init_cb)
			goto fail_ex_init_cb;
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x002e,
		    "ex_init_cb=%p.\n", ha->ex_init_cb);
	}

	/* Get consistent memory allocated for Special Features-CB. */
	if (IS_QLA27XX(ha) || IS_QLA28XX(ha)) {
		ha->sf_init_cb = dma_pool_zalloc(ha->s_dma_pool, GFP_KERNEL,
						&ha->sf_init_cb_dma);
		if (!ha->sf_init_cb)
			goto fail_sf_init_cb;
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0199,
			   "sf_init_cb=%p.\n", ha->sf_init_cb);
	}


	/* Get consistent memory allocated for Async Port-Database. */
	if (!IS_FWI2_CAPABLE(ha)) {
		ha->async_pd = dma_pool_alloc(ha->s_dma_pool, GFP_KERNEL,
			&ha->async_pd_dma);
		if (!ha->async_pd)
			goto fail_async_pd;
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x002f,
		    "async_pd=%p.\n", ha->async_pd);
	}

	INIT_LIST_HEAD(&ha->vp_list);

	/* Allocate memory for our loop_id bitmap */
	ha->loop_id_map = kzalloc(BITS_TO_LONGS(LOOPID_MAP_SIZE) * sizeof(long),
	    GFP_KERNEL);
	if (!ha->loop_id_map)
		goto fail_loop_id_map;
	else {
		qla2x00_set_reserved_loop_ids(ha);
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x0123,
		    "loop_id_map=%p.\n", ha->loop_id_map);
	}

	ha->sfp_data = dma_alloc_coherent(&ha->pdev->dev,
	    SFP_DEV_SIZE, &ha->sfp_data_dma, GFP_KERNEL);
	if (!ha->sfp_data) {
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x011b,
		    "Unable to allocate memory for SFP read-data.\n");
		goto fail_sfp_data;
	}

	ha->flt = dma_alloc_coherent(&ha->pdev->dev,
	    sizeof(struct qla_flt_header) + FLT_REGIONS_SIZE, &ha->flt_dma,
	    GFP_KERNEL);
	if (!ha->flt) {
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x011b,
		    "Unable to allocate memory for FLT.\n");
		goto fail_flt_buffer;
	}

	/* allocate the purex dma pool */
	ha->purex_dma_pool = dma_pool_create(name, &ha->pdev->dev,
	    ELS_MAX_PAYLOAD, 8, 0);

	if (!ha->purex_dma_pool) {
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0x011b,
		    "Unable to allocate purex_dma_pool.\n");
		goto fail_flt;
	}

	ha->elsrej.size = sizeof(struct fc_els_ls_rjt) + 16;
	ha->elsrej.c = dma_alloc_coherent(&ha->pdev->dev,
	    ha->elsrej.size, &ha->elsrej.cdma, GFP_KERNEL);

	if (!ha->elsrej.c) {
		(*klpe_ql_dbg_pci)(ql_dbg_init, ha->pdev, 0xffff,
		    "Alloc failed for els reject cmd.\n");
		goto fail_elsrej;
	}
	ha->elsrej.c->er_cmd = ELS_LS_RJT;
	ha->elsrej.c->er_reason = ELS_RJT_LOGIC;
	ha->elsrej.c->er_explan = ELS_EXPL_UNAB_DATA;
	return 0;

fail_elsrej:
	dma_pool_destroy(ha->purex_dma_pool);
fail_flt:
	dma_free_coherent(&ha->pdev->dev, SFP_DEV_SIZE,
	    ha->flt, ha->flt_dma);

fail_flt_buffer:
	dma_free_coherent(&ha->pdev->dev, SFP_DEV_SIZE,
	    ha->sfp_data, ha->sfp_data_dma);
fail_sfp_data:
	kfree(ha->loop_id_map);
fail_loop_id_map:
	dma_pool_free(ha->s_dma_pool, ha->async_pd, ha->async_pd_dma);
fail_async_pd:
	dma_pool_free(ha->s_dma_pool, ha->sf_init_cb, ha->sf_init_cb_dma);
fail_sf_init_cb:
	dma_pool_free(ha->s_dma_pool, ha->ex_init_cb, ha->ex_init_cb_dma);
fail_ex_init_cb:
	kfree(ha->npiv_info);
fail_npiv_info:
	dma_free_coherent(&ha->pdev->dev, ((*rsp)->length + 1) *
		sizeof(response_t), (*rsp)->ring, (*rsp)->dma);
	(*rsp)->ring = NULL;
	(*rsp)->dma = 0;
fail_rsp_ring:
	kfree(*rsp);
	*rsp = NULL;
fail_rsp:
	dma_free_coherent(&ha->pdev->dev, ((*req)->length + 1) *
		sizeof(request_t), (*req)->ring, (*req)->dma);
	(*req)->ring = NULL;
	(*req)->dma = 0;
fail_req_ring:
	kfree(*req);
	*req = NULL;
fail_req:
	dma_free_coherent(&ha->pdev->dev, sizeof(struct ct_sns_pkt),
		ha->ct_sns, ha->ct_sns_dma);
	ha->ct_sns = NULL;
	ha->ct_sns_dma = 0;
fail_free_ms_iocb:
	dma_pool_free(ha->s_dma_pool, ha->ms_iocb, ha->ms_iocb_dma);
	ha->ms_iocb = NULL;
	ha->ms_iocb_dma = 0;

	if (ha->sns_cmd)
		dma_free_coherent(&ha->pdev->dev, sizeof(struct sns_cmd_pkt),
		    ha->sns_cmd, ha->sns_cmd_dma);
fail_dma_pool:
	if ((*klpe_ql2xenabledif)) {
		struct dsd_dma *dsd, *nxt;

		list_for_each_entry_safe(dsd, nxt, &ha->pool.unusable.head,
		    list) {
			list_del(&dsd->list);
			dma_pool_free(ha->dif_bundl_pool, dsd->dsd_addr,
			    dsd->dsd_list_dma);
			ha->dif_bundle_dma_allocs--;
			kfree(dsd);
			ha->dif_bundle_kallocs--;
			ha->pool.unusable.count--;
		}
		dma_pool_destroy(ha->dif_bundl_pool);
		ha->dif_bundl_pool = NULL;
	}

fail_dif_bundl_dma_pool:
	if (IS_QLA82XX(ha) || (*klpe_ql2xenabledif)) {
		dma_pool_destroy(ha->fcp_cmnd_dma_pool);
		ha->fcp_cmnd_dma_pool = NULL;
	}
fail_dl_dma_pool:
	if (IS_QLA82XX(ha) || (*klpe_ql2xenabledif)) {
		dma_pool_destroy(ha->dl_dma_pool);
		ha->dl_dma_pool = NULL;
	}
fail_s_dma_pool:
	dma_pool_destroy(ha->s_dma_pool);
	ha->s_dma_pool = NULL;
fail_free_nvram:
	kfree(ha->nvram);
	ha->nvram = NULL;
fail_free_ctx_mempool:
	mempool_destroy(ha->ctx_mempool);
	ha->ctx_mempool = NULL;
fail_free_srb_mempool:
	mempool_destroy(ha->srb_mempool);
	ha->srb_mempool = NULL;
fail_free_gid_list:
	dma_free_coherent(&ha->pdev->dev, qla2x00_gid_list_size(ha),
	ha->gid_list,
	ha->gid_list_dma);
	ha->gid_list = NULL;
	ha->gid_list_dma = 0;
fail_free_tgt_mem:
	(*klpe_qlt_mem_free)(ha);
fail_free_btree:
	btree_destroy32(&ha->host_map);
fail_free_init_cb:
	dma_free_coherent(&ha->pdev->dev, ha->init_cb_size, ha->init_cb,
	ha->init_cb_dma);
	ha->init_cb = NULL;
	ha->init_cb_dma = 0;
fail_free_vp_map:
	kfree(ha->vp_map);
	ha->vp_map = NULL;
fail:
	(*klpe_ql_log)(ql_log_fatal, NULL, 0x0030,
	    "Memory allocation failure.\n");
	return -ENOMEM;
}


#include "livepatch_bsc1223681.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "qla2xxx"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ctx_cachep", (void *)&klpe_ctx_cachep, "qla2xxx" },
	{ "ql2x_ini_mode", (void *)&klpe_ql2x_ini_mode, "qla2xxx" },
	{ "ql2xenabledif", (void *)&klpe_ql2xenabledif, "qla2xxx" },
	{ "ql2xsecenable", (void *)&klpe_ql2xsecenable, "qla2xxx" },
	{ "ql_dbg_pci", (void *)&klpe_ql_dbg_pci, "qla2xxx" },
	{ "ql_log", (void *)&klpe_ql_log, "qla2xxx" },
	{ "ql_log_pci", (void *)&klpe_ql_log_pci, "qla2xxx" },
	{ "qlt_mem_alloc", (void *)&klpe_qlt_mem_alloc, "qla2xxx" },
	{ "qlt_mem_free", (void *)&klpe_qlt_mem_free, "qla2xxx" },
	{ "srb_cachep", (void *)&klpe_srb_cachep, "qla2xxx" },
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

int livepatch_bsc1223681_init(void)
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

void livepatch_bsc1223681_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SCSI_QLA_FC) */
