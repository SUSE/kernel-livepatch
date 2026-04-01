/*
 * livepatch_bsc1252036
 *
 * Fix for CVE-2025-39973, bsc#1252036
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_I40E)

#if !IS_MODULE(CONFIG_I40E)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1252036.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e.h */
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/netdevice.h>
#include <linux/ioport.h>
#include <linux/iommu.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/sctp.h>
#include <linux/pkt_sched.h>
#include <linux/ipv6.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/clocksource.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>
#include <net/xdp_sock.h>

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_status.h */
enum i40e_status_code {
	I40E_SUCCESS				= 0,
	I40E_ERR_NVM				= -1,
	I40E_ERR_NVM_CHECKSUM			= -2,
	I40E_ERR_PHY				= -3,
	I40E_ERR_CONFIG				= -4,
	I40E_ERR_PARAM				= -5,
	I40E_ERR_MAC_TYPE			= -6,
	I40E_ERR_UNKNOWN_PHY			= -7,
	I40E_ERR_LINK_SETUP			= -8,
	I40E_ERR_ADAPTER_STOPPED		= -9,
	I40E_ERR_INVALID_MAC_ADDR		= -10,
	I40E_ERR_DEVICE_NOT_SUPPORTED		= -11,
	I40E_ERR_MASTER_REQUESTS_PENDING	= -12,
	I40E_ERR_INVALID_LINK_SETTINGS		= -13,
	I40E_ERR_AUTONEG_NOT_COMPLETE		= -14,
	I40E_ERR_RESET_FAILED			= -15,
	I40E_ERR_SWFW_SYNC			= -16,
	I40E_ERR_NO_AVAILABLE_VSI		= -17,
	I40E_ERR_NO_MEMORY			= -18,
	I40E_ERR_BAD_PTR			= -19,
	I40E_ERR_RING_FULL			= -20,
	I40E_ERR_INVALID_PD_ID			= -21,
	I40E_ERR_INVALID_QP_ID			= -22,
	I40E_ERR_INVALID_CQ_ID			= -23,
	I40E_ERR_INVALID_CEQ_ID			= -24,
	I40E_ERR_INVALID_AEQ_ID			= -25,
	I40E_ERR_INVALID_SIZE			= -26,
	I40E_ERR_INVALID_ARP_INDEX		= -27,
	I40E_ERR_INVALID_FPM_FUNC_ID		= -28,
	I40E_ERR_QP_INVALID_MSG_SIZE		= -29,
	I40E_ERR_QP_TOOMANY_WRS_POSTED		= -30,
	I40E_ERR_INVALID_FRAG_COUNT		= -31,
	I40E_ERR_QUEUE_EMPTY			= -32,
	I40E_ERR_INVALID_ALIGNMENT		= -33,
	I40E_ERR_FLUSHED_QUEUE			= -34,
	I40E_ERR_INVALID_PUSH_PAGE_INDEX	= -35,
	I40E_ERR_INVALID_IMM_DATA_SIZE		= -36,
	I40E_ERR_TIMEOUT			= -37,
	I40E_ERR_OPCODE_MISMATCH		= -38,
	I40E_ERR_CQP_COMPL_ERROR		= -39,
	I40E_ERR_INVALID_VF_ID			= -40,
	I40E_ERR_INVALID_HMCFN_ID		= -41,
	I40E_ERR_BACKING_PAGE_ERROR		= -42,
	I40E_ERR_NO_PBLCHUNKS_AVAILABLE		= -43,
	I40E_ERR_INVALID_PBLE_INDEX		= -44,
	I40E_ERR_INVALID_SD_INDEX		= -45,
	I40E_ERR_INVALID_PAGE_DESC_INDEX	= -46,
	I40E_ERR_INVALID_SD_TYPE		= -47,
	I40E_ERR_MEMCPY_FAILED			= -48,
	I40E_ERR_INVALID_HMC_OBJ_INDEX		= -49,
	I40E_ERR_INVALID_HMC_OBJ_COUNT		= -50,
	I40E_ERR_INVALID_SRQ_ARM_LIMIT		= -51,
	I40E_ERR_SRQ_ENABLED			= -52,
	I40E_ERR_ADMIN_QUEUE_ERROR		= -53,
	I40E_ERR_ADMIN_QUEUE_TIMEOUT		= -54,
	I40E_ERR_BUF_TOO_SHORT			= -55,
	I40E_ERR_ADMIN_QUEUE_FULL		= -56,
	I40E_ERR_ADMIN_QUEUE_NO_WORK		= -57,
	I40E_ERR_BAD_IWARP_CQE			= -58,
	I40E_ERR_NVM_BLANK_MODE			= -59,
	I40E_ERR_NOT_IMPLEMENTED		= -60,
	I40E_ERR_PE_DOORBELL_NOT_ENABLED	= -61,
	I40E_ERR_DIAG_TEST_FAILED		= -62,
	I40E_ERR_NOT_READY			= -63,
	I40E_NOT_SUPPORTED			= -64,
	I40E_ERR_FIRMWARE_API_VERSION		= -65,
	I40E_ERR_ADMIN_QUEUE_CRITICAL_ERROR	= -66,
};

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_osdep.h */
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/tcp.h>
#include <linux/pci.h>
#include <linux/highuid.h>
#include <linux/io-64-nonatomic-lo-hi.h>

#define wr32(a, reg, value)	writel((value), ((a)->hw_addr + (reg)))
#define rd32(a, reg)		readl((a)->hw_addr + (reg))

#define i40e_flush(a)		readl((a)->hw_addr + I40E_GLGEN_STAT)

struct i40e_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
};

struct i40e_virt_mem {
	void *va;
	u32 size;
};

typedef enum i40e_status_code i40e_status;

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_register.h */
#define I40E_GLGEN_STAT 0x000B612C /* Reset: POR */

#define I40E_GLINT_CTL 0x0003F800 /* Reset: CORER */

#define I40E_GLINT_CTL_DIS_AUTOMASK_VF0_SHIFT 1
#define I40E_GLINT_CTL_DIS_AUTOMASK_VF0_MASK I40E_MASK(0x1, I40E_GLINT_CTL_DIS_AUTOMASK_VF0_SHIFT)

#define I40E_QINT_RQCTL(_Q) (0x0003A000 + ((_Q) * 4)) /* _i=0...1535 */ /* Reset: CORER */

#define I40E_QINT_RQCTL_ITR_INDX_SHIFT 11

#define I40E_QINT_RQCTL_NEXTQ_INDX_SHIFT 16

#define I40E_QINT_RQCTL_NEXTQ_TYPE_SHIFT 27

#define I40E_QINT_RQCTL_CAUSE_ENA_SHIFT 30

#define I40E_QINT_TQCTL(_Q) (0x0003C000 + ((_Q) * 4)) /* _i=0...1535 */ /* Reset: CORER */

#define I40E_VPINT_AEQCTL(_VF) (0x0002B800 + ((_VF) * 4)) /* _i=0...127 */ /* Reset: CORER */

#define I40E_VPINT_AEQCTL_MSIX_INDX_SHIFT 0

#define I40E_VPINT_AEQCTL_ITR_INDX_SHIFT 11

#define I40E_VPINT_AEQCTL_CAUSE_ENA_SHIFT 30
#define I40E_VPINT_AEQCTL_CAUSE_ENA_MASK I40E_MASK(0x1, I40E_VPINT_AEQCTL_CAUSE_ENA_SHIFT)

#define I40E_VPINT_CEQCTL(_INTVF) (0x00026800 + ((_INTVF) * 4)) /* _i=0...511 */ /* Reset: CORER */

#define I40E_VPINT_CEQCTL_MSIX_INDX_SHIFT 0

#define I40E_VPINT_CEQCTL_ITR_INDX_SHIFT 11

#define I40E_VPINT_CEQCTL_NEXTQ_INDX_SHIFT 16
#define I40E_VPINT_CEQCTL_NEXTQ_INDX_MASK I40E_MASK(0x7FF, I40E_VPINT_CEQCTL_NEXTQ_INDX_SHIFT)
#define I40E_VPINT_CEQCTL_NEXTQ_TYPE_SHIFT 27
#define I40E_VPINT_CEQCTL_NEXTQ_TYPE_MASK I40E_MASK(0x3, I40E_VPINT_CEQCTL_NEXTQ_TYPE_SHIFT)
#define I40E_VPINT_CEQCTL_CAUSE_ENA_SHIFT 30
#define I40E_VPINT_CEQCTL_CAUSE_ENA_MASK I40E_MASK(0x1, I40E_VPINT_CEQCTL_CAUSE_ENA_SHIFT)

#define I40E_VPINT_LNKLST0(_VF) (0x0002A800 + ((_VF) * 4)) /* _i=0...127 */ /* Reset: VFR */

#define I40E_VPINT_LNKLST0_FIRSTQ_INDX_SHIFT 0
#define I40E_VPINT_LNKLST0_FIRSTQ_INDX_MASK I40E_MASK(0x7FF, I40E_VPINT_LNKLST0_FIRSTQ_INDX_SHIFT)

#define I40E_VPINT_LNKLSTN(_INTVF) (0x00025000 + ((_INTVF) * 4)) /* _i=0...511 */ /* Reset: VFR */

#define I40E_VPINT_LNKLSTN_FIRSTQ_INDX_SHIFT 0
#define I40E_VPINT_LNKLSTN_FIRSTQ_INDX_MASK I40E_MASK(0x7FF, I40E_VPINT_LNKLSTN_FIRSTQ_INDX_SHIFT)
#define I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_SHIFT 11
#define I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_MASK I40E_MASK(0x3, I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_SHIFT)

#define I40E_QTX_CTL(_Q) (0x00104000 + ((_Q) * 4)) /* _i=0...1535 */ /* Reset: CORER */

#define I40E_QTX_CTL_PF_INDX_SHIFT 2
#define I40E_QTX_CTL_PF_INDX_MASK I40E_MASK(0xF, I40E_QTX_CTL_PF_INDX_SHIFT)
#define I40E_QTX_CTL_VFVM_INDX_SHIFT 7
#define I40E_QTX_CTL_VFVM_INDX_MASK I40E_MASK(0x1FF, I40E_QTX_CTL_VFVM_INDX_SHIFT)

#define I40E_PFQF_HKEY_MAX_INDEX 12

#define I40E_VFQF_HENA1(_i, _VF) (0x00230800 + ((_i) * 1024 + (_VF) * 4)) /* _i=0...1, _VF=0...127 */ /* Reset: CORER */

#define I40E_VFQF_HLUT1_MAX_INDEX 15

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_adminq_cmd.h */
struct i40e_aq_desc {
	__le16 flags;
	__le16 opcode;
	__le16 datalen;
	__le16 retval;
	__le32 cookie_high;
	__le32 cookie_low;
	union {
		struct {
			__le32 param0;
			__le32 param1;
			__le32 param2;
			__le32 param3;
		} internal;
		struct {
			__le32 param0;
			__le32 param1;
			__le32 addr_high;
			__le32 addr_low;
		} external;
		u8 raw[16];
	} params;
};

enum i40e_admin_queue_err {
	I40E_AQ_RC_OK		= 0,  /* success */
	I40E_AQ_RC_EPERM	= 1,  /* Operation not permitted */
	I40E_AQ_RC_ENOENT	= 2,  /* No such element */
	I40E_AQ_RC_ESRCH	= 3,  /* Bad opcode */
	I40E_AQ_RC_EINTR	= 4,  /* operation interrupted */
	I40E_AQ_RC_EIO		= 5,  /* I/O error */
	I40E_AQ_RC_ENXIO	= 6,  /* No such resource */
	I40E_AQ_RC_E2BIG	= 7,  /* Arg too long */
	I40E_AQ_RC_EAGAIN	= 8,  /* Try again */
	I40E_AQ_RC_ENOMEM	= 9,  /* Out of memory */
	I40E_AQ_RC_EACCES	= 10, /* Permission denied */
	I40E_AQ_RC_EFAULT	= 11, /* Bad address */
	I40E_AQ_RC_EBUSY	= 12, /* Device or resource busy */
	I40E_AQ_RC_EEXIST	= 13, /* object already exists */
	I40E_AQ_RC_EINVAL	= 14, /* Invalid argument */
	I40E_AQ_RC_ENOTTY	= 15, /* Not a typewriter */
	I40E_AQ_RC_ENOSPC	= 16, /* No space left or alloc failure */
	I40E_AQ_RC_ENOSYS	= 17, /* Function not implemented */
	I40E_AQ_RC_ERANGE	= 18, /* Parameter out of range */
	I40E_AQ_RC_EFLUSHED	= 19, /* Cmd flushed due to prev cmd error */
	I40E_AQ_RC_BAD_ADDR	= 20, /* Descriptor contains a bad pointer */
	I40E_AQ_RC_EMODE	= 21, /* Op not allowed in current dev mode */
	I40E_AQ_RC_EFBIG	= 22, /* File too large */
};

struct i40e_aqc_vsi_properties_data {
	/* first 96 byte are written by SW */
	__le16	valid_sections;
	/* switch section */
	__le16	switch_id; /* 12bit id combined with flags below */
	u8	sw_reserved[2];
	/* security section */
	u8	sec_flags;
	u8	sec_reserved;
	/* VLAN section */
	__le16	pvid; /* VLANS include priority bits */
	__le16	fcoe_pvid;
	u8	port_vlan_flags;
	u8	pvlan_reserved[3];
	/* ingress egress up sections */
	__le32	ingress_table; /* bitmap, 3 bits per up */
	__le32	egress_table;   /* same defines as for ingress table */
	/* cascaded PV section */
	__le16	cas_pv_tag;
	u8	cas_pv_flags;
	u8	cas_pv_reserved;
	/* queue mapping section */
	__le16	mapping_flags;

#define I40E_AQ_VSI_QUE_MAP_NONCONTIG	0x1
	__le16	queue_mapping[16];
	__le16	tc_mapping[8];
	/* queueing option section */
	u8	queueing_opt_flags;
	u8	queueing_opt_reserved[3];
	/* scheduler section */
	u8	up_enable_bits;
	u8	sched_reserved;
	/* outer up section */
	__le32	outer_up_table; /* same structure and defines as ingress tbl */
	u8	cmd_reserved[8];
	/* last 32 bytes are written by FW */
	__le16	qs_handle[8];
	__le16	stat_counter_idx;
	__le16	sched_id;
	u8	resp_reserved[12];
};

enum i40e_aq_phy_type {
	I40E_PHY_TYPE_SGMII			= 0x0,
	I40E_PHY_TYPE_1000BASE_KX		= 0x1,
	I40E_PHY_TYPE_10GBASE_KX4		= 0x2,
	I40E_PHY_TYPE_10GBASE_KR		= 0x3,
	I40E_PHY_TYPE_40GBASE_KR4		= 0x4,
	I40E_PHY_TYPE_XAUI			= 0x5,
	I40E_PHY_TYPE_XFI			= 0x6,
	I40E_PHY_TYPE_SFI			= 0x7,
	I40E_PHY_TYPE_XLAUI			= 0x8,
	I40E_PHY_TYPE_XLPPI			= 0x9,
	I40E_PHY_TYPE_40GBASE_CR4_CU		= 0xA,
	I40E_PHY_TYPE_10GBASE_CR1_CU		= 0xB,
	I40E_PHY_TYPE_10GBASE_AOC		= 0xC,
	I40E_PHY_TYPE_40GBASE_AOC		= 0xD,
	I40E_PHY_TYPE_UNRECOGNIZED		= 0xE,
	I40E_PHY_TYPE_UNSUPPORTED		= 0xF,
	I40E_PHY_TYPE_100BASE_TX		= 0x11,
	I40E_PHY_TYPE_1000BASE_T		= 0x12,
	I40E_PHY_TYPE_10GBASE_T			= 0x13,
	I40E_PHY_TYPE_10GBASE_SR		= 0x14,
	I40E_PHY_TYPE_10GBASE_LR		= 0x15,
	I40E_PHY_TYPE_10GBASE_SFPP_CU		= 0x16,
	I40E_PHY_TYPE_10GBASE_CR1		= 0x17,
	I40E_PHY_TYPE_40GBASE_CR4		= 0x18,
	I40E_PHY_TYPE_40GBASE_SR4		= 0x19,
	I40E_PHY_TYPE_40GBASE_LR4		= 0x1A,
	I40E_PHY_TYPE_1000BASE_SX		= 0x1B,
	I40E_PHY_TYPE_1000BASE_LX		= 0x1C,
	I40E_PHY_TYPE_1000BASE_T_OPTICAL	= 0x1D,
	I40E_PHY_TYPE_20GBASE_KR2		= 0x1E,
	I40E_PHY_TYPE_25GBASE_KR		= 0x1F,
	I40E_PHY_TYPE_25GBASE_CR		= 0x20,
	I40E_PHY_TYPE_25GBASE_SR		= 0x21,
	I40E_PHY_TYPE_25GBASE_LR		= 0x22,
	I40E_PHY_TYPE_25GBASE_AOC		= 0x23,
	I40E_PHY_TYPE_25GBASE_ACC		= 0x24,
	I40E_PHY_TYPE_2_5GBASE_T		= 0x26,
	I40E_PHY_TYPE_5GBASE_T			= 0x27,
	I40E_PHY_TYPE_2_5GBASE_T_LINK_STATUS	= 0x30,
	I40E_PHY_TYPE_5GBASE_T_LINK_STATUS	= 0x31,
	I40E_PHY_TYPE_MAX,
	I40E_PHY_TYPE_NOT_SUPPORTED_HIGH_TEMP	= 0xFD,
	I40E_PHY_TYPE_EMPTY			= 0xFE,
	I40E_PHY_TYPE_DEFAULT			= 0xFF,
};

#define I40E_LINK_SPEED_2_5GB_SHIFT	0x0
#define I40E_LINK_SPEED_100MB_SHIFT	0x1
#define I40E_LINK_SPEED_1000MB_SHIFT	0x2
#define I40E_LINK_SPEED_10GB_SHIFT	0x3
#define I40E_LINK_SPEED_40GB_SHIFT	0x4
#define I40E_LINK_SPEED_20GB_SHIFT	0x5
#define I40E_LINK_SPEED_25GB_SHIFT	0x6
#define I40E_LINK_SPEED_5GB_SHIFT	0x7

enum i40e_aq_link_speed {
	I40E_LINK_SPEED_UNKNOWN	= 0,
	I40E_LINK_SPEED_100MB	= BIT(I40E_LINK_SPEED_100MB_SHIFT),
	I40E_LINK_SPEED_1GB	= BIT(I40E_LINK_SPEED_1000MB_SHIFT),
	I40E_LINK_SPEED_2_5GB	= (1 << I40E_LINK_SPEED_2_5GB_SHIFT),
	I40E_LINK_SPEED_5GB	= (1 << I40E_LINK_SPEED_5GB_SHIFT),
	I40E_LINK_SPEED_10GB	= BIT(I40E_LINK_SPEED_10GB_SHIFT),
	I40E_LINK_SPEED_40GB	= BIT(I40E_LINK_SPEED_40GB_SHIFT),
	I40E_LINK_SPEED_20GB	= BIT(I40E_LINK_SPEED_20GB_SHIFT),
	I40E_LINK_SPEED_25GB	= BIT(I40E_LINK_SPEED_25GB_SHIFT),
};

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_adminq.h */
struct i40e_adminq_ring {
	struct i40e_virt_mem dma_head;	/* space for dma structures */
	struct i40e_dma_mem desc_buf;	/* descriptor ring memory */
	struct i40e_virt_mem cmd_buf;	/* command buffer memory */

	union {
		struct i40e_dma_mem *asq_bi;
		struct i40e_dma_mem *arq_bi;
	} r;

	u16 count;		/* Number of descriptors */
	u16 rx_buf_len;		/* Admin Receive Queue buffer length */

	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	/* used for queue tracking */
	u32 head;
	u32 tail;
	u32 len;
	u32 bah;
	u32 bal;
};

struct i40e_asq_cmd_details;

struct i40e_adminq_info {
	struct i40e_adminq_ring arq;    /* receive queue */
	struct i40e_adminq_ring asq;    /* send queue */
	u32 asq_cmd_timeout;            /* send queue cmd write back timeout*/
	u16 num_arq_entries;            /* receive queue depth */
	u16 num_asq_entries;            /* send queue depth */
	u16 arq_buf_size;               /* receive queue buffer size */
	u16 asq_buf_size;               /* send queue buffer size */
	u16 fw_maj_ver;                 /* firmware major version */
	u16 fw_min_ver;                 /* firmware minor version */
	u32 fw_build;                   /* firmware build number */
	u16 api_maj_ver;                /* api major version */
	u16 api_min_ver;                /* api minor version */

	struct mutex asq_mutex; /* Send queue lock */
	struct mutex arq_mutex; /* Receive queue lock */

	/* last status values on send and receive queues */
	enum i40e_admin_queue_err asq_last_status;
	enum i40e_admin_queue_err arq_last_status;
};

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_hmc.h */
struct i40e_hw;

struct i40e_hmc_sd_table {
	struct i40e_virt_mem addr; /* used to track sd_entry allocations */
	u32 sd_cnt;
	u32 ref_cnt;
	struct i40e_hmc_sd_entry *sd_entry; /* (sd_cnt*512) entries max */
};

struct i40e_hmc_info {
	u32 signature;
	/* equals to pci func num for PF and dynamically allocated for VFs */
	u8 hmc_fn_id;
	u16 first_sd_index; /* index of the first available SD */

	/* hmc objects */
	struct i40e_hmc_obj_info *hmc_obj;
	struct i40e_virt_mem hmc_obj_virt_mem;
	struct i40e_hmc_sd_table sd_table;
};

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_lan_hmc.h */
struct i40e_hmc_obj_rxq {
	u16 head;
	u16 cpuid; /* bigger than needed, see above for reason */
	u64 base;
	u16 qlen;
#define I40E_RXQ_CTX_DBUFF_SHIFT 7
	u16 dbuff; /* bigger than needed, see above for reason */
#define I40E_RXQ_CTX_HBUFF_SHIFT 6
	u16 hbuff; /* bigger than needed, see above for reason */
	u8  dtype;
	u8  dsize;
	u8  crcstrip;
	u8  fc_ena;
	u8  l2tsel;
	u8  hsplit_0;
	u8  hsplit_1;
	u8  showiv;
	u32 rxmax; /* bigger than needed, see above for reason */
	u8  tphrdesc_ena;
	u8  tphwdesc_ena;
	u8  tphdata_ena;
	u8  tphhead_ena;
	u16 lrxqthresh; /* bigger than needed, see above for reason */
	u8  prefena;	/* NOTE: normally must be set to 1 at init */
};

struct i40e_hmc_obj_txq {
	u16 head;
	u8  new_context;
	u64 base;
	u8  fc_ena;
	u8  timesync_ena;
	u8  fd_ena;
	u8  alt_vlan_ena;
	u16 thead_wb;
	u8  cpuid;
	u8  head_wb_ena;
	u16 qlen;
	u8  tphrdesc_ena;
	u8  tphrpacket_ena;
	u8  tphwdesc_ena;
	u64 head_wb_addr;
	u32 crc;
	u16 rdylist;
	u8  rdylist_act;
};

static i40e_status (*klpe_i40e_clear_lan_tx_queue_context)(struct i40e_hw *hw,
						      u16 queue);
static i40e_status (*klpe_i40e_set_lan_tx_queue_context)(struct i40e_hw *hw,
						    u16 queue,
						    struct i40e_hmc_obj_txq *s);
static i40e_status (*klpe_i40e_clear_lan_rx_queue_context)(struct i40e_hw *hw,
						      u16 queue);
static i40e_status (*klpe_i40e_set_lan_rx_queue_context)(struct i40e_hw *hw,
						    u16 queue,
						    struct i40e_hmc_obj_rxq *s);

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_type.h */
#define I40E_MASK(mask, shift) ((u32)(mask) << (shift))

#define I40E_MAX_VSI_QP			16
#define I40E_MAX_VF_VSI			4

#define I40E_MAX_PF_UDP_OFFLOAD_PORTS	16

#define I40E_QTX_CTL_VF_QUEUE	0x0

enum i40e_mac_type {
	I40E_MAC_UNKNOWN = 0,
	I40E_MAC_XL710,
	I40E_MAC_VF,
	I40E_MAC_X722,
	I40E_MAC_X722_VF,
	I40E_MAC_GENERIC,
};

enum i40e_media_type {
	I40E_MEDIA_TYPE_UNKNOWN = 0,
	I40E_MEDIA_TYPE_FIBER,
	I40E_MEDIA_TYPE_BASET,
	I40E_MEDIA_TYPE_BACKPLANE,
	I40E_MEDIA_TYPE_CX4,
	I40E_MEDIA_TYPE_DA,
	I40E_MEDIA_TYPE_VIRTUAL
};

enum i40e_fc_mode {
	I40E_FC_NONE = 0,
	I40E_FC_RX_PAUSE,
	I40E_FC_TX_PAUSE,
	I40E_FC_FULL,
	I40E_FC_PFC,
	I40E_FC_DEFAULT
};

enum i40e_vsi_type {
	I40E_VSI_MAIN	= 0,
	I40E_VSI_VMDQ1	= 1,
	I40E_VSI_VMDQ2	= 2,
	I40E_VSI_CTRL	= 3,
	I40E_VSI_FCOE	= 4,
	I40E_VSI_MIRROR	= 5,
	I40E_VSI_SRIOV	= 6,
	I40E_VSI_FDIR	= 7,
	I40E_VSI_IWARP	= 8,
	I40E_VSI_TYPE_UNKNOWN
};

enum i40e_queue_type {
	I40E_QUEUE_TYPE_RX = 0,
	I40E_QUEUE_TYPE_TX,
	I40E_QUEUE_TYPE_PE_CEQ,
	I40E_QUEUE_TYPE_UNKNOWN
};

struct i40e_link_status {
	enum i40e_aq_phy_type phy_type;
	enum i40e_aq_link_speed link_speed;
	u8 link_info;
	u8 an_info;
	u8 req_fec_info;
	u8 fec_info;
	u8 ext_info;
	u8 loopback;
	/* is Link Status Event notification to SW enabled */
	bool lse_enable;
	u16 max_frame_size;
	bool crc_enable;
	u8 pacing;
	u8 requested_speeds;
	u8 module_type[3];
	/* 1st byte: module identifier */
	/* 2nd byte: ethernet compliance codes for 10/40G */
	/* 3rd byte: ethernet compliance codes for 1G */
};

struct i40e_phy_info {
	struct i40e_link_status link_info;
	struct i40e_link_status link_info_old;
	bool get_link_info;
	enum i40e_media_type media_type;
	/* all the phy types the NVM is capable of */
	u64 phy_types;
};

#define I40E_HW_CAP_MAX_GPIO			30

struct i40e_hw_capabilities {
	u32  switch_mode;

	/* Cloud filter modes:
	 * Mode1: Filter on L4 port only
	 * Mode2: Filter for non-tunneled traffic
	 * Mode3: Filter for tunnel traffic
	 */

	u32  management_mode;
	u32  mng_protocols_over_mctp;
	u32  npar_enable;
	u32  os2bmc;
	u32  valid_functions;
	bool sr_iov_1_1;
	bool vmdq;
	bool evb_802_1_qbg; /* Edge Virtual Bridging */
	bool evb_802_1_qbh; /* Bridge Port Extension */
	bool dcb;
	bool fcoe;
	bool iscsi; /* Indicates iSCSI enabled */
	bool flex10_enable;
	bool flex10_capable;
	u32  flex10_mode;

	u32 flex10_status;

	bool sec_rev_disabled;
	bool update_disabled;

	bool mgmt_cem;
	bool ieee_1588;
	bool iwarp;
	bool fd;
	u32 fd_filters_guaranteed;
	u32 fd_filters_best_effort;
	bool rss;
	u32 rss_table_size;
	u32 rss_table_entry_width;
	bool led[I40E_HW_CAP_MAX_GPIO];
	bool sdp[I40E_HW_CAP_MAX_GPIO];
	u32 nvm_image_type;
	u32 num_flow_director_filters;
	u32 num_vfs;
	u32 vf_base_id;
	u32 num_vsis;
	u32 num_rx_qp;
	u32 num_tx_qp;
	u32 base_queue;
	u32 num_msix_vectors;
	u32 num_msix_vectors_vf;
	u32 led_pin_num;
	u32 sdp_pin_num;
	u32 mdio_port_num;
	u32 mdio_port_mode;
	u8 rx_buf_chain_len;
	u32 enabled_tcmap;
	u32 maxtc;
	u64 wr_csr_prot;
};

struct i40e_mac_info {
	enum i40e_mac_type type;
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
	u8 san_addr[ETH_ALEN];
	u8 port_addr[ETH_ALEN];
	u16 max_fcoeq;
};

struct i40e_nvm_info {
	u64 hw_semaphore_timeout; /* usec global time (GTIME resolution) */
	u32 timeout;              /* [ms] */
	u16 sr_size;              /* Shadow RAM size in words */
	bool blank_nvm_mode;      /* is NVM empty (no FW present)*/
	u16 version;              /* NVM package version */
	u32 eetrack;              /* NVM data version */
	u32 oem_ver;              /* OEM version info */
};

enum i40e_nvmupd_state {
	I40E_NVMUPD_STATE_INIT,
	I40E_NVMUPD_STATE_READING,
	I40E_NVMUPD_STATE_WRITING,
	I40E_NVMUPD_STATE_INIT_WAIT,
	I40E_NVMUPD_STATE_WRITE_WAIT,
	I40E_NVMUPD_STATE_ERROR
};

enum i40e_bus_type {
	i40e_bus_type_unknown = 0,
	i40e_bus_type_pci,
	i40e_bus_type_pcix,
	i40e_bus_type_pci_express,
	i40e_bus_type_reserved
};

enum i40e_bus_speed {
	i40e_bus_speed_unknown	= 0,
	i40e_bus_speed_33	= 33,
	i40e_bus_speed_66	= 66,
	i40e_bus_speed_100	= 100,
	i40e_bus_speed_120	= 120,
	i40e_bus_speed_133	= 133,
	i40e_bus_speed_2500	= 2500,
	i40e_bus_speed_5000	= 5000,
	i40e_bus_speed_8000	= 8000,
	i40e_bus_speed_reserved
};

enum i40e_bus_width {
	i40e_bus_width_unknown	= 0,
	i40e_bus_width_pcie_x1	= 1,
	i40e_bus_width_pcie_x2	= 2,
	i40e_bus_width_pcie_x4	= 4,
	i40e_bus_width_pcie_x8	= 8,
	i40e_bus_width_32	= 32,
	i40e_bus_width_64	= 64,
	i40e_bus_width_reserved
};

struct i40e_bus_info {
	enum i40e_bus_speed speed;
	enum i40e_bus_width width;
	enum i40e_bus_type type;

	u16 func;
	u16 device;
	u16 lan_id;
	u16 bus_id;
};

struct i40e_fc_info {
	enum i40e_fc_mode current_mode; /* FC mode in effect */
	enum i40e_fc_mode requested_mode; /* FC mode requested by caller */
};

#define I40E_MAX_TRAFFIC_CLASS		8

#define I40E_DCBX_MAX_APPS		32

struct i40e_dcb_ets_config {
	u8 willing;
	u8 cbs;
	u8 maxtcs;
	u8 prioritytable[I40E_MAX_TRAFFIC_CLASS];
	u8 tcbwtable[I40E_MAX_TRAFFIC_CLASS];
	u8 tsatable[I40E_MAX_TRAFFIC_CLASS];
};

struct i40e_dcb_pfc_config {
	u8 willing;
	u8 mbc;
	u8 pfccap;
	u8 pfcenable;
};

struct i40e_dcb_app_priority_table {
	u8  priority;
	u8  selector;
	u16 protocolid;
};

struct i40e_dcbx_config {
	u8  dcbx_mode;
	u8  app_mode;
	u32 numapps;
	u32 tlv_status; /* CEE mode TLV status */
	struct i40e_dcb_ets_config etscfg;
	struct i40e_dcb_ets_config etsrec;
	struct i40e_dcb_pfc_config pfc;
	struct i40e_dcb_app_priority_table app[I40E_DCBX_MAX_APPS];
};

struct i40e_hw {
	u8 __iomem *hw_addr;
	void *back;

	/* subsystem structs */
	struct i40e_phy_info phy;
	struct i40e_mac_info mac;
	struct i40e_bus_info bus;
	struct i40e_nvm_info nvm;
	struct i40e_fc_info fc;

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;
	u8 port;
	bool adapter_stopped;

	/* capabilities for entire device and PCI func */
	struct i40e_hw_capabilities dev_caps;
	struct i40e_hw_capabilities func_caps;

	/* Flow Director shared filter space */
	u16 fdir_shared_filter_count;

	/* device profile info */
	u8  pf_id;
	u16 main_vsi_seid;

	/* for multi-function MACs */
	u16 partition_id;
	u16 num_partitions;
	u16 num_ports;

	/* Closest numa node to the device */
	u16 numa_node;

	/* Admin Queue info */
	struct i40e_adminq_info aq;

	/* state of nvm update process */
	enum i40e_nvmupd_state nvmupd_state;
	struct i40e_aq_desc nvm_wb_desc;
	struct i40e_aq_desc nvm_aq_event_desc;
	struct i40e_virt_mem nvm_buff;
	bool nvm_release_on_done;
	u16 nvm_wait_opcode;

	/* HMC info */
	struct i40e_hmc_info hmc; /* HMC info struct */

	/* LLDP/DCBX Status */
	u16 dcbx_status;

	/* DCBX info */
	struct i40e_dcbx_config local_dcbx_config; /* Oper/Local Cfg */
	struct i40e_dcbx_config remote_dcbx_config; /* Peer Cfg */
	struct i40e_dcbx_config desired_dcbx_config; /* CEE Desired Cfg */

	u64 flags;

	/* Used in set switch config AQ command */
	u16 switch_tag;
	u16 first_tag;
	u16 second_tag;

	/* debug mask */
	u32 debug_mask;
	char err_str[16];
};

enum i40e_filter_pctype {
	/* Note: Values 0-28 are reserved for future use.
	 * Value 29, 30, 32 are not supported on XL710 and X710.
	 */
	I40E_FILTER_PCTYPE_NONF_UNICAST_IPV4_UDP	= 29,
	I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV4_UDP	= 30,
	I40E_FILTER_PCTYPE_NONF_IPV4_UDP		= 31,
	I40E_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK	= 32,
	I40E_FILTER_PCTYPE_NONF_IPV4_TCP		= 33,
	I40E_FILTER_PCTYPE_NONF_IPV4_SCTP		= 34,
	I40E_FILTER_PCTYPE_NONF_IPV4_OTHER		= 35,
	I40E_FILTER_PCTYPE_FRAG_IPV4			= 36,
	/* Note: Values 37-38 are reserved for future use.
	 * Value 39, 40, 42 are not supported on XL710 and X710.
	 */
	I40E_FILTER_PCTYPE_NONF_UNICAST_IPV6_UDP	= 39,
	I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV6_UDP	= 40,
	I40E_FILTER_PCTYPE_NONF_IPV6_UDP		= 41,
	I40E_FILTER_PCTYPE_NONF_IPV6_TCP_SYN_NO_ACK	= 42,
	I40E_FILTER_PCTYPE_NONF_IPV6_TCP		= 43,
	I40E_FILTER_PCTYPE_NONF_IPV6_SCTP		= 44,
	I40E_FILTER_PCTYPE_NONF_IPV6_OTHER		= 45,
	I40E_FILTER_PCTYPE_FRAG_IPV6			= 46,
	/* Note: Value 47 is reserved for future use */
	I40E_FILTER_PCTYPE_FCOE_OX			= 48,
	I40E_FILTER_PCTYPE_FCOE_RX			= 49,
	I40E_FILTER_PCTYPE_FCOE_OTHER			= 50,
	/* Note: Values 51-62 are reserved for future use */
	I40E_FILTER_PCTYPE_L2_PAYLOAD			= 63,
};

struct i40e_eth_stats {
	u64 rx_bytes;			/* gorc */
	u64 rx_unicast;			/* uprc */
	u64 rx_multicast;		/* mprc */
	u64 rx_broadcast;		/* bprc */
	u64 rx_discards;		/* rdpc */
	u64 rx_unknown_protocol;	/* rupp */
	u64 tx_bytes;			/* gotc */
	u64 tx_unicast;			/* uptc */
	u64 tx_multicast;		/* mptc */
	u64 tx_broadcast;		/* bptc */
	u64 tx_discards;		/* tdpc */
	u64 tx_errors;			/* tepc */
};

struct i40e_hw_port_stats {
	/* eth stats collected by the port */
	struct i40e_eth_stats eth;

	/* additional port specific stats */
	u64 tx_dropped_link_down;	/* tdold */
	u64 crc_errors;			/* crcerrs */
	u64 illegal_bytes;		/* illerrc */
	u64 error_bytes;		/* errbc */
	u64 mac_local_faults;		/* mlfc */
	u64 mac_remote_faults;		/* mrfc */
	u64 rx_length_errors;		/* rlec */
	u64 link_xon_rx;		/* lxonrxc */
	u64 link_xoff_rx;		/* lxoffrxc */
	u64 priority_xon_rx[8];		/* pxonrxc[8] */
	u64 priority_xoff_rx[8];	/* pxoffrxc[8] */
	u64 link_xon_tx;		/* lxontxc */
	u64 link_xoff_tx;		/* lxofftxc */
	u64 priority_xon_tx[8];		/* pxontxc[8] */
	u64 priority_xoff_tx[8];	/* pxofftxc[8] */
	u64 priority_xon_2_xoff[8];	/* pxon2offc[8] */
	u64 rx_size_64;			/* prc64 */
	u64 rx_size_127;		/* prc127 */
	u64 rx_size_255;		/* prc255 */
	u64 rx_size_511;		/* prc511 */
	u64 rx_size_1023;		/* prc1023 */
	u64 rx_size_1522;		/* prc1522 */
	u64 rx_size_big;		/* prc9522 */
	u64 rx_undersize;		/* ruc */
	u64 rx_fragments;		/* rfc */
	u64 rx_oversize;		/* roc */
	u64 rx_jabber;			/* rjc */
	u64 tx_size_64;			/* ptc64 */
	u64 tx_size_127;		/* ptc127 */
	u64 tx_size_255;		/* ptc255 */
	u64 tx_size_511;		/* ptc511 */
	u64 tx_size_1023;		/* ptc1023 */
	u64 tx_size_1522;		/* ptc1522 */
	u64 tx_size_big;		/* ptc9522 */
	u64 mac_short_packet_dropped;	/* mspdc */
	u64 checksum_error;		/* xec */
	/* flow director stats */
	u64 fd_atr_match;
	u64 fd_sb_match;
	u64 fd_atr_tunnel_match;
	u32 fd_atr_status;
	u32 fd_sb_status;
	/* EEE LPI */
	u32 tx_lpi_status;
	u32 rx_lpi_status;
	u64 tx_lpi_count;		/* etlpic */
	u64 rx_lpi_count;		/* erlpic */
};

enum i40e_switch_element_types {
	I40E_SWITCH_ELEMENT_TYPE_MAC	= 1,
	I40E_SWITCH_ELEMENT_TYPE_PF	= 2,
	I40E_SWITCH_ELEMENT_TYPE_VF	= 3,
	I40E_SWITCH_ELEMENT_TYPE_EMP	= 4,
	I40E_SWITCH_ELEMENT_TYPE_BMC	= 6,
	I40E_SWITCH_ELEMENT_TYPE_PE	= 16,
	I40E_SWITCH_ELEMENT_TYPE_VEB	= 17,
	I40E_SWITCH_ELEMENT_TYPE_PA	= 18,
	I40E_SWITCH_ELEMENT_TYPE_VSI	= 19,
};

enum i40e_hash_filter_size {
	I40E_HASH_FILTER_SIZE_1K	= 0,
	I40E_HASH_FILTER_SIZE_2K	= 1,
	I40E_HASH_FILTER_SIZE_4K	= 2,
	I40E_HASH_FILTER_SIZE_8K	= 3,
	I40E_HASH_FILTER_SIZE_16K	= 4,
	I40E_HASH_FILTER_SIZE_32K	= 5,
	I40E_HASH_FILTER_SIZE_64K	= 6,
	I40E_HASH_FILTER_SIZE_128K	= 7,
	I40E_HASH_FILTER_SIZE_256K	= 8,
	I40E_HASH_FILTER_SIZE_512K	= 9,
	I40E_HASH_FILTER_SIZE_1M	= 10,
};

enum i40e_dma_cntx_size {
	I40E_DMA_CNTX_SIZE_512		= 0,
	I40E_DMA_CNTX_SIZE_1K		= 1,
	I40E_DMA_CNTX_SIZE_2K		= 2,
	I40E_DMA_CNTX_SIZE_4K		= 3,
	I40E_DMA_CNTX_SIZE_8K		= 4,
	I40E_DMA_CNTX_SIZE_16K		= 5,
	I40E_DMA_CNTX_SIZE_32K		= 6,
	I40E_DMA_CNTX_SIZE_64K		= 7,
	I40E_DMA_CNTX_SIZE_128K		= 8,
	I40E_DMA_CNTX_SIZE_256K		= 9,
};

enum i40e_hash_lut_size {
	I40E_HASH_LUT_SIZE_128		= 0,
	I40E_HASH_LUT_SIZE_512		= 1,
};

struct i40e_filter_control_settings {
	/* number of PE Quad Hash filter buckets */
	enum i40e_hash_filter_size pe_filt_num;
	/* number of PE Quad Hash contexts */
	enum i40e_dma_cntx_size pe_cntx_num;
	/* number of FCoE filter buckets */
	enum i40e_hash_filter_size fcoe_filt_num;
	/* number of FCoE DDP contexts */
	enum i40e_dma_cntx_size fcoe_cntx_num;
	/* size of the Hash LUT */
	enum i40e_hash_lut_size	hash_lut_size;
	/* enable FDIR filters for PF and its VFs */
	bool enable_fdir;
	/* enable Ethertype filters for PF and its VFs */
	bool enable_ethtype;
	/* enable MAC/VLAN filters for PF and its VFs */
	bool enable_macvlan;
};

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_prototype.h */
#include <linux/avf/virtchnl.h>

static enum i40e_status_code (*klpe_i40e_aq_set_vsi_mc_promisc_on_vlan)(struct i40e_hw *hw,
							 u16 seid, bool enable,
							 u16 vid,
				struct i40e_asq_cmd_details *cmd_details);
static enum i40e_status_code (*klpe_i40e_aq_set_vsi_uc_promisc_on_vlan)(struct i40e_hw *hw,
							 u16 seid, bool enable,
							 u16 vid,
				struct i40e_asq_cmd_details *cmd_details);

static void (*klpe_i40e_write_rx_ctl)(struct i40e_hw *hw, u32 reg_addr, u32 reg_val);

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_client.h */
#define I40E_QUEUE_INVALID_IDX	0xFFFF

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e.h */
#include <linux/avf/virtchnl.h>

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_virtchnl_pf.h */
#define I40E_MAX_VLANID 4095

#define I40E_VIRTCHNL_SUPPORTED_QTYPES 2

#define I40E_MAX_VF_PROMISC_FLAGS	3

enum i40e_vf_states {
	I40E_VF_STATE_INIT = 0,
	I40E_VF_STATE_ACTIVE,
	I40E_VF_STATE_IWARPENA,
	I40E_VF_STATE_DISABLED,
	I40E_VF_STATE_MC_PROMISC,
	I40E_VF_STATE_UC_PROMISC,
	I40E_VF_STATE_PRE_ENABLE,
};

enum i40e_vf_capabilities {
	I40E_VIRTCHNL_VF_CAP_PRIVILEGE = 0,
	I40E_VIRTCHNL_VF_CAP_L2,
	I40E_VIRTCHNL_VF_CAP_IWARP,
};

struct i40evf_channel {
	u16 vsi_idx; /* index in PF struct for all channel VSIs */
	u16 vsi_id; /* VSI ID used by firmware */
	u16 num_qps; /* number of queue pairs requested by user */
	u64 max_tx_rate; /* bandwidth rate allocation for VSIs */
};

struct i40e_vf {
	struct i40e_pf *pf;

	/* VF id in the PF space */
	s16 vf_id;
	/* all VF vsis connect to the same parent */
	enum i40e_switch_element_types parent_type;
	struct virtchnl_version_info vf_ver;
	u32 driver_caps; /* reported by VF driver */

	/* VF Port Extender (PE) stag if used */
	u16 stag;

	struct virtchnl_ether_addr default_lan_addr;
	u16 port_vlan_id;
	bool pf_set_mac;	/* The VMM admin set the VF MAC address */
	bool trusted;

	/* VSI indices - actual VSI pointers are maintained in the PF structure
	 * When assigned, these will be non-zero, because VSI 0 is always
	 * the main LAN VSI for the PF.
	 */
	u16 lan_vsi_idx;	/* index into PF struct */
	u16 lan_vsi_id;		/* ID as used by firmware */

	u8 num_queue_pairs;	/* num of qps assigned to VF vsis */
	u8 num_req_queues;	/* num of requested qps */
	u64 num_mdd_events;	/* num of mdd events detected */
	/* num of continuous malformed or invalid msgs detected */
	u64 num_invalid_msgs;
	u64 num_valid_msgs;	/* num of valid msgs detected */

	unsigned long vf_caps;	/* vf's adv. capabilities */
	unsigned long vf_states;	/* vf's runtime states */
	unsigned int tx_rate;	/* Tx bandwidth limit in Mbps */
	bool link_forced;
	bool link_up;		/* only valid if VF link is forced */
	bool spoofchk;
	u16 num_vlan;

	/* ADq related variables */
	bool adq_enabled; /* flag to enable adq */
	u8 num_tc;
	struct i40evf_channel ch[I40E_MAX_VF_VSI];
	struct hlist_head cloud_filter_list;
	u16 num_cloud_filters;

	/* RDMA Client */
	struct virtchnl_iwarp_qvlist_info *qvlist_info;
};

int klpp_i40e_vc_process_vf_msg(struct i40e_pf *pf, s16 vf_id, u32 v_opcode,
			   u32 v_retval, u8 *msg, u16 msglen);

static bool (*klpe_i40e_reset_vf)(struct i40e_vf *vf, bool flr);

static void (*klpe_i40e_vc_notify_vf_reset)(struct i40e_vf *vf);

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_txrx.h */
#include <net/xdp.h>

#define I40E_QUEUE_END_OF_LIST 0x7FF

#define I40E_DEFAULT_RSS_HENA ( \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_UDP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_SCTP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_TCP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_OTHER) | \
	BIT_ULL(I40E_FILTER_PCTYPE_FRAG_IPV4) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_UDP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_TCP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_SCTP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_OTHER) | \
	BIT_ULL(I40E_FILTER_PCTYPE_FRAG_IPV6) | \
	BIT_ULL(I40E_FILTER_PCTYPE_L2_PAYLOAD))

#define I40E_DEFAULT_RSS_HENA_EXPANDED (I40E_DEFAULT_RSS_HENA | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV4_TCP_SYN_NO_ACK) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_UNICAST_IPV4_UDP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV4_UDP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_IPV6_TCP_SYN_NO_ACK) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_UNICAST_IPV6_UDP) | \
	BIT_ULL(I40E_FILTER_PCTYPE_NONF_MULTICAST_IPV6_UDP))

#define i40e_pf_get_default_rss_hena(pf) \
	(((pf)->hw_features & I40E_HW_MULTIPLE_TCP_UDP_RSS_PCTYPE) ? \
	  I40E_DEFAULT_RSS_HENA_EXPANDED : I40E_DEFAULT_RSS_HENA)

#define I40E_RX_DTYPE_HEADER_SPLIT  1

#define I40E_RX_SPLIT_L2      0x1
#define I40E_RX_SPLIT_IP      0x2
#define I40E_RX_SPLIT_TCP_UDP 0x4
#define I40E_RX_SPLIT_SCTP    0x8

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e.h */
#define I40E_MAX_VEB			16

#define I40E_MAX_NUM_DESCRIPTORS	4096

#define I40E_DEFAULT_QUEUES_PER_VF	4
#define I40E_MAX_VF_QUEUES		16

#define I40E_INT_NAME_STR_LEN		(IFNAMSIZ + 16)

enum i40e_state_t {
	__I40E_TESTING,
	__I40E_CONFIG_BUSY,
	__I40E_CONFIG_DONE,
	__I40E_DOWN,
	__I40E_SERVICE_SCHED,
	__I40E_ADMINQ_EVENT_PENDING,
	__I40E_MDD_EVENT_PENDING,
	__I40E_VFLR_EVENT_PENDING,
	__I40E_RESET_RECOVERY_PENDING,
	__I40E_TIMEOUT_RECOVERY_PENDING,
	__I40E_MISC_IRQ_REQUESTED,
	__I40E_RESET_INTR_RECEIVED,
	__I40E_REINIT_REQUESTED,
	__I40E_PF_RESET_REQUESTED,
	__I40E_PF_RESET_AND_REBUILD_REQUESTED,
	__I40E_CORE_RESET_REQUESTED,
	__I40E_GLOBAL_RESET_REQUESTED,
	__I40E_EMP_RESET_REQUESTED,
	__I40E_EMP_RESET_INTR_RECEIVED,
	__I40E_SUSPENDED,
	__I40E_PTP_TX_IN_PROGRESS,
	__I40E_BAD_EEPROM,
	__I40E_DOWN_REQUESTED,
	__I40E_FD_FLUSH_REQUESTED,
	__I40E_FD_ATR_AUTO_DISABLED,
	__I40E_FD_SB_AUTO_DISABLED,
	__I40E_RESET_FAILED,
	__I40E_PORT_SUSPENDED,
	__I40E_VF_DISABLE,
	__I40E_MACVLAN_SYNC_PENDING,
	__I40E_UDP_FILTER_SYNC_PENDING,
	__I40E_TEMP_LINK_POLLING,
	__I40E_CLIENT_SERVICE_REQUESTED,
	__I40E_CLIENT_L2_CHANGE,
	__I40E_CLIENT_RESET,
	__I40E_VIRTCHNL_OP_PENDING,
	__I40E_RECOVERY_MODE,
	__I40E_VF_RESETS_DISABLED,	/* disable resets during i40e_remove */
	__I40E_IN_REMOVE,
	__I40E_VFS_RELEASING,
	/* This must be last as it determines the size of the BITMAP */
	__I40E_STATE_SIZE__,
};

enum i40e_vsi_state_t {
	__I40E_VSI_DOWN,
	__I40E_VSI_NEEDS_RESTART,
	__I40E_VSI_SYNCING_FILTERS,
	__I40E_VSI_OVERFLOW_PROMISC,
	__I40E_VSI_REINIT_REQUESTED,
	__I40E_VSI_DOWN_REQUESTED,
	__I40E_VSI_RELEASING,
	/* This must be last as it determines the size of the BITMAP */
	__I40E_VSI_STATE_SIZE__,
};

enum i40e_interrupt_policy {
	I40E_INTERRUPT_BEST_CASE,
	I40E_INTERRUPT_MEDIUM,
	I40E_INTERRUPT_LOWEST
};

#define I40E_HKEY_ARRAY_SIZE	((I40E_PFQF_HKEY_MAX_INDEX + 1) * 4)

#define I40E_VF_HLUT_ARRAY_SIZE	((I40E_VFQF_HLUT1_MAX_INDEX + 1) * 4)

struct i40e_tc_info {
	u16	qoffset;	/* Queue offset from base queue */
	u16	qcount;		/* Total Queues */
	u8	netdev_tc;	/* Netdev TC index if netdev associated */
};

struct i40e_tc_configuration {
	u8	numtc;		/* Total number of enabled TCs */
	u8	enabled_tc;	/* TC map */
	struct i40e_tc_info tc_info[I40E_MAX_TRAFFIC_CLASS];
};

struct i40e_udp_port_config {
	/* AdminQ command interface expects port number in Host byte order */
	u16 port;
	u8 type;
	u8 filter_index;
};

struct i40e_pf {
	struct pci_dev *pdev;
	struct i40e_hw hw;
	DECLARE_BITMAP(state, __I40E_STATE_SIZE__);
	struct msix_entry *msix_entries;
	bool fc_autoneg_status;

	u16 eeprom_version;
	u16 num_vmdq_vsis;         /* num vmdq vsis this PF has set up */
	u16 num_vmdq_qps;          /* num queue pairs per vmdq pool */
	u16 num_vmdq_msix;         /* num queue vectors per vmdq pool */
	u16 num_req_vfs;           /* num VFs requested for this PF */
	u16 num_vf_qps;            /* num queue pairs per VF */
	u16 num_lan_qps;           /* num lan queues this PF has set up */
	u16 num_lan_msix;          /* num queue vectors for the base PF vsi */
	u16 num_fdsb_msix;         /* num queue vectors for sideband Fdir */
	u16 num_iwarp_msix;        /* num of iwarp vectors for this PF */
	int iwarp_base_vector;
	int queues_left;           /* queues left unclaimed */
	u16 alloc_rss_size;        /* allocated RSS queues */
	u16 rss_size_max;          /* HW defined max RSS queues */
	u16 fdir_pf_filter_count;  /* num of guaranteed filters for this PF */
	u16 num_alloc_vsi;         /* num VSIs this driver supports */
	u8 atr_sample_rate;
	bool wol_en;

	struct hlist_head fdir_filter_list;
	u16 fdir_pf_active_filters;
	unsigned long fd_flush_timestamp;
	u32 fd_flush_cnt;
	u32 fd_add_err;
	u32 fd_atr_cnt;

	/* Book-keeping of side-band filter count per flow-type.
	 * This is used to detect and handle input set changes for
	 * respective flow-type.
	 */
	u16 fd_tcp4_filter_cnt;
	u16 fd_udp4_filter_cnt;
	u16 fd_sctp4_filter_cnt;
	u16 fd_ip4_filter_cnt;

	/* Flexible filter table values that need to be programmed into
	 * hardware, which expects L3 and L4 to be programmed separately. We
	 * need to ensure that the values are in ascended order and don't have
	 * duplicates, so we track each L3 and L4 values in separate lists.
	 */
	struct list_head l3_flex_pit_list;
	struct list_head l4_flex_pit_list;

	struct i40e_udp_port_config udp_ports[I40E_MAX_PF_UDP_OFFLOAD_PORTS];
	u16 pending_udp_bitmap;

	struct hlist_head cloud_filter_list;
	u16 num_cloud_filters;

	enum i40e_interrupt_policy int_policy;
	u16 rx_itr_default;
	u16 tx_itr_default;
	u32 msg_enable;
	char int_name[I40E_INT_NAME_STR_LEN];
	u16 adminq_work_limit; /* num of admin receive queue desc to process */
	unsigned long service_timer_period;
	unsigned long service_timer_previous;
	struct timer_list service_timer;
	struct work_struct service_task;

	u32 hw_features;
#define I40E_HW_RSS_AQ_CAPABLE			BIT(0)

#define I40E_HW_WB_ON_ITR_CAPABLE		BIT(3)
#define I40E_HW_MULTIPLE_TCP_UDP_RSS_PCTYPE	BIT(4)

#define I40E_HW_OUTER_UDP_CSUM_CAPABLE		BIT(14)
	u32 flags;

#define I40E_FLAG_MFP_ENABLED			BIT(10)
	struct i40e_client_instance *cinst;
	bool stat_offsets_loaded;
	struct i40e_hw_port_stats stats;
	struct i40e_hw_port_stats stats_offsets;
	u32 tx_timeout_count;
	u32 tx_timeout_recovery_level;
	unsigned long tx_timeout_last_recovery;
	u32 tx_sluggish_count;
	u32 hw_csum_rx_error;
	u32 led_status;
	u16 corer_count; /* Core reset count */
	u16 globr_count; /* Global reset count */
	u16 empr_count; /* EMP reset count */
	u16 pfr_count; /* PF reset count */
	u16 sw_int_count; /* SW interrupt count */

	struct mutex switch_mutex;
	u16 lan_vsi;       /* our default LAN VSI */
	u16 lan_veb;       /* initial relay, if exists */
	u16 next_vsi;      /* Next unallocated VSI - 0-based! */
	struct i40e_vsi **vsi;
	struct i40e_veb *veb[I40E_MAX_VEB];

	struct i40e_lump_tracking *qp_pile;
	struct i40e_lump_tracking *irq_pile;

	/* switch config info */
	u16 pf_seid;
	u16 main_vsi_seid;
	u16 mac_seid;
	struct kobject *switch_kobj;
#ifdef CONFIG_DEBUG_FS
	struct dentry *i40e_dbg_pf;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_DEBUG_FS */
	bool cur_promisc;

	u16 instance; /* A unique number per i40e_pf instance in the system */

	/* sr-iov config info */
	struct i40e_vf *vf;
	int num_alloc_vfs;	/* actual number of VFs allocated */
	u32 vf_aq_requests;
	u32 arq_overflows;	/* Not fatal, possibly indicative of problems */

	/* DCBx/DCBNL capability for PF that indicates
	 * whether DCBx is managed by firmware or host
	 * based agent (LLDPAD). Also, indicates what
	 * flavor of DCBx protocol (IEEE/CEE) is supported
	 * by the device. For now we're supporting IEEE
	 * mode only.
	 */
	u16 dcbx_cap;

	struct i40e_filter_control_settings filter_settings;

	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_caps;
	struct sk_buff *ptp_tx_skb;
	unsigned long ptp_tx_start;
	struct hwtstamp_config tstamp_config;
	struct timespec64 ptp_prev_hw_time;
	ktime_t ptp_reset_start;
	struct mutex tmreg_lock; /* Used to protect the SYSTIME registers. */
	u32 ptp_adj_mult;
	u32 tx_hwtstamp_timeouts;
	u32 tx_hwtstamp_skipped;
	u32 rx_hwtstamp_cleared;
	u32 latch_event_flags;
	spinlock_t ptp_rx_lock; /* Used to protect Rx timestamp registers. */
	unsigned long latch_events[4];
	bool ptp_tx;
	bool ptp_rx;
	u16 rss_table_size; /* HW RSS table size */
	u32 max_bw;
	u32 min_bw;

	u32 ioremap_len;
	u32 fd_inv;
	u16 phy_led_val;

	u16 override_q_count;
	u16 last_sw_conf_flags;
	u16 last_sw_conf_valid_flags;
	/* List to keep previous DDP profiles to be rolled back in the future */
	struct list_head ddp_old_prof;
};

enum i40e_filter_state {
	I40E_FILTER_INVALID = 0,	/* Invalid state */
	I40E_FILTER_NEW,		/* New, not sent to FW yet */
	I40E_FILTER_ACTIVE,		/* Added to switch by FW */
	I40E_FILTER_FAILED,		/* Rejected by FW */
	I40E_FILTER_REMOVE,		/* To be removed */
	I40E_FILTER_NEW_SYNC,		/* New, not sent yet, is in i40e_sync_vsi_filters() */
/* There is no 'removed' state; the filter struct is freed */
};
struct i40e_mac_filter {
	struct hlist_node hlist;
	u8 macaddr[ETH_ALEN];
	s16 vlan;
	enum i40e_filter_state state;
};

struct i40e_vsi {
	struct net_device *netdev;
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	bool netdev_registered;
	bool stat_offsets_loaded;

	u32 current_netdev_flags;
	DECLARE_BITMAP(state, __I40E_VSI_STATE_SIZE__);
	unsigned long flags;

	/* Per VSI lock to protect elements/hash (MAC filter) */
	spinlock_t mac_filter_hash_lock;
	/* Fixed size hash table with 2^8 buckets for MAC filters */
	DECLARE_HASHTABLE(mac_filter_hash, 8);
	bool has_vlan_filter;

	/* VSI stats */
	struct rtnl_link_stats64 net_stats;
	struct rtnl_link_stats64 net_stats_offsets;
	struct i40e_eth_stats eth_stats;
	struct i40e_eth_stats eth_stats_offsets;
	u32 tx_restart;
	u32 tx_busy;
	u64 tx_linearize;
	u64 tx_force_wb;
	u32 rx_buf_failed;
	u32 rx_page_failed;

	/* These are containers of ring pointers, allocated at run-time */
	struct i40e_ring **rx_rings;
	struct i40e_ring **tx_rings;
	struct i40e_ring **xdp_rings; /* XDP Tx rings */

	u32  active_filters;
	u32  promisc_threshold;

	u16 work_limit;
	u16 int_rate_limit;	/* value in usecs */

	u16 rss_table_size;	/* HW RSS table size */
	u16 rss_size;		/* Allocated RSS queues */
	u8  *rss_hkey_user;	/* User configured hash keys */
	u8  *rss_lut_user;	/* User configured lookup table entries */
	u16 max_frame;
	u16 rx_buf_len;

	struct bpf_prog *xdp_prog;

	/* List of q_vectors allocated to this VSI */
	struct i40e_q_vector **q_vectors;
	int num_q_vectors;
	int base_vector;
	bool irqs_ready;

	u16 seid;		/* HW index of this VSI (absolute index) */
	u16 id;			/* VSI number */
	u16 uplink_seid;

	u16 base_queue;		/* vsi's first queue in hw array */
	u16 alloc_queue_pairs;	/* Allocated Tx/Rx queues */
	u16 req_queue_pairs;	/* User requested queue pairs */
	u16 num_queue_pairs;	/* Used tx and rx pairs */
	u16 num_desc;
	enum i40e_vsi_type type;  /* VSI type, e.g., LAN, FCoE, etc */
	s16 vf_id;		/* Virtual function ID for SRIOV VSIs */

	struct tc_mqprio_qopt_offload mqprio_qopt; /* queue parameters */
	struct i40e_tc_configuration tc_config;
	struct i40e_aqc_vsi_properties_data info;

	/* VSI BW limit (absolute across all TCs) */
	u16 bw_limit;		/* VSI BW Limit (0 = disabled) */
	u8  bw_max_quanta;	/* Max Quanta when BW limit is enabled */

	/* Relative TC credits across VSIs */
	u8  bw_ets_share_credits[I40E_MAX_TRAFFIC_CLASS];
	/* TC BW limit credits within VSI */
	u16  bw_ets_limit_credits[I40E_MAX_TRAFFIC_CLASS];
	/* TC BW limit max quanta within VSI */
	u8  bw_ets_max_quanta[I40E_MAX_TRAFFIC_CLASS];

	struct i40e_pf *back;	/* Backreference to associated PF */
	u16 idx;		/* index in pf->vsi[] */
	u16 veb_idx;		/* index of VEB parent */
	struct kobject *kobj;	/* sysfs object */
	bool current_isup;	/* Sync 'link up' logging */
	enum i40e_aq_link_speed current_speed;	/* Sync link speed logging */

	/* channel specific fields */
	u16 cnt_q_avail;	/* num of queues available for channel usage */
	u16 orig_rss_size;
	u16 current_rss_size;
	bool reconfig_rss;

	u16 next_base_queue;	/* next queue to be used for channel setup */

	struct list_head ch_list;
	u16 tc_seid_map[I40E_MAX_TRAFFIC_CLASS];

	void *priv;	/* client driver data reference. */

	/* VSI specific handlers */
	irqreturn_t (*irq_handler)(int irq, void *data);

	unsigned long *af_xdp_zc_qps; /* tracks AF_XDP ZC enabled qps */
} ____cacheline_internodealigned_in_smp;

static int (*klpe_i40e_config_rss)(struct i40e_vsi *vsi, u8 *seed, u8 *lut, u16 lut_size);

static struct i40e_vsi *(*klpe_i40e_find_vsi_from_id)(struct i40e_pf *pf, u16 id);

static void (*klpe_i40e_update_eth_stats)(struct i40e_vsi *vsi);

static int (*klpe_i40e_sync_vsi_filters)(struct i40e_vsi *vsi);

static int (*klpe_i40e_vsi_release)(struct i40e_vsi *vsi);

static void (*klpe_i40e_notify_client_of_vf_msg)(struct i40e_vsi *vsi, u32 vf_id,
				  u8 *msg, u16 len);

static int (*klpe_i40e_control_wait_rx_q)(struct i40e_pf *pf, int pf_q, bool enable);
static int (*klpe_i40e_vsi_start_rings)(struct i40e_vsi *vsi);

static int (*klpe_i40e_vf_client_capable)(struct i40e_pf *pf, u32 vf_id);

static void (*klpe_i40e_vlan_stripping_disable)(struct i40e_vsi *vsi);

static int (*klpe_i40e_vsi_add_vlan)(struct i40e_vsi *vsi, u16 vid);

static void (*klpe_i40e_vsi_kill_vlan)(struct i40e_vsi *vsi, u16 vid);
static struct i40e_mac_filter *(*klpe_i40e_add_mac_filter)(struct i40e_vsi *vsi,
					    const u8 *macaddr);
static int (*klpe_i40e_del_mac_filter)(struct i40e_vsi *vsi, const u8 *macaddr);

static int (*klpe_i40e_count_filters)(struct i40e_vsi *vsi);
static struct i40e_mac_filter *(*klpe_i40e_find_mac)(struct i40e_vsi *vsi, const u8 *macaddr);
static void (*klpe_i40e_vlan_stripping_enable)(struct i40e_vsi *vsi);

static int (*klpe_i40e_update_adq_vsi_queues)(struct i40e_vsi *vsi, int vsi_offset);

/* klp-ccp: from drivers/net/ethernet/intel/i40e/i40e_virtchnl_pf.c */
static void (*klpe_i40e_vc_notify_vf_link_state)(struct i40e_vf *vf);
static inline bool klpr_i40e_vc_isvalid_vsi_id(struct i40e_vf *vf, u16 vsi_id)
{
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = (*klpe_i40e_find_vsi_from_id)(pf, vsi_id);

	return (vsi && (vsi->vf_id == vf->vf_id));
}

static inline bool klpr_i40e_vc_isvalid_queue_id(struct i40e_vf *vf, u16 vsi_id,
					    u16 qid)
{
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = (*klpe_i40e_find_vsi_from_id)(pf, vsi_id);

	return (vsi && (qid < vsi->alloc_queue_pairs));
}

static inline bool i40e_vc_isvalid_vector_id(struct i40e_vf *vf, u32 vector_id)
{
	struct i40e_pf *pf = vf->pf;

	return vector_id < pf->hw.func_caps.num_msix_vectors_vf;
}

static u16 klpr_i40e_vc_get_pf_queue_id(struct i40e_vf *vf, u16 vsi_id,
				   u8 vsi_queue_id)
{
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = (*klpe_i40e_find_vsi_from_id)(pf, vsi_id);
	u16 pf_queue_id = I40E_QUEUE_END_OF_LIST;

	if (!vsi)
		return pf_queue_id;

	if (le16_to_cpu(vsi->info.mapping_flags) &
	    I40E_AQ_VSI_QUE_MAP_NONCONTIG)
		pf_queue_id =
			le16_to_cpu(vsi->info.queue_mapping[vsi_queue_id]);
	else
		pf_queue_id = le16_to_cpu(vsi->info.queue_mapping[0]) +
			      vsi_queue_id;

	return pf_queue_id;
}

static u16 (*klpe_i40e_get_real_pf_qid)(struct i40e_vf *vf, u16 vsi_id, u16 queue_id);

static void klpr_i40e_config_irq_link_list(struct i40e_vf *vf, u16 vsi_id,
				      struct virtchnl_vector_map *vecmap)
{
	unsigned long linklistmap = 0, tempmap;
	struct i40e_pf *pf = vf->pf;
	struct i40e_hw *hw = &pf->hw;
	u16 vsi_queue_id, pf_queue_id;
	enum i40e_queue_type qtype;
	u16 next_q, vector_id, size;
	u32 reg, reg_idx;
	u16 itr_idx = 0;

	vector_id = vecmap->vector_id;
	/* setup the head */
	if (0 == vector_id)
		reg_idx = I40E_VPINT_LNKLST0(vf->vf_id);
	else
		reg_idx = I40E_VPINT_LNKLSTN(
		     ((pf->hw.func_caps.num_msix_vectors_vf - 1) * vf->vf_id) +
		     (vector_id - 1));

	if (vecmap->rxq_map == 0 && vecmap->txq_map == 0) {
		/* Special case - No queues mapped on this vector */
		wr32(hw, reg_idx, I40E_VPINT_LNKLST0_FIRSTQ_INDX_MASK);
		goto irq_list_done;
	}
	tempmap = vecmap->rxq_map;
	for_each_set_bit(vsi_queue_id, &tempmap, I40E_MAX_VSI_QP) {
		linklistmap |= (BIT(I40E_VIRTCHNL_SUPPORTED_QTYPES *
				    vsi_queue_id));
	}

	tempmap = vecmap->txq_map;
	for_each_set_bit(vsi_queue_id, &tempmap, I40E_MAX_VSI_QP) {
		linklistmap |= (BIT(I40E_VIRTCHNL_SUPPORTED_QTYPES *
				     vsi_queue_id + 1));
	}

	size = I40E_MAX_VSI_QP * I40E_VIRTCHNL_SUPPORTED_QTYPES;
	next_q = find_first_bit(&linklistmap, size);
	if (unlikely(next_q == size))
		goto irq_list_done;

	vsi_queue_id = next_q / I40E_VIRTCHNL_SUPPORTED_QTYPES;
	qtype = next_q % I40E_VIRTCHNL_SUPPORTED_QTYPES;
	pf_queue_id = (*klpe_i40e_get_real_pf_qid)(vf, vsi_id, vsi_queue_id);
	reg = ((qtype << I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_SHIFT) | pf_queue_id);

	wr32(hw, reg_idx, reg);

	while (next_q < size) {
		switch (qtype) {
		case I40E_QUEUE_TYPE_RX:
			reg_idx = I40E_QINT_RQCTL(pf_queue_id);
			itr_idx = vecmap->rxitr_idx;
			break;
		case I40E_QUEUE_TYPE_TX:
			reg_idx = I40E_QINT_TQCTL(pf_queue_id);
			itr_idx = vecmap->txitr_idx;
			break;
		default:
			break;
		}

		next_q = find_next_bit(&linklistmap, size, next_q + 1);
		if (next_q < size) {
			vsi_queue_id = next_q / I40E_VIRTCHNL_SUPPORTED_QTYPES;
			qtype = next_q % I40E_VIRTCHNL_SUPPORTED_QTYPES;
			pf_queue_id = (*klpe_i40e_get_real_pf_qid)(vf,
							   vsi_id,
							   vsi_queue_id);
		} else {
			pf_queue_id = I40E_QUEUE_END_OF_LIST;
			qtype = 0;
		}

		/* format for the RQCTL & TQCTL regs is same */
		reg = (vector_id) |
		    (qtype << I40E_QINT_RQCTL_NEXTQ_TYPE_SHIFT) |
		    (pf_queue_id << I40E_QINT_RQCTL_NEXTQ_INDX_SHIFT) |
		    BIT(I40E_QINT_RQCTL_CAUSE_ENA_SHIFT) |
		    (itr_idx << I40E_QINT_RQCTL_ITR_INDX_SHIFT);
		wr32(hw, reg_idx, reg);
	}

	/* if the vf is running in polling mode and using interrupt zero,
	 * need to disable auto-mask on enabling zero interrupt for VFs.
	 */
	if ((vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_POLLING) &&
	    (vector_id == 0)) {
		reg = rd32(hw, I40E_GLINT_CTL);
		if (!(reg & I40E_GLINT_CTL_DIS_AUTOMASK_VF0_MASK)) {
			reg |= I40E_GLINT_CTL_DIS_AUTOMASK_VF0_MASK;
			wr32(hw, I40E_GLINT_CTL, reg);
		}
	}

irq_list_done:
	i40e_flush(hw);
}

static void i40e_release_iwarp_qvlist(struct i40e_vf *vf)
{
	struct i40e_pf *pf = vf->pf;
	struct virtchnl_iwarp_qvlist_info *qvlist_info = vf->qvlist_info;
	u32 msix_vf;
	u32 i;

	if (!vf->qvlist_info)
		return;

	msix_vf = pf->hw.func_caps.num_msix_vectors_vf;
	for (i = 0; i < qvlist_info->num_vectors; i++) {
		struct virtchnl_iwarp_qv_info *qv_info;
		u32 next_q_index, next_q_type;
		struct i40e_hw *hw = &pf->hw;
		u32 v_idx, reg_idx, reg;

		qv_info = &qvlist_info->qv_info[i];
		if (!qv_info)
			continue;
		v_idx = qv_info->v_idx;
		if (qv_info->ceq_idx != I40E_QUEUE_INVALID_IDX) {
			/* Figure out the queue after CEQ and make that the
			 * first queue.
			 */
			reg_idx = (msix_vf - 1) * vf->vf_id + qv_info->ceq_idx;
			reg = rd32(hw, I40E_VPINT_CEQCTL(reg_idx));
			next_q_index = (reg & I40E_VPINT_CEQCTL_NEXTQ_INDX_MASK)
					>> I40E_VPINT_CEQCTL_NEXTQ_INDX_SHIFT;
			next_q_type = (reg & I40E_VPINT_CEQCTL_NEXTQ_TYPE_MASK)
					>> I40E_VPINT_CEQCTL_NEXTQ_TYPE_SHIFT;

			reg_idx = ((msix_vf - 1) * vf->vf_id) + (v_idx - 1);
			reg = (next_q_index &
			       I40E_VPINT_LNKLSTN_FIRSTQ_INDX_MASK) |
			       (next_q_type <<
			       I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_SHIFT);

			wr32(hw, I40E_VPINT_LNKLSTN(reg_idx), reg);
		}
	}
	kfree(vf->qvlist_info);
	vf->qvlist_info = NULL;
}

static int i40e_config_iwarp_qvlist(struct i40e_vf *vf,
				    struct virtchnl_iwarp_qvlist_info *qvlist_info)
{
	struct i40e_pf *pf = vf->pf;
	struct i40e_hw *hw = &pf->hw;
	struct virtchnl_iwarp_qv_info *qv_info;
	u32 v_idx, i, reg_idx, reg;
	u32 next_q_idx, next_q_type;
	u32 msix_vf, size;
	int ret = 0;

	msix_vf = pf->hw.func_caps.num_msix_vectors_vf;

	if (qvlist_info->num_vectors > msix_vf) {
		dev_warn(&pf->pdev->dev,
			 "Incorrect number of iwarp vectors %u. Maximum %u allowed.\n",
			 qvlist_info->num_vectors,
			 msix_vf);
		ret = -EINVAL;
		goto err_out;
	}

	size = sizeof(struct virtchnl_iwarp_qvlist_info) +
	       (sizeof(struct virtchnl_iwarp_qv_info) *
						(qvlist_info->num_vectors - 1));
	kfree(vf->qvlist_info);
	vf->qvlist_info = kzalloc(size, GFP_KERNEL);
	if (!vf->qvlist_info) {
		ret = -ENOMEM;
		goto err_out;
	}
	vf->qvlist_info->num_vectors = qvlist_info->num_vectors;

	msix_vf = pf->hw.func_caps.num_msix_vectors_vf;
	for (i = 0; i < qvlist_info->num_vectors; i++) {
		qv_info = &qvlist_info->qv_info[i];
		if (!qv_info)
			continue;
		v_idx = qv_info->v_idx;

		/* Validate vector id belongs to this vf */
		if (!i40e_vc_isvalid_vector_id(vf, v_idx)) {
			ret = -EINVAL;
			goto err_free;
		}

		vf->qvlist_info->qv_info[i] = *qv_info;

		reg_idx = ((msix_vf - 1) * vf->vf_id) + (v_idx - 1);
		/* We might be sharing the interrupt, so get the first queue
		 * index and type, push it down the list by adding the new
		 * queue on top. Also link it with the new queue in CEQCTL.
		 */
		reg = rd32(hw, I40E_VPINT_LNKLSTN(reg_idx));
		next_q_idx = ((reg & I40E_VPINT_LNKLSTN_FIRSTQ_INDX_MASK) >>
				I40E_VPINT_LNKLSTN_FIRSTQ_INDX_SHIFT);
		next_q_type = ((reg & I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_MASK) >>
				I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_SHIFT);

		if (qv_info->ceq_idx != I40E_QUEUE_INVALID_IDX) {
			reg_idx = (msix_vf - 1) * vf->vf_id + qv_info->ceq_idx;
			reg = (I40E_VPINT_CEQCTL_CAUSE_ENA_MASK |
			(v_idx << I40E_VPINT_CEQCTL_MSIX_INDX_SHIFT) |
			(qv_info->itr_idx << I40E_VPINT_CEQCTL_ITR_INDX_SHIFT) |
			(next_q_type << I40E_VPINT_CEQCTL_NEXTQ_TYPE_SHIFT) |
			(next_q_idx << I40E_VPINT_CEQCTL_NEXTQ_INDX_SHIFT));
			wr32(hw, I40E_VPINT_CEQCTL(reg_idx), reg);

			reg_idx = ((msix_vf - 1) * vf->vf_id) + (v_idx - 1);
			reg = (qv_info->ceq_idx &
			       I40E_VPINT_LNKLSTN_FIRSTQ_INDX_MASK) |
			       (I40E_QUEUE_TYPE_PE_CEQ <<
			       I40E_VPINT_LNKLSTN_FIRSTQ_TYPE_SHIFT);
			wr32(hw, I40E_VPINT_LNKLSTN(reg_idx), reg);
		}

		if (qv_info->aeq_idx != I40E_QUEUE_INVALID_IDX) {
			reg = (I40E_VPINT_AEQCTL_CAUSE_ENA_MASK |
			(v_idx << I40E_VPINT_AEQCTL_MSIX_INDX_SHIFT) |
			(qv_info->itr_idx << I40E_VPINT_AEQCTL_ITR_INDX_SHIFT));

			wr32(hw, I40E_VPINT_AEQCTL(vf->vf_id), reg);
		}
	}

	return 0;
err_free:
	kfree(vf->qvlist_info);
	vf->qvlist_info = NULL;
err_out:
	return ret;
}

static int klpp_i40e_config_vsi_tx_queue(struct i40e_vf *vf, u16 vsi_id,
				    u16 vsi_queue_id,
				    struct virtchnl_txq_info *info)
{
	struct i40e_pf *pf = vf->pf;
	struct i40e_hw *hw = &pf->hw;
	struct i40e_hmc_obj_txq tx_ctx;
	struct i40e_vsi *vsi;
	u16 pf_queue_id;
	u32 qtx_ctl;
	int ret = 0;

	if (!klpr_i40e_vc_isvalid_vsi_id(vf, info->vsi_id)) {
		ret = -ENOENT;
		goto error_context;
	}
	pf_queue_id = klpr_i40e_vc_get_pf_queue_id(vf, vsi_id, vsi_queue_id);
	vsi = (*klpe_i40e_find_vsi_from_id)(pf, vsi_id);
	if (!vsi) {
		ret = -ENOENT;
		goto error_context;
	}

	/* clear the context structure first */
	memset(&tx_ctx, 0, sizeof(struct i40e_hmc_obj_txq));

	/* only set the required fields */
	tx_ctx.base = info->dma_ring_addr / 128;

	/* ring_len has to be multiple of 8 */
	if (!IS_ALIGNED(info->ring_len, 8) ||
	    info->ring_len > I40E_MAX_NUM_DESCRIPTORS) {
		ret = -EINVAL;
		goto error_context;
	}
	tx_ctx.qlen = info->ring_len;
	tx_ctx.rdylist = le16_to_cpu(vsi->info.qs_handle[0]);
	tx_ctx.rdylist_act = 0;
	tx_ctx.head_wb_ena = info->headwb_enabled;
	tx_ctx.head_wb_addr = info->dma_headwb_addr;

	/* clear the context in the HMC */
	ret = (*klpe_i40e_clear_lan_tx_queue_context)(hw, pf_queue_id);
	if (ret) {
		dev_err(&pf->pdev->dev,
			"Failed to clear VF LAN Tx queue context %d, error: %d\n",
			pf_queue_id, ret);
		ret = -ENOENT;
		goto error_context;
	}

	/* set the context in the HMC */
	ret = (*klpe_i40e_set_lan_tx_queue_context)(hw, pf_queue_id, &tx_ctx);
	if (ret) {
		dev_err(&pf->pdev->dev,
			"Failed to set VF LAN Tx queue context %d error: %d\n",
			pf_queue_id, ret);
		ret = -ENOENT;
		goto error_context;
	}

	/* associate this queue with the PCI VF function */
	qtx_ctl = I40E_QTX_CTL_VF_QUEUE;
	qtx_ctl |= ((hw->pf_id << I40E_QTX_CTL_PF_INDX_SHIFT)
		    & I40E_QTX_CTL_PF_INDX_MASK);
	qtx_ctl |= (((vf->vf_id + hw->func_caps.vf_base_id)
		     << I40E_QTX_CTL_VFVM_INDX_SHIFT)
		    & I40E_QTX_CTL_VFVM_INDX_MASK);
	wr32(hw, I40E_QTX_CTL(pf_queue_id), qtx_ctl);
	i40e_flush(hw);

error_context:
	return ret;
}

static int klpp_i40e_config_vsi_rx_queue(struct i40e_vf *vf, u16 vsi_id,
				    u16 vsi_queue_id,
				    struct virtchnl_rxq_info *info)
{
	u16 pf_queue_id = klpr_i40e_vc_get_pf_queue_id(vf, vsi_id, vsi_queue_id);
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = pf->vsi[vf->lan_vsi_idx];
	struct i40e_hw *hw = &pf->hw;
	struct i40e_hmc_obj_rxq rx_ctx;
	int ret = 0;

	/* clear the context structure first */
	memset(&rx_ctx, 0, sizeof(struct i40e_hmc_obj_rxq));

	/* only set the required fields */
	rx_ctx.base = info->dma_ring_addr / 128;

	/* ring_len has to be multiple of 32 */
	if (!IS_ALIGNED(info->ring_len, 32) ||
	    info->ring_len > I40E_MAX_NUM_DESCRIPTORS) {
		ret = -EINVAL;
		goto error_param;
	}
	rx_ctx.qlen = info->ring_len;

	if (info->splithdr_enabled) {
		rx_ctx.hsplit_0 = I40E_RX_SPLIT_L2      |
				  I40E_RX_SPLIT_IP      |
				  I40E_RX_SPLIT_TCP_UDP |
				  I40E_RX_SPLIT_SCTP;
		/* header length validation */
		if (info->hdr_size > ((2 * 1024) - 64)) {
			ret = -EINVAL;
			goto error_param;
		}
		rx_ctx.hbuff = info->hdr_size >> I40E_RXQ_CTX_HBUFF_SHIFT;

		/* set split mode 10b */
		rx_ctx.dtype = I40E_RX_DTYPE_HEADER_SPLIT;
	}

	/* databuffer length validation */
	if (info->databuffer_size > ((16 * 1024) - 128)) {
		ret = -EINVAL;
		goto error_param;
	}
	rx_ctx.dbuff = info->databuffer_size >> I40E_RXQ_CTX_DBUFF_SHIFT;

	/* max pkt. length validation */
	if (info->max_pkt_size >= (16 * 1024) || info->max_pkt_size < 64) {
		ret = -EINVAL;
		goto error_param;
	}
	rx_ctx.rxmax = info->max_pkt_size;

	/* if port VLAN is configured increase the max packet size */
	if (vsi->info.pvid)
		rx_ctx.rxmax += VLAN_HLEN;

	/* enable 32bytes desc always */
	rx_ctx.dsize = 1;

	/* default values */
	rx_ctx.lrxqthresh = 1;
	rx_ctx.crcstrip = 1;
	rx_ctx.prefena = 1;
	rx_ctx.l2tsel = 1;

	/* clear the context in the HMC */
	ret = (*klpe_i40e_clear_lan_rx_queue_context)(hw, pf_queue_id);
	if (ret) {
		dev_err(&pf->pdev->dev,
			"Failed to clear VF LAN Rx queue context %d, error: %d\n",
			pf_queue_id, ret);
		ret = -ENOENT;
		goto error_param;
	}

	/* set the context in the HMC */
	ret = (*klpe_i40e_set_lan_rx_queue_context)(hw, pf_queue_id, &rx_ctx);
	if (ret) {
		dev_err(&pf->pdev->dev,
			"Failed to set VF LAN Rx queue context %d error: %d\n",
			pf_queue_id, ret);
		ret = -ENOENT;
		goto error_param;
	}

error_param:
	return ret;
}

static i40e_status (*klpe_i40e_config_vf_promiscuous_mode)(struct i40e_vf *vf,
						   u16 vsi_id,
						   bool allmulti,
						   bool alluni);
static int (*klpe_i40e_vc_send_msg_to_vf)(struct i40e_vf *vf, u32 v_opcode,
				  u32 v_retval, u8 *msg, u16 msglen);

static int klpr_i40e_vc_send_resp_to_vf(struct i40e_vf *vf,
				   enum virtchnl_ops opcode,
				   i40e_status retval)
{
	return (*klpe_i40e_vc_send_msg_to_vf)(vf, opcode, retval, NULL, 0);
}

static int klpr_i40e_vc_get_version_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_version_info info = {
		VIRTCHNL_VERSION_MAJOR, VIRTCHNL_VERSION_MINOR
	};

	vf->vf_ver = *(struct virtchnl_version_info *)msg;
	/* VFs running the 1.0 API expect to get 1.0 back or they will cry. */
	if (VF_IS_V10(&vf->vf_ver))
		info.minor = VIRTCHNL_VERSION_MINOR_NO_VF_CAPS;
	return (*klpe_i40e_vc_send_msg_to_vf)(vf, VIRTCHNL_OP_VERSION,
				      I40E_SUCCESS, (u8 *)&info,
				      sizeof(struct virtchnl_version_info));
}

static void klpr_i40e_del_qch(struct i40e_vf *vf)
{
	struct i40e_pf *pf = vf->pf;
	int i;

	/* first element in the array belongs to primary VF VSI and we shouldn't
	 * delete it. We should however delete the rest of the VSIs created
	 */
	for (i = 1; i < vf->num_tc; i++) {
		if (vf->ch[i].vsi_idx) {
			(*klpe_i40e_vsi_release)(pf->vsi[vf->ch[i].vsi_idx]);
			vf->ch[i].vsi_idx = 0;
			vf->ch[i].vsi_id = 0;
		}
	}
}

static int klpr_i40e_vc_get_vf_resources_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_vf_resource *vfres = NULL;
	struct i40e_pf *pf = vf->pf;
	i40e_status aq_ret = 0;
	struct i40e_vsi *vsi;
	int num_vsis = 1;
	int len = 0;
	int ret;

	if (!test_bit(I40E_VF_STATE_INIT, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	len = (sizeof(struct virtchnl_vf_resource) +
	       sizeof(struct virtchnl_vsi_resource) * num_vsis);

	vfres = kzalloc(len, GFP_KERNEL);
	if (!vfres) {
		aq_ret = I40E_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}
	if (VF_IS_V11(&vf->vf_ver))
		vf->driver_caps = *(u32 *)msg;
	else
		vf->driver_caps = VIRTCHNL_VF_OFFLOAD_L2 |
				  VIRTCHNL_VF_OFFLOAD_RSS_REG |
				  VIRTCHNL_VF_OFFLOAD_VLAN;

	vfres->vf_cap_flags = VIRTCHNL_VF_OFFLOAD_L2;
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi->info.pvid)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_VLAN;

	if ((*klpe_i40e_vf_client_capable)(pf, vf->vf_id) &&
	    (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_IWARP)) {
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_IWARP;
		set_bit(I40E_VF_STATE_IWARPENA, &vf->vf_states);
	} else {
		clear_bit(I40E_VF_STATE_IWARPENA, &vf->vf_states);
	}

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PF) {
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_PF;
	} else {
		if ((pf->hw_features & I40E_HW_RSS_AQ_CAPABLE) &&
		    (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_AQ))
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_AQ;
		else
			vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RSS_REG;
	}

	if (pf->hw_features & I40E_HW_MULTIPLE_TCP_UDP_RSS_PCTYPE) {
		if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2)
			vfres->vf_cap_flags |=
				VIRTCHNL_VF_OFFLOAD_RSS_PCTYPE_V2;
	}

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP;

	if ((pf->hw_features & I40E_HW_OUTER_UDP_CSUM_CAPABLE) &&
	    (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM))
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ENCAP_CSUM;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_RX_POLLING) {
		if (pf->flags & I40E_FLAG_MFP_ENABLED) {
			dev_err(&pf->pdev->dev,
				"VF %d requested polling mode: this feature is supported only when the device is running in single function per port (SFP) mode\n",
				 vf->vf_id);
			aq_ret = I40E_ERR_PARAM;
			goto err;
		}
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_RX_POLLING;
	}

	if (pf->hw_features & I40E_HW_WB_ON_ITR_CAPABLE) {
		if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_WB_ON_ITR)
			vfres->vf_cap_flags |=
					VIRTCHNL_VF_OFFLOAD_WB_ON_ITR;
	}

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_REQ_QUEUES)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_REQ_QUEUES;

	if (vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ)
		vfres->vf_cap_flags |= VIRTCHNL_VF_OFFLOAD_ADQ;

	vfres->num_vsis = num_vsis;
	vfres->num_queue_pairs = vf->num_queue_pairs;
	vfres->max_vectors = pf->hw.func_caps.num_msix_vectors_vf;
	vfres->rss_key_size = I40E_HKEY_ARRAY_SIZE;
	vfres->rss_lut_size = I40E_VF_HLUT_ARRAY_SIZE;

	if (vf->lan_vsi_idx) {
		vfres->vsi_res[0].vsi_id = vf->lan_vsi_id;
		vfres->vsi_res[0].vsi_type = VIRTCHNL_VSI_SRIOV;
		vfres->vsi_res[0].num_queue_pairs = vsi->alloc_queue_pairs;
		/* VFs only use TC 0 */
		vfres->vsi_res[0].qset_handle
					  = le16_to_cpu(vsi->info.qs_handle[0]);
		ether_addr_copy(vfres->vsi_res[0].default_mac_addr,
				vf->default_lan_addr.addr);
	}
	set_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states);

err:
	/* send the response back to the VF */
	ret = (*klpe_i40e_vc_send_msg_to_vf)(vf, VIRTCHNL_OP_GET_VF_RESOURCES,
				     aq_ret, (u8 *)vfres, len);

	kfree(vfres);
	return ret;
}

static void klpr_i40e_vc_reset_vf_msg(struct i40e_vf *vf)
{
	if (test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states))
		(*klpe_i40e_reset_vf)(vf, false);
}

static int klpr_i40e_vc_config_promiscuous_mode_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_promisc_info *info =
	    (struct virtchnl_promisc_info *)msg;
	struct i40e_pf *pf = vf->pf;
	i40e_status aq_ret = 0;
	bool allmulti = false;
	bool alluni = false;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err_out;
	}
	if (!test_bit(I40E_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps)) {
		dev_err(&pf->pdev->dev,
			"Unprivileged VF %d is attempting to configure promiscuous mode\n",
			vf->vf_id);

		/* Lie to the VF on purpose, because this is an error we can
		 * ignore. Unprivileged VF is not a virtual channel error.
		 */
		aq_ret = 0;
		goto err_out;
	}

	if (info->flags > I40E_MAX_VF_PROMISC_FLAGS) {
		aq_ret = I40E_ERR_PARAM;
		goto err_out;
	}

	if (!klpr_i40e_vc_isvalid_vsi_id(vf, info->vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto err_out;
	}

	/* Multicast promiscuous handling*/
	if (info->flags & FLAG_VF_MULTICAST_PROMISC)
		allmulti = true;

	if (info->flags & FLAG_VF_UNICAST_PROMISC)
		alluni = true;
	aq_ret = (*klpe_i40e_config_vf_promiscuous_mode)(vf, info->vsi_id, allmulti,
						 alluni);
	if (!aq_ret) {
		if (allmulti) {
			dev_info(&pf->pdev->dev,
				 "VF %d successfully set multicast promiscuous mode\n",
				 vf->vf_id);
			set_bit(I40E_VF_STATE_MC_PROMISC, &vf->vf_states);
		} else {
			dev_info(&pf->pdev->dev,
				 "VF %d successfully unset multicast promiscuous mode\n",
				 vf->vf_id);
			clear_bit(I40E_VF_STATE_MC_PROMISC, &vf->vf_states);
		}
		if (alluni) {
			dev_info(&pf->pdev->dev,
				 "VF %d successfully set unicast promiscuous mode\n",
				 vf->vf_id);
			set_bit(I40E_VF_STATE_UC_PROMISC, &vf->vf_states);
		} else {
			dev_info(&pf->pdev->dev,
				 "VF %d successfully unset unicast promiscuous mode\n",
				 vf->vf_id);
			clear_bit(I40E_VF_STATE_UC_PROMISC, &vf->vf_states);
		}
	}
err_out:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf,
				       VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE,
				       aq_ret);
}

static int klpr_i40e_vc_config_queues_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_vsi_queue_config_info *qci =
	    (struct virtchnl_vsi_queue_config_info *)msg;
	struct virtchnl_queue_pair_info *qpi;
	u16 vsi_id, vsi_queue_id = 0;
	struct i40e_pf *pf = vf->pf;
	i40e_status aq_ret = 0;
	int i, j = 0, idx = 0;
	struct i40e_vsi *vsi;
	u16 num_qps_all = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (!klpr_i40e_vc_isvalid_vsi_id(vf, qci->vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (qci->num_queue_pairs > I40E_MAX_VF_QUEUES) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (vf->adq_enabled) {
		for (i = 0; i < I40E_MAX_VF_VSI; i++)
			num_qps_all += vf->ch[i].num_qps;
		if (num_qps_all != qci->num_queue_pairs) {
			aq_ret = I40E_ERR_PARAM;
			goto error_param;
		}
	}

	vsi_id = qci->vsi_id;

	for (i = 0; i < qci->num_queue_pairs; i++) {
		qpi = &qci->qpair[i];

		if (!vf->adq_enabled) {
			if (!klpr_i40e_vc_isvalid_queue_id(vf, vsi_id,
						      qpi->txq.queue_id)) {
				aq_ret = I40E_ERR_PARAM;
				goto error_param;
			}

			vsi_queue_id = qpi->txq.queue_id;

			if (qpi->txq.vsi_id != qci->vsi_id ||
			    qpi->rxq.vsi_id != qci->vsi_id ||
			    qpi->rxq.queue_id != vsi_queue_id) {
				aq_ret = I40E_ERR_PARAM;
				goto error_param;
			}
		}

		if (vf->adq_enabled)
			vsi_id = vf->ch[idx].vsi_id;

		if (klpp_i40e_config_vsi_rx_queue(vf, vsi_id, vsi_queue_id,
					     &qpi->rxq) ||
		    klpp_i40e_config_vsi_tx_queue(vf, vsi_id, vsi_queue_id,
					     &qpi->txq)) {
			aq_ret = I40E_ERR_PARAM;
			goto error_param;
		}

		/* For ADq there can be up to 4 VSIs with max 4 queues each.
		 * VF does not know about these additional VSIs and all
		 * it cares is about its own queues. PF configures these queues
		 * to its appropriate VSIs based on TC mapping
		 **/
		if (vf->adq_enabled) {
			if (j == (vf->ch[idx].num_qps - 1)) {
				idx++;
				j = 0; /* resetting the queue count */
				vsi_queue_id = 0;
			} else {
				j++;
				vsi_queue_id++;
			}
		}
	}
	/* set vsi num_queue_pairs in use to num configured by VF */
	if (!vf->adq_enabled) {
		pf->vsi[vf->lan_vsi_idx]->num_queue_pairs =
			qci->num_queue_pairs;
	} else {
		for (i = 0; i < vf->num_tc; i++) {
			vsi = pf->vsi[vf->ch[i].vsi_idx];
			vsi->num_queue_pairs = vf->ch[i].num_qps;

			if ((*klpe_i40e_update_adq_vsi_queues)(vsi, i)) {
				aq_ret = I40E_ERR_CONFIG;
				goto error_param;
			}
		}
	}

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_CONFIG_VSI_QUEUES,
				       aq_ret);
}

static int (*klpe_i40e_validate_queue_map)(struct i40e_vf *vf, u16 vsi_id,
				   unsigned long queuemap);

static int klpr_i40e_vc_config_irq_map_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_irq_map_info *irqmap_info =
	    (struct virtchnl_irq_map_info *)msg;
	struct virtchnl_vector_map *map;
	u16 vsi_id;
	i40e_status aq_ret = 0;
	int i;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (irqmap_info->num_vectors >
	    vf->pf->hw.func_caps.num_msix_vectors_vf) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < irqmap_info->num_vectors; i++) {
		map = &irqmap_info->vecmap[i];
		/* validate msg params */
		if (!i40e_vc_isvalid_vector_id(vf, map->vector_id) ||
		    !klpr_i40e_vc_isvalid_vsi_id(vf, map->vsi_id)) {
			aq_ret = I40E_ERR_PARAM;
			goto error_param;
		}
		vsi_id = map->vsi_id;

		if ((*klpe_i40e_validate_queue_map)(vf, vsi_id, map->rxq_map)) {
			aq_ret = I40E_ERR_PARAM;
			goto error_param;
		}

		if ((*klpe_i40e_validate_queue_map)(vf, vsi_id, map->txq_map)) {
			aq_ret = I40E_ERR_PARAM;
			goto error_param;
		}

		klpr_i40e_config_irq_link_list(vf, vsi_id, map);
	}
error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_CONFIG_IRQ_MAP,
				       aq_ret);
}

static int (*klpe_i40e_ctrl_vf_tx_rings)(struct i40e_vsi *vsi, unsigned long q_map,
				 bool enable);

static int klpr_i40e_ctrl_vf_rx_rings(struct i40e_vsi *vsi, unsigned long q_map,
				 bool enable)
{
	struct i40e_pf *pf = vsi->back;
	int ret = 0;
	u16 q_id;

	for_each_set_bit(q_id, &q_map, I40E_MAX_VF_QUEUES) {
		ret = (*klpe_i40e_control_wait_rx_q)(pf, vsi->base_queue + q_id,
					     enable);
		if (ret)
			break;
	}
	return ret;
}

static bool i40e_vc_validate_vqs_bitmaps(struct virtchnl_queue_select *vqs)
{
	if ((!vqs->rx_queues && !vqs->tx_queues) ||
	    vqs->rx_queues >= BIT(I40E_MAX_VF_QUEUES) ||
	    vqs->tx_queues >= BIT(I40E_MAX_VF_QUEUES))
		return false;

	return true;
}

static int klpr_i40e_vc_enable_queues_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct i40e_pf *pf = vf->pf;
	u16 vsi_id = vqs->vsi_id;
	i40e_status aq_ret = 0;
	int i;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (!klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (!i40e_vc_validate_vqs_bitmaps(vqs)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	/* Use the queue bit map sent by the VF */
	if (klpr_i40e_ctrl_vf_rx_rings(pf->vsi[vf->lan_vsi_idx], vqs->rx_queues,
				  true)) {
		aq_ret = I40E_ERR_TIMEOUT;
		goto error_param;
	}
	if ((*klpe_i40e_ctrl_vf_tx_rings)(pf->vsi[vf->lan_vsi_idx], vqs->tx_queues,
				  true)) {
		aq_ret = I40E_ERR_TIMEOUT;
		goto error_param;
	}

	/* need to start the rings for additional ADq VSI's as well */
	if (vf->adq_enabled) {
		/* zero belongs to LAN VSI */
		for (i = 1; i < vf->num_tc; i++) {
			if ((*klpe_i40e_vsi_start_rings)(pf->vsi[vf->ch[i].vsi_idx]))
				aq_ret = I40E_ERR_TIMEOUT;
		}
	}

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_ENABLE_QUEUES,
				       aq_ret);
}

static int klpr_i40e_vc_disable_queues_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct i40e_pf *pf = vf->pf;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (!klpr_i40e_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (!i40e_vc_validate_vqs_bitmaps(vqs)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	/* Use the queue bit map sent by the VF */
	if ((*klpe_i40e_ctrl_vf_tx_rings)(pf->vsi[vf->lan_vsi_idx], vqs->tx_queues,
				  false)) {
		aq_ret = I40E_ERR_TIMEOUT;
		goto error_param;
	}
	if (klpr_i40e_ctrl_vf_rx_rings(pf->vsi[vf->lan_vsi_idx], vqs->rx_queues,
				  false)) {
		aq_ret = I40E_ERR_TIMEOUT;
		goto error_param;
	}
error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_DISABLE_QUEUES,
				       aq_ret);
}

static int klpr_i40e_vc_request_queues_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_vf_res_request *vfres =
		(struct virtchnl_vf_res_request *)msg;
	int req_pairs = vfres->num_queue_pairs;
	int cur_pairs = vf->num_queue_pairs;
	struct i40e_pf *pf = vf->pf;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states))
		return -EINVAL;

	if (req_pairs <= 0) {
		dev_err(&pf->pdev->dev,
			"VF %d tried to request %d queues.  Ignoring.\n",
			vf->vf_id, req_pairs);
	} else if (req_pairs > I40E_MAX_VF_QUEUES) {
		dev_err(&pf->pdev->dev,
			"VF %d tried to request more than %d queues.\n",
			vf->vf_id,
			I40E_MAX_VF_QUEUES);
		vfres->num_queue_pairs = I40E_MAX_VF_QUEUES;
	} else if (req_pairs - cur_pairs > pf->queues_left) {
		dev_warn(&pf->pdev->dev,
			 "VF %d requested %d more queues, but only %d left.\n",
			 vf->vf_id,
			 req_pairs - cur_pairs,
			 pf->queues_left);
		vfres->num_queue_pairs = pf->queues_left + cur_pairs;
	} else {
		/* successful request */
		vf->num_req_queues = req_pairs;
		(*klpe_i40e_vc_notify_vf_reset)(vf);
		(*klpe_i40e_reset_vf)(vf, false);
		return 0;
	}

	return (*klpe_i40e_vc_send_msg_to_vf)(vf, VIRTCHNL_OP_REQUEST_QUEUES, 0,
				      (u8 *)vfres, sizeof(*vfres));
}

static int klpr_i40e_vc_get_stats_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_queue_select *vqs =
	    (struct virtchnl_queue_select *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_eth_stats stats;
	i40e_status aq_ret = 0;
	struct i40e_vsi *vsi;

	memset(&stats, 0, sizeof(struct i40e_eth_stats));

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (!klpr_i40e_vc_isvalid_vsi_id(vf, vqs->vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (!vsi) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}
	(*klpe_i40e_update_eth_stats)(vsi);
	stats = vsi->eth_stats;

error_param:
	/* send the response back to the VF */
	return (*klpe_i40e_vc_send_msg_to_vf)(vf, VIRTCHNL_OP_GET_STATS, aq_ret,
				      (u8 *)&stats, sizeof(stats));
}

static bool i40e_can_vf_change_mac(struct i40e_vf *vf)
{
	/* If the VF MAC address has been set administratively (via the
	 * ndo_set_vf_mac command), then deny permission to the VF to
	 * add/delete unicast MAC addresses, unless the VF is trusted
	 */
	if (vf->pf_set_mac && !vf->trusted)
		return false;

	return true;
}

#define I40E_VC_MAX_MAC_ADDR_PER_VF (16 + 1 + 1)
#define I40E_VC_MAX_VLAN_PER_VF 8

static inline int klpr_i40e_check_vf_permission(struct i40e_vf *vf,
					   struct virtchnl_ether_addr_list *al)
{
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = pf->vsi[vf->lan_vsi_idx];
	int mac2add_cnt = 0;
	int i;

	for (i = 0; i < al->num_elements; i++) {
		struct i40e_mac_filter *f;
		u8 *addr = al->list[i].addr;

		if (is_broadcast_ether_addr(addr) ||
		    is_zero_ether_addr(addr)) {
			dev_err(&pf->pdev->dev, "invalid VF MAC addr %pM\n",
				addr);
			return I40E_ERR_INVALID_MAC_ADDR;
		}

		/* If the host VMM administrator has set the VF MAC address
		 * administratively via the ndo_set_vf_mac command then deny
		 * permission to the VF to add or delete unicast MAC addresses.
		 * Unless the VF is privileged and then it can do whatever.
		 * The VF may request to set the MAC address filter already
		 * assigned to it so do not return an error in that case.
		 */
		if (!i40e_can_vf_change_mac(vf) &&
		    !is_multicast_ether_addr(addr) &&
		    !ether_addr_equal(addr, vf->default_lan_addr.addr)) {
			dev_err(&pf->pdev->dev,
				"VF attempting to override administratively set MAC address, bring down and up the VF interface to resume normal operation\n");
			return -EPERM;
		}

		/*count filters that really will be added*/
		f = (*klpe_i40e_find_mac)(vsi, addr);
		if (!f)
			++mac2add_cnt;
	}

	/* If this VF is not privileged, then we can't add more than a limited
	 * number of addresses. Check to make sure that the additions do not
	 * push us over the limit.
	 */
	if (!test_bit(I40E_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps) &&
	    ((*klpe_i40e_count_filters)(vsi) + mac2add_cnt) >
		    I40E_VC_MAX_MAC_ADDR_PER_VF) {
		dev_err(&pf->pdev->dev,
			"Cannot add more MAC addresses, VF is not trusted, switch the VF to trusted to add more functionality\n");
		return -EPERM;
	}
	return 0;
}

static int klpr_i40e_vc_add_mac_addr_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = NULL;
	u16 vsi_id = al->vsi_id;
	i40e_status ret = 0;
	int i;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id)) {
		ret = I40E_ERR_PARAM;
		goto error_param;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];

	/* Lock once, because all function inside for loop accesses VSI's
	 * MAC filter list which needs to be protected using same lock.
	 */
	spin_lock_bh(&vsi->mac_filter_hash_lock);

	ret = klpr_i40e_check_vf_permission(vf, al);
	if (ret) {
		spin_unlock_bh(&vsi->mac_filter_hash_lock);
		goto error_param;
	}

	/* add new addresses to the list */
	for (i = 0; i < al->num_elements; i++) {
		struct i40e_mac_filter *f;

		f = (*klpe_i40e_find_mac)(vsi, al->list[i].addr);
		if (!f) {
			f = (*klpe_i40e_add_mac_filter)(vsi, al->list[i].addr);

			if (!f) {
				dev_err(&pf->pdev->dev,
					"Unable to add MAC filter %pM for VF %d\n",
					al->list[i].addr, vf->vf_id);
				ret = I40E_ERR_PARAM;
				spin_unlock_bh(&vsi->mac_filter_hash_lock);
				goto error_param;
			}
			if (is_valid_ether_addr(al->list[i].addr) &&
			    is_zero_ether_addr(vf->default_lan_addr.addr))
				ether_addr_copy(vf->default_lan_addr.addr,
						al->list[i].addr);
		}
	}
	spin_unlock_bh(&vsi->mac_filter_hash_lock);

	/* program the updated filter list */
	ret = (*klpe_i40e_sync_vsi_filters)(vsi);
	if (ret)
		dev_err(&pf->pdev->dev, "Unable to program VF %d MAC filters, error %d\n",
			vf->vf_id, ret);

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_ADD_ETH_ADDR,
				       ret);
}

static int klpr_i40e_vc_del_mac_addr_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_ether_addr_list *al =
	    (struct virtchnl_ether_addr_list *)msg;
	bool was_unimac_deleted = false;
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = NULL;
	u16 vsi_id = al->vsi_id;
	i40e_status ret = 0;
	int i;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id)) {
		ret = I40E_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < al->num_elements; i++) {
		if (is_broadcast_ether_addr(al->list[i].addr) ||
		    is_zero_ether_addr(al->list[i].addr)) {
			dev_err(&pf->pdev->dev, "Invalid MAC addr %pM for VF %d\n",
				al->list[i].addr, vf->vf_id);
			ret = I40E_ERR_INVALID_MAC_ADDR;
			goto error_param;
		}
	}
	vsi = pf->vsi[vf->lan_vsi_idx];

	spin_lock_bh(&vsi->mac_filter_hash_lock);
	/* delete addresses from the list */
	for (i = 0; i < al->num_elements; i++) {
		const u8 *addr = al->list[i].addr;

		/* Allow to delete VF primary MAC only if it was not set
		 * administratively by PF or if VF is trusted.
		 */
		if (ether_addr_equal(addr, vf->default_lan_addr.addr)) {
			if (i40e_can_vf_change_mac(vf))
				was_unimac_deleted = true;
			else
				continue;
		}

		if ((*klpe_i40e_del_mac_filter)(vsi, al->list[i].addr)) {
			ret = I40E_ERR_INVALID_MAC_ADDR;
			spin_unlock_bh(&vsi->mac_filter_hash_lock);
			goto error_param;
		}
	}

	spin_unlock_bh(&vsi->mac_filter_hash_lock);

	/* program the updated filter list */
	ret = (*klpe_i40e_sync_vsi_filters)(vsi);
	if (ret)
		dev_err(&pf->pdev->dev, "Unable to program VF %d MAC filters, error %d\n",
			vf->vf_id, ret);

	if (vf->trusted && was_unimac_deleted) {
		struct i40e_mac_filter *f;
		struct hlist_node *h;
		u8 *macaddr = NULL;
		int bkt;

		/* set last unicast mac address as default */
		spin_lock_bh(&vsi->mac_filter_hash_lock);
		hash_for_each_safe(vsi->mac_filter_hash, bkt, h, f, hlist) {
			if (is_valid_ether_addr(f->macaddr))
				macaddr = f->macaddr;
		}
		if (macaddr)
			ether_addr_copy(vf->default_lan_addr.addr, macaddr);
		spin_unlock_bh(&vsi->mac_filter_hash_lock);
	}
error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_DEL_ETH_ADDR, ret);
}

static int klpr_i40e_vc_add_vlan_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_vlan_filter_list *vfl =
	    (struct virtchnl_vlan_filter_list *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = NULL;
	u16 vsi_id = vfl->vsi_id;
	i40e_status aq_ret = 0;
	int i;

	if ((vf->num_vlan >= I40E_VC_MAX_VLAN_PER_VF) &&
	    !test_bit(I40E_VIRTCHNL_VF_CAP_PRIVILEGE, &vf->vf_caps)) {
		dev_err(&pf->pdev->dev,
			"VF is not trusted, switch the VF to trusted to add more VLAN addresses\n");
		goto error_param;
	}
	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < vfl->num_elements; i++) {
		if (vfl->vlan_id[i] > I40E_MAX_VLANID) {
			aq_ret = I40E_ERR_PARAM;
			dev_err(&pf->pdev->dev,
				"invalid VF VLAN id %d\n", vfl->vlan_id[i]);
			goto error_param;
		}
	}
	vsi = pf->vsi[vf->lan_vsi_idx];
	if (vsi->info.pvid) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	(*klpe_i40e_vlan_stripping_enable)(vsi);
	for (i = 0; i < vfl->num_elements; i++) {
		/* add new VLAN filter */
		int ret = (*klpe_i40e_vsi_add_vlan)(vsi, vfl->vlan_id[i]);
		if (!ret)
			vf->num_vlan++;

		if (test_bit(I40E_VF_STATE_UC_PROMISC, &vf->vf_states))
			(*klpe_i40e_aq_set_vsi_uc_promisc_on_vlan)(&pf->hw, vsi->seid,
							   true,
							   vfl->vlan_id[i],
							   NULL);
		if (test_bit(I40E_VF_STATE_MC_PROMISC, &vf->vf_states))
			(*klpe_i40e_aq_set_vsi_mc_promisc_on_vlan)(&pf->hw, vsi->seid,
							   true,
							   vfl->vlan_id[i],
							   NULL);

		if (ret)
			dev_err(&pf->pdev->dev,
				"Unable to add VLAN filter %d for VF %d, error %d\n",
				vfl->vlan_id[i], vf->vf_id, ret);
	}

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_ADD_VLAN, aq_ret);
}

static int klpr_i40e_vc_remove_vlan_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_vlan_filter_list *vfl =
	    (struct virtchnl_vlan_filter_list *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = NULL;
	u16 vsi_id = vfl->vsi_id;
	i40e_status aq_ret = 0;
	int i;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < vfl->num_elements; i++) {
		if (vfl->vlan_id[i] > I40E_MAX_VLANID) {
			aq_ret = I40E_ERR_PARAM;
			goto error_param;
		}
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	if (vsi->info.pvid) {
		if (vfl->num_elements > 1 || vfl->vlan_id[0])
			aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	for (i = 0; i < vfl->num_elements; i++) {
		(*klpe_i40e_vsi_kill_vlan)(vsi, vfl->vlan_id[i]);
		vf->num_vlan--;

		if (test_bit(I40E_VF_STATE_UC_PROMISC, &vf->vf_states))
			(*klpe_i40e_aq_set_vsi_uc_promisc_on_vlan)(&pf->hw, vsi->seid,
							   false,
							   vfl->vlan_id[i],
							   NULL);
		if (test_bit(I40E_VF_STATE_MC_PROMISC, &vf->vf_states))
			(*klpe_i40e_aq_set_vsi_mc_promisc_on_vlan)(&pf->hw, vsi->seid,
							   false,
							   vfl->vlan_id[i],
							   NULL);
	}

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_DEL_VLAN, aq_ret);
}

static int klpr_i40e_vc_iwarp_msg(struct i40e_vf *vf, u8 *msg, u16 msglen)
{
	struct i40e_pf *pf = vf->pf;
	int abs_vf_id = vf->vf_id + pf->hw.func_caps.vf_base_id;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !test_bit(I40E_VF_STATE_IWARPENA, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	(*klpe_i40e_notify_client_of_vf_msg)(pf->vsi[pf->lan_vsi], abs_vf_id,
				     msg, msglen);

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_IWARP,
				       aq_ret);
}

static int klpr_i40e_vc_iwarp_qvmap_msg(struct i40e_vf *vf, u8 *msg, bool config)
{
	struct virtchnl_iwarp_qvlist_info *qvlist_info =
				(struct virtchnl_iwarp_qvlist_info *)msg;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !test_bit(I40E_VF_STATE_IWARPENA, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto error_param;
	}

	if (config) {
		if (i40e_config_iwarp_qvlist(vf, qvlist_info))
			aq_ret = I40E_ERR_PARAM;
	} else {
		i40e_release_iwarp_qvlist(vf);
	}

error_param:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf,
			       config ? VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP :
			       VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP,
			       aq_ret);
}

static int klpr_i40e_vc_config_rss_key(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_rss_key *vrk =
		(struct virtchnl_rss_key *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = NULL;
	u16 vsi_id = vrk->vsi_id;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id) ||
	    (vrk->key_len != I40E_HKEY_ARRAY_SIZE)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	aq_ret = (*klpe_i40e_config_rss)(vsi, vrk->key, NULL, 0);
err:
	/* send the response to the VF */
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_KEY,
				       aq_ret);
}

static int klpr_i40e_vc_config_rss_lut(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_rss_lut *vrl =
		(struct virtchnl_rss_lut *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_vsi *vsi = NULL;
	u16 vsi_id = vrl->vsi_id;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states) ||
	    !klpr_i40e_vc_isvalid_vsi_id(vf, vsi_id) ||
	    (vrl->lut_entries != I40E_VF_HLUT_ARRAY_SIZE)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	vsi = pf->vsi[vf->lan_vsi_idx];
	aq_ret = (*klpe_i40e_config_rss)(vsi, NULL, vrl->lut, I40E_VF_HLUT_ARRAY_SIZE);
	/* send the response to the VF */
err:
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_CONFIG_RSS_LUT,
				       aq_ret);
}

static int klpr_i40e_vc_get_rss_hena(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_rss_hena *vrh = NULL;
	struct i40e_pf *pf = vf->pf;
	i40e_status aq_ret = 0;
	int len = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}
	len = sizeof(struct virtchnl_rss_hena);

	vrh = kzalloc(len, GFP_KERNEL);
	if (!vrh) {
		aq_ret = I40E_ERR_NO_MEMORY;
		len = 0;
		goto err;
	}
	vrh->hena = i40e_pf_get_default_rss_hena(pf);
err:
	/* send the response back to the VF */
	aq_ret = (*klpe_i40e_vc_send_msg_to_vf)(vf, VIRTCHNL_OP_GET_RSS_HENA_CAPS,
					aq_ret, (u8 *)vrh, len);
	kfree(vrh);
	return aq_ret;
}

static int klpr_i40e_vc_set_rss_hena(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_rss_hena *vrh =
		(struct virtchnl_rss_hena *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_hw *hw = &pf->hw;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}
	(*klpe_i40e_write_rx_ctl)(hw, I40E_VFQF_HENA1(0, vf->vf_id), (u32)vrh->hena);
	(*klpe_i40e_write_rx_ctl)(hw, I40E_VFQF_HENA1(1, vf->vf_id),
			  (u32)(vrh->hena >> 32));

	/* send the response to the VF */
err:
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_SET_RSS_HENA, aq_ret);
}

static int klpr_i40e_vc_enable_vlan_stripping(struct i40e_vf *vf, u8 *msg)
{
	struct i40e_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	(*klpe_i40e_vlan_stripping_enable)(vsi);

	/* send the response to the VF */
err:
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_ENABLE_VLAN_STRIPPING,
				       aq_ret);
}

static int klpr_i40e_vc_disable_vlan_stripping(struct i40e_vf *vf, u8 *msg)
{
	struct i40e_vsi *vsi = vf->pf->vsi[vf->lan_vsi_idx];
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	(*klpe_i40e_vlan_stripping_disable)(vsi);

	/* send the response to the VF */
err:
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_DISABLE_VLAN_STRIPPING,
				       aq_ret);
}

static void (*klpe_i40e_del_all_cloud_filters)(struct i40e_vf *vf);

static int (*klpe_i40e_vc_del_cloud_filter)(struct i40e_vf *vf, u8 *msg);

static int (*klpe_i40e_vc_add_cloud_filter)(struct i40e_vf *vf, u8 *msg);

static int klpr_i40e_vc_add_qch_msg(struct i40e_vf *vf, u8 *msg)
{
	struct virtchnl_tc_info *tci =
		(struct virtchnl_tc_info *)msg;
	struct i40e_pf *pf = vf->pf;
	struct i40e_link_status *ls = &pf->hw.phy.link_info;
	int i, adq_request_qps = 0, speed = 0;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	/* ADq cannot be applied if spoof check is ON */
	if (vf->spoofchk) {
		dev_err(&pf->pdev->dev,
			"Spoof check is ON, turn it OFF to enable ADq\n");
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	if (!(vf->driver_caps & VIRTCHNL_VF_OFFLOAD_ADQ)) {
		dev_err(&pf->pdev->dev,
			"VF %d attempting to enable ADq, but hasn't properly negotiated that capability\n",
			vf->vf_id);
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	/* max number of traffic classes for VF currently capped at 4 */
	if (!tci->num_tc || tci->num_tc > I40E_MAX_VF_VSI) {
		dev_err(&pf->pdev->dev,
			"VF %d trying to set %u TCs, valid range 1-4 TCs per VF\n",
			vf->vf_id, tci->num_tc);
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	/* validate queues for each TC */
	for (i = 0; i < tci->num_tc; i++)
		if (!tci->list[i].count ||
		    tci->list[i].count > I40E_DEFAULT_QUEUES_PER_VF) {
			dev_err(&pf->pdev->dev,
				"VF %d: TC %d trying to set %u queues, valid range 1-4 queues per TC\n",
				vf->vf_id, i, tci->list[i].count);
			aq_ret = I40E_ERR_PARAM;
			goto err;
		}

	/* need Max VF queues but already have default number of queues */
	adq_request_qps = I40E_MAX_VF_QUEUES - I40E_DEFAULT_QUEUES_PER_VF;

	if (pf->queues_left < adq_request_qps) {
		dev_err(&pf->pdev->dev,
			"No queues left to allocate to VF %d\n",
			vf->vf_id);
		aq_ret = I40E_ERR_PARAM;
		goto err;
	} else {
		/* we need to allocate max VF queues to enable ADq so as to
		 * make sure ADq enabled VF always gets back queues when it
		 * goes through a reset.
		 */
		vf->num_queue_pairs = I40E_MAX_VF_QUEUES;
	}

	/* get link speed in MB to validate rate limit */
	switch (ls->link_speed) {
	case VIRTCHNL_LINK_SPEED_100MB:
		speed = SPEED_100;
		break;
	case VIRTCHNL_LINK_SPEED_1GB:
		speed = SPEED_1000;
		break;
	case VIRTCHNL_LINK_SPEED_10GB:
		speed = SPEED_10000;
		break;
	case VIRTCHNL_LINK_SPEED_20GB:
		speed = SPEED_20000;
		break;
	case VIRTCHNL_LINK_SPEED_25GB:
		speed = SPEED_25000;
		break;
	case VIRTCHNL_LINK_SPEED_40GB:
		speed = SPEED_40000;
		break;
	default:
		dev_err(&pf->pdev->dev,
			"Cannot detect link speed\n");
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	/* parse data from the queue channel info */
	vf->num_tc = tci->num_tc;
	for (i = 0; i < vf->num_tc; i++) {
		if (tci->list[i].max_tx_rate) {
			if (tci->list[i].max_tx_rate > speed) {
				dev_err(&pf->pdev->dev,
					"Invalid max tx rate %llu specified for VF %d.",
					tci->list[i].max_tx_rate,
					vf->vf_id);
				aq_ret = I40E_ERR_PARAM;
				goto err;
			} else {
				vf->ch[i].max_tx_rate =
					tci->list[i].max_tx_rate;
			}
		}
		vf->ch[i].num_qps = tci->list[i].count;
	}

	/* set this flag only after making sure all inputs are sane */
	vf->adq_enabled = true;

	/* reset the VF in order to allocate resources */
	(*klpe_i40e_vc_notify_vf_reset)(vf);
	(*klpe_i40e_reset_vf)(vf, false);

	return I40E_SUCCESS;

	/* send the response to the VF */
err:
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_ENABLE_CHANNELS,
				       aq_ret);
}

static int klpr_i40e_vc_del_qch_msg(struct i40e_vf *vf, u8 *msg)
{
	struct i40e_pf *pf = vf->pf;
	i40e_status aq_ret = 0;

	if (!test_bit(I40E_VF_STATE_ACTIVE, &vf->vf_states)) {
		aq_ret = I40E_ERR_PARAM;
		goto err;
	}

	if (vf->adq_enabled) {
		(*klpe_i40e_del_all_cloud_filters)(vf);
		klpr_i40e_del_qch(vf);
		vf->adq_enabled = false;
		vf->num_tc = 0;
		dev_info(&pf->pdev->dev,
			 "Deleting Queue Channels and cloud filters for ADq on VF %d\n",
			 vf->vf_id);
	} else {
		dev_info(&pf->pdev->dev, "VF %d trying to delete queue channels but ADq isn't enabled\n",
			 vf->vf_id);
		aq_ret = I40E_ERR_PARAM;
	}

	/* reset the VF in order to allocate resources */
	(*klpe_i40e_vc_notify_vf_reset)(vf);
	(*klpe_i40e_reset_vf)(vf, false);

	return I40E_SUCCESS;

err:
	return klpr_i40e_vc_send_resp_to_vf(vf, VIRTCHNL_OP_DISABLE_CHANNELS,
				       aq_ret);
}

int klpp_i40e_vc_process_vf_msg(struct i40e_pf *pf, s16 vf_id, u32 v_opcode,
			   u32 __always_unused v_retval, u8 *msg, u16 msglen)
{
	struct i40e_hw *hw = &pf->hw;
	int local_vf_id = vf_id - (s16)hw->func_caps.vf_base_id;
	struct i40e_vf *vf;
	int ret;

	pf->vf_aq_requests++;
	if (local_vf_id < 0 || local_vf_id >= pf->num_alloc_vfs)
		return -EINVAL;
	vf = &(pf->vf[local_vf_id]);

	/* Check if VF is disabled. */
	if (test_bit(I40E_VF_STATE_DISABLED, &vf->vf_states))
		return I40E_ERR_PARAM;

	/* perform basic checks on the msg */
	ret = virtchnl_vc_validate_vf_msg(&vf->vf_ver, v_opcode, msg, msglen);

	/* perform additional checks specific to this driver */
	if (v_opcode == VIRTCHNL_OP_CONFIG_RSS_KEY) {
		struct virtchnl_rss_key *vrk = (struct virtchnl_rss_key *)msg;

		if (vrk->key_len != I40E_HKEY_ARRAY_SIZE)
			ret = -EINVAL;
	} else if (v_opcode == VIRTCHNL_OP_CONFIG_RSS_LUT) {
		struct virtchnl_rss_lut *vrl = (struct virtchnl_rss_lut *)msg;

		if (vrl->lut_entries != I40E_VF_HLUT_ARRAY_SIZE)
			ret = -EINVAL;
	}

	if (ret) {
		klpr_i40e_vc_send_resp_to_vf(vf, v_opcode, I40E_ERR_PARAM);
		dev_err(&pf->pdev->dev, "Invalid message from VF %d, opcode %d, len %d\n",
			local_vf_id, v_opcode, msglen);
		switch (ret) {
		case VIRTCHNL_STATUS_ERR_PARAM:
			return -EPERM;
		default:
			return -EINVAL;
		}
	}

	switch (v_opcode) {
	case VIRTCHNL_OP_VERSION:
		ret = klpr_i40e_vc_get_version_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_VF_RESOURCES:
		ret = klpr_i40e_vc_get_vf_resources_msg(vf, msg);
		(*klpe_i40e_vc_notify_vf_link_state)(vf);
		break;
	case VIRTCHNL_OP_RESET_VF:
		klpr_i40e_vc_reset_vf_msg(vf);
		ret = 0;
		break;
	case VIRTCHNL_OP_CONFIG_PROMISCUOUS_MODE:
		ret = klpr_i40e_vc_config_promiscuous_mode_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_VSI_QUEUES:
		ret = klpr_i40e_vc_config_queues_msg(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_IRQ_MAP:
		ret = klpr_i40e_vc_config_irq_map_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_QUEUES:
		ret = klpr_i40e_vc_enable_queues_msg(vf, msg);
		(*klpe_i40e_vc_notify_vf_link_state)(vf);
		break;
	case VIRTCHNL_OP_DISABLE_QUEUES:
		ret = klpr_i40e_vc_disable_queues_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_ETH_ADDR:
		ret = klpr_i40e_vc_add_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_ETH_ADDR:
		ret = klpr_i40e_vc_del_mac_addr_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_VLAN:
		ret = klpr_i40e_vc_add_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_VLAN:
		ret = klpr_i40e_vc_remove_vlan_msg(vf, msg);
		break;
	case VIRTCHNL_OP_GET_STATS:
		ret = klpr_i40e_vc_get_stats_msg(vf, msg);
		break;
	case VIRTCHNL_OP_IWARP:
		ret = klpr_i40e_vc_iwarp_msg(vf, msg, msglen);
		break;
	case VIRTCHNL_OP_CONFIG_IWARP_IRQ_MAP:
		ret = klpr_i40e_vc_iwarp_qvmap_msg(vf, msg, true);
		break;
	case VIRTCHNL_OP_RELEASE_IWARP_IRQ_MAP:
		ret = klpr_i40e_vc_iwarp_qvmap_msg(vf, msg, false);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_KEY:
		ret = klpr_i40e_vc_config_rss_key(vf, msg);
		break;
	case VIRTCHNL_OP_CONFIG_RSS_LUT:
		ret = klpr_i40e_vc_config_rss_lut(vf, msg);
		break;
	case VIRTCHNL_OP_GET_RSS_HENA_CAPS:
		ret = klpr_i40e_vc_get_rss_hena(vf, msg);
		break;
	case VIRTCHNL_OP_SET_RSS_HENA:
		ret = klpr_i40e_vc_set_rss_hena(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_VLAN_STRIPPING:
		ret = klpr_i40e_vc_enable_vlan_stripping(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_VLAN_STRIPPING:
		ret = klpr_i40e_vc_disable_vlan_stripping(vf, msg);
		break;
	case VIRTCHNL_OP_REQUEST_QUEUES:
		ret = klpr_i40e_vc_request_queues_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ENABLE_CHANNELS:
		ret = klpr_i40e_vc_add_qch_msg(vf, msg);
		break;
	case VIRTCHNL_OP_DISABLE_CHANNELS:
		ret = klpr_i40e_vc_del_qch_msg(vf, msg);
		break;
	case VIRTCHNL_OP_ADD_CLOUD_FILTER:
		ret = (*klpe_i40e_vc_add_cloud_filter)(vf, msg);
		break;
	case VIRTCHNL_OP_DEL_CLOUD_FILTER:
		ret = (*klpe_i40e_vc_del_cloud_filter)(vf, msg);
		break;
	case VIRTCHNL_OP_UNKNOWN:
	default:
		dev_err(&pf->pdev->dev, "Unsupported opcode %d from VF %d\n",
			v_opcode, local_vf_id);
		ret = klpr_i40e_vc_send_resp_to_vf(vf, v_opcode,
					      I40E_ERR_NOT_IMPLEMENTED);
		break;
	}

	return ret;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "i40e"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "i40e_add_mac_filter", (void *)&klpe_i40e_add_mac_filter, "i40e" },
	{ "i40e_aq_set_vsi_mc_promisc_on_vlan",
	  (void *)&klpe_i40e_aq_set_vsi_mc_promisc_on_vlan, "i40e" },
	{ "i40e_aq_set_vsi_uc_promisc_on_vlan",
	  (void *)&klpe_i40e_aq_set_vsi_uc_promisc_on_vlan, "i40e" },
	{ "i40e_clear_lan_rx_queue_context",
	  (void *)&klpe_i40e_clear_lan_rx_queue_context, "i40e" },
	{ "i40e_clear_lan_tx_queue_context",
	  (void *)&klpe_i40e_clear_lan_tx_queue_context, "i40e" },
	{ "i40e_config_rss", (void *)&klpe_i40e_config_rss, "i40e" },
	{ "i40e_config_vf_promiscuous_mode",
	  (void *)&klpe_i40e_config_vf_promiscuous_mode, "i40e" },
	{ "i40e_control_wait_rx_q", (void *)&klpe_i40e_control_wait_rx_q,
	  "i40e" },
	{ "i40e_count_filters", (void *)&klpe_i40e_count_filters, "i40e" },
	{ "i40e_ctrl_vf_tx_rings", (void *)&klpe_i40e_ctrl_vf_tx_rings,
	  "i40e" },
	{ "i40e_del_all_cloud_filters",
	  (void *)&klpe_i40e_del_all_cloud_filters, "i40e" },
	{ "i40e_del_mac_filter", (void *)&klpe_i40e_del_mac_filter, "i40e" },
	{ "i40e_find_mac", (void *)&klpe_i40e_find_mac, "i40e" },
	{ "i40e_find_vsi_from_id", (void *)&klpe_i40e_find_vsi_from_id,
	  "i40e" },
	{ "i40e_get_real_pf_qid", (void *)&klpe_i40e_get_real_pf_qid, "i40e" },
	{ "i40e_notify_client_of_vf_msg",
	  (void *)&klpe_i40e_notify_client_of_vf_msg, "i40e" },
	{ "i40e_reset_vf", (void *)&klpe_i40e_reset_vf, "i40e" },
	{ "i40e_set_lan_rx_queue_context",
	  (void *)&klpe_i40e_set_lan_rx_queue_context, "i40e" },
	{ "i40e_set_lan_tx_queue_context",
	  (void *)&klpe_i40e_set_lan_tx_queue_context, "i40e" },
	{ "i40e_sync_vsi_filters", (void *)&klpe_i40e_sync_vsi_filters,
	  "i40e" },
	{ "i40e_update_adq_vsi_queues",
	  (void *)&klpe_i40e_update_adq_vsi_queues, "i40e" },
	{ "i40e_update_eth_stats", (void *)&klpe_i40e_update_eth_stats,
	  "i40e" },
	{ "i40e_validate_queue_map", (void *)&klpe_i40e_validate_queue_map,
	  "i40e" },
	{ "i40e_vc_add_cloud_filter", (void *)&klpe_i40e_vc_add_cloud_filter,
	  "i40e" },
	{ "i40e_vc_del_cloud_filter", (void *)&klpe_i40e_vc_del_cloud_filter,
	  "i40e" },
	{ "i40e_vc_notify_vf_link_state",
	  (void *)&klpe_i40e_vc_notify_vf_link_state, "i40e" },
	{ "i40e_vc_notify_vf_reset", (void *)&klpe_i40e_vc_notify_vf_reset,
	  "i40e" },
	{ "i40e_vc_send_msg_to_vf", (void *)&klpe_i40e_vc_send_msg_to_vf,
	  "i40e" },
	{ "i40e_vf_client_capable", (void *)&klpe_i40e_vf_client_capable,
	  "i40e" },
	{ "i40e_vlan_stripping_disable",
	  (void *)&klpe_i40e_vlan_stripping_disable, "i40e" },
	{ "i40e_vlan_stripping_enable",
	  (void *)&klpe_i40e_vlan_stripping_enable, "i40e" },
	{ "i40e_vsi_add_vlan", (void *)&klpe_i40e_vsi_add_vlan, "i40e" },
	{ "i40e_vsi_kill_vlan", (void *)&klpe_i40e_vsi_kill_vlan, "i40e" },
	{ "i40e_vsi_release", (void *)&klpe_i40e_vsi_release, "i40e" },
	{ "i40e_vsi_start_rings", (void *)&klpe_i40e_vsi_start_rings, "i40e" },
	{ "i40e_write_rx_ctl", (void *)&klpe_i40e_write_rx_ctl, "i40e" },
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

int livepatch_bsc1252036_init(void)
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

void livepatch_bsc1252036_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_I40E) */
