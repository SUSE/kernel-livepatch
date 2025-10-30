/*
 * livepatch_bsc1248631
 *
 * Fix for CVE-2025-38664, bsc#1248631
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

#if IS_ENABLED(CONFIG_ICE)

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_common.h */
#include <linux/bitfield.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice.h */
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/compiler.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/cpumask.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>
#include <linux/dma-mapping.h>

/* klp-ccp: from include/linux/pci.h */
#define LINUX_PCI_H

/* klp-ccp: from include/linux/io.h */
#define _LINUX_IO_H

/* klp-ccp: from include/linux/pci_ids.h */
#define _LINUX_PCI_IDS_H

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice.h */
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/bitmap.h>
#include <linux/log2.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_sched.h>
#include <linux/ctype.h>

/* klp-ccp: from include/uapi/linux/bpf.h */
#define _UAPI__LINUX_BPF_H__

#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))

/* klp-ccp: from include/linux/btf.h */
#define _LINUX_BTF_H 1

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice.h */
#include <linux/btf.h>

/* klp-ccp: from include/linux/auxiliary_bus.h */
#define _AUXILIARY_BUS_H_

/* klp-ccp: from include/linux/avf/virtchnl.h */
#define _VIRTCHNL_H_

/* klp-ccp: from include/net/pkt_sched.h */
#define __NET_PKT_SCHED_H

/* klp-ccp: from include/net/netns/generic.h */
#define __NET_GENERIC_H__

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice.h */
#include <net/pkt_sched.h>

#include <net/ip.h>

/* klp-ccp: from include/net/devlink.h */
#define _NET_DEVLINK_H_

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice.h */
#include <net/ipv6.h>

#include <net/geneve.h>

#include <net/udp_tunnel.h>

/* klp-ccp: from include/net/dst_metadata.h */
#define __NET_DST_METADATA_H 1

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_osdep.h */
#include <linux/types.h>
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/bitops.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/iopoll.h>
#include <linux/pci_ids.h>

#include <net/udp_tunnel.h>

struct ice_dma_mem {
	void *va;
	dma_addr_t pa;
	size_t size;
};

struct ice_hw;
struct device *ice_hw_to_dev(struct ice_hw *hw);

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_adminq_cmd.h */
#define ICE_MAX_VSI			768
#define ICE_AQC_TOPO_MAX_LEVEL_NUM	0x9

struct ice_pkg_ver {
	u8 major;
	u8 minor;
	u8 update;
	u8 draft;
};

#define ICE_PKG_NAME_SIZE	32
#define ICE_SEG_ID_SIZE		28

enum ice_aqc_fw_logging_mod {
	ICE_AQC_FW_LOG_ID_GENERAL = 0,
	ICE_AQC_FW_LOG_ID_CTRL,
	ICE_AQC_FW_LOG_ID_LINK,
	ICE_AQC_FW_LOG_ID_LINK_TOPO,
	ICE_AQC_FW_LOG_ID_DNL,
	ICE_AQC_FW_LOG_ID_I2C,
	ICE_AQC_FW_LOG_ID_SDP,
	ICE_AQC_FW_LOG_ID_MDIO,
	ICE_AQC_FW_LOG_ID_ADMINQ,
	ICE_AQC_FW_LOG_ID_HDMA,
	ICE_AQC_FW_LOG_ID_LLDP,
	ICE_AQC_FW_LOG_ID_DCBX,
	ICE_AQC_FW_LOG_ID_DCB,
	ICE_AQC_FW_LOG_ID_XLR,
	ICE_AQC_FW_LOG_ID_NVM,
	ICE_AQC_FW_LOG_ID_AUTH,
	ICE_AQC_FW_LOG_ID_VPD,
	ICE_AQC_FW_LOG_ID_IOSF,
	ICE_AQC_FW_LOG_ID_PARSER,
	ICE_AQC_FW_LOG_ID_SW,
	ICE_AQC_FW_LOG_ID_SCHEDULER,
	ICE_AQC_FW_LOG_ID_TXQ,
	ICE_AQC_FW_LOG_ID_RSVD,
	ICE_AQC_FW_LOG_ID_POST,
	ICE_AQC_FW_LOG_ID_WATCHDOG,
	ICE_AQC_FW_LOG_ID_TASK_DISPATCH,
	ICE_AQC_FW_LOG_ID_MNG,
	ICE_AQC_FW_LOG_ID_SYNCE,
	ICE_AQC_FW_LOG_ID_HEALTH,
	ICE_AQC_FW_LOG_ID_TSDRV,
	ICE_AQC_FW_LOG_ID_PFREG,
	ICE_AQC_FW_LOG_ID_MDLVER,
	ICE_AQC_FW_LOG_ID_MAX,
};

enum ice_aq_err {
	ICE_AQ_RC_OK		= 0,  /* Success */
	ICE_AQ_RC_EPERM		= 1,  /* Operation not permitted */
	ICE_AQ_RC_ENOENT	= 2,  /* No such element */
	ICE_AQ_RC_ENOMEM	= 9,  /* Out of memory */
	ICE_AQ_RC_EBUSY		= 12, /* Device or resource busy */
	ICE_AQ_RC_EEXIST	= 13, /* Object already exists */
	ICE_AQ_RC_EINVAL	= 14, /* Invalid argument */
	ICE_AQ_RC_ENOSPC	= 16, /* No space left or allocation failure */
	ICE_AQ_RC_ENOSYS	= 17, /* Function not implemented */
	ICE_AQ_RC_EMODE		= 21, /* Op not allowed in current dev mode */
	ICE_AQ_RC_ENOSEC	= 24, /* Missing security manifest */
	ICE_AQ_RC_EBADSIG	= 25, /* Bad RSA signature */
	ICE_AQ_RC_ESVN		= 26, /* SVN number prohibits this package */
	ICE_AQ_RC_EBADMAN	= 27, /* Manifest hash mismatch */
	ICE_AQ_RC_EBADBUF	= 28, /* Buffer hash mismatches manifest */
};

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_controlq.h */
enum ice_ctl_q {
	ICE_CTL_Q_UNKNOWN = 0,
	ICE_CTL_Q_ADMIN,
	ICE_CTL_Q_MAILBOX,
	ICE_CTL_Q_SB,
};

struct ice_ctl_q_ring {
	void *dma_head;			/* Virtual address to DMA head */
	struct ice_dma_mem desc_buf;	/* descriptor ring memory */

	union {
		struct ice_dma_mem *sq_bi;
		struct ice_dma_mem *rq_bi;
	} r;

	u16 count;		/* Number of descriptors */

	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	/* used for queue tracking */
	u32 head;
	u32 tail;
	u32 len;
	u32 bah;
	u32 bal;
	u32 len_mask;
	u32 len_ena_mask;
	u32 len_crit_mask;
	u32 head_mask;
};

struct ice_ctl_q_info {
	enum ice_ctl_q qtype;
	struct ice_ctl_q_ring rq;	/* receive queue */
	struct ice_ctl_q_ring sq;	/* send queue */
	u16 num_rq_entries;		/* receive queue depth */
	u16 num_sq_entries;		/* send queue depth */
	u16 rq_buf_size;		/* receive queue buffer size */
	u16 sq_buf_size;		/* send queue buffer size */
	enum ice_aq_err sq_last_status;	/* last status on send queue */
	struct mutex sq_lock;		/* Send queue lock */
	struct mutex rq_lock;		/* Receive queue lock */
};

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_ddp.h */
enum ice_ddp_state {
	/* Indicates that this call to ice_init_pkg
	 * successfully loaded the requested DDP package
	 */
	ICE_DDP_PKG_SUCCESS = 0,

	/* Generic error for already loaded errors, it is mapped later to
	 * the more specific one (one of the next 3)
	 */
	ICE_DDP_PKG_ALREADY_LOADED = -1,

	/* Indicates that a DDP package of the same version has already been
	 * loaded onto the device by a previous call or by another PF
	 */
	ICE_DDP_PKG_SAME_VERSION_ALREADY_LOADED = -2,

	/* The device has a DDP package that is not supported by the driver */
	ICE_DDP_PKG_ALREADY_LOADED_NOT_SUPPORTED = -3,

	/* The device has a compatible package
	 * (but different from the request) already loaded
	 */
	ICE_DDP_PKG_COMPATIBLE_ALREADY_LOADED = -4,

	/* The firmware loaded on the device is not compatible with
	 * the DDP package loaded
	 */
	ICE_DDP_PKG_FW_MISMATCH = -5,

	/* The DDP package file is invalid */
	ICE_DDP_PKG_INVALID_FILE = -6,

	/* The version of the DDP package provided is higher than
	 * the driver supports
	 */
	ICE_DDP_PKG_FILE_VERSION_TOO_HIGH = -7,

	/* The version of the DDP package provided is lower than the
	 * driver supports
	 */
	ICE_DDP_PKG_FILE_VERSION_TOO_LOW = -8,

	/* The signature of the DDP package file provided is invalid */
	ICE_DDP_PKG_FILE_SIGNATURE_INVALID = -9,

	/* The DDP package file security revision is too low and not
	 * supported by firmware
	 */
	ICE_DDP_PKG_FILE_REVISION_TOO_LOW = -10,

	/* An error occurred in firmware while loading the DDP package */
	ICE_DDP_PKG_LOAD_ERROR = -11,

	/* Other errors */
	ICE_DDP_PKG_ERR = -12
};

enum ice_block {
	ICE_BLK_SW = 0,
	ICE_BLK_ACL,
	ICE_BLK_FD,
	ICE_BLK_RSS,
	ICE_BLK_PE,
	ICE_BLK_COUNT
};

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_flex_type.h */
enum ice_tunnel_type {
	TNL_VXLAN = 0,
	TNL_GENEVE,
	TNL_GRETAP,
	TNL_GTPC,
	TNL_GTPU,
	TNL_PFCP,
	__TNL_TYPE_CNT,
	TNL_LAST = 0xFF,
	TNL_ALL = 0xFF,
};

struct ice_tunnel_entry {
	enum ice_tunnel_type type;
	u16 boost_addr;
	u16 port;
	struct ice_boost_tcam_entry *boost_entry;
	u8 valid;
};

#define ICE_TUNNEL_MAX_ENTRIES	16

struct ice_tunnel_table {
	struct ice_tunnel_entry tbl[ICE_TUNNEL_MAX_ENTRIES];
	u16 count;
	u16 valid_count[__TNL_TYPE_CNT];
};

struct ice_dvm_entry {
	u16 boost_addr;
	u16 enable;
	struct ice_boost_tcam_entry *boost_entry;
};

#define ICE_DVM_MAX_ENTRIES	48

struct ice_dvm_table {
	struct ice_dvm_entry tbl[ICE_DVM_MAX_ENTRIES];
	u16 count;
};

struct ice_es {
	u32 sid;
	u16 count;
	u16 fvw;
	u16 *ref_count;
	u32 *mask_ena;
	struct list_head prof_map;
	struct ice_fv_word *t;
	u8 *symm;	/* symmetric setting per profile (RSS blk)*/
	struct mutex prof_map_lock;	/* protect access to profiles list */
	u8 *written;
	u8 reverse; /* set to true to reverse FV order */
};

#define ICE_XLT1_CNT	1024

struct ice_xlt1 {
	struct ice_ptg_entry *ptg_tbl;
	struct ice_ptg_ptype *ptypes;
	u8 *t;
	u32 sid;
	u16 count;
};

struct ice_xlt2 {
	struct ice_vsig_entry *vsig_tbl;
	struct ice_vsig_vsi *vsis;
	u16 *t;
	u32 sid;
	u16 count;
};

struct ice_prof_tcam {
	u32 sid;
	u16 count;
	u16 max_prof_id;
	struct ice_prof_tcam_entry *t;
	u8 cdid_bits; /* # CDID bits to use in key, 0, 2, 4, or 8 */
};

struct ice_prof_redir {
	u8 *t;
	u32 sid;
	u16 count;
};

struct ice_mask {
	u16 mask;	/* 16-bit mask */
	u16 idx;	/* index */
	u16 ref;	/* reference count */
	u8 in_use;	/* non-zero if used */
};

struct ice_masks {
	struct mutex lock; /* lock to protect this structure */
	u16 first;	/* first mask owned by the PF */
	u16 count;	/* number of masks owned by the PF */
#define ICE_PROF_MASK_COUNT 32
	struct ice_mask masks[ICE_PROF_MASK_COUNT];
};

struct ice_prof_id {
	unsigned long *id;
	int count;
};

struct ice_blk_info {
	struct ice_xlt1 xlt1;
	struct ice_xlt2 xlt2;
	struct ice_prof_id prof_id;
	struct ice_prof_tcam prof;
	struct ice_prof_redir prof_redir;
	struct ice_es es;
	struct ice_masks masks;
	u8 overwrite; /* set to true to allow overwrite of table entries */
	u8 is_list_init;
};

#define ICE_FLOW_PTYPE_MAX		ICE_XLT1_CNT

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_fwlog.h */
struct ice_fwlog_module_entry {
	/* module ID for the corresponding firmware logging event */
	u16 module_id;
	/* verbosity level for the module_id */
	u8 log_level;
};

struct ice_fwlog_cfg {
	/* list of modules for configuring log level */
	struct ice_fwlog_module_entry module_entries[ICE_AQC_FW_LOG_ID_MAX];
	/* options used to configure firmware logging */
	u16 options;
	/* set before calling ice_fwlog_init() so the PF registers for firmware
	 * logging on initialization
	 */
	/* set in the ice_fwlog_get() response if the PF is registered for FW
	 * logging events over ARQ
	 */

	/* minimum number of log events sent per Admin Receive Queue event */
	u16 log_resolution;
};

struct ice_fwlog_ring {
	struct ice_fwlog_data *rings;
	u16 index;
	u16 size;
	u16 head;
	u16 tail;
};

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_type.h */
enum ice_mac_type {
	ICE_MAC_UNKNOWN = 0,
	ICE_MAC_E810,
	ICE_MAC_E830,
	ICE_MAC_GENERIC,
	ICE_MAC_GENERIC_3K_E825,
};

enum ice_fltr_ptype {
	/* NONE - used for undef/error */
	ICE_FLTR_PTYPE_NONF_NONE = 0,
	ICE_FLTR_PTYPE_NONF_ETH,
	ICE_FLTR_PTYPE_NONF_IPV4_UDP,
	ICE_FLTR_PTYPE_NONF_IPV4_TCP,
	ICE_FLTR_PTYPE_NONF_IPV4_SCTP,
	ICE_FLTR_PTYPE_NONF_IPV4_OTHER,
	ICE_FLTR_PTYPE_NONF_IPV4_GTPU_IPV4_UDP,
	ICE_FLTR_PTYPE_NONF_IPV4_GTPU_IPV4_TCP,
	ICE_FLTR_PTYPE_NONF_IPV4_GTPU_IPV4_ICMP,
	ICE_FLTR_PTYPE_NONF_IPV4_GTPU_IPV4_OTHER,
	ICE_FLTR_PTYPE_NONF_IPV6_GTPU_IPV6_OTHER,
	ICE_FLTR_PTYPE_NONF_IPV4_L2TPV3,
	ICE_FLTR_PTYPE_NONF_IPV6_L2TPV3,
	ICE_FLTR_PTYPE_NONF_IPV4_ESP,
	ICE_FLTR_PTYPE_NONF_IPV6_ESP,
	ICE_FLTR_PTYPE_NONF_IPV4_AH,
	ICE_FLTR_PTYPE_NONF_IPV6_AH,
	ICE_FLTR_PTYPE_NONF_IPV4_NAT_T_ESP,
	ICE_FLTR_PTYPE_NONF_IPV6_NAT_T_ESP,
	ICE_FLTR_PTYPE_NONF_IPV4_PFCP_NODE,
	ICE_FLTR_PTYPE_NONF_IPV4_PFCP_SESSION,
	ICE_FLTR_PTYPE_NONF_IPV6_PFCP_NODE,
	ICE_FLTR_PTYPE_NONF_IPV6_PFCP_SESSION,
	ICE_FLTR_PTYPE_NON_IP_L2,
	ICE_FLTR_PTYPE_FRAG_IPV4,
	ICE_FLTR_PTYPE_NONF_IPV6_UDP,
	ICE_FLTR_PTYPE_NONF_IPV6_TCP,
	ICE_FLTR_PTYPE_NONF_IPV6_SCTP,
	ICE_FLTR_PTYPE_NONF_IPV6_OTHER,
	ICE_FLTR_PTYPE_MAX,
};

struct ice_hw_common_caps {
	u32 valid_functions;
	/* DCB capabilities */
	u32 active_tc_bitmap;
	u32 maxtc;

	/* Tx/Rx queues */
	u16 num_rxq;		/* Number/Total Rx queues */
	u16 rxq_first_id;	/* First queue ID for Rx queues */
	u16 num_txq;		/* Number/Total Tx queues */
	u16 txq_first_id;	/* First queue ID for Tx queues */

	/* MSI-X vectors */
	u16 num_msix_vectors;
	u16 msix_vector_first_id;

	/* Max MTU for function or device */
	u16 max_mtu;

	/* Virtualization support */
	u8 sr_iov_1_1;			/* SR-IOV enabled */

	/* RSS related capabilities */
	u16 rss_table_size;		/* 512 for PFs and 64 for VFs */
	u8 rss_table_entry_width;	/* RSS Entry width in bits */

	u8 dcb;
	u8 ieee_1588;
	u8 rdma;
	u8 roce_lag;
	u8 sriov_lag;

	bool nvm_update_pending_nvm;
	bool nvm_update_pending_orom;
	bool nvm_update_pending_netlist;
	bool nvm_unified_update;
	/* PCIe reset avoidance */
	bool pcie_reset_avoidance;
	/* Post update reset restriction */
	bool reset_restrict_support;
	bool tx_sched_topo_comp_mode_en;
};

enum ice_time_ref_freq {
	ICE_TIME_REF_FREQ_25_000	= 0,
	ICE_TIME_REF_FREQ_122_880	= 1,
	ICE_TIME_REF_FREQ_125_000	= 2,
	ICE_TIME_REF_FREQ_153_600	= 3,
	ICE_TIME_REF_FREQ_156_250	= 4,
	ICE_TIME_REF_FREQ_245_760	= 5,

	NUM_ICE_TIME_REF_FREQ,

	ICE_TIME_REF_FREQ_INVALID	= -1,
};

struct ice_ts_func_info {
	/* Function specific info */
	enum ice_time_ref_freq time_ref;
	u8 clk_freq;
	u8 clk_src;
	u8 tmr_index_assoc;
	u8 ena;
	u8 tmr_index_owned;
	u8 src_tmr_owned;
	u8 tmr_ena;
};

struct ice_ts_dev_info {
	/* Device specific info */
	u32 ena_ports;
	u32 tmr_own_map;
	u32 tmr0_owner;
	u32 tmr1_owner;
	u8 tmr0_owned;
	u8 tmr1_owned;
	u8 ena;
	u8 tmr0_ena;
	u8 tmr1_ena;
	u8 ts_ll_read;
	u8 ts_ll_int_read;
};

struct ice_nac_topology {
	u32 mode;
	u8 id;
};

struct ice_hw_func_caps {
	struct ice_hw_common_caps common_cap;
	u32 num_allocd_vfs;		/* Number of allocated VFs */
	u32 vf_base_id;			/* Logical ID of the first VF */
	u32 guar_num_vsi;
	u32 fd_fltr_guar;		/* Number of filters guaranteed */
	u32 fd_fltr_best_effort;	/* Number of best effort filters */
	struct ice_ts_func_info ts_func_info;
};

struct ice_hw_dev_caps {
	struct ice_hw_common_caps common_cap;
	u32 num_vfs_exposed;		/* Total number of VFs exposed */
	u32 num_vsi_allocd_to_host;	/* Excluding EMP VSI */
	u32 num_flow_director_fltr;	/* Number of FD filters available */
	struct ice_ts_dev_info ts_dev_info;
	u32 num_funcs;
	struct ice_nac_topology nac_topo;
	/* bitmap of supported sensors
	 * bit 0 - internal temperature sensor
	 * bit 31:1 - Reserved
	 */
	u32 supported_sensors;
};

struct ice_bus_info {
	u16 device;
	u8 func;
};

struct ice_orom_info {
	u8 major;			/* Major version of OROM */
	u8 patch;			/* Patch version of OROM */
	u16 build;			/* Build version of OROM */
};

struct ice_nvm_info {
	u32 eetrack;
	u8 major;
	u8 minor;
};

struct ice_netlist_info {
	u32 major;			/* major high/low */
	u32 minor;			/* minor high/low */
	u32 type;			/* type high/low */
	u32 rev;			/* revision high/low */
	u32 hash;			/* SHA-1 hash word */
	u16 cust_ver;			/* customer version */
};

enum ice_flash_bank {
	ICE_INVALID_FLASH_BANK,
	ICE_1ST_FLASH_BANK,
	ICE_2ND_FLASH_BANK,
};

struct ice_bank_info {
	u32 nvm_ptr;				/* Pointer to 1st NVM bank */
	u32 nvm_size;				/* Size of NVM bank */
	u32 orom_ptr;				/* Pointer to 1st OROM bank */
	u32 orom_size;				/* Size of OROM bank */
	u32 netlist_ptr;			/* Pointer to 1st Netlist bank */
	u32 netlist_size;			/* Size of Netlist bank */
	u32 active_css_hdr_len;			/* Active CSS header length */
	u32 inactive_css_hdr_len;		/* Inactive CSS header length */
	enum ice_flash_bank nvm_bank;		/* Active NVM bank */
	enum ice_flash_bank orom_bank;		/* Active OROM bank */
	enum ice_flash_bank netlist_bank;	/* Active Netlist bank */
};

struct ice_flash_info {
	struct ice_orom_info orom;	/* Option ROM version info */
	struct ice_nvm_info nvm;	/* NVM version information */
	struct ice_netlist_info netlist;/* Netlist version info */
	struct ice_bank_info banks;	/* Flash Bank information */
	u16 sr_words;			/* Shadow RAM size in words */
	u32 flash_size;			/* Size of available flash in bytes */
	u8 blank_nvm_mode;		/* is NVM empty (no FW present) */
};

enum ice_mbx_snapshot_state {
	ICE_MAL_VF_DETECT_STATE_NEW_SNAPSHOT = 0,
	ICE_MAL_VF_DETECT_STATE_TRAVERSE,
	ICE_MAL_VF_DETECT_STATE_DETECT,
	ICE_MAL_VF_DETECT_STATE_INVALID = 0xFFFFFFFF,
};

struct ice_mbx_snap_buffer_data {
	enum ice_mbx_snapshot_state state;
	u32 head;
	u32 tail;
	u32 num_iterations;
	u16 num_msg_proc;
	u16 num_pending_arq;
	u16 max_num_msgs_mbx;
};

struct ice_mbx_snapshot {
	struct ice_mbx_snap_buffer_data mbx_buf;
	struct list_head mbx_vf;
};

struct ice_eth56g_params {
	u8 num_phys;
	bool onestep_ena;
	bool sfd_ena;
	u32 peer_delay;
};

union ice_phy_params {
	struct ice_eth56g_params eth56g;
};

enum ice_phy_model {
	ICE_PHY_UNSUP = -1,
	ICE_PHY_E810 = 1,
	ICE_PHY_E82X,
	ICE_PHY_ETH56G,
};

struct ice_ptp_hw {
	enum ice_phy_model phy_model;
	union ice_phy_params phy;
	u8 num_lports;
	u8 ports_per_phy;
};

struct ice_hw {
	u8 __iomem *hw_addr;
	void *back;
	struct ice_aqc_layer_props *layer_info;
	struct ice_port_info *port_info;
	/* PSM clock frequency for calculating RL profile params */
	u32 psm_clk_freq;
	u64 debug_mask;		/* bitmap for debug mask */
	enum ice_mac_type mac_type;

	u16 fd_ctr_base;	/* FD counter base index */

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;

	u8 pf_id;		/* device profile info */
	u8 logical_pf_id;

	u16 max_burst_size;	/* driver sets this value */

	u8 recp_reuse:1;	/* indicates whether FW supports recipe reuse */

	/* Tx Scheduler values */
	u8 num_tx_sched_layers;
	u8 num_tx_sched_phys_layers;
	u8 flattened_layers;
	u8 max_cgds;
	u8 sw_entry_point_layer;
	u16 max_children[ICE_AQC_TOPO_MAX_LEVEL_NUM];
	struct list_head agg_list;	/* lists all aggregator */

	struct ice_vsi_ctx *vsi_ctx[ICE_MAX_VSI];
	u8 evb_veb;		/* true for VEB, false for VEPA */
	u8 reset_ongoing;	/* true if HW is in reset, false otherwise */
	struct ice_bus_info bus;
	struct ice_flash_info flash;
	struct ice_hw_dev_caps dev_caps;	/* device capabilities */
	struct ice_hw_func_caps func_caps;	/* function capabilities */

	struct ice_switch_info *switch_info;	/* switch filter lists */

	/* Control Queue info */
	struct ice_ctl_q_info adminq;
	struct ice_ctl_q_info sbq;
	struct ice_ctl_q_info mailboxq;

	u8 api_branch;		/* API branch version */
	u8 api_maj_ver;		/* API major version */
	u8 api_min_ver;		/* API minor version */
	u8 api_patch;		/* API patch version */
	u8 fw_branch;		/* firmware branch version */
	u8 fw_maj_ver;		/* firmware major version */
	u8 fw_min_ver;		/* firmware minor version */
	u8 fw_patch;		/* firmware patch version */
	u32 fw_build;		/* firmware build number */

	struct ice_fwlog_cfg fwlog_cfg;
	bool fwlog_supported; /* does hardware support FW logging? */
	struct ice_fwlog_ring fwlog_ring;

/* Device max aggregate bandwidths corresponding to the GL_PWR_MODE_CTL
 * register. Used for determining the ITR/INTRL granularity during
 * initialization.
 */
	/* ITR granularity for different speeds */
	/* ITR granularity in 1 us */
	u8 itr_gran;
	/* INTRL granularity for different speeds */
	/* INTRL granularity in 1 us */
	u8 intrl_gran;

	struct ice_ptp_hw ptp;

	/* Active package version (currently active) */
	struct ice_pkg_ver active_pkg_ver;
	u32 pkg_seg_id;
	u32 pkg_sign_type;
	u32 active_track_id;
	u8 pkg_has_signing_seg:1;
	u8 active_pkg_name[ICE_PKG_NAME_SIZE];
	u8 active_pkg_in_nvm;

	/* Driver's package ver - (from the Ice Metadata section) */
	struct ice_pkg_ver pkg_ver;
	u8 pkg_name[ICE_PKG_NAME_SIZE];

	/* Driver's Ice segment format version and ID (from the Ice seg) */
	struct ice_pkg_ver ice_seg_fmt_ver;
	u8 ice_seg_id[ICE_SEG_ID_SIZE];

	/* Pointer to the ice segment */
	struct ice_seg *seg;

	/* Pointer to allocated copy of pkg memory */
	u8 *pkg_copy;
	u32 pkg_size;

	/* tunneling info */
	struct mutex tnl_lock;
	struct ice_tunnel_table tnl;

	struct udp_tunnel_nic_shared udp_tunnel_shared;
	struct udp_tunnel_nic_info udp_tunnel_nic;

	/* dvm boost update information */
	struct ice_dvm_table dvm_upd;

	/* HW block tables */
	struct ice_blk_info blk[ICE_BLK_COUNT];
	struct mutex fl_profs_locks[ICE_BLK_COUNT];	/* lock fltr profiles */
	struct list_head fl_profs[ICE_BLK_COUNT];

	/* Flow Director filter info */
	int fdir_active_fltr;

	struct mutex fdir_fltr_lock;	/* protect Flow Director */
	struct list_head fdir_list_head;

	/* Book-keeping of side-band filter count per flow-type.
	 * This is used to detect and handle input set changes for
	 * respective flow-type.
	 */
	u16 fdir_fltr_cnt[ICE_FLTR_PTYPE_MAX];

	struct ice_fd_hw_prof **fdir_prof;
	DECLARE_BITMAP(fdir_perfect_fltr, ICE_FLTR_PTYPE_MAX);
	struct mutex rss_locks;	/* protect RSS configuration */
	struct list_head rss_list_head;
	struct ice_mbx_snapshot mbx_snapshot;
	DECLARE_BITMAP(hw_ptype, ICE_FLOW_PTYPE_MAX);
	u8 dvm_ena;
	u16 io_expander_handle;
	u8 cgu_part_number;
};

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_vf_lib.h */
#include <linux/types.h>
#include <linux/hashtable.h>
#include <linux/bitmap.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <net/devlink.h>
#include <linux/avf/virtchnl.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_vsi_vlan_lib.h */
#include <linux/types.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_vlan.h */
#include <linux/types.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_virtchnl.h */
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/if_ether.h>
#include <linux/avf/virtchnl.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_ptp.h */
#include <linux/kthread.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_repr.h */
#include <net/dst_metadata.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_eswitch.h */
#include <net/devlink.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_sf_eth.h */
#include <linux/auxiliary_bus.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_lag.h */
#include <linux/netdevice.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_adapter.h */
#include <linux/types.h>
#include <linux/spinlock_types.h>
#include <linux/refcount_types.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_flex_pipe.h */
enum ice_ddp_state ice_init_pkg(struct ice_hw *hw, u8 *buff, u32 len);
bool ice_is_init_pkg_successful(enum ice_ddp_state state);

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_common.h */
#include <linux/avf/virtchnl.h>

/* klp-ccp: from drivers/net/ethernet/intel/ice/ice_ddp.c */
bool ice_is_init_pkg_successful(enum ice_ddp_state state);

enum ice_ddp_state ice_init_pkg(struct ice_hw *hw, u8 *buf, u32 len);

enum ice_ddp_state klpp_ice_copy_and_init_pkg(struct ice_hw *hw, const u8 *buf,
					 u32 len)
{
	enum ice_ddp_state state;
	u8 *buf_copy;

	if (!buf || !len)
		return ICE_DDP_PKG_ERR;

	buf_copy = devm_kmemdup(ice_hw_to_dev(hw), buf, len, GFP_KERNEL);
	if (!buf_copy)
		return ICE_DDP_PKG_ERR;

	state = ice_init_pkg(hw, buf_copy, len);
	if (!ice_is_init_pkg_successful(state)) {
		/* Free the copy, since we failed to initialize the package */
		devm_kfree(ice_hw_to_dev(hw), buf_copy);
	} else {
		/* Track the copied pkg so we can free it later */
		hw->pkg_copy = buf_copy;
		hw->pkg_size = len;
	}

	return state;
}


#include "livepatch_bsc1248631.h"

#include <linux/livepatch.h>

extern typeof(ice_hw_to_dev) ice_hw_to_dev
	 KLP_RELOC_SYMBOL(ice, ice, ice_hw_to_dev);
extern typeof(ice_init_pkg) ice_init_pkg
	 KLP_RELOC_SYMBOL(ice, ice, ice_init_pkg);
extern typeof(ice_is_init_pkg_successful) ice_is_init_pkg_successful
	 KLP_RELOC_SYMBOL(ice, ice, ice_is_init_pkg_successful);

#endif /* IS_ENABLED(CONFIG_ICE) */
