/*
 * livepatch_bsc1264567
 *
 * Fix for CVE-2026-43120, bsc#1264567
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

#if IS_ENABLED(CONFIG_INFINIBAND_IRDMA)

#if !IS_MODULE(CONFIG_INFINIBAND_IRDMA)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1264567.h"


/* klp-ccp: from drivers/infiniband/hw/irdma/main.h */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_vlan.h>
#include <net/addrconf.h>
#include <net/netevent.h>
#include <net/tcp.h>
#include <net/ip6_route.h>
#include <net/flow.h>
#include <net/secure_seq.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/inetdevice.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/crc32c.h>
#include <linux/kthread.h>
#include <linux/auxiliary_bus.h>
#include <linux/net/intel/iidc.h>
#include <crypto/hash.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/rdma_cm.h>
#include <rdma/iw_cm.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_cache.h>
#include <rdma/uverbs_ioctl.h>
/* klp-ccp: from drivers/infiniband/hw/irdma/osdep.h */
#include <linux/pci.h>
#include <linux/bitfield.h>
#include <linux/net/intel/iidc.h>
#include <crypto/hash.h>
#include <rdma/ib_verbs.h>

struct irdma_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
} __packed;

struct irdma_virt_mem {
	void *va;
	u32 size;
} __packed;

struct irdma_pci_f;

/* klp-ccp: from drivers/infiniband/hw/irdma/defs.h */
enum irdma_protocol_used {
	IRDMA_ANY_PROTOCOL = 0,
	IRDMA_IWARP_PROTOCOL_ONLY = 1,
	IRDMA_ROCE_PROTOCOL_ONLY = 2,
};

#define	IRDMA_MAX_STATS_COUNT_GEN_1	12
#define IRDMA_MAX_USER_PRIORITY		8

enum irdma_cqp_op_type {
	IRDMA_OP_CEQ_DESTROY			= 1,
	IRDMA_OP_AEQ_DESTROY			= 2,
	IRDMA_OP_DELETE_ARP_CACHE_ENTRY		= 3,
	IRDMA_OP_MANAGE_APBVT_ENTRY		= 4,
	IRDMA_OP_CEQ_CREATE			= 5,
	IRDMA_OP_AEQ_CREATE			= 6,
	IRDMA_OP_MANAGE_QHASH_TABLE_ENTRY	= 7,
	IRDMA_OP_QP_MODIFY			= 8,
	IRDMA_OP_QP_UPLOAD_CONTEXT		= 9,
	IRDMA_OP_CQ_CREATE			= 10,
	IRDMA_OP_CQ_DESTROY			= 11,
	IRDMA_OP_QP_CREATE			= 12,
	IRDMA_OP_QP_DESTROY			= 13,
	IRDMA_OP_ALLOC_STAG			= 14,
	IRDMA_OP_MR_REG_NON_SHARED		= 15,
	IRDMA_OP_DEALLOC_STAG			= 16,
	IRDMA_OP_MW_ALLOC			= 17,
	IRDMA_OP_QP_FLUSH_WQES			= 18,
	IRDMA_OP_ADD_ARP_CACHE_ENTRY		= 19,
	IRDMA_OP_MANAGE_PUSH_PAGE		= 20,
	IRDMA_OP_UPDATE_PE_SDS			= 21,
	IRDMA_OP_MANAGE_HMC_PM_FUNC_TABLE	= 22,
	IRDMA_OP_SUSPEND			= 23,
	IRDMA_OP_RESUME				= 24,
	IRDMA_OP_MANAGE_VF_PBLE_BP		= 25,
	IRDMA_OP_QUERY_FPM_VAL			= 26,
	IRDMA_OP_COMMIT_FPM_VAL			= 27,
	IRDMA_OP_AH_CREATE			= 28,
	IRDMA_OP_AH_MODIFY			= 29,
	IRDMA_OP_AH_DESTROY			= 30,
	IRDMA_OP_MC_CREATE			= 31,
	IRDMA_OP_MC_DESTROY			= 32,
	IRDMA_OP_MC_MODIFY			= 33,
	IRDMA_OP_STATS_ALLOCATE			= 34,
	IRDMA_OP_STATS_FREE			= 35,
	IRDMA_OP_STATS_GATHER			= 36,
	IRDMA_OP_WS_ADD_NODE			= 37,
	IRDMA_OP_WS_MODIFY_NODE			= 38,
	IRDMA_OP_WS_DELETE_NODE			= 39,
	IRDMA_OP_WS_FAILOVER_START		= 40,
	IRDMA_OP_WS_FAILOVER_COMPLETE		= 41,
	IRDMA_OP_SET_UP_MAP			= 42,
	IRDMA_OP_GEN_AE				= 43,
	IRDMA_OP_QUERY_RDMA_FEATURES		= 44,
	IRDMA_OP_ALLOC_LOCAL_MAC_ENTRY		= 45,
	IRDMA_OP_ADD_LOCAL_MAC_ENTRY		= 46,
	IRDMA_OP_DELETE_LOCAL_MAC_ENTRY		= 47,
	IRDMA_OP_CQ_MODIFY			= 48,

	/* Must be last entry*/
	IRDMA_MAX_CQP_OPS			= 49,
};

#define IRDMA_CQPSQ_STAG_IDX_S 8

/* klp-ccp: from drivers/infiniband/hw/irdma/hmc.h */
#define IRDMA_MAX_SD_ENTRIES			11

#define IRDMA_HMC_MAX_SD_COUNT			8192

struct irdma_hmc_sd_table {
	struct irdma_virt_mem addr;
	u32 sd_cnt;
	u32 use_cnt;
	struct irdma_hmc_sd_entry *sd_entry;
};

struct irdma_hmc_info {
	u32 signature;
	u8 hmc_fn_id;
	u16 first_sd_index;
	struct irdma_hmc_obj_info *hmc_obj;
	struct irdma_virt_mem hmc_obj_virt_mem;
	struct irdma_hmc_sd_table sd_table;
	u16 sd_indexes[IRDMA_HMC_MAX_SD_COUNT];
};

struct irdma_update_sd_entry {
	u64 cmd;
	u64 data;
};

struct irdma_update_sds_info {
	u32 cnt;
	u8 hmc_fn_id;
	struct irdma_update_sd_entry entry[IRDMA_MAX_SD_ENTRIES];
};

struct irdma_hmc_fcn_info {
	u32 vf_id;
	u8 free_fcn;
};

/* klp-ccp: from drivers/infiniband/hw/irdma/irdma.h */
enum irdma_registers {
	IRDMA_CQPTAIL,
	IRDMA_CQPDB,
	IRDMA_CCQPSTATUS,
	IRDMA_CCQPHIGH,
	IRDMA_CCQPLOW,
	IRDMA_CQARM,
	IRDMA_CQACK,
	IRDMA_AEQALLOC,
	IRDMA_CQPERRCODES,
	IRDMA_WQEALLOC,
	IRDMA_GLINT_DYN_CTL,
	IRDMA_DB_ADDR_OFFSET,
	IRDMA_GLPCI_LBARCTRL,
	IRDMA_GLPE_CPUSTATUS0,
	IRDMA_GLPE_CPUSTATUS1,
	IRDMA_GLPE_CPUSTATUS2,
	IRDMA_PFINT_AEQCTL,
	IRDMA_GLINT_CEQCTL,
	IRDMA_VSIQF_PE_CTL1,
	IRDMA_PFHMC_PDINV,
	IRDMA_GLHMC_VFPDINV,
	IRDMA_GLPE_CRITERR,
	IRDMA_GLINT_RATE,
	IRDMA_MAX_REGS, /* Must be last entry */
};

enum irdma_shifts {
	IRDMA_CCQPSTATUS_CCQP_DONE_S,
	IRDMA_CCQPSTATUS_CCQP_ERR_S,
	IRDMA_CQPSQ_STAG_PDID_S,
	IRDMA_CQPSQ_CQ_CEQID_S,
	IRDMA_CQPSQ_CQ_CQID_S,
	IRDMA_COMMIT_FPM_CQCNT_S,
	IRDMA_MAX_SHIFTS,
};

enum irdma_masks {
	IRDMA_CCQPSTATUS_CCQP_DONE_M,
	IRDMA_CCQPSTATUS_CCQP_ERR_M,
	IRDMA_CQPSQ_STAG_PDID_M,
	IRDMA_CQPSQ_CQ_CEQID_M,
	IRDMA_CQPSQ_CQ_CQID_M,
	IRDMA_COMMIT_FPM_CQCNT_M,
	IRDMA_MAX_MASKS, /* Must be last entry */
};

#define IRDMA_MAX_MGS_PER_CTX	8

struct irdma_mcast_grp_ctx_entry_info {
	u32 qp_id;
	bool valid_entry;
	u16 dest_port;
	u32 use_cnt;
};

struct irdma_mcast_grp_info {
	u8 dest_mac_addr[ETH_ALEN];
	u16 vlan_id;
	u8 hmc_fcn_id;
	bool ipv4_valid:1;
	bool vlan_valid:1;
	u16 mg_id;
	u32 no_of_mgs;
	u32 dest_ip_addr[4];
	u16 qs_handle;
	struct irdma_dma_mem dma_mem_mc;
	struct irdma_mcast_grp_ctx_entry_info mg_ctx_info[IRDMA_MAX_MGS_PER_CTX];
};

struct irdma_uk_attrs {
	u64 feature_flags;
	u32 max_hw_wq_frags;
	u32 max_hw_read_sges;
	u32 max_hw_inline;
	u32 max_hw_rq_quanta;
	u32 max_hw_wq_quanta;
	u32 min_hw_cq_size;
	u32 max_hw_cq_size;
	u16 max_hw_sq_chunk;
	u16 min_hw_wq_size;
	u8 hw_rev;
};

struct irdma_hw_attrs {
	struct irdma_uk_attrs uk_attrs;
	u64 max_hw_outbound_msg_size;
	u64 max_hw_inbound_msg_size;
	u64 max_mr_size;
	u64 page_size_cap;
	u32 min_hw_qp_id;
	u32 min_hw_aeq_size;
	u32 max_hw_aeq_size;
	u32 min_hw_ceq_size;
	u32 max_hw_ceq_size;
	u32 max_hw_device_pages;
	u32 max_hw_vf_fpm_id;
	u32 first_hw_vf_fpm_id;
	u32 max_hw_ird;
	u32 max_hw_ord;
	u32 max_hw_wqes;
	u32 max_hw_pds;
	u32 max_hw_ena_vf_count;
	u32 max_qp_wr;
	u32 max_pe_ready_count;
	u32 max_done_count;
	u32 max_sleep_count;
	u32 max_cqp_compl_wait_time_ms;
	u16 max_stat_inst;
	u16 max_stat_idx;
};

/* klp-ccp: from drivers/infiniband/hw/irdma/user.h */
#define irdma_stag_index u32

#define irdma_stag_key u8

#define IRDMA_ACCESS_FLAGS_LOCALREAD		0x01
#define IRDMA_ACCESS_FLAGS_LOCALWRITE		0x02

#define IRDMA_ACCESS_FLAGS_REMOTEREAD		0x05

#define IRDMA_ACCESS_FLAGS_REMOTEWRITE		0x0a
#define IRDMA_ACCESS_FLAGS_BIND_WINDOW		0x10
#define IRDMA_ACCESS_FLAGS_ZERO_BASED		0x20

enum irdma_device_caps_const {
	IRDMA_WQE_SIZE =			4,
	IRDMA_CQP_WQE_SIZE =			8,
	IRDMA_CQE_SIZE =			4,
	IRDMA_EXTENDED_CQE_SIZE =		8,
	IRDMA_AEQE_SIZE =			2,
	IRDMA_CEQE_SIZE =			1,
	IRDMA_CQP_CTX_SIZE =			8,
	IRDMA_SHADOW_AREA_SIZE =		8,
	IRDMA_QUERY_FPM_BUF_SIZE =		176,
	IRDMA_COMMIT_FPM_BUF_SIZE =		176,
	IRDMA_GATHER_STATS_BUF_SIZE =		1024,
	IRDMA_MIN_IW_QP_ID =			0,
	IRDMA_MAX_IW_QP_ID =			262143,
	IRDMA_MIN_CEQID =			0,
	IRDMA_MAX_CEQID =			1023,
	IRDMA_CEQ_MAX_COUNT =			IRDMA_MAX_CEQID + 1,
	IRDMA_MIN_CQID =			0,
	IRDMA_MAX_CQID =			524287,
	IRDMA_MIN_AEQ_ENTRIES =			1,
	IRDMA_MAX_AEQ_ENTRIES =			524287,
	IRDMA_MIN_CEQ_ENTRIES =			1,
	IRDMA_MAX_CEQ_ENTRIES =			262143,
	IRDMA_MIN_CQ_SIZE =			1,
	IRDMA_MAX_CQ_SIZE =			1048575,
	IRDMA_DB_ID_ZERO =			0,
	IRDMA_MAX_WQ_FRAGMENT_COUNT =		13,
	IRDMA_MAX_SGE_RD =			13,
	IRDMA_MAX_OUTBOUND_MSG_SIZE =		2147483647,
	IRDMA_MAX_INBOUND_MSG_SIZE =		2147483647,
	IRDMA_MAX_PUSH_PAGE_COUNT =		1024,
	IRDMA_MAX_PE_ENA_VF_COUNT =		32,
	IRDMA_MAX_VF_FPM_ID =			47,
	IRDMA_MAX_SQ_PAYLOAD_SIZE =		2145386496,
	IRDMA_MAX_INLINE_DATA_SIZE =		101,
	IRDMA_MAX_WQ_ENTRIES =			32768,
	IRDMA_Q2_BUF_SIZE =			256,
	IRDMA_QP_CTX_SIZE =			256,
	IRDMA_MAX_PDS =				262144,
	IRDMA_MIN_WQ_SIZE_GEN2 =                8,
};

enum irdma_addressing_type {
	IRDMA_ADDR_TYPE_ZERO_BASED = 0,
	IRDMA_ADDR_TYPE_VA_BASED   = 1,
};

struct irdma_ring {
	u32 head;
	u32 tail;
	u32 size;
};

struct irdma_cq_uk {
	struct irdma_cqe *cq_base;
	u32 __iomem *cqe_alloc_db;
	u32 __iomem *cq_ack_db;
	__le64 *shadow_area;
	u32 cq_id;
	u32 cq_size;
	struct irdma_ring cq_ring;
	u8 polarity;
	bool avoid_mem_cflct:1;
};

/* klp-ccp: from drivers/infiniband/hw/irdma/uda.h */
struct irdma_ah_info {
	struct irdma_sc_vsi *vsi;
	u32 pd_idx;
	u32 dst_arpindex;
	u32 dest_ip_addr[4];
	u32 src_ip_addr[4];
	u32 flow_label;
	u32 ah_idx;
	u16 vlan_tag;
	u8 insert_vlan_tag;
	u8 tc_tos;
	u8 hop_ttl;
	u8 mac_addr[ETH_ALEN];
	bool ah_valid:1;
	bool ipv4_valid:1;
	bool do_lpbk:1;
};

/* klp-ccp: from drivers/infiniband/hw/irdma/ws.h */
struct irdma_ws_node;

/* klp-ccp: from drivers/infiniband/hw/irdma/type.h */
enum irdma_hw_stats_index {
	/* gen1 - 32-bit */
	IRDMA_HW_STAT_INDEX_IP4RXDISCARD	= 0,
	IRDMA_HW_STAT_INDEX_IP4RXTRUNC		= 1,
	IRDMA_HW_STAT_INDEX_IP4TXNOROUTE	= 2,
	IRDMA_HW_STAT_INDEX_IP6RXDISCARD	= 3,
	IRDMA_HW_STAT_INDEX_IP6RXTRUNC		= 4,
	IRDMA_HW_STAT_INDEX_IP6TXNOROUTE	= 5,
	IRDMA_HW_STAT_INDEX_TCPRTXSEG		= 6,
	IRDMA_HW_STAT_INDEX_TCPRXOPTERR		= 7,
	IRDMA_HW_STAT_INDEX_TCPRXPROTOERR	= 8,
	IRDMA_HW_STAT_INDEX_RXVLANERR		= 9,
		/* gen1 - 64-bit */
	IRDMA_HW_STAT_INDEX_IP4RXOCTS		= 10,
	IRDMA_HW_STAT_INDEX_IP4RXPKTS		= 11,
	IRDMA_HW_STAT_INDEX_IP4RXFRAGS		= 12,
	IRDMA_HW_STAT_INDEX_IP4RXMCPKTS		= 13,
	IRDMA_HW_STAT_INDEX_IP4TXOCTS		= 14,
	IRDMA_HW_STAT_INDEX_IP4TXPKTS		= 15,
	IRDMA_HW_STAT_INDEX_IP4TXFRAGS		= 16,
	IRDMA_HW_STAT_INDEX_IP4TXMCPKTS		= 17,
	IRDMA_HW_STAT_INDEX_IP6RXOCTS		= 18,
	IRDMA_HW_STAT_INDEX_IP6RXPKTS		= 19,
	IRDMA_HW_STAT_INDEX_IP6RXFRAGS		= 20,
	IRDMA_HW_STAT_INDEX_IP6RXMCPKTS		= 21,
	IRDMA_HW_STAT_INDEX_IP6TXOCTS		= 22,
	IRDMA_HW_STAT_INDEX_IP6TXPKTS		= 23,
	IRDMA_HW_STAT_INDEX_IP6TXFRAGS		= 24,
	IRDMA_HW_STAT_INDEX_IP6TXMCPKTS		= 25,
	IRDMA_HW_STAT_INDEX_TCPRXSEGS		= 26,
	IRDMA_HW_STAT_INDEX_TCPTXSEG		= 27,
	IRDMA_HW_STAT_INDEX_RDMARXRDS		= 28,
	IRDMA_HW_STAT_INDEX_RDMARXSNDS		= 29,
	IRDMA_HW_STAT_INDEX_RDMARXWRS		= 30,
	IRDMA_HW_STAT_INDEX_RDMATXRDS		= 31,
	IRDMA_HW_STAT_INDEX_RDMATXSNDS		= 32,
	IRDMA_HW_STAT_INDEX_RDMATXWRS		= 33,
	IRDMA_HW_STAT_INDEX_RDMAVBND		= 34,
	IRDMA_HW_STAT_INDEX_RDMAVINV		= 35,
	IRDMA_HW_STAT_INDEX_IP4RXMCOCTS         = 36,
	IRDMA_HW_STAT_INDEX_IP4TXMCOCTS         = 37,
	IRDMA_HW_STAT_INDEX_IP6RXMCOCTS         = 38,
	IRDMA_HW_STAT_INDEX_IP6TXMCOCTS         = 39,
	IRDMA_HW_STAT_INDEX_UDPRXPKTS           = 40,
	IRDMA_HW_STAT_INDEX_UDPTXPKTS           = 41,
	IRDMA_HW_STAT_INDEX_MAX_GEN_1           = 42, /* Must be same value as next entry */
	/* gen2 - 64-bit */
	IRDMA_HW_STAT_INDEX_RXNPECNMARKEDPKTS   = 42,
	/* gen2 - 32-bit */
	IRDMA_HW_STAT_INDEX_RXRPCNPHANDLED      = 43,
	IRDMA_HW_STAT_INDEX_RXRPCNPIGNORED      = 44,
	IRDMA_HW_STAT_INDEX_TXNPCNPSENT         = 45,
	IRDMA_HW_STAT_INDEX_MAX_GEN_2		= 46,
};

enum irdma_feature_type {
	IRDMA_FEATURE_FW_INFO = 0,
	IRDMA_HW_VERSION_INFO = 1,
	IRDMA_QSETS_MAX       = 26,
	IRDMA_MAX_FEATURES, /* Must be last entry */
};

enum irdma_vm_vf_type {
	IRDMA_VF_TYPE = 0,
	IRDMA_VM_TYPE,
	IRDMA_PF_TYPE,
};

enum irdma_quad_entry_type {
	IRDMA_QHASH_TYPE_TCP_ESTABLISHED = 1,
	IRDMA_QHASH_TYPE_TCP_SYN,
	IRDMA_QHASH_TYPE_UDP_UNICAST,
	IRDMA_QHASH_TYPE_UDP_MCAST,
	IRDMA_QHASH_TYPE_ROCE_MCAST,
	IRDMA_QHASH_TYPE_ROCEV2_HW,
};

enum irdma_quad_hash_manage_type {
	IRDMA_QHASH_MANAGE_TYPE_DELETE = 0,
	IRDMA_QHASH_MANAGE_TYPE_ADD,
	IRDMA_QHASH_MANAGE_TYPE_MODIFY,
};

struct irdma_dcqcn_cc_params {
	u8 cc_cfg_valid;
	u8 min_dec_factor;
	u8 min_rate;
	u8 dcqcn_f;
	u16 rai_factor;
	u16 hai_factor;
	u16 dcqcn_t;
	u32 dcqcn_b;
	u32 rreduce_mperiod;
};

struct irdma_stats_gather_info {
	bool use_hmc_fcn_index:1;
	bool use_stats_inst:1;
	u8 hmc_fcn_index;
	u8 stats_inst_index;
	struct irdma_dma_mem stats_buff_mem;
	void *gather_stats_va;
	void *last_gather_stats_va;
};

struct irdma_hw {
	u8 __iomem *hw_addr;
	u8 __iomem *priv_hw_addr;
	struct device *device;
	struct irdma_hmc_info hmc;
};

struct irdma_sc_pd {
	struct irdma_sc_dev *dev;
	u32 pd_id;
	int abi_ver;
};

struct irdma_sc_cqp {
	u32 size;
	u64 sq_pa;
	u64 host_ctx_pa;
	void *back_cqp;
	struct irdma_sc_dev *dev;
	int (*process_cqp_sds)(struct irdma_sc_dev *dev,
			       struct irdma_update_sds_info *info);
	struct irdma_dma_mem sdbuf;
	struct irdma_ring sq_ring;
	struct irdma_cqp_quanta *sq_base;
	struct irdma_dcqcn_cc_params dcqcn_params;
	__le64 *host_ctx;
	u64 *scratch_array;
	u64 requested_ops;
	atomic64_t completed_ops;
	u32 cqp_id;
	u32 sq_size;
	u32 hw_sq_size;
	u16 hw_maj_ver;
	u16 hw_min_ver;
	u8 struct_ver;
	u8 polarity;
	u8 hmc_profile;
	u8 ena_vf_count;
	u8 timeout_count;
	u8 ceqs_per_vf;
	bool en_datacenter_tcp:1;
	bool disable_packed:1;
	bool rocev2_rto_policy:1;
	enum irdma_protocol_used protocol_used;
};

struct irdma_sc_aeq {
	u32 size;
	u64 aeq_elem_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_aeqe *aeqe_base;
	void *pbl_list;
	u32 elem_cnt;
	struct irdma_ring aeq_ring;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	u32 msix_idx;
	u8 polarity;
	bool virtual_map:1;
};

struct irdma_sc_cq {
	struct irdma_cq_uk cq_uk;
	u64 cq_pa;
	u64 shadow_area_pa;
	struct irdma_sc_dev *dev;
	struct irdma_sc_vsi *vsi;
	void *pbl_list;
	void *back_cq;
	u32 ceq_id;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u8 cq_type;
	u8 tph_val;
	u32 first_pm_pbl_idx;
	bool ceqe_mask:1;
	bool virtual_map:1;
	bool check_overflow:1;
	bool ceq_id_valid:1;
	bool tph_en;
};

struct irdma_stats_inst_info {
	bool use_hmc_fcn_index;
	u8 hmc_fn_id;
	u8 stats_idx;
};

struct irdma_up_info {
	u8 map[8];
	u8 cnp_up_override;
	u8 hmc_fcn_idx;
	bool use_vlan:1;
	bool use_cnp_up_override:1;
};

struct irdma_ws_node_info {
	u16 id;
	u16 vsi;
	u16 parent_id;
	u16 qs_handle;
	bool type_leaf:1;
	bool enable:1;
	u8 prio_type;
	u8 tc;
	u8 weight;
};

struct irdma_hmc_fpm_misc {
	u32 max_ceqs;
	u32 max_sds;
	u32 xf_block_size;
	u32 q1_block_size;
	u32 ht_multiplier;
	u32 timer_bucket;
	u32 rrf_block_size;
	u32 ooiscf_block_size;
};

struct irdma_qos {
	struct list_head qplist;
	struct mutex qos_mutex; /* protect QoS attributes per QoS level */
	u64 lan_qos_handle;
	u32 l2_sched_node_id;
	u16 qs_handle;
	u8 traffic_class;
	u8 rel_bw;
	u8 prio_type;
	bool valid;
};

struct irdma_sc_vsi {
	u16 vsi_idx;
	struct irdma_sc_dev *dev;
	void *back_vsi;
	u32 ilq_count;
	struct irdma_virt_mem ilq_mem;
	struct irdma_puda_rsrc *ilq;
	u32 ieq_count;
	struct irdma_virt_mem ieq_mem;
	struct irdma_puda_rsrc *ieq;
	u32 exception_lan_q;
	u16 mtu;
	u16 vm_id;
	enum irdma_vm_vf_type vm_vf_type;
	bool stats_inst_alloc:1;
	bool tc_change_pending:1;
	struct irdma_vsi_pestat *pestat;
	atomic_t qp_suspend_reqs;
	int (*register_qset)(struct irdma_sc_vsi *vsi,
			     struct irdma_ws_node *tc_node);
	void (*unregister_qset)(struct irdma_sc_vsi *vsi,
				struct irdma_ws_node *tc_node);
	u8 qos_rel_bw;
	u8 qos_prio_type;
	u8 stats_idx;
	u8 dscp_map[IIDC_MAX_DSCP_MAPPING];
	struct irdma_qos qos[IRDMA_MAX_USER_PRIORITY];
	u64 hw_stats_regs[IRDMA_HW_STAT_INDEX_MAX_GEN_1];
	bool dscp_mode:1;
};

struct irdma_sc_dev {
	struct list_head cqp_cmd_head; /* head of the CQP command list */
	spinlock_t cqp_lock; /* protect CQP list access */
	bool stats_idx_array[IRDMA_MAX_STATS_COUNT_GEN_1];
	struct irdma_dma_mem vf_fpm_query_buf[IRDMA_MAX_PE_ENA_VF_COUNT];
	u64 fpm_query_buf_pa;
	u64 fpm_commit_buf_pa;
	__le64 *fpm_query_buf;
	__le64 *fpm_commit_buf;
	struct irdma_hw *hw;
	u8 __iomem *db_addr;
	u32 __iomem *wqe_alloc_db;
	u32 __iomem *cq_arm_db;
	u32 __iomem *aeq_alloc_db;
	u32 __iomem *cqp_db;
	u32 __iomem *cq_ack_db;
	u32 __iomem *ceq_itr_mask_db;
	u32 __iomem *aeq_itr_mask_db;
	u32 __iomem *hw_regs[IRDMA_MAX_REGS];
	u32 ceq_itr;   /* Interrupt throttle, usecs between interrupts: 0 disabled. 2 - 8160 */
	u64 hw_masks[IRDMA_MAX_MASKS];
	u64 hw_shifts[IRDMA_MAX_SHIFTS];
	const struct irdma_hw_stat_map *hw_stats_map;
	u64 hw_stats_regs[IRDMA_HW_STAT_INDEX_MAX_GEN_1];
	u64 feature_info[IRDMA_MAX_FEATURES];
	u64 cqp_cmd_stats[IRDMA_MAX_CQP_OPS];
	struct irdma_hw_attrs hw_attrs;
	struct irdma_hmc_info *hmc_info;
	struct irdma_sc_cqp *cqp;
	struct irdma_sc_aeq *aeq;
	struct irdma_sc_ceq *ceq[IRDMA_CEQ_MAX_COUNT];
	struct irdma_sc_cq *ccq;
	const struct irdma_irq_ops *irq_ops;
	struct irdma_hmc_fpm_misc hmc_fpm_misc;
	struct irdma_ws_node *ws_tree_root;
	struct mutex ws_mutex; /* ws tree mutex */
	u16 num_vfs;
	u8 hmc_fn_id;
	u8 vf_id;
	bool vchnl_up:1;
	bool ceq_valid:1;
	u8 pci_rev;
	int (*ws_add)(struct irdma_sc_vsi *vsi, u8 user_pri);
	void (*ws_remove)(struct irdma_sc_vsi *vsi, u8 user_pri);
	void (*ws_reset)(struct irdma_sc_vsi *vsi);
};

struct irdma_modify_cq_info {
	u64 cq_pa;
	struct irdma_cqe *cq_base;
	u32 cq_size;
	u32 shadow_read_threshold;
	u8 pbl_chunk_size;
	u32 first_pm_pbl_idx;
	bool virtual_map:1;
	bool check_overflow;
	bool cq_resize:1;
};

struct irdma_create_qp_info {
	bool ord_valid:1;
	bool tcp_ctx_valid:1;
	bool cq_num_valid:1;
	bool arp_cache_idx_valid:1;
	bool mac_valid:1;
	bool force_lpb;
	u8 next_iwarp_state;
};

struct irdma_modify_qp_info {
	u64 rx_win0;
	u64 rx_win1;
	u16 new_mss;
	u8 next_iwarp_state;
	u8 curr_iwarp_state;
	u8 termlen;
	bool ord_valid:1;
	bool tcp_ctx_valid:1;
	bool udp_ctx_valid:1;
	bool cq_num_valid:1;
	bool arp_cache_idx_valid:1;
	bool reset_tcp_conn:1;
	bool remove_hash_idx:1;
	bool dont_send_term:1;
	bool dont_send_fin:1;
	bool cached_var_valid:1;
	bool mss_change:1;
	bool force_lpb:1;
	bool mac_valid:1;
};

struct irdma_allocate_stag_info {
	u64 total_len;
	u64 first_pm_pbl_idx;
	u32 chunk_size;
	u32 stag_idx;
	u32 page_size;
	u32 pd_id;
	u16 access_rights;
	bool remote_access:1;
	bool use_hmc_fcn_index:1;
	bool use_pf_rid:1;
	bool all_memory:1;
	u8 hmc_fcn_index;
};

struct irdma_mw_alloc_info {
	u32 mw_stag_index;
	u32 page_size;
	u32 pd_id;
	bool remote_access:1;
	bool mw_wide:1;
	bool mw1_bind_dont_vldt_key:1;
};

struct irdma_reg_ns_stag_info {
	u64 reg_addr_pa;
	u64 va;
	u64 total_len;
	u32 page_size;
	u32 chunk_size;
	u32 first_pm_pbl_index;
	enum irdma_addressing_type addr_type;
	irdma_stag_index stag_idx;
	u16 access_rights;
	u32 pd_id;
	irdma_stag_key stag_key;
	bool use_hmc_fcn_index:1;
	u8 hmc_fcn_index;
	bool use_pf_rid:1;
	bool all_memory:1;
};

struct irdma_dealloc_stag_info {
	u32 stag_idx;
	u32 pd_id;
	bool mr:1;
	bool dealloc_pbl:1;
};

struct irdma_upload_context_info {
	u64 buf_pa;
	u32 qp_id;
	u8 qp_type;
	bool freeze_qp:1;
	bool raw_format:1;
};

struct irdma_local_mac_entry_info {
	u8 mac_addr[6];
	u16 entry_idx;
};

struct irdma_add_arp_cache_entry_info {
	u8 mac_addr[ETH_ALEN];
	u32 reach_max;
	u16 arp_index;
	bool permanent;
};

struct irdma_apbvt_info {
	u16 port;
	bool add;
};

struct irdma_qhash_table_info {
	struct irdma_sc_vsi *vsi;
	enum irdma_quad_hash_manage_type manage;
	enum irdma_quad_entry_type entry_type;
	bool vlan_valid:1;
	bool ipv4_valid:1;
	u8 mac_addr[ETH_ALEN];
	u16 vlan_id;
	u8 user_pri;
	u32 qp_num;
	u32 dest_ip[4];
	u32 src_ip[4];
	u16 dest_port;
	u16 src_port;
};

struct irdma_cqp_manage_push_page_info {
	u32 push_idx;
	u16 qs_handle;
	u8 free_page;
	u8 push_page_type;
};

struct irdma_qp_flush_info {
	u16 sq_minor_code;
	u16 sq_major_code;
	u16 rq_minor_code;
	u16 rq_major_code;
	u16 ae_code;
	u8 ae_src;
	bool sq:1;
	bool rq:1;
	bool userflushcode:1;
	bool generate_ae:1;
};

struct irdma_gen_ae_info {
	u16 ae_code;
	u8 ae_src;
};

struct cqp_info {
	union {
		struct {
			struct irdma_sc_qp *qp;
			struct irdma_create_qp_info info;
			u64 scratch;
		} qp_create;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_modify_qp_info info;
			u64 scratch;
		} qp_modify;

		struct {
			struct irdma_sc_qp *qp;
			u64 scratch;
			bool remove_hash_idx;
			bool ignore_mw_bnd;
		} qp_destroy;

		struct {
			struct irdma_sc_cq *cq;
			u64 scratch;
			bool check_overflow;
		} cq_create;

		struct {
			struct irdma_sc_cq *cq;
			struct irdma_modify_cq_info info;
			u64 scratch;
		} cq_modify;

		struct {
			struct irdma_sc_cq *cq;
			u64 scratch;
		} cq_destroy;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_allocate_stag_info info;
			u64 scratch;
		} alloc_stag;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_mw_alloc_info info;
			u64 scratch;
		} mw_alloc;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_reg_ns_stag_info info;
			u64 scratch;
		} mr_reg_non_shared;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_dealloc_stag_info info;
			u64 scratch;
		} dealloc_stag;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_add_arp_cache_entry_info info;
			u64 scratch;
		} add_arp_cache_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
			u16 arp_index;
		} del_arp_cache_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_local_mac_entry_info info;
			u64 scratch;
		} add_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
			u8 entry_idx;
			u8 ignore_ref_count;
		} del_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			u64 scratch;
		} alloc_local_mac_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_cqp_manage_push_page_info info;
			u64 scratch;
		} manage_push_page;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_upload_context_info info;
			u64 scratch;
		} qp_upload_context;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_hmc_fcn_info info;
			u64 scratch;
		} manage_hmc_pm;

		struct {
			struct irdma_sc_ceq *ceq;
			u64 scratch;
		} ceq_create;

		struct {
			struct irdma_sc_ceq *ceq;
			u64 scratch;
		} ceq_destroy;

		struct {
			struct irdma_sc_aeq *aeq;
			u64 scratch;
		} aeq_create;

		struct {
			struct irdma_sc_aeq *aeq;
			u64 scratch;
		} aeq_destroy;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_qp_flush_info info;
			u64 scratch;
		} qp_flush_wqes;

		struct {
			struct irdma_sc_qp *qp;
			struct irdma_gen_ae_info info;
			u64 scratch;
		} gen_ae;

		struct {
			struct irdma_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u8 hmc_fn_id;
			u64 scratch;
		} query_fpm_val;

		struct {
			struct irdma_sc_cqp *cqp;
			void *fpm_val_va;
			u64 fpm_val_pa;
			u8 hmc_fn_id;
			u64 scratch;
		} commit_fpm_val;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_apbvt_info info;
			u64 scratch;
		} manage_apbvt_entry;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_qhash_table_info info;
			u64 scratch;
		} manage_qhash_table_entry;

		struct {
			struct irdma_sc_dev *dev;
			struct irdma_update_sds_info info;
			u64 scratch;
		} update_pe_sds;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_sc_qp *qp;
			u64 scratch;
		} suspend_resume;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_create;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ah_info info;
			u64 scratch;
		} ah_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_create;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_destroy;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_mcast_grp_info info;
			u64 scratch;
		} mc_modify;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_stats_inst_info info;
			u64 scratch;
		} stats_manage;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_stats_gather_info info;
			u64 scratch;
		} stats_gather;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_ws_node_info info;
			u64 scratch;
		} ws_node;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_up_info info;
			u64 scratch;
		} up_map;

		struct {
			struct irdma_sc_cqp *cqp;
			struct irdma_dma_mem query_buff_mem;
			u64 scratch;
		} query_rdma;
	} u;
};

struct cqp_cmds_info {
	struct list_head cqp_cmd_entry;
	u8 cqp_cmd;
	u8 post_sq;
	struct cqp_info in;
};

/* klp-ccp: from drivers/infiniband/hw/irdma/pble.h */
enum irdma_pble_level {
	PBLE_LEVEL_0 = 0,
	PBLE_LEVEL_1 = 1,
	PBLE_LEVEL_2 = 2,
};

struct irdma_pble_chunkinfo {
	struct irdma_chunk *pchunk;
	u64 bit_idx;
	u64 bits_used;
};

struct irdma_pble_info {
	u64 *addr;
	u32 idx;
	u32 cnt;
	struct irdma_pble_chunkinfo chunkinfo;
};

struct irdma_pble_level2 {
	struct irdma_pble_info root;
	struct irdma_pble_info *leaf;
	struct irdma_virt_mem leafmem;
	u32 leaf_cnt;
};

struct irdma_pble_alloc {
	u32 total_cnt;
	enum irdma_pble_level level;
	union {
		struct irdma_pble_info level1;
		struct irdma_pble_level2 level2;
	};
};

struct irdma_hmc_pble_rsrc;

void irdma_free_pble(struct irdma_hmc_pble_rsrc *pble_rsrc,
		     struct irdma_pble_alloc *palloc);

/* klp-ccp: from drivers/infiniband/hw/irdma/cm.h */
struct irdma_kmem_info;

struct irdma_mpa_priv_info;

struct irdma_cm_node;

struct irdma_cm_core {
	struct irdma_device *iwdev;
	struct irdma_sc_dev *dev;
	struct list_head listen_list;
	DECLARE_HASHTABLE(cm_hash_tbl, 8);
	DECLARE_HASHTABLE(apbvt_hash_tbl, 8);
	struct timer_list tcp_timer;
	struct workqueue_struct *event_wq;
	spinlock_t ht_lock; /* protect CM node (active side) list */
	spinlock_t listen_list_lock; /* protect listener list */
	spinlock_t apbvt_lock; /*serialize apbvt add/del entries*/
	u64 stats_nodes_created;
	u64 stats_nodes_destroyed;
	u64 stats_listen_created;
	u64 stats_listen_destroyed;
	u64 stats_listen_nodes_created;
	u64 stats_listen_nodes_destroyed;
	u64 stats_lpbs;
	u64 stats_accepts;
	u64 stats_rejects;
	u64 stats_connect_errs;
	u64 stats_passive_errs;
	u64 stats_pkt_retrans;
	u64 stats_backlog_drops;
	struct irdma_puda_buf *(*form_cm_frame)(struct irdma_cm_node *cm_node,
						struct irdma_kmem_info *options,
						struct irdma_kmem_info *hdr,
						struct irdma_mpa_priv_info *pdata,
						u8 flags);
	int (*cm_create_ah)(struct irdma_cm_node *cm_node, bool wait);
	void (*cm_free_ah)(struct irdma_cm_node *cm_node);
};

/* klp-ccp: from drivers/infiniband/hw/irdma/main.h */
#include <rdma/irdma-abi.h>

/* klp-ccp: from drivers/infiniband/hw/irdma/verbs.h */
#define IRDMA_MAX_SAVED_PHY_PGADDR	4

struct irdma_pd {
	struct ib_pd ibpd;
	struct irdma_sc_pd sc_pd;
};

struct irdma_hmc_pble {
	union {
		u32 idx;
		dma_addr_t addr;
	};
};

struct irdma_cq_mr {
	struct irdma_hmc_pble cq_pbl;
	dma_addr_t shadow;
	bool split;
};

struct irdma_qp_mr {
	struct irdma_hmc_pble sq_pbl;
	struct irdma_hmc_pble rq_pbl;
	dma_addr_t shadow;
	struct page *sq_page;
};

struct irdma_pbl {
	struct list_head list;
	union {
		struct irdma_qp_mr qp_mr;
		struct irdma_cq_mr cq_mr;
	};

	bool pbl_allocated:1;
	bool on_list:1;
	u64 user_base;
	struct irdma_pble_alloc pble_alloc;
	struct irdma_mr *iwmr;
};

struct irdma_mr {
	union {
		struct ib_mr ibmr;
		struct ib_mw ibmw;
	};
	struct ib_umem *region;
	int access;
	u8 is_hwreg;
	u16 type;
	u32 page_cnt;
	u64 page_size;
	u32 npages;
	u32 stag;
	u64 len;
	u64 pgaddrmem[IRDMA_MAX_SAVED_PHY_PGADDR];
	struct irdma_pbl iwpbl;
};

/* klp-ccp: from drivers/infiniband/hw/irdma/main.h */
enum init_completion_state {
	INVALID_STATE = 0,
	INITIAL_STATE,
	CQP_CREATED,
	HMC_OBJS_CREATED,
	HW_RSRC_INITIALIZED,
	CCQ_CREATED,
	CEQ0_CREATED, /* Last state of probe */
	ILQ_CREATED,
	IEQ_CREATED,
	CEQS_CREATED,
	PBLE_CHUNK_MEM,
	AEQ_CREATED,
	IP_ADDR_REGISTERED,  /* Last state of open */
};

struct irdma_cqp_compl_info {
	u32 op_ret_val;
	u16 maj_err_code;
	u16 min_err_code;
	bool error;
	u8 op_code;
};

struct irdma_cqp_request {
	struct cqp_cmds_info info;
	wait_queue_head_t waitq;
	struct list_head list;
	refcount_t refcnt;
	void (*callback_fcn)(struct irdma_cqp_request *cqp_request);
	void *param;
	struct irdma_cqp_compl_info compl_info;
	bool request_done; /* READ/WRITE_ONCE macros operate on it */
	bool waiting:1;
	bool dynamic:1;
};

struct irdma_cqp {
	struct irdma_sc_cqp sc_cqp;
	spinlock_t req_lock; /* protect CQP request list */
	spinlock_t compl_lock; /* protect CQP completion processing */
	wait_queue_head_t waitq;
	wait_queue_head_t remove_wq;
	struct irdma_dma_mem sq;
	struct irdma_dma_mem host_ctx;
	u64 *scratch_array;
	struct irdma_cqp_request *cqp_requests;
	struct list_head cqp_avail_reqs;
	struct list_head cqp_pending_reqs;
};

struct irdma_ccq {
	struct irdma_sc_cq sc_cq;
	struct irdma_dma_mem mem_cq;
	struct irdma_dma_mem shadow_area;
};

struct irdma_aeq {
	struct irdma_sc_aeq sc_aeq;
	struct irdma_dma_mem mem;
	struct irdma_pble_alloc palloc;
	bool virtual_map;
};

struct irdma_mc_table_info {
	u32 mgn;
	u32 dest_ip[4];
	bool lan_fwd:1;
	bool ipv4_valid:1;
};

struct mc_table_list {
	struct list_head list;
	struct irdma_mc_table_info mc_info;
	struct irdma_mcast_grp_info mc_grp_ctx;
};

struct irdma_gen_ops {
	void (*request_reset)(struct irdma_pci_f *rf);
	int (*register_qset)(struct irdma_sc_vsi *vsi,
			     struct irdma_ws_node *tc_node);
	void (*unregister_qset)(struct irdma_sc_vsi *vsi,
				struct irdma_ws_node *tc_node);
};

struct irdma_pci_f {
	bool reset:1;
	bool rsrc_created:1;
	bool msix_shared:1;
	u8 rsrc_profile;
	u8 *hmc_info_mem;
	u8 *mem_rsrc;
	u8 rdma_ver;
	u8 rst_to;
	u8 pf_id;
	enum irdma_protocol_used protocol_used;
	u32 sd_type;
	u32 msix_count;
	u32 max_mr;
	u32 max_qp;
	u32 max_cq;
	u32 max_ah;
	u32 next_ah;
	u32 max_mcg;
	u32 next_mcg;
	u32 max_pd;
	u32 next_qp;
	u32 next_cq;
	u32 next_pd;
	u32 max_mr_size;
	u32 max_cqe;
	u32 mr_stagmask;
	u32 used_pds;
	u32 used_cqs;
	u32 used_mrs;
	u32 used_qps;
	u32 arp_table_size;
	u32 next_arp_index;
	u32 ceqs_count;
	u32 next_ws_node_id;
	u32 max_ws_node_id;
	u32 limits_sel;
	unsigned long *allocated_ws_nodes;
	unsigned long *allocated_qps;
	unsigned long *allocated_cqs;
	unsigned long *allocated_mrs;
	unsigned long *allocated_pds;
	unsigned long *allocated_mcgs;
	unsigned long *allocated_ahs;
	unsigned long *allocated_arps;
	enum init_completion_state init_state;
	struct irdma_sc_dev sc_dev;
	struct pci_dev *pcidev;
	void *cdev;
	struct irdma_hw hw;
	struct irdma_cqp cqp;
	struct irdma_ccq ccq;
	struct irdma_aeq aeq;
	struct irdma_ceq *ceqlist;
	struct irdma_hmc_pble_rsrc *pble_rsrc;
	struct irdma_arp_entry *arp_table;
	spinlock_t arp_lock; /*protect ARP table access*/
	spinlock_t rsrc_lock; /* protect HW resource array access */
	spinlock_t qptable_lock; /*protect QP table access*/
	spinlock_t cqtable_lock; /*protect CQ table access*/
	struct irdma_qp **qp_table;
	struct irdma_cq **cq_table;
	spinlock_t qh_list_lock; /* protect mc_qht_list */
	struct mc_table_list mc_qht_list;
	struct irdma_msix_vector *iw_msixtbl;
	struct irdma_qvlist_info *iw_qvlist;
	struct tasklet_struct dpc_tasklet;
	struct msix_entry *msix_entries;
	struct irdma_dma_mem obj_mem;
	struct irdma_dma_mem obj_next;
	atomic_t vchnl_msgs;
	wait_queue_head_t vchnl_waitq;
	struct workqueue_struct *cqp_cmpl_wq;
	struct work_struct cqp_cmpl_work;
	struct irdma_sc_vsi default_vsi;
	void *back_fcn;
	struct irdma_gen_ops gen_ops;
	struct irdma_device *iwdev;
};

struct irdma_device {
	struct ib_device ibdev;
	struct irdma_pci_f *rf;
	struct net_device *netdev;
	struct workqueue_struct *cleanup_wq;
	struct irdma_sc_vsi vsi;
	struct irdma_cm_core cm_core;
	DECLARE_HASHTABLE(ah_hash_tbl, 8);
	struct mutex ah_tbl_lock; /* protect AH hash table access */
	u32 roce_cwnd;
	u32 roce_ackcreds;
	u32 vendor_id;
	u32 vendor_part_id;
	u32 push_mode;
	u32 rcv_wnd;
	u16 mac_ip_table_idx;
	u16 vsi_num;
	u8 rcv_wscale;
	u8 iw_status;
	bool roce_mode:1;
	bool roce_dcqcn_en:1;
	bool dcb_vlan_mode:1;
	bool iw_ooo:1;
	enum init_completion_state init_state;

	wait_queue_head_t suspend_wq;
};

static inline struct irdma_device *to_iwdev(struct ib_device *ibdev)
{
	return container_of(ibdev, struct irdma_device, ibdev);
}

static inline struct irdma_pd *to_iwpd(struct ib_pd *ibpd)
{
	return container_of(ibpd, struct irdma_pd, ibpd);
}

static inline struct irdma_mr *to_iwmr(struct ib_mr *ibmr)
{
	return container_of(ibmr, struct irdma_mr, ibmr);
}

struct irdma_cqp_request *irdma_alloc_and_get_cqp_request(struct irdma_cqp *cqp,
							  bool wait);

void irdma_put_cqp_request(struct irdma_cqp *cqp,
			   struct irdma_cqp_request *cqp_request);

int irdma_handle_cqp_op(struct irdma_pci_f *rf,
			struct irdma_cqp_request *cqp_request);

/* klp-ccp: from drivers/infiniband/hw/irdma/verbs.c */
static inline u16 irdma_get_mr_access(int access)
{
	u16 hw_access = 0;

	hw_access |= (access & IB_ACCESS_LOCAL_WRITE) ?
		     IRDMA_ACCESS_FLAGS_LOCALWRITE : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_WRITE) ?
		     IRDMA_ACCESS_FLAGS_REMOTEWRITE : 0;
	hw_access |= (access & IB_ACCESS_REMOTE_READ) ?
		     IRDMA_ACCESS_FLAGS_REMOTEREAD : 0;
	hw_access |= (access & IB_ACCESS_MW_BIND) ?
		     IRDMA_ACCESS_FLAGS_BIND_WINDOW : 0;
	hw_access |= (access & IB_ZERO_BASED) ?
		     IRDMA_ACCESS_FLAGS_ZERO_BASED : 0;
	hw_access |= IRDMA_ACCESS_FLAGS_LOCALREAD;

	return hw_access;
}

static int irdma_hwreg_mr(struct irdma_device *iwdev, struct irdma_mr *iwmr,
			  u16 access)
{
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct irdma_reg_ns_stag_info *stag_info;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct irdma_pd *iwpd = to_iwpd(pd);
	struct irdma_pble_alloc *palloc = &iwpbl->pble_alloc;
	struct irdma_cqp_request *cqp_request;
	struct cqp_cmds_info *cqp_info;
	int ret;

	cqp_request = irdma_alloc_and_get_cqp_request(&iwdev->rf->cqp, true);
	if (!cqp_request)
		return -ENOMEM;

	cqp_info = &cqp_request->info;
	stag_info = &cqp_info->in.u.mr_reg_non_shared.info;
	memset(stag_info, 0, sizeof(*stag_info));
	stag_info->va = iwpbl->user_base;
	stag_info->stag_idx = iwmr->stag >> IRDMA_CQPSQ_STAG_IDX_S;
	stag_info->stag_key = (u8)iwmr->stag;
	stag_info->total_len = iwmr->len;
	stag_info->access_rights = irdma_get_mr_access(access);
	stag_info->pd_id = iwpd->sc_pd.pd_id;
	stag_info->all_memory = pd->flags & IB_PD_UNSAFE_GLOBAL_RKEY;
	if (stag_info->access_rights & IRDMA_ACCESS_FLAGS_ZERO_BASED)
		stag_info->addr_type = IRDMA_ADDR_TYPE_ZERO_BASED;
	else
		stag_info->addr_type = IRDMA_ADDR_TYPE_VA_BASED;
	stag_info->page_size = iwmr->page_size;

	if (iwpbl->pbl_allocated) {
		if (palloc->level == PBLE_LEVEL_1) {
			stag_info->first_pm_pbl_index = palloc->level1.idx;
			stag_info->chunk_size = 1;
		} else {
			stag_info->first_pm_pbl_index = palloc->level2.root.idx;
			stag_info->chunk_size = 3;
		}
	} else {
		stag_info->reg_addr_pa = iwmr->pgaddrmem[0];
	}

	cqp_info->cqp_cmd = IRDMA_OP_MR_REG_NON_SHARED;
	cqp_info->post_sq = 1;
	cqp_info->in.u.mr_reg_non_shared.dev = &iwdev->rf->sc_dev;
	cqp_info->in.u.mr_reg_non_shared.scratch = (uintptr_t)cqp_request;
	ret = irdma_handle_cqp_op(iwdev->rf, cqp_request);
	irdma_put_cqp_request(&iwdev->rf->cqp, cqp_request);

	if (!ret)
		iwmr->is_hwreg = 1;

	return ret;
}

extern int irdma_reg_user_mr_type_mem(struct irdma_mr *iwmr, int access,
				      bool create_stag);

extern int irdma_hwdereg_mr(struct ib_mr *ib_mr);

static int klpp_irdma_rereg_mr_trans(struct irdma_mr *iwmr, u64 start, u64 len,
				u64 virt)
{
	struct irdma_device *iwdev = to_iwdev(iwmr->ibmr.device);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	struct ib_pd *pd = iwmr->ibmr.pd;
	struct ib_umem *region;
	int err;

	region = ib_umem_get(pd->device, start, len, iwmr->access);
	if (IS_ERR(region))
		return PTR_ERR(region);

	iwmr->region = region;
	iwmr->ibmr.iova = virt;
	iwmr->ibmr.pd = pd;
	iwmr->page_size = ib_umem_find_best_pgsz(region,
				iwdev->rf->sc_dev.hw_attrs.page_size_cap,
				virt);
	if (unlikely(!iwmr->page_size)) {
		err = -EOPNOTSUPP;
		goto err;
	}

	iwmr->len = region->length;
	iwpbl->user_base = virt;
	iwmr->page_cnt = ib_umem_num_dma_blocks(region, iwmr->page_size);

	err = irdma_reg_user_mr_type_mem(iwmr, iwmr->access, false);
	if (err)
		goto err;

	return 0;

err:
	ib_umem_release(region);
	iwmr->region = NULL;
	return err;
}

struct ib_mr *klpp_irdma_rereg_user_mr(struct ib_mr *ib_mr, int flags,
					 u64 start, u64 len, u64 virt,
					 int new_access, struct ib_pd *new_pd,
					 struct ib_udata *udata)
{
	struct irdma_device *iwdev = to_iwdev(ib_mr->device);
	struct irdma_mr *iwmr = to_iwmr(ib_mr);
	struct irdma_pbl *iwpbl = &iwmr->iwpbl;
	int ret;

	if (len > iwdev->rf->sc_dev.hw_attrs.max_mr_size)
		return ERR_PTR(-EINVAL);

	if (flags & ~(IB_MR_REREG_TRANS | IB_MR_REREG_PD | IB_MR_REREG_ACCESS))
		return ERR_PTR(-EOPNOTSUPP);

	ret = irdma_hwdereg_mr(ib_mr);
	if (ret)
		return ERR_PTR(ret);

	if (flags & IB_MR_REREG_ACCESS)
		iwmr->access = new_access;

	if (flags & IB_MR_REREG_PD) {
		iwmr->ibmr.pd = new_pd;
		iwmr->ibmr.device = new_pd->device;
	}

	if (flags & IB_MR_REREG_TRANS) {
		if (iwpbl->pbl_allocated) {
			irdma_free_pble(iwdev->rf->pble_rsrc,
					&iwpbl->pble_alloc);
			iwpbl->pbl_allocated = false;
		}
		if (iwmr->region) {
			ib_umem_release(iwmr->region);
			iwmr->region = NULL;
		}

		ret = klpp_irdma_rereg_mr_trans(iwmr, start, len, virt);
	} else
		ret = irdma_hwreg_mr(iwdev, iwmr, iwmr->access);
	if (ret)
		return ERR_PTR(ret);

	return NULL;
}


#include <linux/livepatch.h>

extern typeof(ib_umem_find_best_pgsz) ib_umem_find_best_pgsz
	 KLP_RELOC_SYMBOL(irdma, ib_uverbs, ib_umem_find_best_pgsz);
extern typeof(ib_umem_get) ib_umem_get
	 KLP_RELOC_SYMBOL(irdma, ib_uverbs, ib_umem_get);
extern typeof(ib_umem_release) ib_umem_release
	 KLP_RELOC_SYMBOL(irdma, ib_uverbs, ib_umem_release);
extern typeof(irdma_alloc_and_get_cqp_request) irdma_alloc_and_get_cqp_request
	 KLP_RELOC_SYMBOL(irdma, irdma, irdma_alloc_and_get_cqp_request);
extern typeof(irdma_free_pble) irdma_free_pble
	 KLP_RELOC_SYMBOL(irdma, irdma, irdma_free_pble);
extern typeof(irdma_handle_cqp_op) irdma_handle_cqp_op
	 KLP_RELOC_SYMBOL(irdma, irdma, irdma_handle_cqp_op);
extern typeof(irdma_hwdereg_mr) irdma_hwdereg_mr
	 KLP_RELOC_SYMBOL(irdma, irdma, irdma_hwdereg_mr);
extern typeof(irdma_put_cqp_request) irdma_put_cqp_request
	 KLP_RELOC_SYMBOL(irdma, irdma, irdma_put_cqp_request);
extern typeof(irdma_reg_user_mr_type_mem) irdma_reg_user_mr_type_mem
	 KLP_RELOC_SYMBOL(irdma, irdma, irdma_reg_user_mr_type_mem);

#endif /* IS_ENABLED(CONFIG_INFINIBAND_IRDMA) */
