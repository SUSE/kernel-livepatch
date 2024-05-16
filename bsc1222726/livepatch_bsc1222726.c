/*
 * livepatch_bsc1222726
 *
 * Fix for CVE-2024-26766, bsc#1222726
 *
 *  Upstream commit:
 *  e6f57c688191 ("IB/hfi1: Fix sdma.h tx->num_descs off-by-one error")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  dc4bba01c38b3eb6cc6eecdf1a76f0022a0a0a17
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

#if IS_ENABLED(CONFIG_INFINIBAND_HFI1)

#if !IS_MODULE(CONFIG_INFINIBAND_HFI1)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/infiniband/hw/hfi1/sdma.c */
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/netdevice.h>
#include <linux/moduleparam.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>

/* klp-ccp: from include/linux/highmem.h */
#define _LINUX_HIGHMEM_H

/* klp-ccp: from include/asm-generic/cacheflush.h */
#define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 0

/* klp-ccp: from drivers/infiniband/hw/hfi1/hfi.h */
#include <linux/refcount.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/completion.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/i2c.h>
#include <linux/xarray.h>
#include <rdma/ib_hdrs.h>

/* klp-ccp: from include/rdma/opa_smi.h */
#define OPA_SMI_H

/* klp-ccp: from include/rdma/ib_mad.h */
#define IB_MAD_H

/* klp-ccp: from drivers/infiniband/hw/hfi1/hfi.h */
#include <rdma/rdma_vt.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/chip_registers.h */
#define CCE_NUM_INT_CSRS 12

#define CCE_NUM_MSIX_VECTORS 256

/* klp-ccp: from drivers/infiniband/hw/hfi1/opfn.h */
#include <linux/workqueue.h>
#include <rdma/ib_verbs.h>

/* klp-ccp: from include/rdma/rdmavt_qp.h */
#define DEF_RDMAVT_INCQP_H

/* klp-ccp: from include/rdma/rdmavt_cq.h */
#define DEF_RDMAVT_INCCQ_H

/* klp-ccp: from drivers/infiniband/hw/hfi1/verbs.h */
#include <linux/types.h>
#include <linux/seqlock.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/kref.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_hdrs.h>
#include <rdma/rdma_vt.h>
#include <rdma/rdmavt_qp.h>
#include <rdma/rdmavt_cq.h>
/* klp-ccp: from drivers/infiniband/hw/hfi1/iowait.h */
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/sched.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/sdma_txreq.h */
#define NUM_DESC 6

struct sdma_desc {
	/* private:  don't use directly */
	u64 qw[2];
	void *pinning_ctx;
};

#define SDMA_TXREQ_F_URGENT       0x0001

struct sdma_txreq;
typedef void (*callback_t)(struct sdma_txreq *, int);

struct sdma_txreq {
	struct list_head list;
	/* private: */
	struct sdma_desc *descp;
	/* private: */
	void *coalesce_buf;
	/* private: */
	struct iowait *wait;
	/* private: */
	callback_t                  complete;
#ifdef CONFIG_HFI1_DEBUG_SDMA_ORDER
#error "klp-ccp: non-taken branch"
#endif
	u16                         packet_len;
	/* private: - down-counted to trigger last */
	u16                         tlen;
	/* private: */
	u16                         num_desc;
	/* private: */
	u16                         desc_limit;
	/* private: */
	u16                         next_descq_idx;
	/* private: */
	u16 coalesce_idx;
	/* private: flags */
	u16                         flags;
	/* private: */
	struct sdma_desc descs[NUM_DESC];
};

/* klp-ccp: from drivers/infiniband/hw/hfi1/tid_rdma.h */
struct hfi1_pkt_state;

/* klp-ccp: from drivers/infiniband/hw/hfi1/verbs.h */
struct hfi1_ibdev {
	struct rvt_dev_info rdi; /* Must be first */

	/* QP numbers are shared by all IB ports */
	/* protect txwait list */
	seqlock_t txwait_lock ____cacheline_aligned_in_smp;
	struct list_head txwait;        /* list for wait verbs_txreq */
	struct list_head memwait;       /* list for wait kernel memory */
	struct kmem_cache *verbs_txreq_cache;
	u64 n_txwait;
	u64 n_kmem_wait;
	u64 n_tidwait;

	/* protect iowait lists */
	seqlock_t iowait_lock ____cacheline_aligned_in_smp;
	u64 n_piowait;
	u64 n_piodrain;
	struct timer_list mem_timer;

#ifdef CONFIG_DEBUG_FS
	struct dentry *hfi1_ibdev_dbg;
	/* per HFI symlinks to above */
	struct dentry *hfi1_ibdev_link;
#ifdef CONFIG_FAULT_INJECTION
	struct fault *fault;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

/* klp-ccp: from drivers/infiniband/hw/hfi1/pio.h */
#define SC_MAX    4	/* count of send context types */

struct pio_buf;

struct sc_config_sizes {
	short int size;
	short int count;
};

/* klp-ccp: from drivers/infiniband/hw/hfi1/mad.h */
#include <rdma/opa_smi.h>

/* klp-ccp: from drivers/infiniband/hw/hfi1/platform.h */
enum platform_config_table_type_encoding {
	PLATFORM_CONFIG_TABLE_RESERVED,
	PLATFORM_CONFIG_SYSTEM_TABLE,
	PLATFORM_CONFIG_PORT_TABLE,
	PLATFORM_CONFIG_RX_PRESET_TABLE,
	PLATFORM_CONFIG_TX_PRESET_TABLE,
	PLATFORM_CONFIG_QSFP_ATTEN_TABLE,
	PLATFORM_CONFIG_VARIABLE_SETTINGS_TABLE,
	PLATFORM_CONFIG_TABLE_MAX
};

struct platform_config {
	size_t size;
	const u8 *data;
};

struct platform_config_data {
	u32 *table;
	u32 *table_metadata;
	u32 num_table;
};

struct platform_config_cache {
	u8  cache_valid;
	struct platform_config_data config_tables[PLATFORM_CONFIG_TABLE_MAX];
};

/* klp-ccp: from drivers/infiniband/hw/hfi1/hfi.h */
#define NUM_CCE_ERR_STATUS_COUNTERS 41
#define NUM_RCV_ERR_STATUS_COUNTERS 64
#define NUM_MISC_ERR_STATUS_COUNTERS 13
#define NUM_SEND_PIO_ERR_STATUS_COUNTERS 36
#define NUM_SEND_DMA_ERR_STATUS_COUNTERS 4
#define NUM_SEND_EGRESS_ERR_STATUS_COUNTERS 64
#define NUM_SEND_ERR_STATUS_COUNTERS 3
#define NUM_SEND_CTXT_ERR_STATUS_COUNTERS 5
#define NUM_SEND_DMA_ENG_ERR_STATUS_COUNTERS 24

struct hfi1_msix_info {
	/* lock to synchronize in_use_msix access */
	spinlock_t msix_lock;
	DECLARE_BITMAP(in_use_msix, CCE_NUM_MSIX_VECTORS);
	struct hfi1_msix_entry *msix_entries;
	u16 max_requested;
};

struct rcv_array_data {
	u16 ngroups;
	u16 nctxt_extra;
	u8 group_size;
};

struct per_vl_data {
	u16 mtu;
	struct send_context *sc;
};

#define PER_VL_SEND_CONTEXTS 16

struct err_info_rcvport {
	u8 status_and_code;
	u64 packet_flit1;
	u64 packet_flit2;
};

struct err_info_constraint {
	u8 status;
	u16 pkey;
	u32 slid;
};

struct hfi1_vnic_data {
	struct kmem_cache *txreq_cache;
	u8 num_vports;
};

struct hfi1_vnic_vport_info;

#define BOARD_VERS_MAX 96 /* how long the version string can be */
#define SERIAL_MAX 16 /* length of the serial number */

typedef int (*send_routine)(struct rvt_qp *, struct hfi1_pkt_state *, u64);

struct hfi1_devdata {
	struct hfi1_ibdev verbs_dev;     /* must be first */
	/* pointers to related structs for this device */
	/* pci access data structure */
	struct pci_dev *pcidev;
	struct cdev user_cdev;
	struct cdev diag_cdev;
	struct cdev ui_cdev;
	struct device *user_device;
	struct device *diag_device;
	struct device *ui_device;

	/* first mapping up to RcvArray */
	u8 __iomem *kregbase1;
	resource_size_t physaddr;

	/* second uncached mapping from RcvArray to pio send buffers */
	u8 __iomem *kregbase2;
	/* for detecting offset above kregbase2 address */
	u32 base2_start;

	/* Per VL data. Enough for all VLs but not all elements are set/used. */
	struct per_vl_data vld[PER_VL_SEND_CONTEXTS];
	/* send context data */
	struct send_context_info *send_contexts;
	/* map hardware send contexts to software index */
	u8 *hw_to_sw;
	/* spinlock for allocating and releasing send context resources */
	spinlock_t sc_lock;
	/* lock for pio_map */
	spinlock_t pio_map_lock;
	/* Send Context initialization lock. */
	spinlock_t sc_init_lock;
	/* lock for sdma_map */
	spinlock_t                          sde_map_lock;
	/* array of kernel send contexts */
	struct send_context **kernel_send_context;
	/* array of vl maps */
	struct pio_vl_map __rcu *pio_map;
	/* default flags to last descriptor */
	u64 default_desc1;

	/* fields common to all SDMA engines */

	volatile __le64                    *sdma_heads_dma; /* DMA'ed by chip */
	dma_addr_t                          sdma_heads_phys;
	void                               *sdma_pad_dma; /* DMA'ed by chip */
	dma_addr_t                          sdma_pad_phys;
	/* for deallocation */
	size_t                              sdma_heads_size;
	/* num used */
	u32                                 num_sdma;
	/* array of engines sized by num_sdma */
	struct sdma_engine                 *per_sdma;
	/* array of vl maps */
	struct sdma_vl_map __rcu           *sdma_map;
	/* SPC freeze waitqueue and variable */
	wait_queue_head_t		  sdma_unfreeze_wq;
	atomic_t			  sdma_unfreeze_count;

	u32 lcb_access_count;		/* count of LCB users */

	/* common data between shared ASIC HFIs in this OS */
	struct hfi1_asic_data *asic_data;

	/* mem-mapped pointer to base of PIO buffers */
	void __iomem *piobase;
	/*
	 * write-combining mem-mapped pointer to base of RcvArray
	 * memory.
	 */
	void __iomem *rcvarray_wc;
	/*
	 * credit return base - a per-NUMA range of DMA address that
	 * the chip will use to update the per-context free counter
	 */
	struct credit_return_base *cr_base;

	/* send context numbers and sizes for each type */
	struct sc_config_sizes sc_sizes[SC_MAX];

	char *boardname; /* human readable board info */

	u64 ctx0_seq_drop;

	/* reset value */
	u64 z_int_counter;
	u64 z_rcv_limit;
	u64 z_send_schedule;

	u64 __percpu *send_schedule;
	/* number of reserved contexts for netdev usage */
	u16 num_netdev_contexts;
	/* number of receive contexts in use by the driver */
	u32 num_rcv_contexts;
	/* number of pio send contexts in use by the driver */
	u32 num_send_contexts;
	/*
	 * number of ctxts available for PSM open
	 */
	u32 freectxts;
	/* total number of available user/PSM contexts */
	u32 num_user_contexts;
	/* base receive interrupt timeout, in CSR units */
	u32 rcv_intr_timeout_csr;

	spinlock_t sendctrl_lock; /* protect changes to SendCtrl */
	spinlock_t rcvctrl_lock; /* protect changes to RcvCtrl */
	spinlock_t uctxt_lock; /* protect rcd changes */
	struct mutex dc8051_lock; /* exclusive access to 8051 */
	struct workqueue_struct *update_cntr_wq;
	struct work_struct update_cntr_work;
	/* exclusive access to 8051 memory */
	spinlock_t dc8051_memlock;
	int dc8051_timed_out;	/* remember if the 8051 timed out */
	/*
	 * A page that will hold event notification bitmaps for all
	 * contexts. This page will be mapped into all processes.
	 */
	unsigned long *events;
	/*
	 * per unit status, see also portdata statusp
	 * mapped read-only into user processes so they can get unit and
	 * IB link status cheaply
	 */
	struct hfi1_status *status;

	/* revision register shadow */
	u64 revision;
	/* Base GUID for device (network order) */
	u64 base_guid;

	/* both sides of the PCIe link are gen3 capable */
	u8 link_gen3_capable;
	u8 dc_shutdown;
	/* localbus width (1, 2,4,8,16,32) from config space  */
	u32 lbus_width;
	/* localbus speed in MHz */
	u32 lbus_speed;
	int unit; /* unit # of this chip */
	int node; /* home node of this chip */

	/* save these PCI fields to restore after a reset */
	u32 pcibar0;
	u32 pcibar1;
	u32 pci_rom;
	u16 pci_command;
	u16 pcie_devctl;
	u16 pcie_lnkctl;
	u16 pcie_devctl2;
	u32 pci_msix0;
	u32 pci_tph2;

	/*
	 * ASCII serial number, from flash, large enough for original
	 * all digit strings, and longer serial number format
	 */
	u8 serial[SERIAL_MAX];
	/* human readable board version */
	u8 boardversion[BOARD_VERS_MAX];
	u8 lbus_info[32]; /* human readable localbus info */
	/* chip major rev, from CceRevision */
	u8 majrev;
	/* chip minor rev, from CceRevision */
	u8 minrev;
	/* hardware ID */
	u8 hfi1_id;
	/* implementation code */
	u8 icode;
	/* vAU of this device */
	u8 vau;
	/* vCU of this device */
	u8 vcu;
	/* link credits of this device */
	u16 link_credits;
	/* initial vl15 credits to use */
	u16 vl15_init;

	/*
	 * Cached value for vl15buf, read during verify cap interrupt. VL15
	 * credits are to be kept at 0 and set when handling the link-up
	 * interrupt. This removes the possibility of receiving VL15 MAD
	 * packets before this HFI is ready.
	 */
	u16 vl15buf_cached;

	/* Misc small ints */
	u8 n_krcv_queues;
	u8 qos_shift;

	u16 irev;	/* implementation revision */
	u32 dc8051_ver; /* 8051 firmware version */

	spinlock_t hfi1_diag_trans_lock; /* protect diag observer ops */
	struct platform_config platform_config;
	struct platform_config_cache pcfg_cache;

	struct diag_client *diag_client;

	/* general interrupt: mask of handled interrupts */
	u64 gi_mask[CCE_NUM_INT_CSRS];

	struct rcv_array_data rcv_entries;

	/* cycle length of PS* counters in HW (in picoseconds) */
	u16 psxmitwait_check_rate;

	/*
	 * 64 bit synthetic counters
	 */
	struct timer_list synth_stats_timer;

	/* MSI-X information */
	struct hfi1_msix_info msix_info;

	/*
	 * device counters
	 */
	char *cntrnames;
	size_t cntrnameslen;
	size_t ndevcntrs;
	u64 *cntrs;
	u64 *scntrs;

	/*
	 * remembered values for synthetic counters
	 */
	u64 last_tx;
	u64 last_rx;

	/*
	 * per-port counters
	 */
	size_t nportcntrs;
	char *portcntrnames;
	size_t portcntrnameslen;

	struct err_info_rcvport err_info_rcvport;
	struct err_info_constraint err_info_rcv_constraint;
	struct err_info_constraint err_info_xmit_constraint;

	atomic_t drop_packet;
	bool do_drop;
	u8 err_info_uncorrectable;
	u8 err_info_fmconfig;

	/*
	 * Software counters for the status bits defined by the
	 * associated error status registers
	 */
	u64 cce_err_status_cnt[NUM_CCE_ERR_STATUS_COUNTERS];
	u64 rcv_err_status_cnt[NUM_RCV_ERR_STATUS_COUNTERS];
	u64 misc_err_status_cnt[NUM_MISC_ERR_STATUS_COUNTERS];
	u64 send_pio_err_status_cnt[NUM_SEND_PIO_ERR_STATUS_COUNTERS];
	u64 send_dma_err_status_cnt[NUM_SEND_DMA_ERR_STATUS_COUNTERS];
	u64 send_egress_err_status_cnt[NUM_SEND_EGRESS_ERR_STATUS_COUNTERS];
	u64 send_err_status_cnt[NUM_SEND_ERR_STATUS_COUNTERS];

	/* Software counter that spans all contexts */
	u64 sw_ctxt_err_status_cnt[NUM_SEND_CTXT_ERR_STATUS_COUNTERS];
	/* Software counter that spans all DMA engines */
	u64 sw_send_dma_eng_err_status_cnt[
		NUM_SEND_DMA_ENG_ERR_STATUS_COUNTERS];
	/* Software counter that aggregates all cce_err_status errors */
	u64 sw_cce_err_status_aggregate;
	/* Software counter that aggregates all bypass packet rcv errors */
	u64 sw_rcv_bypass_packet_errors;

	/* Save the enabled LCB error bits */
	u64 lcb_err_en;
	struct cpu_mask_set *comp_vect;
	int *comp_vect_mappings;
	u32 comp_vect_possible_cpus;

	/*
	 * Capability to have different send engines simply by changing a
	 * pointer value.
	 */
	send_routine process_pio_send ____cacheline_aligned_in_smp;
	send_routine process_dma_send;
	void (*pio_inline_send)(struct hfi1_devdata *dd, struct pio_buf *pbuf,
				u64 pbc, const void *from, size_t count);
	int (*process_vnic_dma_send)(struct hfi1_devdata *dd, u8 q_idx,
				     struct hfi1_vnic_vport_info *vinfo,
				     struct sk_buff *skb, u64 pbc, u8 plen);
	/* hfi1_pportdata, points to array of (physical) port-specific
	 * data structs, indexed by pidx (0..n-1)
	 */
	struct hfi1_pportdata *pport;
	/* receive context data */
	struct hfi1_ctxtdata **rcd;
	u64 __percpu *int_counter;
	/* verbs tx opcode stats */
	struct hfi1_opcode_stats_perctx __percpu *tx_opstats;
	/* device (not port) flags, basically device capabilities */
	u16 flags;
	/* Number of physical ports available */
	u8 num_pports;
	/* Lowest context number which can be used by user processes or VNIC */
	u8 first_dyn_alloc_ctxt;
	/* adding a new field here would make it part of this cacheline */

	/* seqlock for sc2vl */
	seqlock_t sc2vl_lock ____cacheline_aligned_in_smp;
	u64 sc2vl[4];
	u64 __percpu *rcv_limit;
	/* adding a new field here would make it part of this cacheline */

	/* OUI comes from the HW. Used everywhere as 3 separate bytes. */
	u8 oui1;
	u8 oui2;
	u8 oui3;

	/* Timer and counter used to detect RcvBufOvflCnt changes */
	struct timer_list rcverr_timer;

	wait_queue_head_t event_queue;

	/* receive context tail dummy address */
	__le64 *rcvhdrtail_dummy_kvaddr;
	dma_addr_t rcvhdrtail_dummy_dma;

	u32 rcv_ovfl_cnt;
	/* Serialize ASPM enable/disable between multiple verbs contexts */
	spinlock_t aspm_lock;
	/* Number of verbs contexts which have disabled ASPM */
	atomic_t aspm_disabled_cnt;
	/* Keeps track of user space clients */
	refcount_t user_refcount;
	/* Used to wait for outstanding user space clients before dev removal */
	struct completion user_comp;

	bool eprom_available;	/* true if EPROM is available for this device */
	bool aspm_supported;	/* Does HW support ASPM */
	bool aspm_enabled;	/* ASPM state: enabled/disabled */
	struct rhashtable *sdma_rht;

	/* vnic data */
	struct hfi1_vnic_data vnic;
	/* Lock to protect IRQ SRC register access */
	spinlock_t irq_src_lock;
	int vnic_num_vports;
	struct hfi1_netdev_rx *netdev_rx;
	struct hfi1_affinity_node *affinity_entry;

	/* Keeps track of IPoIB RSM rule users */
	atomic_t ipoib_rsm_usr_num;
};

/* klp-ccp: from drivers/infiniband/hw/hfi1/qp.h */
#include <linux/hash.h>
#include <rdma/rdmavt_qp.h>
/* klp-ccp: from drivers/infiniband/hw/hfi1/sdma.h */
#include <linux/types.h>
#include <linux/list.h>
#include <asm/byteorder.h>
#include <linux/workqueue.h>
#include <linux/rculist.h>

#define SDMA_MAP_NONE          0

#define SDMA_DESC0_LAST_DESC_FLAG       BIT_ULL(62)
#define SDMA_DESC0_BYTE_COUNT_SHIFT     48
#define SDMA_DESC0_BYTE_COUNT_WIDTH     14
#define SDMA_DESC0_BYTE_COUNT_MASK \
	((1ULL << SDMA_DESC0_BYTE_COUNT_WIDTH) - 1)

#define SDMA_DESC0_PHY_ADDR_SHIFT       0
#define SDMA_DESC0_PHY_ADDR_WIDTH       48
#define SDMA_DESC0_PHY_ADDR_MASK \
	((1ULL << SDMA_DESC0_PHY_ADDR_WIDTH) - 1)

#define SDMA_DESC1_GENERATION_SHIFT     2
#define SDMA_DESC1_GENERATION_WIDTH     2
#define SDMA_DESC1_GENERATION_MASK \
	((1ULL << SDMA_DESC1_GENERATION_WIDTH) - 1)

#define SDMA_DESC1_INT_REQ_FLAG         BIT_ULL(1)
#define SDMA_DESC1_HEAD_TO_HOST_FLAG    BIT_ULL(0)

static inline void make_tx_sdma_desc(
	struct sdma_txreq *tx,
	int type,
	void *pinning_ctx,
	dma_addr_t addr,
	size_t len)
{
	struct sdma_desc *desc = &tx->descp[tx->num_desc];

	if (!tx->num_desc) {
		/* qw[0] zero; qw[1] first, ahg mode already in from init */
		desc->qw[1] |= ((u64)type & SDMA_DESC1_GENERATION_MASK)
				<< SDMA_DESC1_GENERATION_SHIFT;
	} else {
		desc->qw[0] = 0;
		desc->qw[1] = ((u64)type & SDMA_DESC1_GENERATION_MASK)
				<< SDMA_DESC1_GENERATION_SHIFT;
	}
	desc->qw[0] |= (((u64)addr & SDMA_DESC0_PHY_ADDR_MASK)
				<< SDMA_DESC0_PHY_ADDR_SHIFT) |
			(((u64)len & SDMA_DESC0_BYTE_COUNT_MASK)
				<< SDMA_DESC0_BYTE_COUNT_SHIFT);
	desc->pinning_ctx = pinning_ctx;
}

static void (*klpe___sdma_txclean)(struct hfi1_devdata *, struct sdma_txreq *);

static inline void _sdma_close_tx(struct hfi1_devdata *dd,
				  struct sdma_txreq *tx)
{
	u16 last_desc = tx->num_desc - 1;

	tx->descp[last_desc].qw[0] |= SDMA_DESC0_LAST_DESC_FLAG;
	tx->descp[last_desc].qw[1] |= dd->default_desc1;
	if (tx->flags & SDMA_TXREQ_F_URGENT)
		tx->descp[last_desc].qw[1] |= (SDMA_DESC1_HEAD_TO_HOST_FLAG |
					       SDMA_DESC1_INT_REQ_FLAG);
}

/* klp-ccp: from drivers/infiniband/hw/hfi1/verbs_txreq.h */
#include <linux/types.h>
#include <linux/slab.h>

static int (*klpe__extend_sdma_tx_descs)(struct hfi1_devdata *dd, struct sdma_txreq *tx);

int klpp__pad_sdma_tx_descs(struct hfi1_devdata *dd, struct sdma_txreq *tx)
{
	int rval = 0;

	if ((unlikely(tx->num_desc == tx->desc_limit))) {
		rval = (*klpe__extend_sdma_tx_descs)(dd, tx);
		if (rval) {
			(*klpe___sdma_txclean)(dd, tx);
			return rval;
		}
	}

	/* finish the one just added */
	make_tx_sdma_desc(
		tx,
		SDMA_MAP_NONE,
		NULL,
		dd->sdma_pad_phys,
		sizeof(u32) - (tx->packet_len & (sizeof(u32) - 1)));
	tx->num_desc++;
	_sdma_close_tx(dd, tx);
	return rval;
}


#include "livepatch_bsc1222726.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "hfi1"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__sdma_txclean", (void *)&klpe___sdma_txclean, "hfi1" },
	{ "_extend_sdma_tx_descs", (void *)&klpe__extend_sdma_tx_descs,
	  "hfi1" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1222726_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1222726_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_INFINIBAND_HFI1) */
