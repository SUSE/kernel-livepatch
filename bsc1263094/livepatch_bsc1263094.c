/*
 * livepatch_bsc1263094
 *
 * Fix for CVE-2026-31505, bsc#1263094
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

#if IS_ENABLED(CONFIG_IAVF)

#if !IS_MODULE(CONFIG_IAVF)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1263094.h"


/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_ethtool.c */
#include <linux/bitfield.h>
#include <linux/uaccess.h>
/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf.h */
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sctp.h>
#include <linux/ipv6.h>
#include <linux/kernel.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/dma-mapping.h>
#include <linux/etherdevice.h>
#include <linux/socket.h>
#include <linux/jiffies.h>
#include <net/ip6_checksum.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/udp.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_skbedit.h>
/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_osdep.h */
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/tcp.h>
#include <linux/pci.h>
#include <linux/io-64-nonatomic-lo-hi.h>

struct iavf_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
};

struct iavf_virt_mem {
	void *va;
	u32 size;
};

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_adminq_cmd.h */
enum iavf_admin_queue_err {
	IAVF_AQ_RC_OK		= 0,  /* success */
	IAVF_AQ_RC_EPERM	= 1,  /* Operation not permitted */
	IAVF_AQ_RC_ENOENT	= 2,  /* No such element */
	IAVF_AQ_RC_ESRCH	= 3,  /* Bad opcode */
	IAVF_AQ_RC_EINTR	= 4,  /* operation interrupted */
	IAVF_AQ_RC_EIO		= 5,  /* I/O error */
	IAVF_AQ_RC_ENXIO	= 6,  /* No such resource */
	IAVF_AQ_RC_E2BIG	= 7,  /* Arg too long */
	IAVF_AQ_RC_EAGAIN	= 8,  /* Try again */
	IAVF_AQ_RC_ENOMEM	= 9,  /* Out of memory */
	IAVF_AQ_RC_EACCES	= 10, /* Permission denied */
	IAVF_AQ_RC_EFAULT	= 11, /* Bad address */
	IAVF_AQ_RC_EBUSY	= 12, /* Device or resource busy */
	IAVF_AQ_RC_EEXIST	= 13, /* object already exists */
	IAVF_AQ_RC_EINVAL	= 14, /* Invalid argument */
	IAVF_AQ_RC_ENOTTY	= 15, /* Not a typewriter */
	IAVF_AQ_RC_ENOSPC	= 16, /* No space left or alloc failure */
	IAVF_AQ_RC_ENOSYS	= 17, /* Function not implemented */
	IAVF_AQ_RC_ERANGE	= 18, /* Parameter out of range */
	IAVF_AQ_RC_EFLUSHED	= 19, /* Cmd flushed due to prev cmd error */
	IAVF_AQ_RC_BAD_ADDR	= 20, /* Descriptor contains a bad pointer */
	IAVF_AQ_RC_EMODE	= 21, /* Op not allowed in current dev mode */
	IAVF_AQ_RC_EFBIG	= 22, /* File too large */
};

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_adminq.h */
struct iavf_adminq_ring {
	struct iavf_virt_mem dma_head;	/* space for dma structures */
	struct iavf_dma_mem desc_buf;	/* descriptor ring memory */
	struct iavf_virt_mem cmd_buf;	/* command buffer memory */

	union {
		struct iavf_dma_mem *asq_bi;
		struct iavf_dma_mem *arq_bi;
	} r;

	u16 count;		/* Number of descriptors */
	u16 rx_buf_len;		/* Admin Receive Queue buffer length */

	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;
};

struct iavf_adminq_info {
	struct iavf_adminq_ring arq;    /* receive queue */
	struct iavf_adminq_ring asq;    /* send queue */
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
	enum iavf_admin_queue_err asq_last_status;
	enum iavf_admin_queue_err arq_last_status;
};

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_type.h */
struct iavf_hw_capabilities {
	bool dcb;
	bool fcoe;
	u32 num_vsis;
	u32 num_rx_qp;
	u32 num_tx_qp;
	u32 base_queue;
	u32 num_msix_vectors_vf;
};

struct iavf_mac_info {
	u8 addr[ETH_ALEN];
	u8 perm_addr[ETH_ALEN];
};

enum iavf_bus_type {
	iavf_bus_type_unknown = 0,
	iavf_bus_type_pci,
	iavf_bus_type_pcix,
	iavf_bus_type_pci_express,
	iavf_bus_type_reserved
};

enum iavf_bus_speed {
	iavf_bus_speed_unknown	= 0,
	iavf_bus_speed_33	= 33,
	iavf_bus_speed_66	= 66,
	iavf_bus_speed_100	= 100,
	iavf_bus_speed_120	= 120,
	iavf_bus_speed_133	= 133,
	iavf_bus_speed_2500	= 2500,
	iavf_bus_speed_5000	= 5000,
	iavf_bus_speed_8000	= 8000,
	iavf_bus_speed_reserved
};

enum iavf_bus_width {
	iavf_bus_width_unknown	= 0,
	iavf_bus_width_pcie_x1	= 1,
	iavf_bus_width_pcie_x2	= 2,
	iavf_bus_width_pcie_x4	= 4,
	iavf_bus_width_pcie_x8	= 8,
	iavf_bus_width_32	= 32,
	iavf_bus_width_64	= 64,
	iavf_bus_width_reserved
};

struct iavf_bus_info {
	enum iavf_bus_speed speed;
	enum iavf_bus_width width;
	enum iavf_bus_type type;

	u16 func;
	u16 device;
	u16 lan_id;
	u16 bus_id;
};

struct iavf_hw {
	u8 __iomem *hw_addr;
	void *back;

	/* subsystem structs */
	struct iavf_mac_info mac;
	struct iavf_bus_info bus;

	/* pci info */
	u16 device_id;
	u16 vendor_id;
	u16 subsystem_device_id;
	u16 subsystem_vendor_id;
	u8 revision_id;

	/* capabilities for entire device and PCI func */
	struct iavf_hw_capabilities dev_caps;

	/* Admin Queue info */
	struct iavf_adminq_info aq;

	/* debug mask */
	u32 debug_mask;
	char err_str[16];
};

struct iavf_eth_stats {
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

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf.h */
#include <linux/avf/virtchnl.h>

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_txrx.h */
struct iavf_queue_stats {
	u64 packets;
	u64 bytes;
};

struct iavf_tx_queue_stats {
	u64 restart_queue;
	u64 tx_busy;
	u64 tx_done_old;
	u64 tx_linearize;
	u64 tx_force_wb;
	u64 tx_lost_interrupt;
};

struct iavf_rx_queue_stats {
	u64 non_eop_descs;
	u64 alloc_page_failed;
	u64 alloc_buff_failed;
};

struct iavf_ring {
	struct iavf_ring *next;		/* pointer to next ring in q_vector */
	void *desc;			/* Descriptor ring memory */
	union {
		struct page_pool *pp;	/* Used on Rx for buffer management */
		struct device *dev;	/* Used on Tx for DMA mapping */
	};
	struct net_device *netdev;	/* netdev ring maps to */
	union {
		struct libeth_fqe *rx_fqes;
		struct iavf_tx_buffer *tx_bi;
	};
	u8 __iomem *tail;
	u32 truesize;

	u16 queue_index;		/* Queue number of ring */

	/* high bit set means dynamic, use accessors routines to read/write.
	 * hardware only supports 2us resolution for the ITR registers.
	 * these values always store the USER setting, and must be converted
	 * before programming to a register.
	 */
	u16 itr_setting;

	u16 count;			/* Number of descriptors */

	/* used in interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;

	u16 flags;
/* BIT(2) is free */

	/* stats structs */
	struct iavf_queue_stats	stats;
	struct u64_stats_sync syncp;
	union {
		struct iavf_tx_queue_stats tx_stats;
		struct iavf_rx_queue_stats rx_stats;
	};

	int prev_pkt_ctr;		/* For Tx stall detection */
	unsigned int size;		/* length of descriptor ring in bytes */
	dma_addr_t dma;			/* physical address of ring */

	struct iavf_vsi *vsi;		/* Backreference to associated VSI */
	struct iavf_q_vector *q_vector;	/* Backreference to associated vector */

	struct rcu_head rcu;		/* to avoid race on free */
	struct sk_buff *skb;		/* When iavf_clean_rx_ring_irq() must
					 * return before it sees the EOP for
					 * the current packet, we save that skb
					 * here and resume receiving this
					 * packet the next time
					 * iavf_clean_rx_ring_irq() is called
					 * for this ring.
					 */

	u32 rx_buf_len;
} ____cacheline_internodealigned_in_smp;

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf.h */
#include <linux/bitmap.h>

enum iavf_vsi_state_t {
	__IAVF_VSI_DOWN,
	/* This must be last as it determines the size of the BITMAP */
	__IAVF_VSI_STATE_SIZE__,
};

struct iavf_vsi {
	struct iavf_adapter *back;
	struct net_device *netdev;
	u16 seid;
	u16 id;
	DECLARE_BITMAP(state, __IAVF_VSI_STATE_SIZE__);
	int base_vector;
	u16 qs_handle;
};

#define IAVF_MAX_TRAFFIC_CLASS	4

enum iavf_tc_state_t {
	__IAVF_TC_INVALID, /* no traffic class, default state */
	__IAVF_TC_RUNNING, /* traffic classes have been created */
};

struct iavf_channel_config {
	struct virtchnl_channel_info ch_info[IAVF_MAX_TRAFFIC_CLASS];
	enum iavf_tc_state_t state;
	u8 total_qps;
};

enum iavf_state_t {
	__IAVF_STARTUP,		/* driver loaded, probe complete */
	__IAVF_REMOVE,		/* driver is being unloaded */
	__IAVF_INIT_VERSION_CHECK,	/* aq msg sent, awaiting reply */
	__IAVF_INIT_GET_RESOURCES,	/* aq msg sent, awaiting reply */
	__IAVF_INIT_EXTENDED_CAPS,	/* process extended caps which require aq msg exchange */
	__IAVF_INIT_CONFIG_ADAPTER,
	__IAVF_INIT_SW,		/* got resources, setting up structs */
	__IAVF_INIT_FAILED,	/* init failed, restarting procedure */
	__IAVF_RESETTING,		/* in reset */
	__IAVF_COMM_FAILED,		/* communication with PF failed */
	/* Below here, watchdog is running */
	__IAVF_DOWN,			/* ready, can be opened */
	__IAVF_DOWN_PENDING,		/* descending, waiting for watchdog */
	__IAVF_TESTING,		/* in ethtool self-test */
	__IAVF_RUNNING,		/* opened, working */
};

struct iavf_adapter {
	struct workqueue_struct *wq;
	struct work_struct reset_task;
	struct work_struct adminq_task;
	struct work_struct finish_config;
	wait_queue_head_t down_waitqueue;
	wait_queue_head_t reset_waitqueue;
	wait_queue_head_t vc_waitqueue;
	struct iavf_q_vector *q_vectors;
	struct list_head vlan_filter_list;
	int num_vlan_filters;
	struct list_head mac_filter_list;
	struct mutex crit_lock;
	/* Lock to protect accesses to MAC and VLAN lists */
	spinlock_t mac_vlan_list_lock;
	char misc_vector_name[IFNAMSIZ + 9];
	int num_active_queues;
	int num_req_queues;

	/* TX */
	struct iavf_ring *tx_rings;
	u32 tx_timeout_count;
	u32 tx_desc_count;

	/* RX */
	struct iavf_ring *rx_rings;
	u64 hw_csum_rx_error;
	u32 rx_desc_count;
	int num_msix_vectors;
	struct msix_entry *msix_entries;

	u32 flags;
/* BIT(15) is free, was IAVF_FLAG_LEGACY_RX */
/* duplicates for common code */
	/* flags for admin queue service task */
	u64 aq_required;

#define IAVF_FLAG_AQ_REQUEST_STATS		BIT_ULL(29)
	u64 extended_caps;
	/* Lock to prevent possible clobbering of
	 * current_netdev_promisc_flags
	 */
	spinlock_t current_netdev_promisc_flags_lock;
	netdev_features_t current_netdev_promisc_flags;

	/* OS defined structs */
	struct net_device *netdev;
	struct pci_dev *pdev;

	struct iavf_hw hw; /* defined in iavf_type.h */

	enum iavf_state_t state;
	enum iavf_state_t last_state;
	unsigned long crit_section;

	struct delayed_work watchdog_task;
	bool link_up;
	enum virtchnl_link_speed link_speed;
	/* This is only populated if the VIRTCHNL_VF_CAP_ADV_LINK_SPEED is set
	 * in vf_res->vf_cap_flags. Use ADV_LINK_SUPPORT macro to determine if
	 * this field is valid. This field should be used going forward and the
	 * enum virtchnl_link_speed above should be considered the legacy way of
	 * storing/communicating link speeds.
	 */
	u32 link_speed_mbps;

	enum virtchnl_ops current_op;
/* RSS by the PF should be preferred over RSS via other methods. */
	struct virtchnl_vf_resource *vf_res; /* incl. all VSIs */
	struct virtchnl_vsi_resource *vsi_res; /* our LAN VSI */
	struct virtchnl_version_info pf_version;
	struct virtchnl_vlan_caps vlan_v2_caps;
	u16 msg_enable;
	struct iavf_eth_stats current_stats;
	struct iavf_vsi vsi;
	u32 aq_wait_count;
	/* RSS stuff */
	enum virtchnl_rss_algorithm hfunc;
	u64 hena;
	u16 rss_key_size;
	u16 rss_lut_size;
	u8 *rss_key;
	u8 *rss_lut;
	/* ADQ related members */
	struct iavf_channel_config ch_config;
	u8 num_tc;
	struct list_head cloud_filter_list;
	/* lock to protect access to the cloud filter list */
	spinlock_t cloud_filter_list_lock;
	u16 num_cloud_filters;
	/* snapshot of "num_active_queues" before setup_tc for qdisc add
	 * is invoked. This information is useful during qdisc del flow,
	 * to restore correct number of queues
	 */
	int orig_num_active_queues;

	u16 fdir_active_fltr;
	u16 raw_fdir_active_fltr;
	struct list_head fdir_list_head;
	spinlock_t fdir_fltr_lock;	/* protect the Flow Director filter list */

	struct list_head adv_rss_list_head;
	spinlock_t adv_rss_lock;	/* protect the RSS management list */
};

void iavf_schedule_aq_request(struct iavf_adapter *adapter, u64 flags);

/* klp-ccp: from drivers/net/ethernet/intel/iavf/iavf_ethtool.c */
struct iavf_stats {
	char stat_string[ETH_GSTRING_LEN];
	int sizeof_stat;
	int stat_offset;
};

extern const struct iavf_stats iavf_gstrings_queue_stats[2];

extern void
iavf_add_one_ethtool_stat(u64 *data, void *pointer,
			  const struct iavf_stats *stat);

static void
__iavf_add_ethtool_stats(u64 **data, void *pointer,
			 const struct iavf_stats stats[],
			 const unsigned int size)
{
	unsigned int i;

	for (i = 0; i < size; i++)
		iavf_add_one_ethtool_stat((*data)++, pointer, &stats[i]);
}

#define iavf_add_ethtool_stats(data, pointer, stats) \
	__iavf_add_ethtool_stats(data, pointer, stats, ARRAY_SIZE(stats))

extern void
iavf_add_queue_stats(u64 **data, struct iavf_ring *ring);

extern void __iavf_add_stat_strings(u8 **p, const struct iavf_stats stats[],
				    const unsigned int size, ...);

#define iavf_add_stat_strings(p, stats, ...) \
	__iavf_add_stat_strings(p, stats, ARRAY_SIZE(stats), ## __VA_ARGS__)

extern const struct iavf_stats iavf_gstrings_stats[12];

#define IAVF_STATS_LEN	ARRAY_SIZE(iavf_gstrings_stats)

#define IAVF_QUEUE_STATS_LEN	ARRAY_SIZE(iavf_gstrings_queue_stats)

int klpp_iavf_get_sset_count(struct net_device *netdev, int sset)
{
	/* Report the maximum number queues, even if not every queue is
	 * currently configured. Since allocation of queues is in pairs,
	 * use netdev->num_tx_queues * 2. The num_tx_queues is set at
	 * device creation and never changes.
	 */

	if (sset == ETH_SS_STATS)
		return IAVF_STATS_LEN +
		       (IAVF_QUEUE_STATS_LEN * 2 * netdev->num_tx_queues);
	else
		return -EINVAL;
}

void klpp_iavf_get_ethtool_stats(struct net_device *netdev,
				   struct ethtool_stats *stats, u64 *data)
{
	struct iavf_adapter *adapter = netdev_priv(netdev);
	unsigned int i;

	/* Explicitly request stats refresh */
	iavf_schedule_aq_request(adapter, IAVF_FLAG_AQ_REQUEST_STATS);

	iavf_add_ethtool_stats(&data, adapter, iavf_gstrings_stats);

	rcu_read_lock();
	/* Use num_tx_queues to report stats for the maximum number of queues.
	 * Queues beyond num_active_queues will report zero.
	 */
	for (i = 0; i < netdev->num_tx_queues; i++) {
		struct iavf_ring *tx_ring = NULL, *rx_ring = NULL;

		if (i < adapter->num_active_queues) {
			tx_ring = &adapter->tx_rings[i];
			rx_ring = &adapter->rx_rings[i];
		}

		iavf_add_queue_stats(&data, tx_ring);
		iavf_add_queue_stats(&data, rx_ring);
	}
	rcu_read_unlock();
}

static void klpp_iavf_get_stat_strings(struct net_device *netdev, u8 *data)
{
	unsigned int i;

	iavf_add_stat_strings(&data, iavf_gstrings_stats);

	/* Queues are always allocated in pairs, so we just use
	 * num_tx_queues for both Tx and Rx queues.
	 */
	for (i = 0; i < netdev->num_tx_queues; i++) {
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats,
				      "tx", i);
		iavf_add_stat_strings(&data, iavf_gstrings_queue_stats,
				      "rx", i);
	}
}

void klpp_iavf_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		klpp_iavf_get_stat_strings(netdev, data);
		break;
	default:
		break;
	}
}


#include <linux/livepatch.h>

extern typeof(__iavf_add_stat_strings) __iavf_add_stat_strings
	 KLP_RELOC_SYMBOL(iavf, iavf, __iavf_add_stat_strings);
extern typeof(iavf_add_one_ethtool_stat) iavf_add_one_ethtool_stat
	 KLP_RELOC_SYMBOL(iavf, iavf, iavf_add_one_ethtool_stat);
extern typeof(iavf_add_queue_stats) iavf_add_queue_stats
	 KLP_RELOC_SYMBOL(iavf, iavf, iavf_add_queue_stats);
extern typeof(iavf_gstrings_queue_stats) iavf_gstrings_queue_stats
	 KLP_RELOC_SYMBOL(iavf, iavf, iavf_gstrings_queue_stats);
extern typeof(iavf_gstrings_stats) iavf_gstrings_stats
	 KLP_RELOC_SYMBOL(iavf, iavf, iavf_gstrings_stats);
extern typeof(iavf_schedule_aq_request) iavf_schedule_aq_request
	 KLP_RELOC_SYMBOL(iavf, iavf, iavf_schedule_aq_request);

#endif /* IS_ENABLED(CONFIG_IAVF) */
