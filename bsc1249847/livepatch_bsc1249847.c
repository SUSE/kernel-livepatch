/*
 * livepatch_bsc1249847
 *
 * Fix for CVE-2022-50252, bsc#1249847
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

#if IS_ENABLED(CONFIG_IGB)

/* klp-ccp: from drivers/net/ethernet/intel/igb/igb_main.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/checksum.h>

/* klp-ccp: from drivers/net/ethernet/intel/igb/igb_main.c */
#include <linux/net_tstamp.h>

#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <linux/if_ether.h>

#include <linux/prefetch.h>

#include <linux/etherdevice.h>

#include <linux/i2c.h>

/* klp-ccp: from drivers/net/ethernet/intel/igb/e1000_hw.h */
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/netdevice.h>

/* klp-ccp: from drivers/net/ethernet/intel/igb/e1000_regs.h */
#define E1000_EITR(_n) (0x01680 + (0x4 * (_n)))

struct e1000_hw;

/* klp-ccp: from drivers/net/ethernet/intel/igb/e1000_hw.h */
enum e1000_mac_type {
	e1000_undefined = 0,
	e1000_82575,
	e1000_82576,
	e1000_82580,
	e1000_i350,
	e1000_i354,
	e1000_i210,
	e1000_i211,
	e1000_num_macs  /* List is 1-based, so subtract 1 for true count. */
};

enum e1000_media_type {
	e1000_media_type_unknown = 0,
	e1000_media_type_copper = 1,
	e1000_media_type_fiber = 2,
	e1000_media_type_internal_serdes = 3,
	e1000_num_media_types
};

enum e1000_nvm_type {
	e1000_nvm_unknown = 0,
	e1000_nvm_none,
	e1000_nvm_eeprom_spi,
	e1000_nvm_flash_hw,
	e1000_nvm_invm,
	e1000_nvm_flash_sw
};

enum e1000_nvm_override {
	e1000_nvm_override_none = 0,
	e1000_nvm_override_spi_small,
	e1000_nvm_override_spi_large,
};

enum e1000_phy_type {
	e1000_phy_unknown = 0,
	e1000_phy_none,
	e1000_phy_m88,
	e1000_phy_igp,
	e1000_phy_igp_2,
	e1000_phy_gg82563,
	e1000_phy_igp_3,
	e1000_phy_ife,
	e1000_phy_82580,
	e1000_phy_i210,
	e1000_phy_bcm54616,
};

enum e1000_bus_type {
	e1000_bus_type_unknown = 0,
	e1000_bus_type_pci,
	e1000_bus_type_pcix,
	e1000_bus_type_pci_express,
	e1000_bus_type_reserved
};

enum e1000_bus_speed {
	e1000_bus_speed_unknown = 0,
	e1000_bus_speed_33,
	e1000_bus_speed_66,
	e1000_bus_speed_100,
	e1000_bus_speed_120,
	e1000_bus_speed_133,
	e1000_bus_speed_2500,
	e1000_bus_speed_5000,
	e1000_bus_speed_reserved
};

enum e1000_bus_width {
	e1000_bus_width_unknown = 0,
	e1000_bus_width_pcie_x1,
	e1000_bus_width_pcie_x2,
	e1000_bus_width_pcie_x4 = 4,
	e1000_bus_width_pcie_x8 = 8,
	e1000_bus_width_32,
	e1000_bus_width_64,
	e1000_bus_width_reserved
};

enum e1000_1000t_rx_status {
	e1000_1000t_rx_status_not_ok = 0,
	e1000_1000t_rx_status_ok,
	e1000_1000t_rx_status_undefined = 0xFF
};

enum e1000_rev_polarity {
	e1000_rev_polarity_normal = 0,
	e1000_rev_polarity_reversed,
	e1000_rev_polarity_undefined = 0xFF
};

enum e1000_fc_mode {
	e1000_fc_none = 0,
	e1000_fc_rx_pause,
	e1000_fc_tx_pause,
	e1000_fc_full,
	e1000_fc_default = 0xFF
};

struct e1000_hw_stats {
	u64 crcerrs;
	u64 algnerrc;
	u64 symerrs;
	u64 rxerrc;
	u64 mpc;
	u64 scc;
	u64 ecol;
	u64 mcc;
	u64 latecol;
	u64 colc;
	u64 dc;
	u64 tncrs;
	u64 sec;
	u64 cexterr;
	u64 rlec;
	u64 xonrxc;
	u64 xontxc;
	u64 xoffrxc;
	u64 xofftxc;
	u64 fcruc;
	u64 prc64;
	u64 prc127;
	u64 prc255;
	u64 prc511;
	u64 prc1023;
	u64 prc1522;
	u64 gprc;
	u64 bprc;
	u64 mprc;
	u64 gptc;
	u64 gorc;
	u64 gotc;
	u64 rnbc;
	u64 ruc;
	u64 rfc;
	u64 roc;
	u64 rjc;
	u64 mgprc;
	u64 mgpdc;
	u64 mgptc;
	u64 tor;
	u64 tot;
	u64 tpr;
	u64 tpt;
	u64 ptc64;
	u64 ptc127;
	u64 ptc255;
	u64 ptc511;
	u64 ptc1023;
	u64 ptc1522;
	u64 mptc;
	u64 bptc;
	u64 tsctc;
	u64 tsctfc;
	u64 iac;
	u64 icrxptc;
	u64 icrxatc;
	u64 ictxptc;
	u64 ictxatc;
	u64 ictxqec;
	u64 ictxqmtc;
	u64 icrxdmtc;
	u64 icrxoc;
	u64 cbtmpc;
	u64 htdpmc;
	u64 cbrdpc;
	u64 cbrmpc;
	u64 rpthc;
	u64 hgptc;
	u64 htcbdpc;
	u64 hgorc;
	u64 hgotc;
	u64 lenerrs;
	u64 scvpc;
	u64 hrmpc;
	u64 doosync;
	u64 o2bgptc;
	u64 o2bspc;
	u64 b2ospc;
	u64 b2ogprc;
};

struct e1000_host_mng_dhcp_cookie {
	u32 signature;
	u8  status;
	u8  reserved0;
	u16 vlan_id;
	u32 reserved1;
	u16 reserved2;
	u8  reserved3;
	u8  checksum;
};

/* klp-ccp: from drivers/net/ethernet/intel/igb/e1000_phy.h */
enum e1000_ms_type {
	e1000_ms_hw_default = 0,
	e1000_ms_force_master,
	e1000_ms_force_slave,
	e1000_ms_auto
};

enum e1000_smart_speed {
	e1000_smart_speed_default = 0,
	e1000_smart_speed_on,
	e1000_smart_speed_off
};

struct e1000_sfp_flags {
	u8 e1000_base_sx:1;
	u8 e1000_base_lx:1;
	u8 e1000_base_cx:1;
	u8 e1000_base_t:1;
	u8 e100_base_lx:1;
	u8 e100_base_fx:1;
	u8 e10_base_bx10:1;
	u8 e10_base_px:1;
};

/* klp-ccp: from drivers/net/ethernet/intel/igb/e1000_hw.h */
struct e1000_mac_operations {
	s32 (*check_for_link)(struct e1000_hw *);
	s32 (*reset_hw)(struct e1000_hw *);
	s32 (*init_hw)(struct e1000_hw *);
	bool (*check_mng_mode)(struct e1000_hw *);
	s32 (*setup_physical_interface)(struct e1000_hw *);
	void (*rar_set)(struct e1000_hw *, u8 *, u32);
	s32 (*read_mac_addr)(struct e1000_hw *);
	s32 (*get_speed_and_duplex)(struct e1000_hw *, u16 *, u16 *);
	s32 (*acquire_swfw_sync)(struct e1000_hw *, u16);
	void (*release_swfw_sync)(struct e1000_hw *, u16);
#ifdef CONFIG_IGB_HWMON
	s32 (*get_thermal_sensor_data)(struct e1000_hw *);
	s32 (*init_thermal_sensor_thresh)(struct e1000_hw *);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	void (*write_vfta)(struct e1000_hw *, u32, u32);
};

struct e1000_phy_operations {
	s32 (*acquire)(struct e1000_hw *);
	s32 (*check_polarity)(struct e1000_hw *);
	s32 (*check_reset_block)(struct e1000_hw *);
	s32 (*force_speed_duplex)(struct e1000_hw *);
	s32 (*get_cfg_done)(struct e1000_hw *hw);
	s32 (*get_cable_length)(struct e1000_hw *);
	s32 (*get_phy_info)(struct e1000_hw *);
	s32 (*read_reg)(struct e1000_hw *, u32, u16 *);
	void (*release)(struct e1000_hw *);
	s32 (*reset)(struct e1000_hw *);
	s32 (*set_d0_lplu_state)(struct e1000_hw *, bool);
	s32 (*set_d3_lplu_state)(struct e1000_hw *, bool);
	s32 (*write_reg)(struct e1000_hw *, u32, u16);
	s32 (*read_i2c_byte)(struct e1000_hw *, u8, u8, u8 *);
	s32 (*write_i2c_byte)(struct e1000_hw *, u8, u8, u8);
};

struct e1000_nvm_operations {
	s32 (*acquire)(struct e1000_hw *);
	s32 (*read)(struct e1000_hw *, u16, u16, u16 *);
	void (*release)(struct e1000_hw *);
	s32 (*write)(struct e1000_hw *, u16, u16, u16 *);
	s32 (*update)(struct e1000_hw *);
	s32 (*validate)(struct e1000_hw *);
	s32 (*valid_led_default)(struct e1000_hw *, u16 *);
};

#define E1000_MAX_SENSORS		3

struct e1000_thermal_diode_data {
	u8 location;
	u8 temp;
	u8 caution_thresh;
	u8 max_op_thresh;
};

struct e1000_thermal_sensor_data {
	struct e1000_thermal_diode_data sensor[E1000_MAX_SENSORS];
};

struct e1000_info {
	s32 (*get_invariants)(struct e1000_hw *);
	struct e1000_mac_operations *mac_ops;
	const struct e1000_phy_operations *phy_ops;
	struct e1000_nvm_operations *nvm_ops;
};

struct e1000_mac_info {
	struct e1000_mac_operations ops;

	u8 addr[6];
	u8 perm_addr[6];

	enum e1000_mac_type type;

	u32 ledctl_default;
	u32 ledctl_mode1;
	u32 ledctl_mode2;
	u32 mc_filter_type;
	u32 txcw;

	u16 mta_reg_count;
	u16 uta_reg_count;

	/* Maximum size of the MTA register table in all supported adapters */
	
#define MAX_MTA_REG 128
u32 mta_shadow[MAX_MTA_REG];
	u16 rar_entry_count;

	u8  forced_speed_duplex;

	bool adaptive_ifs;
	bool arc_subsystem_valid;
	bool asf_firmware_present;
	bool autoneg;
	bool autoneg_failed;
	bool disable_hw_init_bits;
	bool get_link_status;
	bool ifs_params_forced;
	bool in_ifs_mode;
	bool report_tx_early;
	bool serdes_has_link;
	bool tx_pkt_filtering;
	struct e1000_thermal_sensor_data thermal_sensor_data;
};

struct e1000_phy_info {
	struct e1000_phy_operations ops;

	enum e1000_phy_type type;

	enum e1000_1000t_rx_status local_rx;
	enum e1000_1000t_rx_status remote_rx;
	enum e1000_ms_type ms_type;
	enum e1000_ms_type original_ms_type;
	enum e1000_rev_polarity cable_polarity;
	enum e1000_smart_speed smart_speed;

	u32 addr;
	u32 id;
	u32 reset_delay_us; /* in usec */
	u32 revision;

	enum e1000_media_type media_type;

	u16 autoneg_advertised;
	u16 autoneg_mask;
	u16 cable_length;
	u16 max_cable_length;
	u16 min_cable_length;
	u16 pair_length[4];

	u8 mdix;

	bool disable_polarity_correction;
	bool is_mdix;
	bool polarity_correction;
	bool reset_disable;
	bool speed_downgraded;
	bool autoneg_wait_to_complete;
};

struct e1000_nvm_info {
	struct e1000_nvm_operations ops;
	enum e1000_nvm_type type;
	enum e1000_nvm_override override;

	u32 flash_bank_size;
	u32 flash_base_addr;

	u16 word_size;
	u16 delay_usec;
	u16 address_bits;
	u16 opcode_bits;
	u16 page_size;
};

struct e1000_bus_info {
	enum e1000_bus_type type;
	enum e1000_bus_speed speed;
	enum e1000_bus_width width;

	u32 snoop;

	u16 func;
	u16 pci_cmd_word;
};

struct e1000_fc_info {
	u32 high_water;     /* Flow control high-water mark */
	u32 low_water;      /* Flow control low-water mark */
	u16 pause_time;     /* Flow control pause timer */
	bool send_xon;      /* Flow control send XON */
	bool strict_ieee;   /* Strict IEEE mode */
	enum e1000_fc_mode current_mode; /* Type of flow control */
	enum e1000_fc_mode requested_mode;
};

struct e1000_mbx_operations {
	s32 (*init_params)(struct e1000_hw *hw);
	s32 (*read)(struct e1000_hw *hw, u32 *msg, u16 size, u16 mbx_id,
		    bool unlock);
	s32 (*write)(struct e1000_hw *hw, u32 *msg, u16 size, u16 mbx_id);
	s32 (*read_posted)(struct e1000_hw *hw, u32 *msg, u16 size, u16 mbx_id);
	s32 (*write_posted)(struct e1000_hw *hw, u32 *msg, u16 size,
			    u16 mbx_id);
	s32 (*check_for_msg)(struct e1000_hw *hw, u16 mbx_id);
	s32 (*check_for_ack)(struct e1000_hw *hw, u16 mbx_id);
	s32 (*check_for_rst)(struct e1000_hw *hw, u16 mbx_id);
	s32 (*unlock)(struct e1000_hw *hw, u16 mbx_id);
};

struct e1000_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct e1000_mbx_info {
	struct e1000_mbx_operations ops;
	struct e1000_mbx_stats stats;
	u32 timeout;
	u32 usec_delay;
	u16 size;
};

struct e1000_dev_spec_82575 {
	bool sgmii_active;
	bool global_device_reset;
	bool eee_disable;
	bool clear_semaphore_once;
	struct e1000_sfp_flags eth_flags;
	bool module_plugged;
	u8 media_port;
	bool media_changed;
	bool mas_capable;
};

struct e1000_hw {
	void *back;

	u8 __iomem *hw_addr;
	u8 __iomem *flash_address;
	unsigned long io_base;

	struct e1000_mac_info  mac;
	struct e1000_fc_info   fc;
	struct e1000_phy_info  phy;
	struct e1000_nvm_info  nvm;
	struct e1000_bus_info  bus;
	struct e1000_mbx_info mbx;
	struct e1000_host_mng_dhcp_cookie mng_cookie;

	union {
		struct e1000_dev_spec_82575	_82575;
	} dev_spec;

	u16 device_id;
	u16 subsystem_vendor_id;
	u16 subsystem_device_id;
	u16 vendor_id;

	u8  revision_id;
};

/* klp-ccp: from drivers/net/ethernet/intel/igb/igb.h */
#include <linux/timecounter.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/bitops.h>
#include <linux/if_vlan.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>
#include <linux/pci.h>

#define IGB_START_ITR		648 /* ~6000 ints/sec */

#define MAX_Q_VECTORS		8
#define MAX_MSIX_ENTRIES	10

struct vf_mac_filter {
	struct list_head l;
	int vf;
	bool free;
	u8 vf_mac[ETH_ALEN];
};

struct igb_tx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 restart_queue;
	u64 restart_queue2;
};

struct igb_rx_queue_stats {
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 csum_err;
	u64 alloc_failed;
};

struct igb_ring_container {
	struct igb_ring *ring;		/* pointer to linked list of rings */
	unsigned int total_bytes;	/* total bytes processed this int */
	unsigned int total_packets;	/* total packets processed this int */
	u16 work_limit;			/* total work allowed per interrupt */
	u8 count;			/* total number of rings in vector */
	u8 itr;				/* current ITR setting for ring */
};

struct igb_ring {
	struct igb_q_vector *q_vector;	/* backlink to q_vector */
	struct net_device *netdev;	/* back pointer to net_device */
	struct device *dev;		/* device pointer for dma mapping */
	union {				/* array of buffer info structs */
		struct igb_tx_buffer *tx_buffer_info;
		struct igb_rx_buffer *rx_buffer_info;
	};
	void *desc;			/* descriptor ring memory */
	unsigned long flags;		/* ring specific flags */
	void __iomem *tail;		/* pointer to ring tail register */
	dma_addr_t dma;			/* phys address of the ring */
	unsigned int  size;		/* length of desc. ring in bytes */

	u16 count;			/* number of desc. in the ring */
	u8 queue_index;			/* logical index of the ring*/
	u8 reg_idx;			/* physical index of the ring */
	bool cbs_enable;		/* indicates if CBS is enabled */
	s32 idleslope;			/* idleSlope in kbps */
	s32 sendslope;			/* sendSlope in kbps */
	s32 hicredit;			/* hiCredit in bytes */
	s32 locredit;			/* loCredit in bytes */

	/* everything past this point are written often */
	u16 next_to_clean;
	u16 next_to_use;
	u16 next_to_alloc;

	union {
		/* TX */
		struct {
			struct igb_tx_queue_stats tx_stats;
			struct u64_stats_sync tx_syncp;
			struct u64_stats_sync tx_syncp2;
		};
		/* RX */
		struct {
			struct sk_buff *skb;
			struct igb_rx_queue_stats rx_stats;
			struct u64_stats_sync rx_syncp;
		};
	};
} ____cacheline_internodealigned_in_smp;

struct igb_q_vector {
	struct igb_adapter *adapter;	/* backlink */
	int cpu;			/* CPU for DCA */
	u32 eims_value;			/* EIMS mask value */

	u16 itr_val;
	u8 set_itr;
	void __iomem *itr_register;

	struct igb_ring_container rx, tx;

	struct napi_struct napi;
	struct rcu_head rcu;	/* to avoid race with update stats on free */
	char name[IFNAMSIZ + 9];

	/* for dynamic allocation of rings associated with this q_vector */
	struct igb_ring ring[0] ____cacheline_internodealigned_in_smp;
};

enum e1000_ring_flags_t {
	IGB_RING_FLAG_RX_3K_BUFFER,
	IGB_RING_FLAG_RX_BUILD_SKB_ENABLED,
	IGB_RING_FLAG_RX_SCTP_CSUM,
	IGB_RING_FLAG_RX_LB_VLAN_BSWAP,
	IGB_RING_FLAG_TX_CTX_IDX,
	IGB_RING_FLAG_TX_DETECT_HANG
};

#define MAX_ETYPE_FILTER	(4 - 1)

#define IGB_N_PEROUT	2
#define IGB_N_SDP	4
#define IGB_RETA_SIZE	128

struct igb_adapter {
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];

	struct net_device *netdev;

	unsigned long state;
	unsigned int flags;

	unsigned int num_q_vectors;
	struct msix_entry msix_entries[MAX_MSIX_ENTRIES];

	/* Interrupt Throttle Rate */
	u32 rx_itr_setting;
	u32 tx_itr_setting;
	u16 tx_itr;
	u16 rx_itr;

	/* TX */
	u16 tx_work_limit;
	u32 tx_timeout_count;
	int num_tx_queues;
	struct igb_ring *tx_ring[16];

	/* RX */
	int num_rx_queues;
	struct igb_ring *rx_ring[16];

	u32 max_frame_size;
	u32 min_frame_size;

	struct timer_list watchdog_timer;
	struct timer_list phy_info_timer;

	u16 mng_vlan_id;
	u32 bd_number;
	u32 wol;
	u32 en_mng_pt;
	u16 link_speed;
	u16 link_duplex;

	u8 __iomem *io_addr; /* Mainly for iounmap use */

	struct work_struct reset_task;
	struct work_struct watchdog_task;
	bool fc_autoneg;
	u8  tx_timeout_factor;
	struct timer_list blink_timer;
	unsigned long led_status;

	/* OS defined structs */
	struct pci_dev *pdev;

	spinlock_t stats64_lock;
	struct rtnl_link_stats64 stats64;

	/* structs defined in e1000_hw.h */
	struct e1000_hw hw;
	struct e1000_hw_stats stats;
	struct e1000_phy_info phy_info;

	u32 test_icr;
	struct igb_ring test_tx_ring;
	struct igb_ring test_rx_ring;

	int msg_enable;

	struct igb_q_vector *q_vector[MAX_Q_VECTORS];
	u32 eims_enable_mask;
	u32 eims_other;

	/* to not mess up cache alignment, always add to the bottom */
	u16 tx_ring_count;
	u16 rx_ring_count;
	unsigned int vfs_allocated_count;
	struct vf_data_storage *vf_data;
	int vf_rate_link_speed;
	u32 rss_queues;
	u32 wvbr;
	u32 *shadow_vfta;

	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_caps;
	struct delayed_work ptp_overflow_work;
	struct work_struct ptp_tx_work;
	struct sk_buff *ptp_tx_skb;
	struct hwtstamp_config tstamp_config;
	unsigned long ptp_tx_start;
	unsigned long last_rx_ptp_check;
	unsigned long last_rx_timestamp;
	unsigned int ptp_flags;
	spinlock_t tmreg_lock;
	struct cyclecounter cc;
	struct timecounter tc;
	u32 tx_hwtstamp_timeouts;
	u32 tx_hwtstamp_skipped;
	u32 rx_hwtstamp_cleared;
	bool pps_sys_wrap_on;

	struct ptp_pin_desc sdp_config[IGB_N_SDP];
	struct {
		struct timespec64 start;
		struct timespec64 period;
	} perout[IGB_N_PEROUT];

	char fw_version[32];
#ifdef CONFIG_IGB_HWMON
	struct hwmon_buff *igb_hwmon_buff;
	bool ets;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct i2c_algo_bit_data i2c_algo;
	struct i2c_adapter i2c_adap;
	struct i2c_client *i2c_client;
	u32 rss_indir_tbl_init;
	u8 rss_indir_tbl[IGB_RETA_SIZE];

	unsigned long link_check_timeout;
	int copper_tries;
	struct e1000_info ei;
	u16 eee_advert;

	/* RX network flow classification support */
	struct hlist_head nfc_filter_list;
	struct hlist_head cls_flower_list;
	unsigned int nfc_filter_count;
	/* lock for RX network flow classification filter */
	spinlock_t nfc_lock;
	bool etype_bitmap[MAX_ETYPE_FILTER];

	struct igb_mac_addr *mac_table;
	struct vf_mac_filter vf_macs;
	struct vf_mac_filter *vf_mac_list;
	/* lock for VF resources */
	spinlock_t vfs_lock;
};

/* klp-ccp: from drivers/net/ethernet/intel/igb/igb_main.c */
static int (*klpe_igb_poll)(struct napi_struct *, int);

#define Q_IDX_82576(i) (((i & 0x1) << 3) + (i >> 1))

static void igb_cache_ring_register(struct igb_adapter *adapter)
{
	int i = 0, j = 0;
	u32 rbase_offset = adapter->vfs_allocated_count;

	switch (adapter->hw.mac.type) {
	case e1000_82576:
		/* The queues are allocated for virtualization such that VF 0
		 * is allocated queues 0 and 8, VF 1 queues 1 and 9, etc.
		 * In order to avoid collision we start at the first free queue
		 * and continue consuming queues in the same sequence
		 */
		if (adapter->vfs_allocated_count) {
			for (; i < adapter->rss_queues; i++)
				adapter->rx_ring[i]->reg_idx = rbase_offset +
							       Q_IDX_82576(i);
		}
		/* Fall through */
	case e1000_82575:
	case e1000_82580:
	case e1000_i350:
	case e1000_i354:
	case e1000_i210:
	case e1000_i211:
		/* Fall through */
	default:
		for (; i < adapter->num_rx_queues; i++)
			adapter->rx_ring[i]->reg_idx = rbase_offset + i;
		for (; j < adapter->num_tx_queues; j++)
			adapter->tx_ring[j]->reg_idx = rbase_offset + j;
		break;
	}
}

static void igb_free_q_vector(struct igb_adapter *adapter, int v_idx)
{
	struct igb_q_vector *q_vector = adapter->q_vector[v_idx];

	adapter->q_vector[v_idx] = NULL;

	/* igb_get_stats64() might access the rings on this vector,
	 * we must wait a grace period before freeing it.
	 */
	if (q_vector)
		kfree_rcu(q_vector, rcu);
}

static void (*klpe_igb_reset_interrupt_capability)(struct igb_adapter *adapter);

static void (*klpe_igb_set_interrupt_capability)(struct igb_adapter *adapter, bool msix);

static void igb_add_ring(struct igb_ring *ring,
			 struct igb_ring_container *head)
{
	head->ring = ring;
	head->count++;
}

static int klpr_igb_alloc_q_vector(struct igb_adapter *adapter,
			      int v_count, int v_idx,
			      int txr_count, int txr_idx,
			      int rxr_count, int rxr_idx)
{
	struct igb_q_vector *q_vector;
	struct igb_ring *ring;
	int ring_count;
	size_t size;

	/* igb only supports 1 Tx and/or 1 Rx queue per vector */
	if (txr_count > 1 || rxr_count > 1)
		return -ENOMEM;

	ring_count = txr_count + rxr_count;
	size = struct_size(q_vector, ring, ring_count);

	/* allocate q_vector and rings */
	q_vector = adapter->q_vector[v_idx];
	if (!q_vector) {
		q_vector = kzalloc(size, GFP_KERNEL);
	} else if (size > ksize(q_vector)) {
		struct igb_q_vector *new_q_vector;

		new_q_vector = kzalloc(size, GFP_KERNEL);
		if (new_q_vector)
			kfree_rcu(q_vector, rcu);
		q_vector = new_q_vector;
	} else {
		memset(q_vector, 0, size);
	}
	if (!q_vector)
		return -ENOMEM;

	/* initialize NAPI */
	netif_napi_add(adapter->netdev, &q_vector->napi,
		       (*klpe_igb_poll), 64);

	/* tie q_vector and adapter together */
	adapter->q_vector[v_idx] = q_vector;
	q_vector->adapter = adapter;

	/* initialize work limits */
	q_vector->tx.work_limit = adapter->tx_work_limit;

	/* initialize ITR configuration */
	q_vector->itr_register = adapter->io_addr + E1000_EITR(0);
	q_vector->itr_val = IGB_START_ITR;

	/* initialize pointer to rings */
	ring = q_vector->ring;

	/* intialize ITR */
	if (rxr_count) {
		/* rx or rx/tx vector */
		if (!adapter->rx_itr_setting || adapter->rx_itr_setting > 3)
			q_vector->itr_val = adapter->rx_itr_setting;
	} else {
		/* tx only vector */
		if (!adapter->tx_itr_setting || adapter->tx_itr_setting > 3)
			q_vector->itr_val = adapter->tx_itr_setting;
	}

	if (txr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Tx values */
		igb_add_ring(ring, &q_vector->tx);

		/* For 82575, context index must be unique per ring. */
		if (adapter->hw.mac.type == e1000_82575)
			set_bit(IGB_RING_FLAG_TX_CTX_IDX, &ring->flags);

		/* apply Tx specific ring traits */
		ring->count = adapter->tx_ring_count;
		ring->queue_index = txr_idx;

		ring->cbs_enable = false;
		ring->idleslope = 0;
		ring->sendslope = 0;
		ring->hicredit = 0;
		ring->locredit = 0;

		u64_stats_init(&ring->tx_syncp);
		u64_stats_init(&ring->tx_syncp2);

		/* assign ring to adapter */
		adapter->tx_ring[txr_idx] = ring;

		/* push pointer to next ring */
		ring++;
	}

	if (rxr_count) {
		/* assign generic ring traits */
		ring->dev = &adapter->pdev->dev;
		ring->netdev = adapter->netdev;

		/* configure backlink on ring */
		ring->q_vector = q_vector;

		/* update q_vector Rx values */
		igb_add_ring(ring, &q_vector->rx);

		/* set flag indicating ring supports SCTP checksum offload */
		if (adapter->hw.mac.type >= e1000_82576)
			set_bit(IGB_RING_FLAG_RX_SCTP_CSUM, &ring->flags);

		/* On i350, i354, i210, and i211, loopback VLAN packets
		 * have the tag byte-swapped.
		 */
		if (adapter->hw.mac.type >= e1000_i350)
			set_bit(IGB_RING_FLAG_RX_LB_VLAN_BSWAP, &ring->flags);

		/* apply Rx specific ring traits */
		ring->count = adapter->rx_ring_count;
		ring->queue_index = rxr_idx;

		u64_stats_init(&ring->rx_syncp);

		/* assign ring to adapter */
		adapter->rx_ring[rxr_idx] = ring;
	}

	return 0;
}

static int klpr_igb_alloc_q_vectors(struct igb_adapter *adapter)
{
	int q_vectors = adapter->num_q_vectors;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int rxr_idx = 0, txr_idx = 0, v_idx = 0;
	int err;

	if (q_vectors >= (rxr_remaining + txr_remaining)) {
		for (; rxr_remaining; v_idx++) {
			err = klpr_igb_alloc_q_vector(adapter, q_vectors, v_idx,
						 0, 0, 1, rxr_idx);

			if (err)
				goto err_out;

			/* update counts and index */
			rxr_remaining--;
			rxr_idx++;
		}
	}

	for (; v_idx < q_vectors; v_idx++) {
		int rqpv = DIV_ROUND_UP(rxr_remaining, q_vectors - v_idx);
		int tqpv = DIV_ROUND_UP(txr_remaining, q_vectors - v_idx);

		err = klpr_igb_alloc_q_vector(adapter, q_vectors, v_idx,
					 tqpv, txr_idx, rqpv, rxr_idx);

		if (err)
			goto err_out;

		/* update counts and index */
		rxr_remaining -= rqpv;
		txr_remaining -= tqpv;
		rxr_idx++;
		txr_idx++;
	}

	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--)
		igb_free_q_vector(adapter, v_idx);

	return -ENOMEM;
}

int klpp_igb_init_interrupt_scheme(struct igb_adapter *adapter, bool msix)
{
	struct pci_dev *pdev = adapter->pdev;
	int err;

	(*klpe_igb_set_interrupt_capability)(adapter, msix);

	err = klpr_igb_alloc_q_vectors(adapter);
	if (err) {
		dev_err(&pdev->dev, "Unable to allocate memory for vectors\n");
		goto err_alloc_q_vectors;
	}

	igb_cache_ring_register(adapter);

	return 0;

err_alloc_q_vectors:
	(*klpe_igb_reset_interrupt_capability)(adapter);
	return err;
}

static int (*klpe_igb_poll)(struct napi_struct *napi, int budget);


#include "livepatch_bsc1249847.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "igb"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "igb_poll", (void *)&klpe_igb_poll, "igb" },
	{ "igb_reset_interrupt_capability",
	  (void *)&klpe_igb_reset_interrupt_capability, "igb" },
	{ "igb_set_interrupt_capability",
	  (void *)&klpe_igb_set_interrupt_capability, "igb" },
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

int livepatch_bsc1249847_init(void)
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

void livepatch_bsc1249847_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_IGB) */
