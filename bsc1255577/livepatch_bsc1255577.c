/*
 * livepatch_bsc1255577
 *
 * Fix for CVE-2022-50700, bsc#1255577
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_ATH10K)

#if !IS_MODULE(CONFIG_ATH10K)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/wireless/ath/ath10k/core.h */
#include <linux/completion.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/uuid.h>
#include <linux/time.h>

/* klp-ccp: from drivers/net/wireless/ath/ath10k/htt.h */
#include <linux/bug.h>
#include <linux/interrupt.h>
#include <linux/dmapool.h>

/* From hw.h */
#define WCN3990_HW_1_0_DEV_VERSION	ATH10K_HW_WCN3990

#define DECLARE_HASHTABLE(name, bits)                                   	\
	struct hlist_head name[1 << (bits)]

/* klp-ccp: from drivers/net/wireless/ath/ath10k/htt.h */
#include <linux/kfifo.h>
#include <net/mac80211.h>

/* klp-ccp: from drivers/net/wireless/ath/ath10k/htc.h */
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/skbuff.h>
#include <linux/timer.h>

struct ath10k;

struct ath10k_htc_hdr {
	u8 eid; /* @enum ath10k_htc_ep_id */
	u8 flags; /* @enum ath10k_htc_tx_flags, ath10k_htc_rx_flags */
	__le16 len;
	union {
		u8 trailer_len; /* for rx */
		u8 control_byte0;
	} __packed;
	union {
		u8 seq_no; /* for tx */
		u8 control_byte1;
	} __packed;
	u8 pad0;
	u8 pad1;
} __packed __aligned(4);

enum ath10k_htc_svc_gid {
	ATH10K_HTC_SVC_GRP_RSVD = 0,
	ATH10K_HTC_SVC_GRP_WMI = 1,
	ATH10K_HTC_SVC_GRP_NMI = 2,
	ATH10K_HTC_SVC_GRP_HTT = 3,
	ATH10K_LOG_SERVICE_GROUP = 6,

	ATH10K_HTC_SVC_GRP_TEST = 254,
	ATH10K_HTC_SVC_GRP_LAST = 255,
};

#define SVC(group, idx) \
	(int)(((int)(group) << 8) | (int)(idx))

enum ath10k_htc_svc_id {
	/* NOTE: service ID of 0x0000 is reserved and should never be used */
	ATH10K_HTC_SVC_ID_RESERVED	= 0x0000,
	ATH10K_HTC_SVC_ID_UNUSED	= ATH10K_HTC_SVC_ID_RESERVED,

	ATH10K_HTC_SVC_ID_RSVD_CTRL	= SVC(ATH10K_HTC_SVC_GRP_RSVD, 1),
	ATH10K_HTC_SVC_ID_WMI_CONTROL	= SVC(ATH10K_HTC_SVC_GRP_WMI, 0),
	ATH10K_HTC_SVC_ID_WMI_DATA_BE	= SVC(ATH10K_HTC_SVC_GRP_WMI, 1),
	ATH10K_HTC_SVC_ID_WMI_DATA_BK	= SVC(ATH10K_HTC_SVC_GRP_WMI, 2),
	ATH10K_HTC_SVC_ID_WMI_DATA_VI	= SVC(ATH10K_HTC_SVC_GRP_WMI, 3),
	ATH10K_HTC_SVC_ID_WMI_DATA_VO	= SVC(ATH10K_HTC_SVC_GRP_WMI, 4),

	ATH10K_HTC_SVC_ID_NMI_CONTROL	= SVC(ATH10K_HTC_SVC_GRP_NMI, 0),
	ATH10K_HTC_SVC_ID_NMI_DATA	= SVC(ATH10K_HTC_SVC_GRP_NMI, 1),

	ATH10K_HTC_SVC_ID_HTT_DATA_MSG	= SVC(ATH10K_HTC_SVC_GRP_HTT, 0),

	ATH10K_HTC_SVC_ID_HTT_DATA2_MSG = SVC(ATH10K_HTC_SVC_GRP_HTT, 1),
	ATH10K_HTC_SVC_ID_HTT_DATA3_MSG = SVC(ATH10K_HTC_SVC_GRP_HTT, 2),
	ATH10K_HTC_SVC_ID_HTT_LOG_MSG = SVC(ATH10K_LOG_SERVICE_GROUP, 0),
	/* raw stream service (i.e. flash, tcmd, calibration apps) */
	ATH10K_HTC_SVC_ID_TEST_RAW_STREAMS = SVC(ATH10K_HTC_SVC_GRP_TEST, 0),
};

enum ath10k_htc_ep_id {
	ATH10K_HTC_EP_UNUSED = -1,
	ATH10K_HTC_EP_0 = 0,
	ATH10K_HTC_EP_1 = 1,
	ATH10K_HTC_EP_2,
	ATH10K_HTC_EP_3,
	ATH10K_HTC_EP_4,
	ATH10K_HTC_EP_5,
	ATH10K_HTC_EP_6,
	ATH10K_HTC_EP_7,
	ATH10K_HTC_EP_8,
	ATH10K_HTC_EP_COUNT,
};

struct ath10k_htc_ops {
	void (*target_send_suspend_complete)(struct ath10k *ar);
};

struct ath10k_htc_ep_ops {
	void (*ep_tx_complete)(struct ath10k *, struct sk_buff *);
	void (*ep_rx_complete)(struct ath10k *, struct sk_buff *);
	void (*ep_tx_credits)(struct ath10k *);
};

#define ATH10K_HTC_MAX_CTRL_MSG_LEN 256

struct ath10k_htc_ep {
	struct ath10k_htc *htc;
	enum ath10k_htc_ep_id eid;
	enum ath10k_htc_svc_id service_id;
	struct ath10k_htc_ep_ops ep_ops;

	int max_tx_queue_depth;
	int max_ep_message_len;
	u8 ul_pipe_id;
	u8 dl_pipe_id;

	u8 seq_no; /* for debugging */
	int tx_credits;
	bool tx_credit_flow_enabled;
};

struct ath10k_htc {
	struct ath10k *ar;
	struct ath10k_htc_ep endpoint[ATH10K_HTC_EP_COUNT];

	/* protects endpoints */
	spinlock_t tx_lock;

	struct ath10k_htc_ops htc_ops;

	u8 control_resp_buffer[ATH10K_HTC_MAX_CTRL_MSG_LEN];
	int control_resp_len;

	struct completion ctl_resp;

	int total_transmit_credits;
	int target_credit_size;
	u8 max_msgs_per_htc_bundle;
};


/* klp-ccp: from drivers/net/wireless/ath/ath10k/hw.h */
enum ath10k_fw_wmi_op_version {
	ATH10K_FW_WMI_OP_VERSION_UNSET = 0,

	ATH10K_FW_WMI_OP_VERSION_MAIN = 1,
	ATH10K_FW_WMI_OP_VERSION_10_1 = 2,
	ATH10K_FW_WMI_OP_VERSION_10_2 = 3,
	ATH10K_FW_WMI_OP_VERSION_TLV = 4,
	ATH10K_FW_WMI_OP_VERSION_10_2_4 = 5,
	ATH10K_FW_WMI_OP_VERSION_10_4 = 6,

	/* keep last */
	ATH10K_FW_WMI_OP_VERSION_MAX,
};

enum ath10k_fw_htt_op_version {
	ATH10K_FW_HTT_OP_VERSION_UNSET = 0,

	ATH10K_FW_HTT_OP_VERSION_MAIN = 1,

	/* also used in 10.2 and 10.2.4 branches */
	ATH10K_FW_HTT_OP_VERSION_10_1 = 2,

	ATH10K_FW_HTT_OP_VERSION_TLV = 3,

	ATH10K_FW_HTT_OP_VERSION_10_4 = 4,

	/* keep last */
	ATH10K_FW_HTT_OP_VERSION_MAX,
};

enum ath10k_hw_rev {
	ATH10K_HW_QCA988X,
	ATH10K_HW_QCA6174,
	ATH10K_HW_QCA99X0,
	ATH10K_HW_QCA9888,
	ATH10K_HW_QCA9984,
	ATH10K_HW_QCA9377,
	ATH10K_HW_QCA4019,
	ATH10K_HW_QCA9887,
	ATH10K_HW_WCN3990,
};

enum ath10k_hw_cc_wraparound_type {
	ATH10K_HW_CC_WRAP_DISABLED = 0,

	/* This type is when the HW chip has a quirky Cycle Counter
	 * wraparound which resets to 0x7fffffff instead of 0. All
	 * other CC related counters (e.g. Rx Clear Count) are divided
	 * by 2 so they never wraparound themselves.
	 */
	ATH10K_HW_CC_WRAP_SHIFTED_ALL = 1,

	/* Each hw counter wrapsaround independently. When the
	 * counter overflows the repestive counter is right shifted
	 * by 1, i.e reset to 0x7fffffff, and other counters will be
	 * running unaffected. In this type of wraparound, it should
	 * be possible to report accurate Rx busy time unlike the
	 * first type.
	 */
	ATH10K_HW_CC_WRAP_SHIFTED_EACH = 2,
};

struct ath10k_hw_params {
	u32 id;
	u16 dev_id;
	const char *name;
	u32 patch_load_addr;
	int uart_pin;
	u32 otp_exe_param;

	/* Type of hw cycle counter wraparound logic, for more info
	 * refer enum ath10k_hw_cc_wraparound_type.
	 */
	enum ath10k_hw_cc_wraparound_type cc_wraparound_type;

	/* Some of chip expects fragment descriptor to be continuous
	 * memory for any TX operation. Set continuous_frag_desc flag
	 * for the hardware which have such requirement.
	 */
	bool continuous_frag_desc;

	/* CCK hardware rate table mapping for the newer chipsets
	 * like QCA99X0, QCA4019 got revised. The CCK h/w rate values
	 * are in a proper order with respect to the rate/preamble
	 */
	bool cck_rate_map_rev2;

	u32 channel_counters_freq_hz;

	/* Mgmt tx descriptors threshold for limiting probe response
	 * frames.
	 */
	u32 max_probe_resp_desc_thres;

	u32 tx_chain_mask;
	u32 rx_chain_mask;
	u32 max_spatial_stream;
	u32 cal_data_len;

	struct ath10k_hw_params_fw {
		const char *dir;
		const char *board;
		size_t board_size;
		size_t board_ext_size;
	} fw;

	/* qca99x0 family chips deliver broadcast/multicast management
	 * frames encrypted and expect software do decryption.
	 */
	bool sw_decrypt_mcast_mgmt;

	const struct ath10k_hw_ops *hw_ops;

	/* Number of bytes used for alignment in rx_hdr_status of rx desc. */
	int decap_align_bytes;

	/* hw specific clock control parameters */
	const struct ath10k_hw_clk_params *hw_clk;
	int target_cpu_freq;

	/* Number of bytes to be discarded for each FFT sample */
	int spectral_bin_discard;

	/* The board may have a restricted NSS for 160 or 80+80 vs what it
	 * can do for 80Mhz.
	 */
	int vht160_mcs_rx_highest;
	int vht160_mcs_tx_highest;

	/* Number of ciphers supported (i.e First N) in cipher_suites array */
	int n_cipher_suites;

	u32 num_peers;
	u32 ast_skid_limit;
	u32 num_wds_entries;

	/* Targets supporting physical addressing capability above 32-bits */
	bool target_64bit;

	/* Target rx ring fill level */
	u32 rx_ring_fill_level;

	/* target supporting per ce IRQ */
	bool per_ce_irq;

	/* target supporting shadow register for ce write */
	bool shadow_reg_support;

	/* target supporting retention restore on ddr */
	bool rri_on_ddr;

	/* Number of bytes to be the offset for each FFT sample */
	int spectral_bin_offset;

#ifndef __GENKSYMS__
	bool hw_filter_reset_required;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

/* klp-ccp: from drivers/net/wireless/ath/ath10k/rx_desc.h */
#include <linux/bitops.h>

/* klp-ccp: from drivers/net/wireless/ath/ath10k/htt.h */
enum htt_q_depth_type {
	HTT_Q_DEPTH_TYPE_BYTES = 0,
	HTT_Q_DEPTH_TYPE_MSDUS = 1,
};

enum htt_tx_mode_switch_mode {
	HTT_TX_MODE_SWITCH_PUSH = 0,
	HTT_TX_MODE_SWITCH_PUSH_PULL = 1,
};

struct htt_tx_done {
	u16 msdu_id;
	u16 status;
	u8 ack_rssi;
};

struct ath10k_htt {
	struct ath10k *ar;
	enum ath10k_htc_ep_id eid;

	u8 target_version_major;
	u8 target_version_minor;
	struct completion target_version_received;
	u8 max_num_amsdu;
	u8 max_num_ampdu;

	const enum htt_t2h_msg_type *t2h_msg_types;
	u32 t2h_msg_types_max;

	struct {
		/*
		 * Ring of network buffer objects - This ring is
		 * used exclusively by the host SW. This ring
		 * mirrors the dev_addrs_ring that is shared
		 * between the host SW and the MAC HW. The host SW
		 * uses this netbufs ring to locate the network
		 * buffer objects whose data buffers the HW has
		 * filled.
		 */
		struct sk_buff **netbufs_ring;

		/* This is used only with firmware supporting IN_ORD_IND.
		 *
		 * With Full Rx Reorder the HTT Rx Ring is more of a temporary
		 * buffer ring from which buffer addresses are copied by the
		 * firmware to MAC Rx ring. Firmware then delivers IN_ORD_IND
		 * pointing to specific (re-ordered) buffers.
		 *
		 * FIXME: With kernel generic hashing functions there's a lot
		 * of hash collisions for sk_buffs.
		 */
		bool in_ord_rx;
		DECLARE_HASHTABLE(skb_table, 4);

		/*
		 * Ring of buffer addresses -
		 * This ring holds the "physical" device address of the
		 * rx buffers the host SW provides for the MAC HW to
		 * fill.
		 */
		union {
			__le64 *paddrs_ring_64;
			__le32 *paddrs_ring_32;
		};

		/*
		 * Base address of ring, as a "physical" device address
		 * rather than a CPU address.
		 */
		dma_addr_t base_paddr;

		/* how many elems in the ring (power of 2) */
		int size;

		/* size - 1 */
		unsigned int size_mask;

		/* how many rx buffers to keep in the ring */
		int fill_level;

		/* how many rx buffers (full+empty) are in the ring */
		int fill_cnt;

		/*
		 * alloc_idx - where HTT SW has deposited empty buffers
		 * This is allocated in consistent mem, so that the FW can
		 * read this variable, and program the HW's FW_IDX reg with
		 * the value of this shadow register.
		 */
		struct {
			__le32 *vaddr;
			dma_addr_t paddr;
		} alloc_idx;

		/* where HTT SW has processed bufs filled by rx MAC DMA */
		struct {
			unsigned int msdu_payld;
		} sw_rd_idx;

		/*
		 * refill_retry_timer - timer triggered when the ring is
		 * not refilled to the level expected
		 */
		struct timer_list refill_retry_timer;

		/* Protects access to all rx ring buffer state variables */
		spinlock_t lock;
	} rx_ring;

	unsigned int prefetch_len;

	/* Protects access to pending_tx, num_pending_tx */
	spinlock_t tx_lock;
	int max_num_pending_tx;
	int num_pending_tx;
	int num_pending_mgmt_tx;
	struct idr pending_tx;
	wait_queue_head_t empty_tx_wq;

	/* FIFO for storing tx done status {ack, no-ack, discard} and msdu id */
	DECLARE_KFIFO_PTR(txdone_fifo, struct htt_tx_done);

	/* set if host-fw communication goes haywire
	 * used to avoid further failures
	 */
	bool rx_confused;
	atomic_t num_mpdus_ready;

	/* This is used to group tx/rx completions separately and process them
	 * in batches to reduce cache stalls
	 */
	struct sk_buff_head rx_msdus_q;
	struct sk_buff_head rx_in_ord_compl_q;
	struct sk_buff_head tx_fetch_ind_q;

	/* rx_status template */
	struct ieee80211_rx_status rx_status;

	struct {
		dma_addr_t paddr;
		union {
			struct htt_msdu_ext_desc *vaddr_desc_32;
			struct htt_msdu_ext_desc_64 *vaddr_desc_64;
		};
		size_t size;
	} frag_desc;

	struct {
		dma_addr_t paddr;
		union {
			struct ath10k_htt_txbuf_32 *vaddr_txbuff_32;
			struct ath10k_htt_txbuf_64 *vaddr_txbuff_64;
		};
		size_t size;
	} txbuf;

	struct {
		bool enabled;
		struct htt_q_state *vaddr;
		dma_addr_t paddr;
		u16 num_push_allowed;
		u16 num_peers;
		u16 num_tids;
		enum htt_tx_mode_switch_mode mode;
		enum htt_q_depth_type type;
	} tx_q_state;

	bool tx_mem_allocated;
	const struct ath10k_htt_tx_ops *tx_ops;
	const struct ath10k_htt_rx_ops *rx_ops;
};

/* klp-ccp: from drivers/net/wireless/ath/ath10k/wmi.h */
#include <linux/types.h>
#include <net/mac80211.h>

enum wmi_service {
	WMI_SERVICE_BEACON_OFFLOAD = 0,
	WMI_SERVICE_SCAN_OFFLOAD,
	WMI_SERVICE_ROAM_OFFLOAD,
	WMI_SERVICE_BCN_MISS_OFFLOAD,
	WMI_SERVICE_STA_PWRSAVE,
	WMI_SERVICE_STA_ADVANCED_PWRSAVE,
	WMI_SERVICE_AP_UAPSD,
	WMI_SERVICE_AP_DFS,
	WMI_SERVICE_11AC,
	WMI_SERVICE_BLOCKACK,
	WMI_SERVICE_PHYERR,
	WMI_SERVICE_BCN_FILTER,
	WMI_SERVICE_RTT,
	WMI_SERVICE_RATECTRL,
	WMI_SERVICE_WOW,
	WMI_SERVICE_RATECTRL_CACHE,
	WMI_SERVICE_IRAM_TIDS,
	WMI_SERVICE_ARPNS_OFFLOAD,
	WMI_SERVICE_NLO,
	WMI_SERVICE_GTK_OFFLOAD,
	WMI_SERVICE_SCAN_SCH,
	WMI_SERVICE_CSA_OFFLOAD,
	WMI_SERVICE_CHATTER,
	WMI_SERVICE_COEX_FREQAVOID,
	WMI_SERVICE_PACKET_POWER_SAVE,
	WMI_SERVICE_FORCE_FW_HANG,
	WMI_SERVICE_GPIO,
	WMI_SERVICE_STA_DTIM_PS_MODULATED_DTIM,
	WMI_SERVICE_STA_UAPSD_BASIC_AUTO_TRIG,
	WMI_SERVICE_STA_UAPSD_VAR_AUTO_TRIG,
	WMI_SERVICE_STA_KEEP_ALIVE,
	WMI_SERVICE_TX_ENCAP,
	WMI_SERVICE_BURST,
	WMI_SERVICE_SMART_ANTENNA_SW_SUPPORT,
	WMI_SERVICE_SMART_ANTENNA_HW_SUPPORT,
	WMI_SERVICE_ROAM_SCAN_OFFLOAD,
	WMI_SERVICE_AP_PS_DETECT_OUT_OF_SYNC,
	WMI_SERVICE_EARLY_RX,
	WMI_SERVICE_STA_SMPS,
	WMI_SERVICE_FWTEST,
	WMI_SERVICE_STA_WMMAC,
	WMI_SERVICE_TDLS,
	WMI_SERVICE_MCC_BCN_INTERVAL_CHANGE,
	WMI_SERVICE_ADAPTIVE_OCS,
	WMI_SERVICE_BA_SSN_SUPPORT,
	WMI_SERVICE_FILTER_IPSEC_NATKEEPALIVE,
	WMI_SERVICE_WLAN_HB,
	WMI_SERVICE_LTE_ANT_SHARE_SUPPORT,
	WMI_SERVICE_BATCH_SCAN,
	WMI_SERVICE_QPOWER,
	WMI_SERVICE_PLMREQ,
	WMI_SERVICE_THERMAL_MGMT,
	WMI_SERVICE_RMC,
	WMI_SERVICE_MHF_OFFLOAD,
	WMI_SERVICE_COEX_SAR,
	WMI_SERVICE_BCN_TXRATE_OVERRIDE,
	WMI_SERVICE_NAN,
	WMI_SERVICE_L1SS_STAT,
	WMI_SERVICE_ESTIMATE_LINKSPEED,
	WMI_SERVICE_OBSS_SCAN,
	WMI_SERVICE_TDLS_OFFCHAN,
	WMI_SERVICE_TDLS_UAPSD_BUFFER_STA,
	WMI_SERVICE_TDLS_UAPSD_SLEEP_STA,
	WMI_SERVICE_IBSS_PWRSAVE,
	WMI_SERVICE_LPASS,
	WMI_SERVICE_EXTSCAN,
	WMI_SERVICE_D0WOW,
	WMI_SERVICE_HSOFFLOAD,
	WMI_SERVICE_ROAM_HO_OFFLOAD,
	WMI_SERVICE_RX_FULL_REORDER,
	WMI_SERVICE_DHCP_OFFLOAD,
	WMI_SERVICE_STA_RX_IPA_OFFLOAD_SUPPORT,
	WMI_SERVICE_MDNS_OFFLOAD,
	WMI_SERVICE_SAP_AUTH_OFFLOAD,
	WMI_SERVICE_ATF,
	WMI_SERVICE_COEX_GPIO,
	WMI_SERVICE_ENHANCED_PROXY_STA,
	WMI_SERVICE_TT,
	WMI_SERVICE_PEER_CACHING,
	WMI_SERVICE_AUX_SPECTRAL_INTF,
	WMI_SERVICE_AUX_CHAN_LOAD_INTF,
	WMI_SERVICE_BSS_CHANNEL_INFO_64,
	WMI_SERVICE_EXT_RES_CFG_SUPPORT,
	WMI_SERVICE_MESH_11S,
	WMI_SERVICE_MESH_NON_11S,
	WMI_SERVICE_PEER_STATS,
	WMI_SERVICE_RESTRT_CHNL_SUPPORT,
	WMI_SERVICE_PERIODIC_CHAN_STAT_SUPPORT,
	WMI_SERVICE_TX_MODE_PUSH_ONLY,
	WMI_SERVICE_TX_MODE_PUSH_PULL,
	WMI_SERVICE_TX_MODE_DYNAMIC,
	WMI_SERVICE_VDEV_RX_FILTER,
	WMI_SERVICE_BTCOEX,
	WMI_SERVICE_CHECK_CAL_VERSION,
	WMI_SERVICE_DBGLOG_WARN2,
	WMI_SERVICE_BTCOEX_DUTY_CYCLE,
	WMI_SERVICE_4_WIRE_COEX_SUPPORT,
	WMI_SERVICE_EXTENDED_NSS_SUPPORT,
	WMI_SERVICE_PROG_GPIO_BAND_SELECT,
	WMI_SERVICE_SMART_LOGGING_SUPPORT,
	WMI_SERVICE_TDLS_CONN_TRACKER_IN_HOST_MODE,
	WMI_SERVICE_TDLS_EXPLICIT_MODE_ONLY,
	WMI_SERVICE_MGMT_TX_WMI,
	WMI_SERVICE_TDLS_WIDER_BANDWIDTH,
	WMI_SERVICE_HTT_MGMT_TX_COMP_VALID_FLAGS,
	WMI_SERVICE_HOST_DFS_CHECK_SUPPORT,
	WMI_SERVICE_TPC_STATS_FINAL,
	WMI_SERVICE_RESET_CHIP,
	WMI_SERVICE_SPOOF_MAC_SUPPORT,

	/* keep last */
	WMI_SERVICE_MAX,
};

#define WMI_MAX_MEM_REQS 16

/* klp-ccp: from drivers/net/wireless/ath/ath.h */
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <net/mac80211.h>

#define	ATH_KEYMAX	        128     /* max key cache size we handle */

struct ath_ani {
	bool caldone;
	unsigned int longcal_timer;
	unsigned int shortcal_timer;
	unsigned int resetcal_timer;
	unsigned int checkani_timer;
	struct timer_list timer;
};

struct ath_cycle_counters {
	u32 cycles;
	u32 rx_busy;
	u32 rx_frame;
	u32 tx_frame;
};

enum ath_device_state {
	ATH_HW_UNAVAILABLE,
	ATH_HW_INITIALIZED,
};

struct ath_regulatory {
	char alpha2[2];
	enum nl80211_dfs_regions region;
	u16 country_code;
	u16 max_power_level;
	u16 current_rd;
	int16_t power_limit;
	struct reg_dmn_pair_mapping *regpair;
};

enum ath_crypt_caps {
	ATH_CRYPT_CAP_CIPHER_AESCCM		= BIT(0),
	ATH_CRYPT_CAP_MIC_COMBINED		= BIT(1),
};

struct ath_common {
	void *ah;
	void *priv;
	struct ieee80211_hw *hw;
	int debug_mask;
	enum ath_device_state state;
	unsigned long op_flags;

	struct ath_ani ani;

	u16 cachelsz;
	u16 curaid;
	u8 macaddr[ETH_ALEN];
	u8 curbssid[ETH_ALEN] __aligned(2);
	u8 bssidmask[ETH_ALEN];

	u32 rx_bufsize;

	u32 keymax;
	DECLARE_BITMAP(keymap, ATH_KEYMAX);
	DECLARE_BITMAP(tkip_keymap, ATH_KEYMAX);
	DECLARE_BITMAP(ccmp_keymap, ATH_KEYMAX);
	enum ath_crypt_caps crypt_caps;

	unsigned int clockrate;

	spinlock_t cc_lock;
	struct ath_cycle_counters cc_ani;
	struct ath_cycle_counters cc_survey;

	struct ath_regulatory regulatory;
	struct ath_regulatory reg_world_copy;
	const struct ath_ops *ops;
	const struct ath_bus_ops *bus_ops;
	const struct ath_ps_ops *ps_ops;

	bool btcoex_enabled;
	bool disable_ani;
	bool bt_ant_diversity;

	int last_rssi;
	struct ieee80211_supported_band sbands[NUM_NL80211_BANDS];
};

/* klp-ccp: from drivers/net/wireless/ath/regd.h */
#include <linux/nl80211.h>
#include <net/cfg80211.h>

/* klp-ccp: from drivers/net/wireless/ath/dfs_pattern_detector.h */
#include <linux/types.h>
#include <linux/list.h>
#include <linux/nl80211.h>

/* klp-ccp: from drivers/net/wireless/ath/ath10k/thermal.h */
struct ath10k_thermal {
	struct thermal_cooling_device *cdev;
	struct completion wmi_sync;

	/* protected by conf_mutex */
	u32 throttle_state;
	u32 quiet_period;
	/* temperature value in Celcius degree
	 * protected by data_lock
	 */
	int temperature;
};

/* klp-ccp: from drivers/net/wireless/ath/ath10k/wow.h */
struct ath10k_wow {
	u32 max_num_patterns;
	struct completion wakeup_completed;
	struct wiphy_wowlan_support wowlan_support;
};

/* klp-ccp: from drivers/net/wireless/ath/ath10k/core.h */
#define ATH10K_NUM_CHANS 41

#define ATH10K_SMBIOS_BDF_EXT_STR_LENGTH 0x20

enum ath10k_bus {
	ATH10K_BUS_PCI,
	ATH10K_BUS_AHB,
	ATH10K_BUS_SDIO,
	ATH10K_BUS_USB,
	ATH10K_BUS_SNOC,
};

struct ath10k_skb_cb {
	dma_addr_t paddr;
	u8 flags;
	u8 eid;
	u16 msdu_id;
	struct ieee80211_vif *vif;
	struct ieee80211_txq *txq;
} __packed;

static inline struct ath10k_skb_cb *ATH10K_SKB_CB(struct sk_buff *skb)
{
	BUILD_BUG_ON(sizeof(struct ath10k_skb_cb) >
		     IEEE80211_TX_INFO_DRIVER_DATA_SIZE);
	return (struct ath10k_skb_cb *)&IEEE80211_SKB_CB(skb)->driver_data;
}

struct ath10k_bmi {
	bool done_sent;
};

struct ath10k_mem_chunk {
	void *vaddr;
	dma_addr_t paddr;
	u32 len;
	u32 req_id;
};

struct ath10k_wmi {
	enum ath10k_htc_ep_id eid;
	struct completion service_ready;
	struct completion unified_ready;
	struct completion barrier;
	struct completion radar_confirm;
	wait_queue_head_t tx_credits_wq;
	DECLARE_BITMAP(svc_map, WMI_SERVICE_MAX);
	struct wmi_cmd_map *cmd;
	struct wmi_vdev_param_map *vdev_param;
	struct wmi_pdev_param_map *pdev_param;
	const struct wmi_ops *ops;
	const struct wmi_peer_flags_map *peer_flags;

	u32 mgmt_max_num_pending_tx;

	/* Protected by data_lock */
	struct idr mgmt_pending_tx;

	u32 num_mem_chunks;
	u32 rx_decap_mode;
	struct ath10k_mem_chunk mem_chunks[WMI_MAX_MEM_REQS];
};

enum ath10k_radar_confirmation_state {
	ATH10K_RADAR_CONFIRMATION_IDLE = 0,
	ATH10K_RADAR_CONFIRMATION_INPROGRESS,
	ATH10K_RADAR_CONFIRMATION_STOPPED,
};

struct ath10k_radar_found_info {
	u32 pri_min;
	u32 pri_max;
	u32 width_min;
	u32 width_max;
	u32 sidx_min;
	u32 sidx_max;
};

#define ATH10K_MAX_NUM_PEER_IDS (1 << 11) /* htt rx_desc limit */

enum ath10k_state {
	ATH10K_STATE_OFF = 0,
	ATH10K_STATE_ON,

	/* When doing firmware recovery the device is first powered down.
	 * mac80211 is supposed to call in to start() hook later on. It is
	 * however possible that driver unloading and firmware crash overlap.
	 * mac80211 can wait on conf_mutex in stop() while the device is
	 * stopped in ath10k_core_restart() work holding conf_mutex. The state
	 * RESTARTED means that the device is up and mac80211 has started hw
	 * reconfiguration. Once mac80211 is done with the reconfiguration we
	 * set the state to STATE_ON in reconfig_complete().
	 */
	ATH10K_STATE_RESTARTING,
	ATH10K_STATE_RESTARTED,

	/* The device has crashed while restarting hw. This state is like ON
	 * but commands are blocked in HTC and -ECOMM response is given. This
	 * prevents completion timeouts and makes the driver more responsive to
	 * userspace commands. This is also prevents recursive recovery.
	 */
	ATH10K_STATE_WEDGED,

	/* factory tests */
	ATH10K_STATE_UTF,
};

enum ath10k_fw_features {
	/* wmi_mgmt_rx_hdr contains extra RSSI information */
	ATH10K_FW_FEATURE_EXT_WMI_MGMT_RX = 0,

	/* Firmware from 10X branch. Deprecated, don't use in new code. */
	ATH10K_FW_FEATURE_WMI_10X = 1,

	/* firmware support tx frame management over WMI, otherwise it's HTT */
	ATH10K_FW_FEATURE_HAS_WMI_MGMT_TX = 2,

	/* Firmware does not support P2P */
	ATH10K_FW_FEATURE_NO_P2P = 3,

	/* Firmware 10.2 feature bit. The ATH10K_FW_FEATURE_WMI_10X feature
	 * bit is required to be set as well. Deprecated, don't use in new
	 * code.
	 */
	ATH10K_FW_FEATURE_WMI_10_2 = 4,

	/* Some firmware revisions lack proper multi-interface client powersave
	 * implementation. Enabling PS could result in connection drops,
	 * traffic stalls, etc.
	 */
	ATH10K_FW_FEATURE_MULTI_VIF_PS_SUPPORT = 5,

	/* Some firmware revisions have an incomplete WoWLAN implementation
	 * despite WMI service bit being advertised. This feature flag is used
	 * to distinguish whether WoWLAN is really supported or not.
	 */
	ATH10K_FW_FEATURE_WOWLAN_SUPPORT = 6,

	/* Don't trust error code from otp.bin */
	ATH10K_FW_FEATURE_IGNORE_OTP_RESULT = 7,

	/* Some firmware revisions pad 4th hw address to 4 byte boundary making
	 * it 8 bytes long in Native Wifi Rx decap.
	 */
	ATH10K_FW_FEATURE_NO_NWIFI_DECAP_4ADDR_PADDING = 8,

	/* Firmware supports bypassing PLL setting on init. */
	ATH10K_FW_FEATURE_SUPPORTS_SKIP_CLOCK_INIT = 9,

	/* Raw mode support. If supported, FW supports receiving and trasmitting
	 * frames in raw mode.
	 */
	ATH10K_FW_FEATURE_RAW_MODE_SUPPORT = 10,

	/* Firmware Supports Adaptive CCA*/
	ATH10K_FW_FEATURE_SUPPORTS_ADAPTIVE_CCA = 11,

	/* Firmware supports management frame protection */
	ATH10K_FW_FEATURE_MFP_SUPPORT = 12,

	/* Firmware supports pull-push model where host shares it's software
	 * queue state with firmware and firmware generates fetch requests
	 * telling host which queues to dequeue tx from.
	 *
	 * Primary function of this is improved MU-MIMO performance with
	 * multiple clients.
	 */
	ATH10K_FW_FEATURE_PEER_FLOW_CONTROL = 13,

	/* Firmware supports BT-Coex without reloading firmware via pdev param.
	 * To support Bluetooth coexistence pdev param, WMI_COEX_GPIO_SUPPORT of
	 * extended resource config should be enabled always. This firmware IE
	 * is used to configure WMI_COEX_GPIO_SUPPORT.
	 */
	ATH10K_FW_FEATURE_BTCOEX_PARAM = 14,

	/* Unused flag and proven to be not working, enable this if you want
	 * to experiment sending NULL func data frames in HTT TX
	 */
	ATH10K_FW_FEATURE_SKIP_NULL_FUNC_WAR = 15,

	/* Firmware allow other BSS mesh broadcast/multicast frames without
	 * creating monitor interface. Appropriate rxfilters are programmed for
	 * mesh vdev by firmware itself. This feature flags will be used for
	 * not creating monitor vdev while configuring mesh node.
	 */
	ATH10K_FW_FEATURE_ALLOWS_MESH_BCAST = 16,

	/* Firmware does not support power save in station mode. */
	ATH10K_FW_FEATURE_NO_PS = 17,

	/* Firmware allows management tx by reference instead of by value. */
	ATH10K_FW_FEATURE_MGMT_TX_BY_REF = 18,

	/* Firmware load is done externally, not by bmi */
	ATH10K_FW_FEATURE_NON_BMI = 19,

	/* keep last */
	ATH10K_FW_FEATURE_COUNT,
};

enum ath10k_cal_mode {
	ATH10K_CAL_MODE_FILE,
	ATH10K_CAL_MODE_OTP,
	ATH10K_CAL_MODE_DT,
	ATH10K_PRE_CAL_MODE_FILE,
	ATH10K_PRE_CAL_MODE_DT,
	ATH10K_CAL_MODE_EEPROM,
};

enum ath10k_scan_state {
	ATH10K_SCAN_IDLE,
	ATH10K_SCAN_STARTING,
	ATH10K_SCAN_RUNNING,
	ATH10K_SCAN_ABORTING,
};

struct ath10k_fw_file {
	const struct firmware *firmware;

	char fw_version[ETHTOOL_FWVERS_LEN];

	DECLARE_BITMAP(fw_features, ATH10K_FW_FEATURE_COUNT);

	enum ath10k_fw_wmi_op_version wmi_op_version;
	enum ath10k_fw_htt_op_version htt_op_version;

	const void *firmware_data;
	size_t firmware_len;

	const void *otp_data;
	size_t otp_len;

	const void *codeswap_data;
	size_t codeswap_len;

	/* The original idea of struct ath10k_fw_file was that it only
	 * contains struct firmware and pointers to various parts (actual
	 * firmware binary, otp, metadata etc) of the file. This seg_info
	 * is actually created separate but as this is used similarly as
	 * the other firmware components it's more convenient to have it
	 * here.
	 */
	struct ath10k_swap_code_seg_info *firmware_swap_code_seg_info;
};

struct ath10k_fw_components {
	const struct firmware *board;
	const void *board_data;
	size_t board_len;

	struct ath10k_fw_file fw_file;
};

struct ath10k_per_peer_tx_stats {
	u32	succ_bytes;
	u32	retry_bytes;
	u32	failed_bytes;
	u8	ratecode;
	u8	flags;
	u16	peer_id;
	u16	succ_pkts;
	u16	retry_pkts;
	u16	failed_pkts;
	u16	duration;
	u32	reserved1;
	u32	reserved2;
};

struct ath10k {
	struct ath_common ath_common;
	struct ieee80211_hw *hw;
	struct ieee80211_ops *ops;
	struct device *dev;
	u8 mac_addr[ETH_ALEN];

	enum ath10k_hw_rev hw_rev;
	u16 dev_id;
	u32 chip_id;
	u32 target_version;
	u8 fw_version_major;
	u32 fw_version_minor;
	u16 fw_version_release;
	u16 fw_version_build;
	u32 fw_stats_req_mask;
	u32 phy_capability;
	u32 hw_min_tx_power;
	u32 hw_max_tx_power;
	u32 hw_eeprom_rd;
	u32 ht_cap_info;
	u32 vht_cap_info;
	u32 num_rf_chains;
	u32 max_spatial_stream;
	/* protected by conf_mutex */
	u32 low_5ghz_chan;
	u32 high_5ghz_chan;
	bool ani_enabled;

	bool p2p;

	struct {
		enum ath10k_bus bus;
		const struct ath10k_hif_ops *ops;
	} hif;

	struct completion target_suspend;

	const struct ath10k_hw_regs *regs;
	const struct ath10k_hw_ce_regs *hw_ce_regs;
	const struct ath10k_hw_values *hw_values;
	struct ath10k_bmi bmi;
	struct ath10k_wmi wmi;
	struct ath10k_htc htc;
	struct ath10k_htt htt;

	struct ath10k_hw_params hw_params;

	/* contains the firmware images used with ATH10K_FIRMWARE_MODE_NORMAL */
	struct ath10k_fw_components normal_mode_fw;

	/* READ-ONLY images of the running firmware, which can be either
	 * normal or UTF. Do not modify, release etc!
	 */
	const struct ath10k_fw_components *running_fw;

	const struct firmware *pre_cal_file;
	const struct firmware *cal_file;

	struct {
		u32 vendor;
		u32 device;
		u32 subsystem_vendor;
		u32 subsystem_device;

		bool bmi_ids_valid;
		u8 bmi_board_id;
		u8 bmi_chip_id;

		char bdf_ext[ATH10K_SMBIOS_BDF_EXT_STR_LENGTH];
	} id;

	int fw_api;
	int bd_api;
	enum ath10k_cal_mode cal_mode;

	struct {
		struct completion started;
		struct completion completed;
		struct completion on_channel;
		struct delayed_work timeout;
		enum ath10k_scan_state state;
		bool is_roc;
		int vdev_id;
		int roc_freq;
		bool roc_notify;
	} scan;

	struct {
		struct ieee80211_supported_band sbands[NUM_NL80211_BANDS];
	} mac;

	/* should never be NULL; needed for regular htt rx */
	struct ieee80211_channel *rx_channel;

	/* valid during scan; needed for mgmt rx during scan */
	struct ieee80211_channel *scan_channel;

	/* current operating channel definition */
	struct cfg80211_chan_def chandef;

	/* currently configured operating channel in firmware */
	struct ieee80211_channel *tgt_oper_chan;

	unsigned long long free_vdev_map;
	struct ath10k_vif *monitor_arvif;
	bool monitor;
	int monitor_vdev_id;
	bool monitor_started;
	unsigned int filter_flags;
	unsigned long dev_flags;
	bool dfs_block_radar_events;

	/* protected by conf_mutex */
	bool radar_enabled;
	int num_started_vdevs;

	/* Protected by conf-mutex */
	u8 cfg_tx_chainmask;
	u8 cfg_rx_chainmask;

#ifndef __GENKSYMS__
	int last_wmi_vdev_start_status; /* moved here for kABI compatibility */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct completion install_key_done;

	struct completion vdev_setup_done;

	struct workqueue_struct *workqueue;
	/* Auxiliary workqueue */
	struct workqueue_struct *workqueue_aux;

	/* prevents concurrent FW reconfiguration */
	struct mutex conf_mutex;

	/* protects shared structure data */
	spinlock_t data_lock;
	/* protects: ar->txqs, artxq->list */
	spinlock_t txqs_lock;

	struct list_head txqs;
	struct list_head arvifs;
	struct list_head peers;
	struct ath10k_peer *peer_map[ATH10K_MAX_NUM_PEER_IDS];
	wait_queue_head_t peer_mapping_wq;

	/* protected by conf_mutex */
	int num_peers;
	int num_stations;

	int max_num_peers;
	int max_num_stations;
	int max_num_vdevs;
	int max_num_tdls_vdevs;
	int num_active_peers;
	int num_tids;

	struct work_struct svc_rdy_work;
	struct sk_buff *svc_rdy_skb;

	struct work_struct offchan_tx_work;
	struct sk_buff_head offchan_tx_queue;
	struct completion offchan_tx_completed;
	struct sk_buff *offchan_tx_skb;

	struct work_struct wmi_mgmt_tx_work;
	struct sk_buff_head wmi_mgmt_tx_queue;

	enum ath10k_state state;

	struct work_struct register_work;
	struct work_struct restart_work;

	/* cycle count is reported twice for each visited channel during scan.
	 * access protected by data_lock
	 */
	u32 survey_last_rx_clear_count;
	u32 survey_last_cycle_count;
	struct survey_info survey[ATH10K_NUM_CHANS];

	/* Channel info events are expected to come in pairs without and with
	 * COMPLETE flag set respectively for each channel visit during scan.
	 *
	 * However there are deviations from this rule. This flag is used to
	 * avoid reporting garbage data.
	 */
	bool ch_info_can_report_survey;
	struct completion bss_survey_done;

	struct dfs_pattern_detector *dfs_detector;

	unsigned long tx_paused; /* see ATH10K_TX_PAUSE_ */

#ifdef CONFIG_ATH10K_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	u32 pktlog_filter;

#ifdef CONFIG_DEV_COREDUMP
	struct {
		struct ath10k_fw_crash_data *fw_crash_data;
	} coredump;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct {
		/* protected by conf_mutex */
		struct ath10k_fw_components utf_mode_fw;

		/* protected by data_lock */
		bool utf_monitor;
	} testmode;

	struct {
		/* protected by data_lock */
		u32 fw_crash_counter;
		u32 fw_warm_reset_counter;
		u32 fw_cold_reset_counter;
	} stats;

	struct ath10k_thermal thermal;
	struct ath10k_wow wow;
	struct ath10k_per_peer_tx_stats peer_tx_stats;

	/* NAPI */
	struct net_device napi_dev;
	struct napi_struct napi;

	struct work_struct set_coverage_class_work;
	/* protected by conf_mutex */
	struct {
		/* writing also protected by data_lock */
		s16 coverage_class;

		u32 reg_phyclk;
		u32 reg_slottime_conf;
		u32 reg_slottime_orig;
		u32 reg_ack_cts_timeout_conf;
		u32 reg_ack_cts_timeout_orig;
	} fw_coverage;

	u32 ampdu_reference;

	void *ce_priv;

	u32 sta_tid_stats_mask;

	/* protected by data_lock */
	enum ath10k_radar_confirmation_state radar_conf_state;
	struct ath10k_radar_found_info last_radar_info;
	struct work_struct radar_confirmation_work;

	/* must be last */
	u8 drv_priv[0] __aligned(sizeof(void *));
};

/* klp-ccp: from drivers/net/wireless/ath/ath10k/hif.h */
#include <linux/kernel.h>

/* klp-ccp: from drivers/net/wireless/ath/ath10k/debug.h */
#include <linux/types.h>
/* klp-ccp: from drivers/net/wireless/ath/ath10k/trace.h */
#include <trace/define_trace.h>

/* klp-ccp: from drivers/net/wireless/ath/ath10k/debug.h */
enum ath10k_debug_mask {
	ATH10K_DBG_PCI		= 0x00000001,
	ATH10K_DBG_WMI		= 0x00000002,
	ATH10K_DBG_HTC		= 0x00000004,
	ATH10K_DBG_HTT		= 0x00000008,
	ATH10K_DBG_MAC		= 0x00000010,
	ATH10K_DBG_BOOT		= 0x00000020,
	ATH10K_DBG_PCI_DUMP	= 0x00000040,
	ATH10K_DBG_HTT_DUMP	= 0x00000080,
	ATH10K_DBG_MGMT		= 0x00000100,
	ATH10K_DBG_DATA		= 0x00000200,
	ATH10K_DBG_BMI		= 0x00000400,
	ATH10K_DBG_REGULATORY	= 0x00000800,
	ATH10K_DBG_TESTMODE	= 0x00001000,
	ATH10K_DBG_WMI_PRINT	= 0x00002000,
	ATH10K_DBG_PCI_PS	= 0x00004000,
	ATH10K_DBG_AHB		= 0x00008000,
	ATH10K_DBG_SDIO		= 0x00010000,
	ATH10K_DBG_SDIO_DUMP	= 0x00020000,
	ATH10K_DBG_USB		= 0x00040000,
	ATH10K_DBG_USB_BULK	= 0x00080000,
	ATH10K_DBG_SNOC		= 0x00100000,
	ATH10K_DBG_ANY		= 0xffffffff,
};

static __printf(2, 3) void (*klpe_ath10k_warn)(struct ath10k *ar, const char *fmt, ...);

#ifdef CONFIG_ATH10K_DEBUG
#error "klp-ccp: non-taken branch"
#else /* CONFIG_ATH10K_DEBUG */

static inline int ath10k_dbg(struct ath10k *ar,
			     enum ath10k_debug_mask dbg_mask,
			     const char *fmt, ...)
{
	return 0;
}

#endif /* CONFIG_ATH10K_DEBUG */

/* klp-ccp: from drivers/net/wireless/ath/ath10k/htc.c */
static inline void ath10k_htc_restore_tx_skb(struct ath10k_htc *htc,
					     struct sk_buff *skb)
{
	struct ath10k_skb_cb *skb_cb = ATH10K_SKB_CB(skb);

	dma_unmap_single(htc->ar->dev, skb_cb->paddr, skb->len, DMA_TO_DEVICE);
	skb_pull(skb, sizeof(struct ath10k_htc_hdr));
}

void klpp_ath10k_htc_notify_tx_completion(struct ath10k_htc_ep *ep,
				     struct sk_buff *skb)
{
	struct ath10k *ar = ep->htc->ar;

	ath10k_dbg(ar, ATH10K_DBG_HTC, "%s: ep %d skb %pK\n", __func__,
		   ep->eid, skb);

	/* A corner case where the copy completion is reaching to host but still
	 * copy engine is processing it due to which host unmaps corresponding
	 * memory and causes SMMU fault, hence as workaround adding delay
	 * the unmapping memory to avoid SMMU faults.
	 */
	if ((ar->hw_params.id == WCN3990_HW_1_0_DEV_VERSION)  &&
	    ep->ul_pipe_id == 3)
		mdelay(2);

	ath10k_htc_restore_tx_skb(ep->htc, skb);

	if (!ep->ep_ops.ep_tx_complete) {
		(*klpe_ath10k_warn)(ar, "no tx handler for eid %d\n", ep->eid);
		dev_kfree_skb_any(skb);
		return;
	}

	ep->ep_ops.ep_tx_complete(ep->htc->ar, skb);
}

typeof(klpp_ath10k_htc_notify_tx_completion) klpp_ath10k_htc_notify_tx_completion;


#include "livepatch_bsc1255577.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ath10k_core"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ath10k_warn", (void *)&klpe_ath10k_warn, "ath10k_core" },
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

int livepatch_bsc1255577_init(void)
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

void livepatch_bsc1255577_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_ATH10K) */
