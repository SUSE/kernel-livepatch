/*
 * livepatch_bsc1225850
 *
 * Fix for CVE-2024-36921, bsc#1225850
 *
 *  Upstream commit:
 *  17f64517bf5c ("wifi: iwlwifi: mvm: guard against invalid STA ID on removal")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  9f17b578a42cbe63048a63f983fdacca262d5d21
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_IWLMVM)

#if !IS_MODULE(CONFIG_IWLMVM)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/mvm.h */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/leds.h>
#include <linux/in6.h>

#ifdef CONFIG_THERMAL
#include <linux/thermal.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#include <linux/ptp_clock_kernel.h>
#include <linux/ktime.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-op-mode.h */
#include <linux/netdevice.h>
#include <linux/debugfs.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-dbg-tlv.h */
#include <linux/device.h>
#include <linux/types.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/file.h */
#include <linux/netdevice.h>
#include <linux/nl80211.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/dbg-tlv.h */
#include <linux/bitops.h>

enum iwl_fw_ini_time_point {
	IWL_FW_INI_TIME_POINT_INVALID,
	IWL_FW_INI_TIME_POINT_EARLY,
	IWL_FW_INI_TIME_POINT_AFTER_ALIVE,
	IWL_FW_INI_TIME_POINT_POST_INIT,
	IWL_FW_INI_TIME_POINT_FW_ASSERT,
	IWL_FW_INI_TIME_POINT_FW_HW_ERROR,
	IWL_FW_INI_TIME_POINT_FW_TFD_Q_HANG,
	IWL_FW_INI_TIME_POINT_FW_DHC_NOTIFICATION,
	IWL_FW_INI_TIME_POINT_FW_RSP_OR_NOTIF,
	IWL_FW_INI_TIME_POINT_USER_TRIGGER,
	IWL_FW_INI_TIME_POINT_PERIODIC,
	IWL_FW_INI_TIME_POINT_RESERVED,
	IWL_FW_INI_TIME_POINT_HOST_ASSERT,
	IWL_FW_INI_TIME_POINT_HOST_ALIVE_TIMEOUT,
	IWL_FW_INI_TIME_POINT_HOST_DEVICE_ENABLE,
	IWL_FW_INI_TIME_POINT_HOST_DEVICE_DISABLE,
	IWL_FW_INI_TIME_POINT_HOST_D3_START,
	IWL_FW_INI_TIME_POINT_HOST_D3_END,
	IWL_FW_INI_TIME_POINT_MISSED_BEACONS,
	IWL_FW_INI_TIME_POINT_ASSOC_FAILED,
	IWL_FW_INI_TIME_POINT_TX_FAILED,
	IWL_FW_INI_TIME_POINT_TX_WFD_ACTION_FRAME_FAILED,
	IWL_FW_INI_TIME_POINT_TX_LATENCY_THRESHOLD,
	IWL_FW_INI_TIME_POINT_HANG_OCCURRED,
	IWL_FW_INI_TIME_POINT_EAPOL_FAILED,
	IWL_FW_INI_TIME_POINT_FAKE_TX,
	IWL_FW_INI_TIME_POINT_DEASSOC,
	IWL_FW_INI_TIME_POINT_NUM,
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-trans.h */
#include <linux/ieee80211.h>
#include <linux/mm.h> /* for page_address */
#include <linux/lockdep.h>
#include <linux/kernel.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-modparams.h */
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-config.h */
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ieee80211.h>
#include <linux/nl80211.h>

struct iwl_tt_tx_backoff {
	s32 temperature;
	u32 backoff;
};

#define TT_TX_BACKOFF_SIZE 6

struct iwl_tt_params {
	u32 ct_kill_entry;
	u32 ct_kill_exit;
	u32 ct_kill_duration;
	u32 dynamic_smps_entry;
	u32 dynamic_smps_exit;
	u32 tx_protection_entry;
	u32 tx_protection_exit;
	struct iwl_tt_tx_backoff tx_backoff[TT_TX_BACKOFF_SIZE];
	u8 support_ct_kill:1,
	   support_dynamic_smps:1,
	   support_tx_protection:1,
	   support_tx_backoff:1;
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/img.h */
#include <linux/types.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/error-dump.h */
#include <linux/types.h>

#define MAX_NUM_LMAC 2

#define TX_FIFO_INTERNAL_MAX_NUM	6
#define TX_FIFO_MAX_NUM			15

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/img.h */
enum iwl_ucode_type {
	IWL_UCODE_REGULAR,
	IWL_UCODE_INIT,
	IWL_UCODE_WOWLAN,
	IWL_UCODE_REGULAR_USNIFFER,
	IWL_UCODE_TYPE_MAX,
};

struct iwl_fw_paging {
	dma_addr_t fw_paging_phys;
	struct page *fw_paging_block;
	u32 fw_paging_size;
	u32 fw_offs;
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-trans.h */
#define IWL_MAX_HW_QUEUES		32
#define IWL_MAX_TVQM_QUEUES		512

#define IWL_MAX_TID_COUNT	8

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/notif-wait.h */
#include <linux/wait.h>

struct iwl_notif_wait_data {
	struct list_head notif_waits;
	spinlock_t notif_wait_lock;
	wait_queue_head_t notif_waitq;
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-eeprom-parse.h */
#include <linux/types.h>
#include <linux/if_ether.h>
#include <net/cfg80211.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/sta.h */
#include <linux/spinlock.h>
#include <net/mac80211.h>
#include <linux/wait.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/tx.h */
#include <linux/ieee80211.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/phy-ctxt.h */
#define NUM_PHY_CTX	3

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/mac.h */
#define MAC_INDEX_AUX		4

#define NUM_MAC_INDEX_DRIVER	MAC_INDEX_AUX

#define IWL_MVM_STATION_COUNT_MAX	16

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/mac-cfg.h */
#define IWL_MVM_FW_MAX_LINK_ID 3

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/datapath.h */
#define IWL_MAX_BAID		32 /* MAX_IMMEDIATE_BA_API_D_VER_3 */

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/phy.h */
#define IWL_MAX_DTS_TRIPS	8

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/config.h */
struct iwl_phy_specific_cfg {
	__le32 filter_cfg_chains[4];
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/binding.h */
#define MAX_BINDINGS		(4)

struct iwl_time_quota_data {
	__le32 id_and_color;
	__le32 quota;
	__le32 max_duration;
	__le32 low_latency;
} __packed;

struct iwl_time_quota_cmd {
	struct iwl_time_quota_data quotas[MAX_BINDINGS];
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/coex.h */
#include <linux/types.h>
#include <linux/bitops.h>

struct iwl_bt_coex_ci_cmd {
	__le64 bt_primary_ci;
	__le32 primary_ch_phy_id;

	__le64 bt_secondary_ci;
	__le32 secondary_ch_phy_id;
} __packed;

struct iwl_bt_coex_profile_notif {
	__le32 mbox_msg[4];
	__le32 msg_idx;
	__le32 bt_ci_compliance;

	__le32 primary_ch_lut;
	__le32 secondary_ch_lut;
	__le32 bt_activity_grading;
	u8 ttc_status;
	u8 rrc_status;
	__le16 reserved;
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/nvm-reg.h */
enum iwl_nvm_section_type {
	NVM_SECTION_TYPE_SW = 1,
	NVM_SECTION_TYPE_REGULATORY = 3,
	NVM_SECTION_TYPE_CALIBRATION = 4,
	NVM_SECTION_TYPE_PRODUCTION = 5,
	NVM_SECTION_TYPE_REGULATORY_SDP = 8,
	NVM_SECTION_TYPE_MAC_OVERRIDE = 11,
	NVM_SECTION_TYPE_PHY_SKU = 12,
	NVM_MAX_NUM_SECTIONS = 13,
};

enum iwl_mcc_source {
	MCC_SOURCE_OLD_FW = 0,
	MCC_SOURCE_ME = 1,
	MCC_SOURCE_BIOS = 2,
	MCC_SOURCE_3G_LTE_HOST = 3,
	MCC_SOURCE_3G_LTE_DEVICE = 4,
	MCC_SOURCE_WIFI = 5,
	MCC_SOURCE_RESERVED = 6,
	MCC_SOURCE_DEFAULT = 7,
	MCC_SOURCE_UNINITIALIZED = 8,
	MCC_SOURCE_MCC_API = 9,
	MCC_SOURCE_GET_CURRENT = 0x10,
	MCC_SOURCE_GETTING_MCC_TEST_MODE = 0x11,
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/power.h */
#define IWL_NUM_CHAIN_LIMITS	2

#define MCC_TO_SAR_OFFSET_TABLE_ROW_SIZE	26
#define MCC_TO_SAR_OFFSET_TABLE_COL_SIZE	13

struct iwl_sar_offset_mapping_cmd {
	u8 offset_map[MCC_TO_SAR_OFFSET_TABLE_ROW_SIZE]
		[MCC_TO_SAR_OFFSET_TABLE_COL_SIZE];
	__le16 reserved;
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/rx.h */
#define IWL_RX_INFO_PHY_CNT 8

struct iwl_rx_phy_info {
	u8 non_cfg_phy_cnt;
	u8 cfg_phy_cnt;
	u8 stat_id;
	u8 reserved1;
	__le32 system_timestamp;
	__le64 timestamp;
	__le32 beacon_time_stamp;
	__le16 phy_flags;
	__le16 channel;
	__le32 non_cfg_phy[IWL_RX_INFO_PHY_CNT];
	__le32 rate_n_flags;
	__le32 byte_count;
	u8 mac_active_msk;
	u8 mac_context_info;
	__le16 frame_time;
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/scan.h */
#define IWL_MVM_MAX_UMAC_SCANS 4

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/sf.h */
enum iwl_sf_state {
	SF_LONG_DELAY_ON = 0, /* should never be called by driver */
	SF_FULL_ON,
	SF_UNINIT,
	SF_INIT_OFF,
	SF_HW_NUM_STATES
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/sta.h */
#define STA_KEY_MAX_NUM (16)

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/stats.h */
struct mvm_statistics_rx_non_phy {
	__le32 bogus_cts;
	__le32 bogus_ack;
	__le32 non_channel_beacons;
	__le32 channel_beacons;
	__le32 num_missed_bcon;
	__le32 adc_rx_saturation_time;
	__le32 ina_detection_search_time;
	__le32 beacon_silence_rssi_a;
	__le32 beacon_silence_rssi_b;
	__le32 beacon_silence_rssi_c;
	__le32 interference_data_flag;
	__le32 channel_load;
	__le32 beacon_rssi_a;
	__le32 beacon_rssi_b;
	__le32 beacon_rssi_c;
	__le32 beacon_energy_a;
	__le32 beacon_energy_b;
	__le32 beacon_energy_c;
	__le32 num_bt_kills;
	__le32 mac_id;
} __packed;

struct mvm_statistics_rx_non_phy_v3 {
	__le32 bogus_cts;	/* CTS received when not expecting CTS */
	__le32 bogus_ack;	/* ACK received when not expecting ACK */
	__le32 non_bssid_frames;	/* number of frames with BSSID that
					 * doesn't belong to the STA BSSID */
	__le32 filtered_frames;	/* count frames that were dumped in the
				 * filtering process */
	__le32 non_channel_beacons;	/* beacons with our bss id but not on
					 * our serving channel */
	__le32 channel_beacons;	/* beacons with our bss id and in our
				 * serving channel */
	__le32 num_missed_bcon;	/* number of missed beacons */
	__le32 adc_rx_saturation_time;	/* count in 0.8us units the time the
					 * ADC was in saturation */
	__le32 ina_detection_search_time;/* total time (in 0.8us) searched
					  * for INA */
	__le32 beacon_silence_rssi_a;	/* RSSI silence after beacon frame */
	__le32 beacon_silence_rssi_b;	/* RSSI silence after beacon frame */
	__le32 beacon_silence_rssi_c;	/* RSSI silence after beacon frame */
	__le32 interference_data_flag;	/* flag for interference data
					 * availability. 1 when data is
					 * available. */
	__le32 channel_load;		/* counts RX Enable time in uSec */
	__le32 dsp_false_alarms;	/* DSP false alarm (both OFDM
					 * and CCK) counter */
	__le32 beacon_rssi_a;
	__le32 beacon_rssi_b;
	__le32 beacon_rssi_c;
	__le32 beacon_energy_a;
	__le32 beacon_energy_b;
	__le32 beacon_energy_c;
	__le32 num_bt_kills;
	__le32 mac_id;
	__le32 directed_data_mpdu;
} __packed;

struct mvm_statistics_rx_phy {
	__le32 unresponded_rts;
	__le32 rxe_frame_lmt_overrun;
	__le32 sent_ba_rsp_cnt;
	__le32 dsp_self_kill;
	__le32 reserved;
} __packed;

struct mvm_statistics_rx_phy_v2 {
	__le32 ina_cnt;
	__le32 fina_cnt;
	__le32 plcp_err;
	__le32 crc32_err;
	__le32 overrun_err;
	__le32 early_overrun_err;
	__le32 crc32_good;
	__le32 false_alarm_cnt;
	__le32 fina_sync_err_cnt;
	__le32 sfd_timeout;
	__le32 fina_timeout;
	__le32 unresponded_rts;
	__le32 rxe_frame_lmt_overrun;
	__le32 sent_ack_cnt;
	__le32 sent_cts_cnt;
	__le32 sent_ba_rsp_cnt;
	__le32 dsp_self_kill;
	__le32 mh_format_err;
	__le32 re_acq_main_rssi_sum;
	__le32 reserved;
} __packed;

struct mvm_statistics_rx_ht_phy_v1 {
	__le32 plcp_err;
	__le32 overrun_err;
	__le32 early_overrun_err;
	__le32 crc32_good;
	__le32 crc32_err;
	__le32 mh_format_err;
	__le32 agg_crc32_good;
	__le32 agg_mpdu_cnt;
	__le32 agg_cnt;
	__le32 unsupport_mcs;
} __packed;

struct mvm_statistics_rx_ht_phy {
	__le32 mh_format_err;
	__le32 agg_mpdu_cnt;
	__le32 agg_cnt;
	__le32 unsupport_mcs;
} __packed;

struct mvm_statistics_rx {
	struct mvm_statistics_rx_phy ofdm;
	struct mvm_statistics_rx_phy cck;
	struct mvm_statistics_rx_non_phy general;
	struct mvm_statistics_rx_ht_phy ofdm_ht;
} __packed;

struct mvm_statistics_rx_v3 {
	struct mvm_statistics_rx_phy_v2 ofdm;
	struct mvm_statistics_rx_phy_v2 cck;
	struct mvm_statistics_rx_non_phy_v3 general;
	struct mvm_statistics_rx_ht_phy_v1 ofdm_ht;
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/location.h */
#define IWL_MVM_TOF_MAX_APS 5

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/rs.h */
#include <net/mac80211.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/sta.h */
struct iwl_mvm;

struct iwl_mvm_int_sta {
	u32 sta_id;
	u8 type;
	u32 tfd_queue_msk;
};

int klpp_iwl_mvm_mld_rm_sta_id(struct iwl_mvm *mvm, u8 sta_id);

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/constants.h */
#include <linux/ieee80211.h>

#define IWL_MVM_UAPSD_NOAGG_BSSIDS_NUM		20

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/paging.h */
#define NUM_OF_FW_PAGING_BLOCKS	33 /* 32 for data and 1 block for CSS */

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/acpi.h */
#define ACPI_SAR_PROFILE_NUM		4

#define ACPI_NUM_GEO_PROFILES_REV3	8

#define ACPI_SAR_NUM_CHAINS_REV2	4

#define ACPI_SAR_NUM_SUB_BANDS_REV2	11

#define ACPI_GEO_NUM_BANDS_REV2		3
#define ACPI_GEO_NUM_CHAINS		2

struct iwl_sar_profile_chain {
	u8 subbands[ACPI_SAR_NUM_SUB_BANDS_REV2];
};

struct iwl_sar_profile {
	bool enabled;
	struct iwl_sar_profile_chain chains[ACPI_SAR_NUM_CHAINS_REV2];
};

struct iwl_geo_profile_band {
	u8 max;
	u8 chains[ACPI_GEO_NUM_CHAINS];
};

struct iwl_geo_profile {
	struct iwl_geo_profile_band bands[ACPI_GEO_NUM_BANDS_REV2];
};

struct iwl_ppag_chain {
	s8 subbands[ACPI_SAR_NUM_SUB_BANDS_REV2];
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/runtime.h */
#define MAX_NUM_TCM 2
#define MAX_NUM_RCM 2
struct iwl_fwrt_shared_mem_cfg {
	int num_lmacs;
	int num_txfifo_entries;
	struct {
		u32 txfifo_size[TX_FIFO_MAX_NUM];
		u32 rxfifo1_size;
	} lmac[MAX_NUM_LMAC];
	u32 rxfifo2_size;
	u32 rxfifo2_control_size;
	u32 internal_txfifo_addr;
	u32 internal_txfifo_size[TX_FIFO_INTERNAL_MAX_NUM];
};

#define IWL_FW_RUNTIME_DUMP_WK_NUM 5

struct iwl_fwrt_dump_data {
	union {
		struct {
			struct iwl_fw_ini_trigger_tlv *trig;
			struct iwl_rx_packet *fw_pkt;
		};
		struct {
			const struct iwl_fw_dump_desc *desc;
			bool monitor_only;
		};
	};
};

struct iwl_fwrt_wk_data  {
	u8 idx;
	struct delayed_work wk;
	struct iwl_fwrt_dump_data dump_data;
};

struct iwl_txf_iter_data {
	int fifo;
	int lmac;
	u32 fifo_size;
	u8 internal_txf;
};

struct iwl_fw_runtime {
	struct iwl_trans *trans;
	const struct iwl_fw *fw;
	struct device *dev;

	const struct iwl_fw_runtime_ops *ops;
	void *ops_ctx;

	const struct iwl_dump_sanitize_ops *sanitize_ops;
	void *sanitize_ctx;

	/* Paging */
	struct iwl_fw_paging fw_paging_db[NUM_OF_FW_PAGING_BLOCKS];
	u16 num_of_paging_blk;
	u16 num_of_pages_in_last_blk;

	enum iwl_ucode_type cur_fw_img;

	/* memory configuration */
	struct iwl_fwrt_shared_mem_cfg smem_cfg;

	/* debug */
	struct {
		struct iwl_fwrt_wk_data wks[IWL_FW_RUNTIME_DUMP_WK_NUM];
		unsigned long active_wks;

		u8 conf;

		/* ts of the beginning of a non-collect fw dbg data period */
		unsigned long non_collect_ts_start[IWL_FW_INI_TIME_POINT_NUM];
		u32 *d3_debug_data;
		u32 lmac_err_id[MAX_NUM_LMAC];
		u32 tcm_err_id[MAX_NUM_TCM];
		u32 rcm_err_id[MAX_NUM_RCM];
		u32 umac_err_id;

		struct iwl_txf_iter_data txf_iter_data;

		struct {
			u8 type;
			u8 subtype;
			u32 lmac_major;
			u32 lmac_minor;
			u32 umac_major;
			u32 umac_minor;
		} fw_ver;
	} dump;
	struct {
#ifdef CONFIG_IWLWIFI_DEBUGFS
		struct delayed_work wk;
		u32 delay;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		u64 seq;
	} timestamp;
#ifdef CONFIG_IWLWIFI_DEBUGFS
	bool tpc_enabled;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_IWLWIFI_DEBUGFS */
#ifdef CONFIG_ACPI
	struct iwl_sar_profile sar_profiles[ACPI_SAR_PROFILE_NUM];
	u8 sar_chain_a_profile;
	u8 sar_chain_b_profile;
	struct iwl_geo_profile geo_profiles[ACPI_NUM_GEO_PROFILES_REV3];
	u32 geo_rev;
	u32 geo_num_profiles;
	bool geo_enabled;
	struct iwl_ppag_chain ppag_chains[IWL_NUM_CHAIN_LIMITS];
	u32 ppag_flags;
	u32 ppag_ver;
	bool ppag_table_valid;
	struct iwl_sar_offset_mapping_cmd sgom_table;
	bool sgom_enabled;
	u8 reduced_power_flags;
#endif
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/dbg.h */
#include <linux/workqueue.h>
#include <net/cfg80211.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-prph.h */
#include <linux/bitfield.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace.h */
#ifndef __IWLWIFI_DEVICE_TRACE
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>

/* klp-ccp: from include/linux/tracepoint.h */
#define _LINUX_TRACEPOINT_H

#define DECLARE_TRACE(name, proto, args)				\
	__DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto))

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace.h */
#include <linux/device.h>

#define TRACE_EVENT(name, proto, ...) \
static inline void trace_ ## name(proto) {}

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace-io.h */
#if !defined(__IWLWIFI_DEVICE_TRACE_IO) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __IWLWIFI_DEVICE_TRACE_IO */

#include <trace/define_trace.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace-ucode.h */
#if !defined(__IWLWIFI_DEVICE_TRACE_UCODE) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __IWLWIFI_DEVICE_TRACE_UCODE */

#include <trace/define_trace.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace-msg.h */
#if !defined(__IWLWIFI_DEVICE_TRACE_MSG) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __IWLWIFI_DEVICE_TRACE_MSG */

#include <trace/define_trace.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace-data.h */
#if !defined(__IWLWIFI_DEVICE_TRACE_DATA) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __IWLWIFI_DEVICE_TRACE_DATA */

#include <trace/define_trace.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace-iwlwifi.h */
#if !defined(__IWLWIFI_DEVICE_TRACE_IWLWIFI) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __IWLWIFI_DEVICE_TRACE_IWLWIFI */

#include <trace/define_trace.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-devtrace.h */
#endif /* __IWLWIFI_DEVICE_TRACE */

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mei/iwl-mei.h */
#include <linux/if_ether.h>
#include <linux/skbuff.h>
#include <linux/ieee80211.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-nvm-parse.h */
#include <net/cfg80211.h>

struct iwl_nvm_section {
	u16 length;
	const u8 *data;
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/mvm.h */
#include <linux/average.h>

#define IWL_MVM_MAX_ADDRESSES		5

struct iwl_mvm_phy_ctxt {
	u16 id;
	u16 color;
	u32 ref;

	enum nl80211_chan_width width;

	struct ieee80211_channel *channel;

	/* track for RLC config command */
	u32 center_freq1;
	bool rlc_disabled;
};

enum iwl_bt_force_ant_mode {
	BT_FORCE_ANT_DIS = 0,
	BT_FORCE_ANT_AUTO,
	BT_FORCE_ANT_BT,
	BT_FORCE_ANT_WIFI,

	BT_FORCE_ANT_MAX,
};

enum iwl_mvm_scan_type {
	IWL_SCAN_TYPE_NOT_SET,
	IWL_SCAN_TYPE_UNASSOC,
	IWL_SCAN_TYPE_WILD,
	IWL_SCAN_TYPE_MILD,
	IWL_SCAN_TYPE_FRAGMENTED,
	IWL_SCAN_TYPE_FAST_BALANCE,
};

enum iwl_mvm_sched_scan_pass_all_states {
	SCHED_SCAN_PASS_ALL_DISABLED,
	SCHED_SCAN_PASS_ALL_ENABLED,
	SCHED_SCAN_PASS_ALL_FOUND,
};

struct iwl_mvm_tt_mgmt {
	struct delayed_work ct_kill_exit;
	bool dynamic_smps;
	u32 tx_backoff;
	u32 min_backoff;
	struct iwl_tt_params params;
	bool throttle;
};

#ifdef CONFIG_THERMAL

struct iwl_mvm_thermal_device {
	struct thermal_trip trips[IWL_MAX_DTS_TRIPS];
	u8 fw_trips_index[IWL_MAX_DTS_TRIPS];
	struct thermal_zone_device *tzone;
};

struct iwl_mvm_cooling_device {
	u32 cur_state;
	struct thermal_cooling_device *cdev;
};
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define IWL_MVM_NUM_LAST_FRAMES_UCODE_RATES 8

struct iwl_mvm_frame_stats {
	u32 legacy_frames;
	u32 ht_frames;
	u32 vht_frames;
	u32 bw_20_frames;
	u32 bw_40_frames;
	u32 bw_80_frames;
	u32 bw_160_frames;
	u32 sgi_frames;
	u32 ngi_frames;
	u32 siso_frames;
	u32 mimo2_frames;
	u32 agg_frames;
	u32 ampdu_count;
	u32 success_frames;
	u32 fail_frames;
	u32 last_rates[IWL_MVM_NUM_LAST_FRAMES_UCODE_RATES];
	int last_frame_idx;
};

enum iwl_mvm_tdls_cs_state {
	IWL_MVM_TDLS_SW_IDLE = 0,
	IWL_MVM_TDLS_SW_REQ_SENT,
	IWL_MVM_TDLS_SW_RESP_RCVD,
	IWL_MVM_TDLS_SW_REQ_RCVD,
	IWL_MVM_TDLS_SW_ACTIVE,
};

enum iwl_mvm_traffic_load {
	IWL_MVM_TRAFFIC_LOW,
	IWL_MVM_TRAFFIC_MEDIUM,
	IWL_MVM_TRAFFIC_HIGH,
};

struct ewma_rate { unsigned long internal; };

struct iwl_mvm_tcm_mac {
	struct {
		u32 pkts[IEEE80211_NUM_ACS];
		u32 airtime;
	} tx;
	struct {
		u32 pkts[IEEE80211_NUM_ACS];
		u32 airtime;
		u32 last_ampdu_ref;
	} rx;
	struct {
		/* track AP's transfer in client mode */
		u64 rx_bytes;
		struct ewma_rate rate;
		bool detected;
	} uapsd_nonagg_detect;
	bool opened_rx_ba_sessions;
};

struct iwl_mvm_tcm {
	struct delayed_work work;
	spinlock_t lock; /* used when time elapsed */
	unsigned long ts; /* timestamp when period ends */
	unsigned long ll_ts;
	unsigned long uapsd_nonagg_ts;
	bool paused;
	struct iwl_mvm_tcm_mac data[NUM_MAC_INDEX_DRIVER];
	struct {
		u32 elapsed; /* milliseconds for this TCM period */
		u32 airtime[NUM_MAC_INDEX_DRIVER];
		enum iwl_mvm_traffic_load load[NUM_MAC_INDEX_DRIVER];
		enum iwl_mvm_traffic_load band_load[NUM_NL80211_BANDS];
		enum iwl_mvm_traffic_load global_load;
		bool low_latency[NUM_MAC_INDEX_DRIVER];
		bool change[NUM_MAC_INDEX_DRIVER];
	} result;
};

enum iwl_mvm_queue_status {
	IWL_MVM_QUEUE_FREE,
	IWL_MVM_QUEUE_RESERVED,
	IWL_MVM_QUEUE_READY,
	IWL_MVM_QUEUE_SHARED,
};

#define IWL_MVM_NUM_CIPHERS             10

struct iwl_mvm_tvqm_txq_info {
	u8 sta_id;
	u8 txq_tid;
};

struct iwl_mvm_dqa_txq_info {
	u8 ra_sta_id; /* The RA this queue is mapped to, if exists */
	bool reserved; /* Is this the TXQ reserved for a STA */
	u8 mac80211_ac; /* The mac80211 AC this queue is mapped to */
	u8 txq_tid; /* The TID "owner" of this queue*/
	u16 tid_bitmap; /* Bitmap of the TIDs mapped to this queue */
	/* Timestamp for inactivation per TID of this queue */
	unsigned long last_frame_time[IWL_MAX_TID_COUNT + 1];
	enum iwl_mvm_queue_status status;
};

struct ptp_data {
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_info;

	struct delayed_work dwork;

	/* The last GP2 reading from the hw */
	u32 last_gp2;

	/* number of wraparounds since scale_update_adj_time_ns */
	u32 wrap_counter;

	/* GP2 time when the scale was last updated */
	u32 scale_update_gp2;

	/* Adjusted time when the scale was last updated in nanoseconds */
	u64 scale_update_adj_time_ns;

	/* clock frequency offset, scaled to 65536000000 */
	u64 scaled_freq;

	/* Delta between hardware clock and ptp clock in nanoseconds */
	s64 delta;
};

struct iwl_time_sync_data {
	struct sk_buff_head frame_list;
	u8 peer_addr[ETH_ALEN];
	bool active;
};

struct iwl_mei_scan_filter {
	bool is_mei_limited_scan;
	struct sk_buff_head scan_res;
	struct work_struct scan_work;
};

struct iwl_mvm {
	/* for logger access */
	struct device *dev;

	struct iwl_trans *trans;
	const struct iwl_fw *fw;
	const struct iwl_cfg *cfg;
	struct iwl_phy_db *phy_db;
	struct ieee80211_hw *hw;

	/* for protecting access to iwl_mvm */
	struct mutex mutex;
	struct list_head async_handlers_list;
	spinlock_t async_handlers_lock;
	struct work_struct async_handlers_wk;

	struct work_struct roc_done_wk;

	unsigned long init_status;

	unsigned long status;

	u32 queue_sync_cookie;
	unsigned long queue_sync_state;
	/*
	 * for beacon filtering -
	 * currently only one interface can be supported
	 */
	struct iwl_mvm_vif *bf_allowed_vif;

	bool hw_registered;
	bool rfkill_safe_init_done;

	u8 cca_40mhz_workaround;

	u32 ampdu_ref;
	bool ampdu_toggle;

	struct iwl_notif_wait_data notif_wait;

	union {
		struct mvm_statistics_rx_v3 rx_stats_v3;
		struct mvm_statistics_rx rx_stats;
	};

	struct {
		u64 rx_time;
		u64 tx_time;
		u64 on_time_rf;
		u64 on_time_scan;
	} radio_stats, accu_radio_stats;

	struct list_head add_stream_txqs;
	union {
		struct iwl_mvm_dqa_txq_info queue_info[IWL_MAX_HW_QUEUES];
		struct iwl_mvm_tvqm_txq_info tvqm_info[IWL_MAX_TVQM_QUEUES];
	};
	struct work_struct add_stream_wk; /* To add streams to queues */
	spinlock_t add_stream_lock;

	const char *nvm_file_name;
	struct iwl_nvm_data *nvm_data;
	struct iwl_mei_nvm *mei_nvm_data;
	struct iwl_mvm_csme_conn_info __rcu *csme_conn_info;
	bool mei_rfkill_blocked;
	bool mei_registered;
	struct work_struct sap_connected_wk;

	/*
	 * NVM built based on the SAP data but that we can't free even after
	 * we get ownership because it contains the cfg80211's channel.
	 */
	struct iwl_nvm_data *temp_nvm_data;

	/* NVM sections */
	struct iwl_nvm_section nvm_sections[NVM_MAX_NUM_SECTIONS];

	struct iwl_fw_runtime fwrt;

	/* EEPROM MAC addresses */
	struct mac_address addresses[IWL_MVM_MAX_ADDRESSES];

	/* data related to data path */
	struct iwl_rx_phy_info last_phy_info;
	struct ieee80211_sta __rcu *fw_id_to_mac_id[IWL_MVM_STATION_COUNT_MAX];
	struct ieee80211_link_sta __rcu *fw_id_to_link_sta[IWL_MVM_STATION_COUNT_MAX];
	unsigned long fw_link_ids_map;
	u8 rx_ba_sessions;

	/* configured by mac80211 */
	u32 rts_threshold;

	/* Scan status, cmd (pre-allocated) and auxiliary station */
	unsigned int scan_status;
	size_t scan_cmd_size;
	void *scan_cmd;
	struct iwl_mcast_filter_cmd *mcast_filter_cmd;
	/* For CDB this is low band scan type, for non-CDB - type. */
	enum iwl_mvm_scan_type scan_type;
	enum iwl_mvm_scan_type hb_scan_type;

	enum iwl_mvm_sched_scan_pass_all_states sched_scan_pass_all;
	struct delayed_work scan_timeout_dwork;

	/* max number of simultaneous scans the FW supports */
	unsigned int max_scans;

	/* UMAC scan tracking */
	u32 scan_uid_status[IWL_MVM_MAX_UMAC_SCANS];

	/* start time of last scan in TSF of the mac that requested the scan */
	u64 scan_start;

	/* the vif that requested the current scan */
	struct iwl_mvm_vif *scan_vif;

	/* rx chain antennas set through debugfs for the scan command */
	u8 scan_rx_ant;

	/* Internal station */
	struct iwl_mvm_int_sta aux_sta;
	struct iwl_mvm_int_sta snif_sta;

	bool last_ebs_successful;

	u8 scan_last_antenna_idx; /* to toggle TX between antennas */
	u8 mgmt_last_antenna_idx;

	/* last smart fifo state that was successfully sent to firmware */
	enum iwl_sf_state sf_state;

	/*
	 * Leave this pointer outside the ifdef below so that it can be
	 * assigned without ifdef in the source code.
	 */
	struct dentry *debugfs_dir;
#ifdef CONFIG_IWLWIFI_DEBUGFS
	u32 dbgfs_sram_offset, dbgfs_sram_len;
	u32 dbgfs_prph_reg_addr;
	bool disable_power_off;
	bool disable_power_off_d3;
	bool beacon_inject_active;

	bool scan_iter_notif_enabled;

	struct debugfs_blob_wrapper nvm_hw_blob;
	struct debugfs_blob_wrapper nvm_sw_blob;
	struct debugfs_blob_wrapper nvm_calib_blob;
	struct debugfs_blob_wrapper nvm_prod_blob;
	struct debugfs_blob_wrapper nvm_phy_sku_blob;
	struct debugfs_blob_wrapper nvm_reg_blob;

	struct iwl_mvm_frame_stats drv_rx_stats;
	spinlock_t drv_stats_lock;
	u16 dbgfs_rx_phyinfo;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct iwl_mvm_phy_ctxt phy_ctxts[NUM_PHY_CTX];

	struct list_head time_event_list;
	spinlock_t time_event_lock;

	/*
	 * A bitmap indicating the index of the key in use. The firmware
	 * can hold 16 keys at most. Reflect this fact.
	 */
	unsigned long fw_key_table[BITS_TO_LONGS(STA_KEY_MAX_NUM)];
	u8 fw_key_deleted[STA_KEY_MAX_NUM];

	struct ieee80211_vif __rcu *vif_id_to_mac[NUM_MAC_INDEX_DRIVER];

	struct ieee80211_bss_conf __rcu *link_id_to_link_conf[IWL_MVM_FW_MAX_LINK_ID + 1];

	/* -1 for always, 0 for never, >0 for that many times */
	s8 fw_restart;
	u8 *error_recovery_buf;

#ifdef CONFIG_IWLWIFI_LEDS
	struct led_classdev led;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct ieee80211_vif *p2p_device_vif;

#ifdef CONFIG_PM
	struct wiphy_wowlan_support wowlan;
	int gtk_ivlen, gtk_icvlen, ptk_ivlen, ptk_icvlen;

	/* sched scan settings for net detect */
	struct ieee80211_scan_ies nd_ies;
	struct cfg80211_match_set *nd_match_sets;
	int n_nd_match_sets;
	struct ieee80211_channel **nd_channels;
	int n_nd_channels;
	bool net_detect;
	u8 offload_tid;
#ifdef CONFIG_IWLWIFI_DEBUGFS
	bool d3_wake_sysassert;
	bool d3_test_active;
	u32 d3_test_pme_ptr;
	struct ieee80211_vif *keep_vif;
	u32 last_netdetect_scans; /* no. of scans in the last net-detect wake */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	wait_queue_head_t rx_sync_waitq;

	/* BT-Coex */
	struct iwl_bt_coex_profile_notif last_bt_notif;
	struct iwl_bt_coex_ci_cmd last_bt_ci_cmd;

	u8 bt_tx_prio;
	enum iwl_bt_force_ant_mode bt_force_ant_mode;

	/* Aux ROC */
	struct list_head aux_roc_te_list;

	/* Thermal Throttling and CTkill */
	struct iwl_mvm_tt_mgmt thermal_throttle;
#ifdef CONFIG_THERMAL
	struct iwl_mvm_thermal_device tz_device;
	struct iwl_mvm_cooling_device cooling_dev;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	s32 temperature;	/* Celsius */
	/*
	 * Debug option to set the NIC temperature. This option makes the
	 * driver think this is the actual NIC temperature, and ignore the
	 * real temperature that is received from the fw
	 */
	bool temperature_test;  /* Debug test temperature is enabled */

	bool fw_static_smps_request;

	unsigned long bt_coex_last_tcm_ts;
	struct iwl_mvm_tcm tcm;

	u8 uapsd_noagg_bssid_write_idx;
	struct mac_address uapsd_noagg_bssids[IWL_MVM_UAPSD_NOAGG_BSSIDS_NUM]
		__aligned(2);

	struct iwl_time_quota_cmd last_quota_cmd;

#ifdef CONFIG_NL80211_TESTMODE
#error "klp-ccp: non-taken branch"
#endif
	u16 aux_queue;
	u16 snif_queue;
	u16 probe_queue;
	u16 p2p_dev_queue;

	/* Indicate if device power save is allowed */
	u8 ps_disabled; /* u8 instead of bool to ease debugfs_create_* usage */
	/* Indicate if 32Khz external clock is valid */
	u32 ext_clock_valid;

	/* This vif used by CSME to send / receive traffic */
	struct ieee80211_vif *csme_vif;
	struct ieee80211_vif __rcu *csa_vif;
	struct ieee80211_vif __rcu *csa_tx_blocked_vif;
	u8 csa_tx_block_bcn_timeout;

	/* system time of last beacon (for AP/GO interface) */
	u32 ap_last_beacon_gp2;

	/* indicates that we transmitted the last beacon */
	bool ibss_manager;

	bool lar_regdom_set;
	enum iwl_mcc_source mcc_src;

	/* TDLS channel switch data */
	struct {
		struct delayed_work dwork;
		enum iwl_mvm_tdls_cs_state state;

		/*
		 * Current cs sta - might be different from periodic cs peer
		 * station. Value is meaningless when the cs-state is idle.
		 */
		u8 cur_sta_id;

		/* TDLS periodic channel-switch peer */
		struct {
			u8 sta_id;
			u8 op_class;
			bool initiator; /* are we the link initiator */
			struct cfg80211_chan_def chandef;
			struct sk_buff *skb; /* ch sw template */
			u32 ch_sw_tm_ie;

			/* timestamp of last ch-sw request sent (GP2 time) */
			u32 sent_timestamp;
		} peer;
	} tdls_cs;


	u32 ciphers[IWL_MVM_NUM_CIPHERS];

	struct cfg80211_ftm_responder_stats ftm_resp_stats;
	struct {
		struct cfg80211_pmsr_request *req;
		struct wireless_dev *req_wdev;
		struct list_head loc_list;
		int responses[IWL_MVM_TOF_MAX_APS];
		struct {
			struct list_head resp;
		} smooth;
		struct list_head pasn_list;
	} ftm_initiator;

	struct list_head resp_pasn_list;

	struct ptp_data ptp_data;

	struct {
		u8 range_resp;
	} cmd_ver;

	struct ieee80211_vif *nan_vif;
	struct iwl_mvm_baid_data __rcu *baid_map[IWL_MAX_BAID];

	/*
	 * Drop beacons from other APs in AP mode when there are no connected
	 * clients.
	 */
	bool drop_bcn_ap_mode;

	struct delayed_work cs_tx_unblock_dwork;

	/* does a monitor vif exist (only one can exist hence bool) */
	bool monitor_on;
	/*
	 * primary channel position relative to he whole bandwidth,
	 * in steps of 80 MHz
	 */
	u8 monitor_p80;

	/* sniffer data to include in radiotap */
	__le16 cur_aid;
	u8 cur_bssid[ETH_ALEN];

#ifdef CONFIG_ACPI
	struct iwl_phy_specific_cfg phy_filters;
#endif
	unsigned long last_6ghz_passive_scan_jiffies;
	unsigned long last_reset_or_resume_time_jiffies;

	bool sta_remove_requires_queue_remove;
	bool mld_api_is_used;

	bool pldr_sync;

	struct iwl_time_sync_data time_sync;

	struct iwl_mei_scan_filter mei_scan_filter;
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/time-sync.h */
#include <linux/ieee80211.h>

#include <linux/livepatch.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/mvm/mld-sta.c */
extern int klpe_iwl_mvm_mld_rm_sta_from_fw(struct iwl_mvm *mvm, u32 sta_id) \
	 KLP_RELOC_SYMBOL(iwlmvm, iwlmvm, iwl_mvm_mld_rm_sta_from_fw);

#define IWL_MVM_INVALID_STA     0xFF

int klpp_iwl_mvm_mld_rm_sta_id(struct iwl_mvm *mvm, u8 sta_id)
{
	int ret;

	lockdep_assert_held(&mvm->mutex);

	if (WARN_ON(sta_id == IWL_MVM_INVALID_STA))
		return 0;

	ret = klpe_iwl_mvm_mld_rm_sta_from_fw(mvm, sta_id);

	RCU_INIT_POINTER(mvm->fw_id_to_mac_id[sta_id], NULL);
	RCU_INIT_POINTER(mvm->fw_id_to_link_sta[sta_id], NULL);
	return ret;
}


#include "livepatch_bsc1225850.h"

#endif /* IS_ENABLED(CONFIG_IWLMVM) */
