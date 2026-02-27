/*
 * livepatch_bsc1257629
 *
 * Fix for CVE-2025-38159, bsc#1257629
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

#if IS_ENABLED(CONFIG_RTW88_CORE)

#if !IS_MODULE(CONFIG_RTW88_CORE)
#error "Live patch supports only CONFIG=m"
#endif


/* klp-ccp: from drivers/net/wireless/realtek/rtw88/main.h */
#include <net/mac80211.h>
#include <linux/vmalloc.h>
#include <linux/firmware.h>
#include <linux/average.h>
#include <linux/bitops.h>
#include <linux/bitfield.h>
#include <linux/iopoll.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>

#define RTW_MAX_MAC_ID_NUM		32
#define RTW_MAX_SEC_CAM_NUM		32

#define RTW_MAX_PATTERN_NUM		12
#define RTW_MAX_PATTERN_MASK_SIZE	16

#define RTW_CHANNEL_WIDTH_MAX		3
#define RTW_RF_PATH_MAX			4

#define RTW_MAX_CHANNEL_NUM_2G 14
#define RTW_MAX_CHANNEL_NUM_5G 49

enum rtw_hci_type {
	RTW_HCI_TYPE_PCIE,
	RTW_HCI_TYPE_USB,
	RTW_HCI_TYPE_SDIO,

	RTW_HCI_TYPE_UNDEFINE,
};

struct rtw_hci {
	struct rtw_hci_ops *ops;
	enum rtw_hci_type type;

	u32 rpwm_addr;
	u32 cpwm_addr;

	u8 bulkout_num;
};

#define RTW_MAX_CHANNEL_WIDTH RTW_CHANNEL_WIDTH_80

enum rtw_bandwidth {
	RTW_CHANNEL_WIDTH_20	= 0,
	RTW_CHANNEL_WIDTH_40	= 1,
	RTW_CHANNEL_WIDTH_80	= 2,
	RTW_CHANNEL_WIDTH_160	= 3,
	RTW_CHANNEL_WIDTH_80_80	= 4,
	RTW_CHANNEL_WIDTH_5	= 5,
	RTW_CHANNEL_WIDTH_10	= 6,
};

enum rtw_bb_path {
	BB_PATH_A = BIT(0),
	BB_PATH_B = BIT(1),
	BB_PATH_C = BIT(2),
	BB_PATH_D = BIT(3),

	BB_PATH_AB = (BB_PATH_A | BB_PATH_B),
	BB_PATH_AC = (BB_PATH_A | BB_PATH_C),
	BB_PATH_AD = (BB_PATH_A | BB_PATH_D),
	BB_PATH_BC = (BB_PATH_B | BB_PATH_C),
	BB_PATH_BD = (BB_PATH_B | BB_PATH_D),
	BB_PATH_CD = (BB_PATH_C | BB_PATH_D),

	BB_PATH_ABC = (BB_PATH_A | BB_PATH_B | BB_PATH_C),
	BB_PATH_ABD = (BB_PATH_A | BB_PATH_B | BB_PATH_D),
	BB_PATH_ACD = (BB_PATH_A | BB_PATH_C | BB_PATH_D),
	BB_PATH_BCD = (BB_PATH_B | BB_PATH_C | BB_PATH_D),

	BB_PATH_ABCD = (BB_PATH_A | BB_PATH_B | BB_PATH_C | BB_PATH_D),
};

enum rtw_rate_section {
	RTW_RATE_SECTION_CCK = 0,
	RTW_RATE_SECTION_OFDM,
	RTW_RATE_SECTION_HT_1S,
	RTW_RATE_SECTION_HT_2S,
	RTW_RATE_SECTION_VHT_1S,
	RTW_RATE_SECTION_VHT_2S,

	/* keep last */
	RTW_RATE_SECTION_MAX,
};

enum rtw_fw_type {
	RTW_NORMAL_FW = 0x0,
	RTW_WOWLAN_FW = 0x1,
};

enum rtw_trx_desc_rate {
	DESC_RATE1M	= 0x00,
	DESC_RATE2M	= 0x01,
	DESC_RATE5_5M	= 0x02,
	DESC_RATE11M	= 0x03,

	DESC_RATE6M	= 0x04,
	DESC_RATE9M	= 0x05,
	DESC_RATE12M	= 0x06,
	DESC_RATE18M	= 0x07,
	DESC_RATE24M	= 0x08,
	DESC_RATE36M	= 0x09,
	DESC_RATE48M	= 0x0a,
	DESC_RATE54M	= 0x0b,

	DESC_RATEMCS0	= 0x0c,
	DESC_RATEMCS1	= 0x0d,
	DESC_RATEMCS2	= 0x0e,
	DESC_RATEMCS3	= 0x0f,
	DESC_RATEMCS4	= 0x10,
	DESC_RATEMCS5	= 0x11,
	DESC_RATEMCS6	= 0x12,
	DESC_RATEMCS7	= 0x13,
	DESC_RATEMCS8	= 0x14,
	DESC_RATEMCS9	= 0x15,
	DESC_RATEMCS10	= 0x16,
	DESC_RATEMCS11	= 0x17,
	DESC_RATEMCS12	= 0x18,
	DESC_RATEMCS13	= 0x19,
	DESC_RATEMCS14	= 0x1a,
	DESC_RATEMCS15	= 0x1b,
	DESC_RATEMCS16	= 0x1c,
	DESC_RATEMCS17	= 0x1d,
	DESC_RATEMCS18	= 0x1e,
	DESC_RATEMCS19	= 0x1f,
	DESC_RATEMCS20	= 0x20,
	DESC_RATEMCS21	= 0x21,
	DESC_RATEMCS22	= 0x22,
	DESC_RATEMCS23	= 0x23,
	DESC_RATEMCS24	= 0x24,
	DESC_RATEMCS25	= 0x25,
	DESC_RATEMCS26	= 0x26,
	DESC_RATEMCS27	= 0x27,
	DESC_RATEMCS28	= 0x28,
	DESC_RATEMCS29	= 0x29,
	DESC_RATEMCS30	= 0x2a,
	DESC_RATEMCS31	= 0x2b,

	DESC_RATEVHT1SS_MCS0	= 0x2c,
	DESC_RATEVHT1SS_MCS1	= 0x2d,
	DESC_RATEVHT1SS_MCS2	= 0x2e,
	DESC_RATEVHT1SS_MCS3	= 0x2f,
	DESC_RATEVHT1SS_MCS4	= 0x30,
	DESC_RATEVHT1SS_MCS5	= 0x31,
	DESC_RATEVHT1SS_MCS6	= 0x32,
	DESC_RATEVHT1SS_MCS7	= 0x33,
	DESC_RATEVHT1SS_MCS8	= 0x34,
	DESC_RATEVHT1SS_MCS9	= 0x35,

	DESC_RATEVHT2SS_MCS0	= 0x36,
	DESC_RATEVHT2SS_MCS1	= 0x37,
	DESC_RATEVHT2SS_MCS2	= 0x38,
	DESC_RATEVHT2SS_MCS3	= 0x39,
	DESC_RATEVHT2SS_MCS4	= 0x3a,
	DESC_RATEVHT2SS_MCS5	= 0x3b,
	DESC_RATEVHT2SS_MCS6	= 0x3c,
	DESC_RATEVHT2SS_MCS7	= 0x3d,
	DESC_RATEVHT2SS_MCS8	= 0x3e,
	DESC_RATEVHT2SS_MCS9	= 0x3f,

	DESC_RATEVHT3SS_MCS0	= 0x40,
	DESC_RATEVHT3SS_MCS1	= 0x41,
	DESC_RATEVHT3SS_MCS2	= 0x42,
	DESC_RATEVHT3SS_MCS3	= 0x43,
	DESC_RATEVHT3SS_MCS4	= 0x44,
	DESC_RATEVHT3SS_MCS5	= 0x45,
	DESC_RATEVHT3SS_MCS6	= 0x46,
	DESC_RATEVHT3SS_MCS7	= 0x47,
	DESC_RATEVHT3SS_MCS8	= 0x48,
	DESC_RATEVHT3SS_MCS9	= 0x49,

	DESC_RATEVHT4SS_MCS0	= 0x4a,
	DESC_RATEVHT4SS_MCS1	= 0x4b,
	DESC_RATEVHT4SS_MCS2	= 0x4c,
	DESC_RATEVHT4SS_MCS3	= 0x4d,
	DESC_RATEVHT4SS_MCS4	= 0x4e,
	DESC_RATEVHT4SS_MCS5	= 0x4f,
	DESC_RATEVHT4SS_MCS6	= 0x50,
	DESC_RATEVHT4SS_MCS7	= 0x51,
	DESC_RATEVHT4SS_MCS8	= 0x52,
	DESC_RATEVHT4SS_MCS9	= 0x53,

	DESC_RATE_MAX,
};

enum rtw_regulatory_domains {
	RTW_REGD_FCC		= 0,
	RTW_REGD_MKK		= 1,
	RTW_REGD_ETSI		= 2,
	RTW_REGD_IC		= 3,
	RTW_REGD_KCC		= 4,
	RTW_REGD_ACMA		= 5,
	RTW_REGD_CHILE		= 6,
	RTW_REGD_UKRAINE	= 7,
	RTW_REGD_MEXICO		= 8,
	RTW_REGD_CN		= 9,
	RTW_REGD_QATAR		= 10,
	RTW_REGD_UK		= 11,

	RTW_REGD_WW,
	RTW_REGD_MAX
};

enum rtw_flags {
	RTW_FLAG_RUNNING,
	RTW_FLAG_FW_RUNNING,
	RTW_FLAG_SCANNING,
	RTW_FLAG_POWERON,
	RTW_FLAG_LEISURE_PS,
	RTW_FLAG_LEISURE_PS_DEEP,
	RTW_FLAG_DIG_DISABLE,
	RTW_FLAG_BUSY_TRAFFIC,
	RTW_FLAG_WOWLAN,
	RTW_FLAG_RESTARTING,
	RTW_FLAG_RESTART_TRIGGERING,
	RTW_FLAG_FORCE_LOWEST_RATE,

	NUM_OF_RTW_FLAGS,
};

enum rtw_evm {
	RTW_EVM_OFDM = 0,
	RTW_EVM_1SS,
	RTW_EVM_2SS_A,
	RTW_EVM_2SS_B,
	/* keep it last */
	RTW_EVM_NUM
};

enum rtw_snr {
	RTW_SNR_OFDM_A = 0,
	RTW_SNR_OFDM_B,
	RTW_SNR_OFDM_C,
	RTW_SNR_OFDM_D,
	RTW_SNR_1SS_A,
	RTW_SNR_1SS_B,
	RTW_SNR_1SS_C,
	RTW_SNR_1SS_D,
	RTW_SNR_2SS_A,
	RTW_SNR_2SS_B,
	RTW_SNR_2SS_C,
	RTW_SNR_2SS_D,
	/* keep it last */
	RTW_SNR_NUM
};

enum rtw_port {
	RTW_PORT_0 = 0,
	RTW_PORT_1 = 1,
	RTW_PORT_2 = 2,
	RTW_PORT_3 = 3,
	RTW_PORT_4 = 4,
	RTW_PORT_NUM
};

enum rtw_wow_flags {
	RTW_WOW_FLAG_EN_MAGIC_PKT,
	RTW_WOW_FLAG_EN_REKEY_PKT,
	RTW_WOW_FLAG_EN_DISCONNECT,

	/* keep it last */
	RTW_WOW_FLAG_MAX,
};

struct rtw_2g_1s_pwr_idx_diff {
#ifdef __LITTLE_ENDIAN
	s8 ofdm:4;
	s8 bw20:4;
#else
#error "klp-ccp: non-taken branch"
#endif
} __packed;

struct rtw_2g_ns_pwr_idx_diff {
#ifdef __LITTLE_ENDIAN
	s8 bw20:4;
	s8 bw40:4;
	s8 cck:4;
	s8 ofdm:4;
#else
#error "klp-ccp: non-taken branch"
#endif
} __packed;

struct rtw_2g_txpwr_idx {
	u8 cck_base[6];
	u8 bw40_base[5];
	struct rtw_2g_1s_pwr_idx_diff ht_1s_diff;
	struct rtw_2g_ns_pwr_idx_diff ht_2s_diff;
	struct rtw_2g_ns_pwr_idx_diff ht_3s_diff;
	struct rtw_2g_ns_pwr_idx_diff ht_4s_diff;
};

struct rtw_5g_ht_1s_pwr_idx_diff {
#ifdef __LITTLE_ENDIAN
	s8 ofdm:4;
	s8 bw20:4;
#else
#error "klp-ccp: non-taken branch"
#endif
} __packed;

struct rtw_5g_ht_ns_pwr_idx_diff {
#ifdef __LITTLE_ENDIAN
	s8 bw20:4;
	s8 bw40:4;
#else
#error "klp-ccp: non-taken branch"
#endif
} __packed;

struct rtw_5g_ofdm_ns_pwr_idx_diff {
#ifdef __LITTLE_ENDIAN
	s8 ofdm_3s:4;
	s8 ofdm_2s:4;
	s8 ofdm_4s:4;
	s8 res:4;
#else
#error "klp-ccp: non-taken branch"
#endif
} __packed;

struct rtw_5g_vht_ns_pwr_idx_diff {
#ifdef __LITTLE_ENDIAN
	s8 bw160:4;
	s8 bw80:4;
#else
#error "klp-ccp: non-taken branch"
#endif
} __packed;

struct rtw_5g_txpwr_idx {
	u8 bw40_base[14];
	struct rtw_5g_ht_1s_pwr_idx_diff ht_1s_diff;
	struct rtw_5g_ht_ns_pwr_idx_diff ht_2s_diff;
	struct rtw_5g_ht_ns_pwr_idx_diff ht_3s_diff;
	struct rtw_5g_ht_ns_pwr_idx_diff ht_4s_diff;
	struct rtw_5g_ofdm_ns_pwr_idx_diff ofdm_diff;
	struct rtw_5g_vht_ns_pwr_idx_diff vht_1s_diff;
	struct rtw_5g_vht_ns_pwr_idx_diff vht_2s_diff;
	struct rtw_5g_vht_ns_pwr_idx_diff vht_3s_diff;
	struct rtw_5g_vht_ns_pwr_idx_diff vht_4s_diff;
};

struct rtw_txpwr_idx {
	struct rtw_2g_txpwr_idx pwr_idx_2g;
	struct rtw_5g_txpwr_idx pwr_idx_5g;
};

struct ewma_tp { unsigned long internal; };

struct rtw_traffic_stats {
	/* units in bytes */
	u64 tx_unicast;
	u64 rx_unicast;

	/* count for packets */
	u64 tx_cnt;
	u64 rx_cnt;

	/* units in Mbps */
	u32 tx_throughput;
	u32 rx_throughput;
	struct ewma_tp tx_ewma_tp;
	struct ewma_tp rx_ewma_tp;
};

enum rtw_lps_mode {
	RTW_MODE_ACTIVE	= 0,
	RTW_MODE_LPS	= 1,
	RTW_MODE_WMM_PS	= 2,
};

enum rtw_lps_deep_mode {
	LPS_DEEP_MODE_NONE	= 0,
	LPS_DEEP_MODE_LCLK	= 1,
	LPS_DEEP_MODE_PG	= 2,
};

enum rtw_pwr_state {
	RTW_RF_OFF	= 0x0,
	RTW_RF_ON	= 0x4,
	RTW_ALL_ON	= 0xc,
};

struct rtw_lps_conf {
	enum rtw_lps_mode mode;
	enum rtw_lps_deep_mode deep_mode;
	enum rtw_lps_deep_mode wow_deep_mode;
	enum rtw_pwr_state state;
	u8 awake_interval;
	u8 rlbm;
	u8 smart_ps;
	u8 port_id;
	bool sec_cam_backup;
	bool pattern_cam_backup;
};

struct rtw_cam_entry {
	bool valid;
	bool group;
	u8 addr[ETH_ALEN];
	u8 hw_key_type;
	struct ieee80211_key_conf *key;
};

struct rtw_sec_desc {
	/* search strategy */
	bool default_key_search;

	u32 total_cam_num;
	struct rtw_cam_entry cam_table[RTW_MAX_SEC_CAM_NUM];
	DECLARE_BITMAP(cam_map, RTW_MAX_SEC_CAM_NUM);
};

struct rtw_tx_report {
	/* protect the tx report queue */
	spinlock_t q_lock;
	struct sk_buff_head queue;
	atomic_t sn;
	struct timer_list purge_timer;
};

struct rtw_bf_info {
	u8 bfer_mu_cnt;
	u8 bfer_su_cnt;
	DECLARE_BITMAP(bfer_su_reg_maping, 2);
	u8 cur_csi_rpt_rate;
};

enum rtw_regd_state {
	RTW_REGD_STATE_WORLDWIDE,
	RTW_REGD_STATE_PROGRAMMED,
	RTW_REGD_STATE_SETTING,

	RTW_REGD_STATE_NR,
};

struct rtw_regd {
	enum rtw_regd_state state;
	const struct rtw_regulatory *regulatory;
	enum nl80211_dfs_regions dfs_region;
};

struct rtw_wow_pattern {
	u16 crc;
	u8 type;
	u8 valid;
	u8 mask[RTW_MAX_PATTERN_MASK_SIZE];
};

struct rtw_pno_request {
	bool inited;
	u32 match_set_cnt;
	struct cfg80211_match_set *match_sets;
	u8 channel_cnt;
	struct ieee80211_channel *channels;
	struct cfg80211_sched_scan_plan scan_plan;
};

struct rtw_wow_param {
	struct ieee80211_vif *wow_vif;
	DECLARE_BITMAP(flags, RTW_WOW_FLAG_MAX);
	u8 txpause;
	u8 pattern_cnt;
	struct rtw_wow_pattern patterns[RTW_MAX_PATTERN_NUM];

	bool ips_enabled;
	struct rtw_pno_request pno_req;
};

enum rtw_coex_bt_state_cnt {
	COEX_CNT_BT_RETRY,
	COEX_CNT_BT_REINIT,
	COEX_CNT_BT_REENABLE,
	COEX_CNT_BT_POPEVENT,
	COEX_CNT_BT_SETUPLINK,
	COEX_CNT_BT_IGNWLANACT,
	COEX_CNT_BT_INQ,
	COEX_CNT_BT_PAGE,
	COEX_CNT_BT_ROLESWITCH,
	COEX_CNT_BT_AFHUPDATE,
	COEX_CNT_BT_INFOUPDATE,
	COEX_CNT_BT_IQK,
	COEX_CNT_BT_IQKFAIL,

	COEX_CNT_BT_MAX
};

enum rtw_coex_wl_state_cnt {
	COEX_CNT_WL_SCANAP,
	COEX_CNT_WL_CONNPKT,
	COEX_CNT_WL_COEXRUN,
	COEX_CNT_WL_NOISY0,
	COEX_CNT_WL_NOISY1,
	COEX_CNT_WL_NOISY2,
	COEX_CNT_WL_5MS_NOEXTEND,
	COEX_CNT_WL_FW_NOTIFY,

	COEX_CNT_WL_MAX
};

struct rtw_coex_rfe {
	bool ant_switch_exist;
	bool ant_switch_diversity;
	bool ant_switch_with_bt;
	u8 rfe_module_type;
	u8 ant_switch_polarity;

	/* true if WLG at BTG, else at WLAG */
	bool wlg_at_btg;
};

#define COEX_WL_TDMA_PARA_LENGTH	5

struct rtw_coex_dm {
	bool cur_ps_tdma_on;
	bool cur_wl_rx_low_gain_en;
	bool ignore_wl_act;

	u8 reason;
	u8 bt_rssi_state[4];
	u8 wl_rssi_state[4];
	u8 wl_ch_info[3];
	u8 cur_ps_tdma;
	u8 cur_table;
	u8 ps_tdma_para[5];
	u8 cur_bt_pwr_lvl;
	u8 cur_bt_lna_lvl;
	u8 cur_wl_pwr_lvl;
	u8 bt_status;
	u32 cur_ant_pos_type;
	u32 cur_switch_status;
	u32 setting_tdma;
	u8 fw_tdma_para[COEX_WL_TDMA_PARA_LENGTH];
};

#define COEX_BTINFO_SRC_MAX	0x6

#define COEX_BTINFO_LENGTH_MAX	10

#define COEX_BT_HIDINFO_NAME	3

#define COEX_BT_HIDINFO_HANDLE_NUM	4

struct rtw_coex_hid {
	u8 hid_handle;
	u8 hid_vendor;
	u8 hid_name[COEX_BT_HIDINFO_NAME];
	bool hid_info_completed;
	bool is_game_hid;
};

struct rtw_coex_hid_handle_list {
	u8 cmd_id;
	u8 len;
	u8 subid;
	u8 handle_cnt;
	u8 handle[COEX_BT_HIDINFO_HANDLE_NUM];
} __packed;

struct rtw_coex_stat {
	bool bt_disabled;
	bool bt_disabled_pre;
	bool bt_link_exist;
	bool bt_whck_test;
	bool bt_inq_page;
	bool bt_inq_remain;
	bool bt_inq;
	bool bt_page;
	bool bt_ble_voice;
	bool bt_ble_exist;
	bool bt_hfp_exist;
	bool bt_a2dp_exist;
	bool bt_hid_exist;
	bool bt_pan_exist; /* PAN or OPP */
	bool bt_opp_exist; /* OPP only */
	bool bt_acl_busy;
	bool bt_fix_2M;
	bool bt_setup_link;
	bool bt_multi_link;
	bool bt_multi_link_pre;
	bool bt_multi_link_remain;
	bool bt_a2dp_sink;
	bool bt_a2dp_active;
	bool bt_reenable;
	bool bt_ble_scan_en;
	bool bt_init_scan;
	bool bt_slave;
	bool bt_418_hid_exist;
	bool bt_ble_hid_exist;
	bool bt_game_hid_exist;
	bool bt_hid_handle_cnt;
	bool bt_mailbox_reply;

	bool wl_under_lps;
	bool wl_under_ips;
	bool wl_hi_pri_task1;
	bool wl_hi_pri_task2;
	bool wl_force_lps_ctrl;
	bool wl_gl_busy;
	bool wl_linkscan_proc;
	bool wl_ps_state_fail;
	bool wl_tx_limit_en;
	bool wl_ampdu_limit_en;
	bool wl_connected;
	bool wl_slot_extend;
	bool wl_cck_lock;
	bool wl_cck_lock_pre;
	bool wl_cck_lock_ever;
	bool wl_connecting;
	bool wl_slot_toggle;
	bool wl_slot_toggle_change; /* if toggle to no-toggle */
	bool wl_mimo_ps;

	u32 bt_supported_version;
	u32 bt_supported_feature;
	u32 hi_pri_tx;
	u32 hi_pri_rx;
	u32 lo_pri_tx;
	u32 lo_pri_rx;
	u32 patch_ver;
	u16 bt_reg_vendor_ae;
	u16 bt_reg_vendor_ac;
	s8 bt_rssi;
	u8 kt_ver;
	u8 gnt_workaround_state;
	u8 tdma_timer_base;
	u8 bt_profile_num;
	u8 bt_info_c2h[COEX_BTINFO_SRC_MAX][COEX_BTINFO_LENGTH_MAX];
	u8 bt_info_lb2;
	u8 bt_info_lb3;
	u8 bt_info_hb0;
	u8 bt_info_hb1;
	u8 bt_info_hb2;
	u8 bt_info_hb3;
	u8 bt_ble_scan_type;
	u8 bt_hid_pair_num;
	u8 bt_hid_slot;
	u8 bt_a2dp_bitpool;
	u8 bt_iqk_state;

	u16 wl_beacon_interval;
	u8 wl_noisy_level;
	u8 wl_fw_dbg_info[10];
	u8 wl_fw_dbg_info_pre[10];
	u8 wl_rx_rate;
	u8 wl_tx_rate;
	u8 wl_rts_rx_rate;
	u8 wl_coex_mode;
	u8 wl_iot_peer;
	u8 ampdu_max_time;
	u8 wl_tput_dir;

	u8 wl_toggle_para[6];
	u8 wl_toggle_interval;

	u16 score_board;
	u16 retry_limit;

	/* counters to record bt states */
	u32 cnt_bt[COEX_CNT_BT_MAX];

	/* counters to record wifi states */
	u32 cnt_wl[COEX_CNT_WL_MAX];

	/* counters to record bt c2h data */
	u32 cnt_bt_info_c2h[COEX_BTINFO_SRC_MAX];

	u32 darfrc;
	u32 darfrch;

	struct rtw_coex_hid hid_info[COEX_BT_HIDINFO_HANDLE_NUM];
	struct rtw_coex_hid_handle_list hid_handle_list;
};

struct rtw_coex {
	struct sk_buff_head queue;
	wait_queue_head_t wait;

	bool under_5g;
	bool stop_dm;
	bool freeze;
	bool freerun;
	bool wl_rf_off;
	bool manual_control;

	struct rtw_coex_stat stat;
	struct rtw_coex_dm dm;
	struct rtw_coex_rfe rfe;

	struct delayed_work bt_relink_work;
	struct delayed_work bt_reenable_work;
	struct delayed_work defreeze_work;
	struct delayed_work wl_remain_work;
	struct delayed_work bt_remain_work;
	struct delayed_work wl_connecting_work;
	struct delayed_work bt_multi_link_remain_work;
	struct delayed_work wl_ccklock_work;

};

#define DPK_RF_PATH_NUM 2

struct ewma_thermal { unsigned long internal; };

struct rtw_dpk_info {
	bool is_dpk_pwr_on;
	bool is_reload;

	DECLARE_BITMAP(dpk_path_ok, DPK_RF_PATH_NUM);

	u8 thermal_dpk[DPK_RF_PATH_NUM];
	struct ewma_thermal avg_thermal[DPK_RF_PATH_NUM];

	u32 gnt_control;
	u32 gnt_value;

	u8 result[RTW_RF_PATH_MAX];
	u8 dpk_txagc[RTW_RF_PATH_MAX];
	u32 coef[RTW_RF_PATH_MAX][20];
	u16 dpk_gs[RTW_RF_PATH_MAX];
	u8 thermal_dpk_delta[RTW_RF_PATH_MAX];
	u8 pre_pwsf[RTW_RF_PATH_MAX];

	u8 dpk_band;
	u8 dpk_ch;
	u8 dpk_bw;
};

#define DACK_MSBK_BACKUP_NUM	0xf
#define DACK_DCK_BACKUP_NUM	0x2

struct rtw_pkt_count {
	u16 num_bcn_pkt;
	u16 num_qry_pkt[DESC_RATE_MAX];
};

struct ewma_evm { unsigned long internal; };

struct ewma_snr { unsigned long internal; };

struct rtw_iqk_info {
	bool done;
	struct {
		u32 s1_x;
		u32 s1_y;
		u32 s0_x;
		u32 s0_y;
	} result;
};

enum rtw_rf_band {
	RF_BAND_2G_CCK,
	RF_BAND_2G_OFDM,
	RF_BAND_5G_L,
	RF_BAND_5G_M,
	RF_BAND_5G_H,
	RF_BAND_MAX
};

#define RF_GAIN_NUM 11

struct rtw_gapk_info {
	u32 rf3f_bp[RF_BAND_MAX][RF_GAIN_NUM][RTW_RF_PATH_MAX];
	u32 rf3f_fs[RTW_RF_PATH_MAX][RF_GAIN_NUM];
	bool txgapk_bp_done;
	s8 offset[RF_GAIN_NUM][RTW_RF_PATH_MAX];
	s8 fianl_offset[RF_GAIN_NUM][RTW_RF_PATH_MAX];
	u8 read_txgain;
	u8 channel;
};

enum rtw_edcca_mode {
	RTW_EDCCA_NORMAL	= 0,
	RTW_EDCCA_ADAPTIVITY	= 1,
};

struct rtw_cfo_track {
	bool is_adjust;
	u8 crystal_cap;
	s32 cfo_tail[RTW_RF_PATH_MAX];
	s32 cfo_cnt[RTW_RF_PATH_MAX];
	u32 packet_count;
	u32 packet_count_pre;
};

struct rtw_dm_info {
	u32 cck_fa_cnt;
	u32 ofdm_fa_cnt;
	u32 total_fa_cnt;
	u32 cck_cca_cnt;
	u32 ofdm_cca_cnt;
	u32 total_cca_cnt;

	u32 cck_ok_cnt;
	u32 cck_err_cnt;
	u32 ofdm_ok_cnt;
	u32 ofdm_err_cnt;
	u32 ht_ok_cnt;
	u32 ht_err_cnt;
	u32 vht_ok_cnt;
	u32 vht_err_cnt;

	u8 min_rssi;
	u8 pre_min_rssi;
	u16 fa_history[4];
	u8 igi_history[4];
	u8 igi_bitmap;
	bool damping;
	u8 damping_cnt;
	u8 damping_rssi;

	u8 cck_gi_u_bnd;
	u8 cck_gi_l_bnd;

	u8 fix_rate;
	u8 tx_rate;
	u32 rrsr_val_init;
	u32 rrsr_mask_min;
	u8 thermal_avg[RTW_RF_PATH_MAX];
	u8 thermal_meter_k;
	u8 thermal_meter_lck;
	s8 delta_power_index[RTW_RF_PATH_MAX];
	s8 delta_power_index_last[RTW_RF_PATH_MAX];
	u8 default_ofdm_index;
	bool pwr_trk_triggered;
	bool pwr_trk_init_trigger;
	struct ewma_thermal avg_thermal[RTW_RF_PATH_MAX];
	s8 txagc_remnant_cck;
	s8 txagc_remnant_ofdm;

	/* backup dack results for each path and I/Q */
	u32 dack_adck[RTW_RF_PATH_MAX];
	u16 dack_msbk[RTW_RF_PATH_MAX][2][DACK_MSBK_BACKUP_NUM];
	u8 dack_dck[RTW_RF_PATH_MAX][2][DACK_DCK_BACKUP_NUM];

	struct rtw_dpk_info dpk_info;
	struct rtw_cfo_track cfo_track;

	/* [bandwidth 0:20M/1:40M][number of path] */
	u8 cck_pd_lv[2][RTW_RF_PATH_MAX];
	u32 cck_fa_avg;
	u8 cck_pd_default;

	/* save the last rx phy status for debug */
	s8 rx_snr[RTW_RF_PATH_MAX];
	u8 rx_evm_dbm[RTW_RF_PATH_MAX];
	s16 cfo_tail[RTW_RF_PATH_MAX];
	u8 rssi[RTW_RF_PATH_MAX];
	u8 curr_rx_rate;
	struct rtw_pkt_count cur_pkt_count;
	struct rtw_pkt_count last_pkt_count;
	struct ewma_evm ewma_evm[RTW_EVM_NUM];
	struct ewma_snr ewma_snr[RTW_SNR_NUM];

	u32 dm_flags; /* enum rtw_dm_cap */
	struct rtw_iqk_info iqk;
	struct rtw_gapk_info gapk;
	bool is_bt_iqk_timeout;

	s8 l2h_th_ini;
	enum rtw_edcca_mode edcca_mode;
	u8 scan_density;
};

struct rtw_efuse {
	u32 size;
	u32 physical_size;
	u32 logical_size;
	u32 protect_size;

	u8 addr[ETH_ALEN];
	u8 channel_plan;
	u8 country_code[2];
	u8 rf_board_option;
	u8 rfe_option;
	u8 power_track_type;
	u8 thermal_meter[RTW_RF_PATH_MAX];
	u8 thermal_meter_k;
	u8 crystal_cap;
	u8 ant_div_cfg;
	u8 ant_div_type;
	u8 regd;
	u8 afe;

	u8 lna_type_2g;
	u8 lna_type_5g;
	u8 glna_type;
	u8 alna_type;
	bool ext_lna_2g;
	bool ext_lna_5g;
	u8 pa_type_2g;
	u8 pa_type_5g;
	u8 gpa_type;
	u8 apa_type;
	bool ext_pa_2g;
	bool ext_pa_5g;
	u8 tx_bb_swing_setting_2g;
	u8 tx_bb_swing_setting_5g;

	bool btcoex;
	/* bt share antenna with wifi */
	bool share_ant;
	u8 bt_setting;

	struct {
		u8 hci;
		u8 bw;
		u8 ptcl;
		u8 nss;
		u8 ant_num;
	} hw_cap;

	struct rtw_txpwr_idx txpwr_idx_table[4];
};

struct rtw_phy_cond {
#ifdef __LITTLE_ENDIAN
	u32 rfe:8;
	u32 intf:4;
	u32 pkg:4;
	u32 plat:4;
	u32 intf_rsvd:4;
	u32 cut:4;
	u32 branch:2;
	u32 neg:1;
	u32 pos:1;
#else
#error "klp-ccp: non-taken branch"
#endif
				};

struct rtw_fifo_conf {
	/* tx fifo information */
	u16 rsvd_boundary;
	u16 rsvd_pg_num;
	u16 rsvd_drv_pg_num;
	u16 txff_pg_num;
	u16 acq_pg_num;
	u16 rsvd_drv_addr;
	u16 rsvd_h2c_info_addr;
	u16 rsvd_h2c_sta_info_addr;
	u16 rsvd_h2cq_addr;
	u16 rsvd_cpu_instr_addr;
	u16 rsvd_fw_txbuf_addr;
	u16 rsvd_csibuf_addr;
	const struct rtw_rqpn *rqpn;
};

struct rtw_fwcd_desc {
	u32 size;
	u8 *next;
	u8 *data;
};

struct rtw_fw_state {
	const struct firmware *firmware;
	struct rtw_dev *rtwdev;
	struct completion completion;
	struct rtw_fwcd_desc fwcd_desc;
	u16 version;
	u8 sub_version;
	u8 sub_index;
	u16 h2c_version;
	u32 feature;
	u32 feature_ext;
	enum rtw_fw_type type;
};

enum rtw_sar_sources {
	RTW_SAR_SOURCE_NONE,
	RTW_SAR_SOURCE_COMMON,
};

enum rtw_sar_bands {
	RTW_SAR_BAND_0,
	RTW_SAR_BAND_1,
	/* RTW_SAR_BAND_2, not used now */
	RTW_SAR_BAND_3,
	RTW_SAR_BAND_4,

	RTW_SAR_BAND_NR,
};

union rtw_sar_cfg {
	s8 common[RTW_SAR_BAND_NR];
};

struct rtw_sar {
	enum rtw_sar_sources src;
	union rtw_sar_cfg cfg[RTW_RF_PATH_MAX][RTW_RATE_SECTION_MAX];
};

struct rtw_hal {
	u32 rcr;

	u32 chip_version;
	u8 cut_version;
	u8 mp_chip;
	u8 oem_id;
	u8 pkg_type;
	struct rtw_phy_cond phy_cond;
	bool rfe_btg;

	u8 ps_mode;
	u8 current_channel;
	u8 current_primary_channel_index;
	u8 current_band_width;
	u8 current_band_type;
	u8 primary_channel;

	/* center channel for different available bandwidth,
	 * val of (bw > current_band_width) is invalid
	 */
	u8 cch_by_bw[RTW_MAX_CHANNEL_WIDTH + 1];

	u8 sec_ch_offset;
	u8 rf_type;
	u8 rf_path_num;
	u8 rf_phy_num;
	u32 antenna_tx;
	u32 antenna_rx;
	u8 bfee_sts_cap;
	bool txrx_1ss;

	/* protect tx power section */
	struct mutex tx_power_mutex;
	s8 tx_pwr_by_rate_offset_2g[RTW_RF_PATH_MAX]
				   [DESC_RATE_MAX];
	s8 tx_pwr_by_rate_offset_5g[RTW_RF_PATH_MAX]
				   [DESC_RATE_MAX];
	s8 tx_pwr_by_rate_base_2g[RTW_RF_PATH_MAX]
				 [RTW_RATE_SECTION_MAX];
	s8 tx_pwr_by_rate_base_5g[RTW_RF_PATH_MAX]
				 [RTW_RATE_SECTION_MAX];
	s8 tx_pwr_limit_2g[RTW_REGD_MAX]
			  [RTW_CHANNEL_WIDTH_MAX]
			  [RTW_RATE_SECTION_MAX]
			  [RTW_MAX_CHANNEL_NUM_2G];
	s8 tx_pwr_limit_5g[RTW_REGD_MAX]
			  [RTW_CHANNEL_WIDTH_MAX]
			  [RTW_RATE_SECTION_MAX]
			  [RTW_MAX_CHANNEL_NUM_5G];
	s8 tx_pwr_tbl[RTW_RF_PATH_MAX]
		     [DESC_RATE_MAX];

	enum rtw_sar_bands sar_band;
	struct rtw_sar sar;

	/* for 8821c set channel */
	u32 ch_param[3];
};

struct rtw_path_div {
	enum rtw_bb_path current_tx_path;
	u32 path_a_sum;
	u32 path_b_sum;
	u16 path_a_cnt;
	u16 path_b_cnt;
};

struct rtw_hw_scan_info {
	struct ieee80211_vif *scanning_vif;
	u8 probe_pg_size;
	u8 op_pri_ch_idx;
	u8 op_pri_ch;
	u8 op_chan;
	u8 op_bw;
};

struct rtw_dev {
	struct ieee80211_hw *hw;
	struct device *dev;

	struct rtw_hci hci;

	struct rtw_hw_scan_info scan_info;
	const struct rtw_chip_info *chip;
	struct rtw_hal hal;
	struct rtw_fifo_conf fifo;
	struct rtw_fw_state fw;
	struct rtw_efuse efuse;
	struct rtw_sec_desc sec;
	struct rtw_traffic_stats stats;
	struct rtw_regd regd;
	struct rtw_bf_info bf_info;

	struct rtw_dm_info dm_info;
	struct rtw_coex coex;

	/* ensures exclusive access from mac80211 callbacks */
	struct mutex mutex;

	/* watch dog every 2 sec */
	struct delayed_work watch_dog_work;
	u32 watch_dog_cnt;

	struct list_head rsvd_page_list;

	/* c2h cmd queue & handler work */
	struct sk_buff_head c2h_queue;
	struct work_struct c2h_work;
	struct work_struct ips_work;
	struct work_struct fw_recovery_work;
	struct work_struct update_beacon_work;

	/* used to protect txqs list */
	spinlock_t txq_lock;
	struct list_head txqs;
	struct workqueue_struct *tx_wq;
	struct work_struct tx_work;
	struct work_struct ba_work;

	struct rtw_tx_report tx_report;

	struct {
		/* indicate the mail box to use with fw */
		u8 last_box_num;
		u32 seq;
	} h2c;

	/* lps power state & handler work */
	struct rtw_lps_conf lps_conf;
	bool ps_enabled;
	bool beacon_loss;
	struct completion lps_leave_check;

	struct dentry *debugfs;

	u8 sta_cnt;
	u32 rts_threshold;

	DECLARE_BITMAP(hw_port, RTW_PORT_NUM);
	DECLARE_BITMAP(mac_id_map, RTW_MAX_MAC_ID_NUM);
	DECLARE_BITMAP(flags, NUM_OF_RTW_FLAGS);

	u8 mp_mode;
	struct rtw_path_div dm_path_div;

	struct rtw_fw_state wow_fw;
	struct rtw_wow_param wow;

	bool need_rfk;
	struct completion fw_scan_density;
	bool ap_active;

	/* hci related data, must be last */
	u8 priv[] __aligned(sizeof(void *));
};

/* klp-ccp: from drivers/net/wireless/realtek/rtw88/coex.h */
#define COEX_H2C69_TDMA_SLOT	0xb
#define PARA1_H2C69_TDMA_4SLOT	0xc1
#define PARA1_H2C69_TDMA_2SLOT	0x1
#define PARA1_H2C69_TBTT_TIMES	GENMASK(5, 0)
#define PARA1_H2C69_TBTT_DIV100	BIT(7)

#define TDMA_TIMER_TYPE_4SLOT 3

/* klp-ccp: from drivers/net/wireless/realtek/rtw88/fw.h */
void rtw_fw_bt_wifi_control(struct rtw_dev *rtwdev, u8 op_code, u8 *data);

/* klp-ccp: from drivers/net/wireless/realtek/rtw88/debug.h */
enum rtw_debug_mask {
	RTW_DBG_PCI		= 0x00000001,
	RTW_DBG_TX		= 0x00000002,
	RTW_DBG_RX		= 0x00000004,
	RTW_DBG_PHY		= 0x00000008,
	RTW_DBG_FW		= 0x00000010,
	RTW_DBG_EFUSE		= 0x00000020,
	RTW_DBG_COEX		= 0x00000040,
	RTW_DBG_RFK		= 0x00000080,
	RTW_DBG_REGD		= 0x00000100,
	RTW_DBG_DEBUGFS		= 0x00000200,
	RTW_DBG_PS		= 0x00000400,
	RTW_DBG_BF		= 0x00000800,
	RTW_DBG_WOW		= 0x00001000,
	RTW_DBG_CFO		= 0x00002000,
	RTW_DBG_PATH_DIV	= 0x00004000,
	RTW_DBG_ADAPTIVITY	= 0x00008000,
	RTW_DBG_HW_SCAN		= 0x00010000,
	RTW_DBG_STATE		= 0x00020000,
	RTW_DBG_SDIO		= 0x00040000,

	RTW_DBG_ALL		= 0xffffffff
};

#ifdef CONFIG_RTW88_DEBUG
#error "klp-ccp: non-taken branch"
#else

static inline void rtw_dbg(struct rtw_dev *rtwdev, enum rtw_debug_mask mask,
			   const char *fmt, ...) {}

#endif /* CONFIG_RTW88_DEBUG */

/* klp-ccp: from drivers/net/wireless/realtek/rtw88/coex.c */
extern void rtw_coex_wl_ccklock_action(struct rtw_dev *rtwdev);

void klpp_rtw_coex_tdma_timer_base(struct rtw_dev *rtwdev, u8 type)
{
	struct rtw_coex *coex = &rtwdev->coex;
	struct rtw_coex_stat *coex_stat = &coex->stat;
	u8 para[6] = {};
	u8 times;
	u16 tbtt_interval = coex_stat->wl_beacon_interval;

	if (coex_stat->tdma_timer_base == type)
		return;

	coex_stat->tdma_timer_base = type;

	para[0] = COEX_H2C69_TDMA_SLOT;

	rtw_dbg(rtwdev, RTW_DBG_COEX, "[BTCoex], tbtt_interval = %d\n",
		tbtt_interval);

	if (type == TDMA_TIMER_TYPE_4SLOT && tbtt_interval < 120) {
		para[1] = PARA1_H2C69_TDMA_4SLOT; /* 4-slot */
	} else if (tbtt_interval < 80 && tbtt_interval > 0) {
		times = 100 / tbtt_interval;
		if (100 % tbtt_interval != 0)
			times++;

		para[1] = FIELD_PREP(PARA1_H2C69_TBTT_TIMES, times);
	} else if (tbtt_interval >= 180) {
		times = tbtt_interval / 100;
		if (tbtt_interval % 100 <= 80)
			times--;

		para[1] = FIELD_PREP(PARA1_H2C69_TBTT_TIMES, times) |
			  FIELD_PREP(PARA1_H2C69_TBTT_DIV100, 1);
	} else {
		para[1] = PARA1_H2C69_TDMA_2SLOT;
	}

	rtw_fw_bt_wifi_control(rtwdev, para[0], &para[1]);

	rtw_dbg(rtwdev, RTW_DBG_COEX, "[BTCoex], %s(): h2c_0x69 = 0x%x\n",
		__func__, para[1]);

	/* no 5ms_wl_slot_extend for 4-slot mode  */
	if (coex_stat->tdma_timer_base == 3)
		rtw_coex_wl_ccklock_action(rtwdev);
}


#include "livepatch_bsc1257629.h"

#include <linux/livepatch.h>

extern typeof(rtw_coex_wl_ccklock_action) rtw_coex_wl_ccklock_action
	 KLP_RELOC_SYMBOL(rtw88_core, rtw88_core, rtw_coex_wl_ccklock_action);
extern typeof(rtw_fw_bt_wifi_control) rtw_fw_bt_wifi_control
	 KLP_RELOC_SYMBOL(rtw88_core, rtw88_core, rtw_fw_bt_wifi_control);

#endif /* IS_ENABLED(CONFIG_RTW88_CORE) */
