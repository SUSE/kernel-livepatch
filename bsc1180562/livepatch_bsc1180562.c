/*
 * livepatch_bsc1180562
 *
 * Fix for CVE-2020-36158, bsc#1180562
 *
 *  Upstream commit:
 *  5c455c5ab332 ("mwifiex: Fix possible buffer overflows in
 *                 mwifiex_cmd_802_11_ad_hoc_start")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  6e082c0fb33dd5c4cee938aa86504938c930f871
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  a833298e67ab77c9485064c9edf6dbcb54334ddc
 *
 *  SLE15-SP2 commit:
 *  3e80605ba06ac5950743aab7fb98533be25cdc7d
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if IS_ENABLED(CONFIG_MWIFIEX)

#if !IS_MODULE(CONFIG_MWIFIEX)
#error "Live patch supports only CONFIG_MWIFIEX=m"
#endif

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/decl.h */
#define pr_fmt(fmt)	"mwifiex" ": " fmt

#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/ieee80211.h>
#include <net/cfg80211.h>

#define MWIFIEX_MAX_BSS_NUM         (3)

struct mwifiex_fw_image;

struct mwifiex_802_11_ssid {
	u32 ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
};

struct mwifiex_wait_queue {
	wait_queue_head_t wait;
	int status;
};

enum mwifiex_wmm_ac_e {
	WMM_AC_BK,
	WMM_AC_BE,
	WMM_AC_VI,
	WMM_AC_VO
} __packed;

struct ieee_types_wmm_ac_parameters {
	u8 aci_aifsn_bitmap;
	u8 ecw_bitmap;
	__le16 tx_op_limit;
} __packed;

struct mwifiex_types_wmm_info {
	u8 oui[4];
	u8 subtype;
	u8 version;
	u8 qos_info;
	u8 reserved;
	struct ieee_types_wmm_ac_parameters ac_params[IEEE80211_NUM_ACS];
} __packed;

struct mwifiex_iface_comb {
	u8 sta_intf;
	u8 uap_intf;
	u8 p2p_intf;
};

struct mwifiex_11h_intf_state {
	bool is_11h_enabled;
	bool is_11h_active;
} __packed;

#include <net/lib80211.h>

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/ioctl.h */
#define MWIFIEX_MAX_MULTICAST_LIST_SIZE	32

enum {
	BAND_B = 1,
	BAND_G = 2,
	BAND_A = 4,
	BAND_GN = 8,
	BAND_AN = 16,
	BAND_AAC = 32,
};

#define MWIFIEX_WPA_PASSHPHRASE_LEN 64
struct wpa_param {
	u8 pairwise_cipher_wpa;
	u8 pairwise_cipher_wpa2;
	u8 group_cipher;
	u32 length;
	u8 passphrase[MWIFIEX_WPA_PASSHPHRASE_LEN];
};

struct wep_key {
	u8 key_index;
	u8 is_default;
	u16 length;
	u8 key[WLAN_KEY_LEN_WEP104];
};

#define MWIFIEX_SUPPORTED_RATES                 14

struct mwifiex_uap_bss_param {
	u8 channel;
	u8 band_cfg;
	u16 rts_threshold;
	u16 frag_threshold;
	u8 retry_limit;
	struct mwifiex_802_11_ssid ssid;
	u8 bcast_ssid_ctl;
	u8 radio_ctl;
	u8 dtim_period;
	u16 beacon_period;
	u16 auth_mode;
	u16 protocol;
	u16 key_mgmt;
	u16 key_mgmt_operation;
	struct wpa_param wpa_cfg;
	struct wep_key wep_cfg[NUM_WEP_KEYS];
	struct ieee80211_ht_cap ht_cap;
	struct ieee80211_vht_cap vht_cap;
	u8 rates[MWIFIEX_SUPPORTED_RATES];
	u32 sta_ao_timer;
	u32 ps_sta_ao_timer;
	u8 qos_info;
	u8 power_constraint;
	struct mwifiex_types_wmm_info wmm_info;
};

#define MAX_NUM_TID     8

#define DBG_CMD_NUM    5
#define MWIFIEX_DBG_SDIO_MP_NUM    10

#define PN_LEN				16

struct mwifiex_ds_mem_rw {
	u32 addr;
	u32 value;
};

#define IEEE_MAX_IE_SIZE		256

struct subsc_evt_cfg {
	u8 abs_value;
	u8 evt_freq;
};

struct mwifiex_ds_misc_subsc_evt {
	u16 action;
	u16 events;
	struct subsc_evt_cfg bcn_l_rssi_cfg;
	struct subsc_evt_cfg bcn_h_rssi_cfg;
};

#define MWIFIEX_MAX_VSIE_LEN       (256)
#define MWIFIEX_MAX_VSIE_NUM       (8)

#define MWIFIEX_VSIE_MASK_ADHOC    0x04

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/fw.h */
#include <linux/if_ether.h>

#define HOSTCMD_SUPPORTED_RATES         14

#define FW_MULTI_BANDS_SUPPORT  (BIT(8) | BIT(9) | BIT(10) | BIT(11) | \
				 BIT(13))
#define IS_SUPPORT_MULTI_BANDS(adapter)        \
	(adapter->fw_cap_info & FW_MULTI_BANDS_SUPPORT)

#define WPA_PN_SIZE		8

enum MWIFIEX_802_11_PRIVACY_FILTER {
	MWIFIEX_802_11_PRIV_FILTER_ACCEPT_ALL,
	MWIFIEX_802_11_PRIV_FILTER_8021X_WEP
};

#define PROPRIETARY_TLV_BASE_ID                 0x0100

#define TLV_TYPE_CHANLIST           (PROPRIETARY_TLV_BASE_ID + 1)

#define HostCmd_CMD_MAC_CONTROL                       0x0028
#define HostCmd_CMD_802_11_AD_HOC_START               0x002b

#define HostCmd_ACT_GEN_SET                   0x0001

#define HostCmd_ACT_MAC_ADHOC_G_PROTECTION_ON BIT(13)

#define HostCmd_BSS_MODE_IBSS               0x0002

struct mwifiex_ie_types_header {
	__le16 type;
	__le16 len;
} __packed;

struct mwifiex_chan_scan_param_set {
	u8 radio_type;
	u8 chan_number;
	u8 chan_scan_mode_bitmap;
	__le16 min_scan_time;
	__le16 max_scan_time;
} __packed;

struct mwifiex_ie_types_chan_list_param_set {
	struct mwifiex_ie_types_header header;
	struct mwifiex_chan_scan_param_set chan_scan_param[1];
} __packed;

struct mwifiex_ie_type_key_param_set {
	__le16 type;
	__le16 length;
	__le16 key_type_id;
	__le16 key_info;
	__le16 key_len;
	u8 key[50];
} __packed;

#define IGTK_PN_LEN		8

struct mwifiex_wep_param {
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_WEP104];
} __packed;

struct mwifiex_tkip_param {
	u8 pn[WPA_PN_SIZE];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_TKIP];
} __packed;

struct mwifiex_aes_param {
	u8 pn[WPA_PN_SIZE];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_CCMP];
} __packed;

struct mwifiex_wapi_param {
	u8 pn[PN_LEN];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_SMS4];
} __packed;

struct mwifiex_cmac_aes_param {
	u8 ipn[IGTK_PN_LEN];
	__le16 key_len;
	u8 key[WLAN_KEY_LEN_AES_CMAC];
} __packed;

struct mwifiex_ie_type_key_param_set_v2 {
	__le16 type;
	__le16 len;
	u8 mac_addr[ETH_ALEN];
	u8 key_idx;
	u8 key_type;
	__le16 key_info;
	union {
		struct mwifiex_wep_param wep;
		struct mwifiex_tkip_param tkip;
		struct mwifiex_aes_param aes;
		struct mwifiex_wapi_param wapi;
		struct mwifiex_cmac_aes_param cmac_aes;
	} key_params;
} __packed;

struct host_cmd_ds_802_11_key_material_v2 {
	__le16 action;
	struct mwifiex_ie_type_key_param_set_v2 key_param_set;
} __packed;

struct host_cmd_ds_802_11_key_material {
	__le16 action;
	struct mwifiex_ie_type_key_param_set key_param_set;
} __packed;

struct host_cmd_ds_gen {
	__le16 command;
	__le16 size;
	__le16 seq_num;
	__le16 result;
};

#define S_DS_GEN        sizeof(struct host_cmd_ds_gen)

struct mwifiex_ps_param {
	__le16 null_pkt_interval;
	__le16 multiple_dtims;
	__le16 bcn_miss_timeout;
	__le16 local_listen_interval;
	__le16 adhoc_wake_period;
	__le16 mode;
	__le16 delay_to_ps;
} __packed;

struct host_cmd_ds_802_11_ps_mode_enh {
	__le16 action;

	union {
		struct mwifiex_ps_param opt_ps;
		__le16 ps_bitmap;
	} params;
} __packed;

struct host_cmd_ds_get_hw_spec {
	__le16 hw_if_version;
	__le16 version;
	__le16 reserved;
	__le16 num_of_mcast_adr;
	u8 permanent_addr[ETH_ALEN];
	__le16 region_code;
	__le16 number_of_antenna;
	__le32 fw_release_number;
	__le32 reserved_1;
	__le32 reserved_2;
	__le32 reserved_3;
	__le32 fw_cap_info;
	__le32 dot_11n_dev_cap;
	u8 dev_mcs_support;
	__le16 mp_end_port;	/* SDIO only, reserved for other interfacces */
	__le16 mgmt_buf_count;	/* mgmt IE buffer count */
	__le32 reserved_5;
	__le32 reserved_6;
	__le32 dot_11ac_dev_cap;
	__le32 dot_11ac_mcs_support;
	u8 tlvs[0];
} __packed;

struct host_cmd_ds_802_11_rssi_info {
	__le16 action;
	__le16 ndata;
	__le16 nbcn;
	__le16 reserved[9];
	long long reserved_1;
} __packed;

struct host_cmd_ds_802_11_rssi_info_rsp {
	__le16 action;
	__le16 ndata;
	__le16 nbcn;
	__le16 data_rssi_last;
	__le16 data_nf_last;
	__le16 data_rssi_avg;
	__le16 data_nf_avg;
	__le16 bcn_rssi_last;
	__le16 bcn_nf_last;
	__le16 bcn_rssi_avg;
	__le16 bcn_nf_avg;
	long long tsf_bcn;
} __packed;

struct host_cmd_ds_802_11_mac_address {
	__le16 action;
	u8 mac_addr[ETH_ALEN];
} __packed;

struct host_cmd_ds_mac_control {
	__le32 action;
};

struct host_cmd_ds_mac_multicast_adr {
	__le16 action;
	__le16 num_of_adrs;
	u8 mac_list[MWIFIEX_MAX_MULTICAST_LIST_SIZE][ETH_ALEN];
} __packed;

struct host_cmd_ds_802_11_deauthenticate {
	u8 mac_addr[ETH_ALEN];
	__le16 reason_code;
} __packed;

struct host_cmd_ds_802_11_associate {
	u8 peer_sta_addr[ETH_ALEN];
	__le16 cap_info_bitmap;
	__le16 listen_interval;
	__le16 beacon_period;
	u8 dtim_period;
} __packed;

struct ieee_types_assoc_rsp {
	__le16 cap_info_bitmap;
	__le16 status_code;
	__le16 a_id;
	u8 ie_buffer[0];
} __packed;

struct host_cmd_ds_802_11_associate_rsp {
	struct ieee_types_assoc_rsp assoc_rsp;
} __packed;

struct ieee_types_cf_param_set {
	u8 element_id;
	u8 len;
	u8 cfp_cnt;
	u8 cfp_period;
	__le16 cfp_max_duration;
	__le16 cfp_duration_remaining;
} __packed;

struct ieee_types_ibss_param_set {
	u8 element_id;
	u8 len;
	__le16 atim_window;
} __packed;

union ieee_types_ss_param_set {
	struct ieee_types_cf_param_set cf_param_set;
	struct ieee_types_ibss_param_set ibss_param_set;
} __packed;

struct ieee_types_fh_param_set {
	u8 element_id;
	u8 len;
	__le16 dwell_time;
	u8 hop_set;
	u8 hop_pattern;
	u8 hop_index;
} __packed;

struct ieee_types_ds_param_set {
	u8 element_id;
	u8 len;
	u8 current_chan;
} __packed;

union ieee_types_phy_param_set {
	struct ieee_types_fh_param_set fh_param_set;
	struct ieee_types_ds_param_set ds_param_set;
} __packed;

struct host_cmd_ds_802_11_ad_hoc_start {
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 bss_mode;
	__le16 beacon_period;
	u8 dtim_period;
	union ieee_types_ss_param_set ss_param_set;
	union ieee_types_phy_param_set phy_param_set;
	u16 reserved1;
	__le16 cap_info_bitmap;
	u8 data_rate[HOSTCMD_SUPPORTED_RATES];
} __packed;

struct host_cmd_ds_802_11_ad_hoc_start_result {
	u8 pad[3];
	u8 bssid[ETH_ALEN];
	u8 pad2[2];
	u8 result;
} __packed;

struct host_cmd_ds_802_11_ad_hoc_join_result {
	u8 result;
} __packed;

struct adhoc_bss_desc {
	u8 bssid[ETH_ALEN];
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 bss_mode;
	__le16 beacon_period;
	u8 dtim_period;
	u8 time_stamp[8];
	u8 local_time[8];
	union ieee_types_phy_param_set phy_param_set;
	union ieee_types_ss_param_set ss_param_set;
	__le16 cap_info_bitmap;
	u8 data_rates[HOSTCMD_SUPPORTED_RATES];

	/*
	 *  DO NOT ADD ANY FIELDS TO THIS STRUCTURE.
	 *  It is used in the Adhoc join command and will cause a
	 *  binary layout mismatch with the firmware
	 */
} __packed;

struct host_cmd_ds_802_11_ad_hoc_join {
	struct adhoc_bss_desc bss_descriptor;
	u16 reserved1;
	u16 reserved2;
} __packed;

struct host_cmd_ds_802_11_get_log {
	__le32 mcast_tx_frame;
	__le32 failed;
	__le32 retry;
	__le32 multi_retry;
	__le32 frame_dup;
	__le32 rts_success;
	__le32 rts_failure;
	__le32 ack_failure;
	__le32 rx_frag;
	__le32 mcast_rx_frame;
	__le32 fcs_error;
	__le32 tx_frame;
	__le32 reserved;
	__le32 wep_icv_err_cnt[4];
	__le32 bcn_rcv_cnt;
	__le32 bcn_miss_cnt;
} __packed;

struct host_cmd_ds_tx_rate_query {
	u8 tx_rate;
	/* Tx Rate Info: For 802.11 AC cards
	 *
	 * [Bit 0-1] tx rate formate: LG = 0, HT = 1, VHT = 2
	 * [Bit 2-3] HT/VHT Bandwidth: BW20 = 0, BW40 = 1, BW80 = 2, BW160 = 3
	 * [Bit 4]   HT/VHT Guard Interval: LGI = 0, SGI = 1
	 *
	 * For non-802.11 AC cards
	 * Ht Info [Bit 0] RxRate format: LG=0, HT=1
	 * [Bit 1]  HT Bandwidth: BW20 = 0, BW40 = 1
	 * [Bit 2]  HT Guard Interval: LGI = 0, SGI = 1
	 */
	u8 ht_info;
} __packed;

struct mwifiex_hs_config_param {
	__le32 conditions;
	u8 gpio;
	u8 gap;
} __packed;

struct hs_activate_param {
	__le16 resp_ctrl;
} __packed;

struct host_cmd_ds_802_11_hs_cfg_enh {
	__le16 action;

	union {
		struct mwifiex_hs_config_param hs_config;
		struct hs_activate_param hs_activate;
	} params;
} __packed;

struct host_cmd_ds_802_11_snmp_mib {
	__le16 query_type;
	__le16 oid;
	__le16 buf_size;
	u8 value[1];
} __packed;

struct host_cmd_ds_tx_rate_cfg {
	__le16 action;
	__le16 cfg_index;
} __packed;

struct host_cmd_ds_txpwr_cfg {
	__le16 action;
	__le16 cfg_index;
	__le32 mode;
} __packed;

struct host_cmd_ds_rf_tx_pwr {
	__le16 action;
	__le16 cur_level;
	u8 max_power;
	u8 min_power;
} __packed;

struct host_cmd_ds_rf_ant_mimo {
	__le16 action_tx;
	__le16 tx_ant_mode;
	__le16 action_rx;
	__le16 rx_ant_mode;
} __packed;

struct host_cmd_ds_rf_ant_siso {
	__le16 action;
	__le16 ant_mode;
} __packed;

struct host_cmd_ds_tdls_oper {
	__le16 tdls_action;
	__le16 reason;
	u8 peer_mac[ETH_ALEN];
} __packed;

struct host_cmd_ds_tdls_config {
	__le16 tdls_action;
	u8 tdls_data[1];
} __packed;

struct mwifiex_chan_desc {
	__le16 start_freq;
	u8 chan_width;
	u8 chan_num;
} __packed;

struct host_cmd_ds_chan_rpt_req {
	struct mwifiex_chan_desc chan_desc;
	__le32 msec_dwell_time;
} __packed;

struct host_cmd_sdio_sp_rx_aggr_cfg {
	u8 action;
	u8 enable;
	__le16 block_size;
} __packed;

#define MWIFIEX_USER_SCAN_CHAN_MAX             50

struct mwifiex_user_scan_chan {
	u8 chan_number;
	u8 radio_type;
	u8 scan_type;
	u8 reserved;
	u32 scan_time;
} __packed;

struct host_cmd_ds_802_11_scan {
	u8 bss_mode;
	u8 bssid[ETH_ALEN];
	u8 tlv_buffer[1];
} __packed;

struct host_cmd_ds_802_11_scan_rsp {
	__le16 bss_descript_size;
	u8 number_of_sets;
	u8 bss_desc_and_tlv_buffer[1];
} __packed;

struct host_cmd_ds_802_11_scan_ext {
	u32   reserved;
	u8    tlv_buffer[1];
} __packed;

struct host_cmd_ds_802_11_bg_scan_config {
	__le16 action;
	u8 enable;
	u8 bss_type;
	u8 chan_per_scan;
	u8 reserved;
	__le16 reserved1;
	__le32 scan_interval;
	__le32 reserved2;
	__le32 report_condition;
	__le16 reserved3;
	u8 tlv[0];
} __packed;

struct host_cmd_ds_802_11_bg_scan_query {
	u8 flush;
} __packed;

struct host_cmd_ds_802_11_bg_scan_query_rsp {
	__le32 report_condition;
	struct host_cmd_ds_802_11_scan_rsp scan_resp;
} __packed;

struct mwifiex_ietypes_domain_param_set {
	struct mwifiex_ie_types_header header;
	u8 country_code[IEEE80211_COUNTRY_STRING_LEN];
	struct ieee80211_country_ie_triplet triplet[1];
} __packed;

struct host_cmd_ds_802_11d_domain_info {
	__le16 action;
	struct mwifiex_ietypes_domain_param_set domain;
} __packed;

struct host_cmd_ds_802_11d_domain_info_rsp {
	__le16 action;
	struct mwifiex_ietypes_domain_param_set domain;
} __packed;

struct host_cmd_ds_11n_addba_req {
	u8 add_req_result;
	u8 peer_mac_addr[ETH_ALEN];
	u8 dialog_token;
	__le16 block_ack_param_set;
	__le16 block_ack_tmo;
	__le16 ssn;
} __packed;

struct host_cmd_ds_11n_addba_rsp {
	u8 add_rsp_result;
	u8 peer_mac_addr[ETH_ALEN];
	u8 dialog_token;
	__le16 status_code;
	__le16 block_ack_param_set;
	__le16 block_ack_tmo;
	__le16 ssn;
} __packed;

struct host_cmd_ds_11n_delba {
	u8 del_result;
	u8 peer_mac_addr[ETH_ALEN];
	__le16 del_ba_param_set;
	__le16 reason_code;
	u8 reserved;
} __packed;

struct host_cmd_ds_11n_cfg {
	__le16 action;
	__le16 ht_tx_cap;
	__le16 ht_tx_info;
	__le16 misc_config;	/* Needed for 802.11AC cards only */
} __packed;

struct host_cmd_ds_txbuf_cfg {
	__le16 action;
	__le16 buff_size;
	__le16 mp_end_port;	/* SDIO only, reserved for other interfacces */
	__le16 reserved3;
} __packed;

struct host_cmd_ds_amsdu_aggr_ctrl {
	__le16 action;
	__le16 enable;
	__le16 curr_buf_size;
} __packed;

struct host_cmd_ds_sta_deauth {
	u8 mac[ETH_ALEN];
	__le16 reason;
} __packed;

struct host_cmd_ds_sta_list {
	__le16 sta_count;
	u8 tlv[0];
} __packed;

struct mwifiex_ie_types_wmm_queue_status {
	struct mwifiex_ie_types_header header;
	u8 queue_index;
	u8 disabled;
	__le16 medium_time;
	u8 flow_required;
	u8 flow_created;
	u32 reserved;
};

struct ieee_types_vendor_header {
	u8 element_id;
	u8 len;
	struct {
		u8 oui[3];
		u8 oui_type;
	} __packed oui;
} __packed;

struct ieee_types_wmm_parameter {
	/*
	 * WMM Parameter IE - Vendor Specific Header:
	 *   element_id  [221/0xdd]
	 *   Len         [24]
	 *   Oui         [00:50:f2]
	 *   OuiType     [2]
	 *   OuiSubType  [1]
	 *   Version     [1]
	 */
	struct ieee_types_vendor_header vend_hdr;
	u8 oui_subtype;
	u8 version;

	u8 qos_info_bitmap;
	u8 reserved;
	struct ieee_types_wmm_ac_parameters ac_params[IEEE80211_NUM_ACS];
} __packed;

struct host_cmd_ds_wmm_get_status {
	u8 queue_status_tlv[sizeof(struct mwifiex_ie_types_wmm_queue_status) *
			      IEEE80211_NUM_ACS];
	u8 wmm_param_tlv[sizeof(struct ieee_types_wmm_parameter) + 2];
} __packed;

struct mwifiex_wmm_ac_status {
	u8 disabled;
	u8 flow_required;
	u8 flow_created;
};

struct mwifiex_ie_types_htcap {
	struct mwifiex_ie_types_header header;
	struct ieee80211_ht_cap ht_cap;
} __packed;

struct mwifiex_ie_types_htinfo {
	struct mwifiex_ie_types_header header;
	struct ieee80211_ht_operation ht_oper;
} __packed;

struct host_cmd_ds_mem_access {
	__le16 action;
	__le16 reserved;
	__le32 addr;
	__le32 value;
} __packed;

struct host_cmd_ds_mac_reg_access {
	__le16 action;
	__le16 offset;
	__le32 value;
} __packed;

struct host_cmd_ds_bbp_reg_access {
	__le16 action;
	__le16 offset;
	u8 value;
	u8 reserved[3];
} __packed;

struct host_cmd_ds_rf_reg_access {
	__le16 action;
	__le16 offset;
	u8 value;
	u8 reserved[3];
} __packed;

struct host_cmd_ds_pmic_reg_access {
	__le16 action;
	__le16 offset;
	u8 value;
	u8 reserved[3];
} __packed;

struct host_cmd_ds_802_11_eeprom_access {
	__le16 action;

	__le16 offset;
	__le16 byte_count;
	u8 value;
} __packed;

struct host_cmd_ds_sys_config {
	__le16 action;
	u8 tlv[0];
};

struct host_cmd_11ac_vht_cfg {
	__le16 action;
	u8 band_config;
	u8 misc_config;
	__le32 cap_info;
	__le32 mcs_tx_set;
	__le32 mcs_rx_set;
} __packed;

struct host_cmd_ds_version_ext {
	u8 version_str_sel;
	char version_str[128];
} __packed;

struct host_cmd_ds_mgmt_frame_reg {
	__le16 action;
	__le32 mask;
} __packed;

struct host_cmd_ds_p2p_mode_cfg {
	__le16 action;
	__le16 mode;
} __packed;

struct host_cmd_ds_remain_on_chan {
	__le16 action;
	u8 status;
	u8 reserved;
	u8 band_cfg;
	u8 channel;
	__le32 duration;
} __packed;

struct host_cmd_ds_802_11_ibss_status {
	__le16 action;
	__le16 enable;
	u8 bssid[ETH_ALEN];
	__le16 beacon_interval;
	__le16 atim_window;
	__le16 use_g_rate_protect;
} __packed;

struct mwifiex_fw_mef_entry {
	u8 mode;
	u8 action;
	__le16 exprsize;
	u8 expr[0];
} __packed;

struct host_cmd_ds_mef_cfg {
	__le32 criteria;
	__le16 num_entries;
	struct mwifiex_fw_mef_entry mef_entry[0];
} __packed;

struct host_cmd_ds_set_bss_mode {
	u8 con_type;
} __packed;

struct host_cmd_ds_pcie_details {
	/* TX buffer descriptor ring address */
	__le32 txbd_addr_lo;
	__le32 txbd_addr_hi;
	/* TX buffer descriptor ring count */
	__le32 txbd_count;

	/* RX buffer descriptor ring address */
	__le32 rxbd_addr_lo;
	__le32 rxbd_addr_hi;
	/* RX buffer descriptor ring count */
	__le32 rxbd_count;

	/* Event buffer descriptor ring address */
	__le32 evtbd_addr_lo;
	__le32 evtbd_addr_hi;
	/* Event buffer descriptor ring count */
	__le32 evtbd_count;

	/* Sleep cookie buffer physical address */
	__le32 sleep_cookie_addr_lo;
	__le32 sleep_cookie_addr_hi;
} __packed;

struct host_cmd_ds_802_11_subsc_evt {
	__le16 action;
	__le16 events;
} __packed;

struct mwifiex_ie {
	__le16 ie_index;
	__le16 mgmt_subtype_mask;
	__le16 ie_length;
	u8 ie_buffer[IEEE_MAX_IE_SIZE];
} __packed;

#define MAX_MGMT_IE_INDEX	16

struct coalesce_filt_field_param {
	u8 operation;
	u8 operand_len;
	__le16 offset;
	u8 operand_byte_stream[4];
};

struct coalesce_receive_filt_rule {
	struct mwifiex_ie_types_header header;
	u8 num_of_fields;
	u8 pkt_type;
	__le16 max_coalescing_delay;
	struct coalesce_filt_field_param params[0];
} __packed;

struct host_cmd_ds_coalesce_cfg {
	__le16 action;
	__le16 num_of_rules;
	struct coalesce_receive_filt_rule rule[0];
} __packed;

struct host_cmd_ds_multi_chan_policy {
	__le16 action;
	__le16 policy;
} __packed;

struct host_cmd_ds_robust_coex {
	__le16 action;
	__le16 reserved;
} __packed;

struct host_cmd_ds_wakeup_reason {
	__le16  wakeup_reason;
} __packed;

struct host_cmd_ds_gtk_rekey_params {
	__le16 action;
	u8 kck[NL80211_KCK_LEN];
	u8 kek[NL80211_KEK_LEN];
	__le32 replay_ctr_low;
	__le32 replay_ctr_high;
} __packed;

struct host_cmd_ds_chan_region_cfg {
	__le16 action;
} __packed;

struct host_cmd_ds_pkt_aggr_ctrl {
	__le16 action;
	__le16 enable;
	__le16 tx_aggr_max_size;
	__le16 tx_aggr_max_num;
	__le16 tx_aggr_align;
} __packed;

struct host_cmd_ds_sta_configure {
	__le16 action;
	u8 tlv_buffer[0];
} __packed;

struct host_cmd_ds_command {
	__le16 command;
	__le16 size;
	__le16 seq_num;
	__le16 result;
	union {
		struct host_cmd_ds_get_hw_spec hw_spec;
		struct host_cmd_ds_mac_control mac_ctrl;
		struct host_cmd_ds_802_11_mac_address mac_addr;
		struct host_cmd_ds_mac_multicast_adr mc_addr;
		struct host_cmd_ds_802_11_get_log get_log;
		struct host_cmd_ds_802_11_rssi_info rssi_info;
		struct host_cmd_ds_802_11_rssi_info_rsp rssi_info_rsp;
		struct host_cmd_ds_802_11_snmp_mib smib;
		struct host_cmd_ds_tx_rate_query tx_rate;
		struct host_cmd_ds_tx_rate_cfg tx_rate_cfg;
		struct host_cmd_ds_txpwr_cfg txp_cfg;
		struct host_cmd_ds_rf_tx_pwr txp;
		struct host_cmd_ds_rf_ant_mimo ant_mimo;
		struct host_cmd_ds_rf_ant_siso ant_siso;
		struct host_cmd_ds_802_11_ps_mode_enh psmode_enh;
		struct host_cmd_ds_802_11_hs_cfg_enh opt_hs_cfg;
		struct host_cmd_ds_802_11_scan scan;
		struct host_cmd_ds_802_11_scan_ext ext_scan;
		struct host_cmd_ds_802_11_scan_rsp scan_resp;
		struct host_cmd_ds_802_11_bg_scan_config bg_scan_config;
		struct host_cmd_ds_802_11_bg_scan_query bg_scan_query;
		struct host_cmd_ds_802_11_bg_scan_query_rsp bg_scan_query_resp;
		struct host_cmd_ds_802_11_associate associate;
		struct host_cmd_ds_802_11_associate_rsp associate_rsp;
		struct host_cmd_ds_802_11_deauthenticate deauth;
		struct host_cmd_ds_802_11_ad_hoc_start adhoc_start;
		struct host_cmd_ds_802_11_ad_hoc_start_result start_result;
		struct host_cmd_ds_802_11_ad_hoc_join_result join_result;
		struct host_cmd_ds_802_11_ad_hoc_join adhoc_join;
		struct host_cmd_ds_802_11d_domain_info domain_info;
		struct host_cmd_ds_802_11d_domain_info_rsp domain_info_resp;
		struct host_cmd_ds_11n_addba_req add_ba_req;
		struct host_cmd_ds_11n_addba_rsp add_ba_rsp;
		struct host_cmd_ds_11n_delba del_ba;
		struct host_cmd_ds_txbuf_cfg tx_buf;
		struct host_cmd_ds_amsdu_aggr_ctrl amsdu_aggr_ctrl;
		struct host_cmd_ds_11n_cfg htcfg;
		struct host_cmd_ds_wmm_get_status get_wmm_status;
		struct host_cmd_ds_802_11_key_material key_material;
		struct host_cmd_ds_802_11_key_material_v2 key_material_v2;
		struct host_cmd_ds_version_ext verext;
		struct host_cmd_ds_mgmt_frame_reg reg_mask;
		struct host_cmd_ds_remain_on_chan roc_cfg;
		struct host_cmd_ds_p2p_mode_cfg mode_cfg;
		struct host_cmd_ds_802_11_ibss_status ibss_coalescing;
		struct host_cmd_ds_mef_cfg mef_cfg;
		struct host_cmd_ds_mem_access mem;
		struct host_cmd_ds_mac_reg_access mac_reg;
		struct host_cmd_ds_bbp_reg_access bbp_reg;
		struct host_cmd_ds_rf_reg_access rf_reg;
		struct host_cmd_ds_pmic_reg_access pmic_reg;
		struct host_cmd_ds_set_bss_mode bss_mode;
		struct host_cmd_ds_pcie_details pcie_host_spec;
		struct host_cmd_ds_802_11_eeprom_access eeprom;
		struct host_cmd_ds_802_11_subsc_evt subsc_evt;
		struct host_cmd_ds_sys_config uap_sys_config;
		struct host_cmd_ds_sta_deauth sta_deauth;
		struct host_cmd_ds_sta_list sta_list;
		struct host_cmd_11ac_vht_cfg vht_cfg;
		struct host_cmd_ds_coalesce_cfg coalesce_cfg;
		struct host_cmd_ds_tdls_config tdls_config;
		struct host_cmd_ds_tdls_oper tdls_oper;
		struct host_cmd_ds_chan_rpt_req chan_rpt_req;
		struct host_cmd_sdio_sp_rx_aggr_cfg sdio_rx_aggr_cfg;
		struct host_cmd_ds_multi_chan_policy mc_policy;
		struct host_cmd_ds_robust_coex coex;
		struct host_cmd_ds_wakeup_reason hs_wakeup_reason;
		struct host_cmd_ds_gtk_rekey_params rekey;
		struct host_cmd_ds_chan_region_cfg reg_cfg;
		struct host_cmd_ds_pkt_aggr_ctrl pkt_aggr_ctrl;
		struct host_cmd_ds_sta_configure sta_cfg;
	} params;
} __packed;

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/main.h */
#include <linux/completion.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <net/lib80211.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/pcie.h */
#include    <linux/completion.h>
#include    <linux/interrupt.h>
/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/usb.h */
#include <linux/completion.h>
/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/sdio.h */
#include <linux/completion.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_ids.h>

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/main.h */
struct mwifiex_adapter;

#define MWIFIEX_UPLD_SIZE               (2312)

#define MAX_EVENT_SIZE                  2048

#define ARP_FILTER_MAX_BUF_SIZE         68

#define MWIFIEX_KEY_BUFFER_SIZE			16

#define FIRST_VALID_CHANNEL				0xff

#define MAX_BITMAP_RATES_SIZE			18

enum MWIFIEX_DEBUG_LEVEL {
	MWIFIEX_DBG_MSG		= 0x00000001,
	MWIFIEX_DBG_FATAL	= 0x00000002,
	MWIFIEX_DBG_ERROR	= 0x00000004,
	MWIFIEX_DBG_DATA	= 0x00000008,
	MWIFIEX_DBG_CMD		= 0x00000010,
	MWIFIEX_DBG_EVENT	= 0x00000020,
	MWIFIEX_DBG_INTR	= 0x00000040,
	MWIFIEX_DBG_IOCTL	= 0x00000080,

	MWIFIEX_DBG_MPA_D	= 0x00008000,
	MWIFIEX_DBG_DAT_D	= 0x00010000,
	MWIFIEX_DBG_CMD_D	= 0x00020000,
	MWIFIEX_DBG_EVT_D	= 0x00040000,
	MWIFIEX_DBG_FW_D	= 0x00080000,
	MWIFIEX_DBG_IF_D	= 0x00100000,

	MWIFIEX_DBG_ENTRY	= 0x10000000,
	MWIFIEX_DBG_WARN	= 0x20000000,
	MWIFIEX_DBG_INFO	= 0x40000000,
	MWIFIEX_DBG_DUMP	= 0x80000000,

	MWIFIEX_DBG_ANY		= 0xffffffff
};

static __printf(3, 4)
void (*klpe__mwifiex_dbg)(const struct mwifiex_adapter *adapter, int mask,
		  const char *fmt, ...);
#define klpr_mwifiex_dbg(adapter, mask, fmt, ...)				\
	(*klpe__mwifiex_dbg)(adapter, MWIFIEX_DBG_##mask, fmt, ##__VA_ARGS__)

struct mwifiex_dbg {
	u32 num_cmd_host_to_card_failure;
	u32 num_cmd_sleep_cfm_host_to_card_failure;
	u32 num_tx_host_to_card_failure;
	u32 num_event_deauth;
	u32 num_event_disassoc;
	u32 num_event_link_lost;
	u32 num_cmd_deauth;
	u32 num_cmd_assoc_success;
	u32 num_cmd_assoc_failure;
	u32 num_tx_timeout;
	u16 timeout_cmd_id;
	u16 timeout_cmd_act;
	u16 last_cmd_id[DBG_CMD_NUM];
	u16 last_cmd_act[DBG_CMD_NUM];
	u16 last_cmd_index;
	u16 last_cmd_resp_id[DBG_CMD_NUM];
	u16 last_cmd_resp_index;
	u16 last_event[DBG_CMD_NUM];
	u16 last_event_index;
	u32 last_mp_wr_bitmap[MWIFIEX_DBG_SDIO_MP_NUM];
	u32 last_mp_wr_ports[MWIFIEX_DBG_SDIO_MP_NUM];
	u32 last_mp_wr_len[MWIFIEX_DBG_SDIO_MP_NUM];
	u32 last_mp_curr_wr_port[MWIFIEX_DBG_SDIO_MP_NUM];
	u8 last_sdio_mp_index;
};

enum MWIFIEX_HARDWARE_STATUS {
	MWIFIEX_HW_STATUS_READY,
	MWIFIEX_HW_STATUS_INITIALIZING,
	MWIFIEX_HW_STATUS_INIT_DONE,
	MWIFIEX_HW_STATUS_RESET,
	MWIFIEX_HW_STATUS_NOT_READY
};

struct mwifiex_tx_param;

struct mwifiex_add_ba_param {
	u32 tx_win_size;
	u32 rx_win_size;
	u32 timeout;
	u8 tx_amsdu;
	u8 rx_amsdu;
};

struct mwifiex_tx_aggr {
	u8 ampdu_user;
	u8 ampdu_ap;
	u8 amsdu;
};

struct mwifiex_tid_tbl {
	struct list_head ra_list;
};

#define WMM_HIGHEST_PRIORITY		7

struct mwifiex_wmm_desc {
	struct mwifiex_tid_tbl tid_tbl_ptr[MAX_NUM_TID];
	u32 packets_out[MAX_NUM_TID];
	u32 pkts_paused[MAX_NUM_TID];
	/* spin lock to protect ra_list */
	spinlock_t ra_list_spinlock;
	struct mwifiex_wmm_ac_status ac_status[IEEE80211_NUM_ACS];
	enum mwifiex_wmm_ac_e ac_down_graded_vals[IEEE80211_NUM_ACS];
	u32 drv_pkt_delay_max;
	u8 queue_priority[IEEE80211_NUM_ACS];
	u32 user_pri_pkt_tx_ctrl[WMM_HIGHEST_PRIORITY + 1];	/* UP: 0 to 7 */
	/* Number of transmit packets queued */
	atomic_t tx_pkts_queued;
	/* Tracks highest priority with a packet queued */
	atomic_t highest_queued_prio;
};

struct mwifiex_802_11_security {
	u8 wpa_enabled;
	u8 wpa2_enabled;
	u8 wapi_enabled;
	u8 wapi_key_on;
	u8 wep_enabled;
	u32 authentication_mode;
	u8 is_authtype_auto;
	u32 encryption_mode;
};

struct mwifiex_bssdescriptor {
	u8 mac_address[ETH_ALEN];
	struct cfg80211_ssid ssid;
	u32 privacy;
	s32 rssi;
	u32 channel;
	u32 freq;
	u16 beacon_period;
	u8 erp_flags;
	u32 bss_mode;
	u8 supported_rates[MWIFIEX_SUPPORTED_RATES];
	u8 data_rates[MWIFIEX_SUPPORTED_RATES];
	/* Network band.
	 * BAND_B(0x01): 'b' band
	 * BAND_G(0x02): 'g' band
	 * BAND_A(0X04): 'a' band
	 */
	u16 bss_band;
	u64 fw_tsf;
	u64 timestamp;
	union ieee_types_phy_param_set phy_param_set;
	union ieee_types_ss_param_set ss_param_set;
	u16 cap_info_bitmap;
	struct ieee_types_wmm_parameter wmm_ie;
	u8  disable_11n;
	struct ieee80211_ht_cap *bcn_ht_cap;
	u16 ht_cap_offset;
	struct ieee80211_ht_operation *bcn_ht_oper;
	u16 ht_info_offset;
	u8 *bcn_bss_co_2040;
	u16 bss_co_2040_offset;
	u8 *bcn_ext_cap;
	u16 ext_cap_offset;
	struct ieee80211_vht_cap *bcn_vht_cap;
	u16 vht_cap_offset;
	struct ieee80211_vht_operation *bcn_vht_oper;
	u16 vht_info_offset;
	struct ieee_types_oper_mode_ntf *oper_mode;
	u16 oper_mode_offset;
	u8 disable_11ac;
	struct ieee_types_vendor_specific *bcn_wpa_ie;
	u16 wpa_offset;
	struct ieee_types_generic *bcn_rsn_ie;
	u16 rsn_offset;
	struct ieee_types_generic *bcn_wapi_ie;
	u16 wapi_offset;
	u8 *beacon_buf;
	u32 beacon_buf_size;
	u8 sensed_11h;
	u8 local_constraint;
	u8 chan_sw_ie_present;
};

struct mwifiex_current_bss_params {
	struct mwifiex_bssdescriptor bss_descriptor;
	u8 wmm_enabled;
	u8 wmm_uapsd_enabled;
	u8 band;
	u32 num_of_rates;
	u8 data_rates[MWIFIEX_SUPPORTED_RATES];
};

struct mwifiex_sleep_params {
	u16 sp_error;
	u16 sp_offset;
	u16 sp_stable_time;
	u8 sp_cal_control;
	u8 sp_ext_sleep_clk;
	u16 sp_reserved;
};

struct mwifiex_sleep_period {
	u16 period;
	u16 reserved;
};

struct mwifiex_wep_key {
	u32 length;
	u32 key_index;
	u32 key_length;
	u8 key_material[MWIFIEX_KEY_BUFFER_SIZE];
};

struct mwifiex_chan_freq_power {
	u16 channel;
	u32 freq;
	u16 max_tx_power;
	u8 unsupported;
};

#define MWIFIEX_MAX_TRIPLET_802_11D		83

struct mwifiex_802_11d_domain_reg {
	u8 country_code[IEEE80211_COUNTRY_STRING_LEN];
	u8 no_of_triplet;
	struct ieee80211_country_ie_triplet
		triplet[MWIFIEX_MAX_TRIPLET_802_11D];
};

struct mwifiex_vendor_spec_cfg_ie {
	u16 mask;
	u16 flag;
	u8 ie[MWIFIEX_MAX_VSIE_LEN];
};

struct wps {
	u8 session_enable;
};

struct mwifiex_roc_cfg {
	u64 cookie;
	struct ieee80211_channel chan;
};

struct mwifiex_private {
	struct mwifiex_adapter *adapter;
	u8 bss_type;
	u8 bss_role;
	u8 bss_priority;
	u8 bss_num;
	u8 bss_started;
	u8 frame_type;
	u8 curr_addr[ETH_ALEN];
	u8 media_connected;
	u8 port_open;
	u8 usb_port;
	u32 num_tx_timeout;
	/* track consecutive timeout */
	u8 tx_timeout_cnt;
	struct net_device *netdev;
	struct net_device_stats stats;
	u32 curr_pkt_filter;
	u32 bss_mode;
	u32 pkt_tx_ctrl;
	u16 tx_power_level;
	u8 max_tx_power_level;
	u8 min_tx_power_level;
	u32 tx_ant;
	u32 rx_ant;
	u8 tx_rate;
	u8 tx_htinfo;
	u8 rxpd_htinfo;
	u8 rxpd_rate;
	u16 rate_bitmap;
	u16 bitmap_rates[MAX_BITMAP_RATES_SIZE];
	u32 data_rate;
	u8 is_data_rate_auto;
	u16 bcn_avg_factor;
	u16 data_avg_factor;
	s16 data_rssi_last;
	s16 data_nf_last;
	s16 data_rssi_avg;
	s16 data_nf_avg;
	s16 bcn_rssi_last;
	s16 bcn_nf_last;
	s16 bcn_rssi_avg;
	s16 bcn_nf_avg;
	struct mwifiex_bssdescriptor *attempted_bss_desc;
	struct cfg80211_ssid prev_ssid;
	u8 prev_bssid[ETH_ALEN];
	struct mwifiex_current_bss_params curr_bss_params;
	u16 beacon_period;
	u8 dtim_period;
	u16 listen_interval;
	u16 atim_window;
	u8 adhoc_channel;
	u8 adhoc_is_link_sensed;
	u8 adhoc_state;
	struct mwifiex_802_11_security sec_info;
	struct mwifiex_wep_key wep_key[NUM_WEP_KEYS];
	u16 wep_key_curr_index;
	u8 wpa_ie[256];
	u16 wpa_ie_len;
	u8 wpa_is_gtk_set;
	struct host_cmd_ds_802_11_key_material aes_key;
	struct host_cmd_ds_802_11_key_material_v2 aes_key_v2;
	u8 wapi_ie[256];
	u16 wapi_ie_len;
	u8 *wps_ie;
	u16 wps_ie_len;
	u8 wmm_required;
	u8 wmm_enabled;
	u8 wmm_qosinfo;
	struct mwifiex_wmm_desc wmm;
	atomic_t wmm_tx_pending[IEEE80211_NUM_ACS];
	struct list_head sta_list;
	/* spin lock for associated station/TDLS peers list */
	spinlock_t sta_list_spinlock;
	struct list_head auto_tdls_list;
	/* spin lock for auto TDLS peer list */
	spinlock_t auto_tdls_lock;
	struct list_head tx_ba_stream_tbl_ptr;
	/* spin lock for tx_ba_stream_tbl_ptr queue */
	spinlock_t tx_ba_stream_tbl_lock;
	struct mwifiex_tx_aggr aggr_prio_tbl[MAX_NUM_TID];
	struct mwifiex_add_ba_param add_ba_param;
	u16 rx_seq[MAX_NUM_TID];
	u8 tos_to_tid_inv[MAX_NUM_TID];
	struct list_head rx_reorder_tbl_ptr;
	/* spin lock for rx_reorder_tbl_ptr queue */
	spinlock_t rx_reorder_tbl_lock;
#define MWIFIEX_ASSOC_RSP_BUF_SIZE  500
	u8 assoc_rsp_buf[MWIFIEX_ASSOC_RSP_BUF_SIZE];
	u32 assoc_rsp_size;

#define MWIFIEX_GENIE_BUF_SIZE      256
	u8 gen_ie_buf[MWIFIEX_GENIE_BUF_SIZE];
	u8 gen_ie_buf_len;

	struct mwifiex_vendor_spec_cfg_ie vs_ie[MWIFIEX_MAX_VSIE_NUM];

#define MWIFIEX_ASSOC_TLV_BUF_SIZE  256
	u8 assoc_tlv_buf[MWIFIEX_ASSOC_TLV_BUF_SIZE];
	u8 assoc_tlv_buf_len;

	u8 *curr_bcn_buf;
	u32 curr_bcn_size;
	/* spin lock for beacon buffer */
	spinlock_t curr_bcn_buf_lock;
	struct wireless_dev wdev;
	struct mwifiex_chan_freq_power cfp;
	u32 versionstrsel;
	char version_str[128];
#ifdef CONFIG_DEBUG_FS
	struct dentry *dfs_dev_dir;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u16 current_key_index;
	struct mutex async_mutex;
	struct cfg80211_scan_request *scan_request;
	u8 cfg_bssid[6];
	struct wps wps;
	u8 scan_block;
	s32 cqm_rssi_thold;
	u32 cqm_rssi_hyst;
	u8 subsc_evt_rssi_state;
	struct mwifiex_ds_misc_subsc_evt async_subsc_evt_storage;
	struct mwifiex_ie mgmt_ie[MAX_MGMT_IE_INDEX];
	u16 beacon_idx;
	u16 proberesp_idx;
	u16 assocresp_idx;
	u16 gen_idx;
	u8 ap_11n_enabled;
	u8 ap_11ac_enabled;
	u32 mgmt_frame_mask;
	struct mwifiex_roc_cfg roc_cfg;
	bool scan_aborting;
	u8 sched_scanning;
	u8 csa_chan;
	unsigned long csa_expire_time;
	u8 del_list_idx;
	bool hs2_enabled;
	struct mwifiex_uap_bss_param bss_cfg;
	struct cfg80211_chan_def bss_chandef;
	struct station_parameters *sta_params;
	struct sk_buff_head tdls_txq;
	u8 check_tdls_tx;
	struct timer_list auto_tdls_timer;
	bool auto_tdls_timer_active;
	struct idr ack_status_frames;
	/* spin lock for ack status */
	spinlock_t ack_status_lock;
	/** rx histogram data */
	struct mwifiex_histogram_data *hist_data;
	struct cfg80211_chan_def dfs_chandef;
	struct workqueue_struct *dfs_cac_workqueue;
	struct delayed_work dfs_cac_work;
	struct timer_list dfs_chan_switch_timer;
	struct workqueue_struct *dfs_chan_sw_workqueue;
	struct delayed_work dfs_chan_sw_work;
	struct cfg80211_beacon_data beacon_after;
	struct mwifiex_11h_intf_state state_11h;
	struct mwifiex_ds_mem_rw mem_rw;
	struct sk_buff_head bypass_txq;
	struct mwifiex_user_scan_chan hidden_chan[MWIFIEX_USER_SCAN_CHAN_MAX];
	u8 assoc_resp_ht_param;
	bool ht_param_present;
};

struct mwifiex_bss_prio_tbl {
	struct list_head bss_prio_head;
	/* spin lock for bss priority  */
	spinlock_t bss_prio_lock;
	struct mwifiex_bss_prio_node *bss_prio_cur;
};

struct bus_aggr_params {
	u16 enable;
	u16 mode;
	u16 tx_aggr_max_size;
	u16 tx_aggr_max_num;
	u16 tx_aggr_align;
};

struct mwifiex_if_ops {
	int (*init_if) (struct mwifiex_adapter *);
	void (*cleanup_if) (struct mwifiex_adapter *);
	int (*check_fw_status) (struct mwifiex_adapter *, u32);
	int (*check_winner_status)(struct mwifiex_adapter *);
	int (*prog_fw) (struct mwifiex_adapter *, struct mwifiex_fw_image *);
	int (*register_dev) (struct mwifiex_adapter *);
	void (*unregister_dev) (struct mwifiex_adapter *);
	int (*enable_int) (struct mwifiex_adapter *);
	void (*disable_int) (struct mwifiex_adapter *);
	int (*process_int_status) (struct mwifiex_adapter *);
	int (*host_to_card) (struct mwifiex_adapter *, u8, struct sk_buff *,
			     struct mwifiex_tx_param *);
	int (*wakeup) (struct mwifiex_adapter *);
	int (*wakeup_complete) (struct mwifiex_adapter *);

	/* Interface specific functions */
	void (*update_mp_end_port) (struct mwifiex_adapter *, u16);
	void (*cleanup_mpa_buf) (struct mwifiex_adapter *);
	int (*cmdrsp_complete) (struct mwifiex_adapter *, struct sk_buff *);
	int (*event_complete) (struct mwifiex_adapter *, struct sk_buff *);
	int (*init_fw_port) (struct mwifiex_adapter *);
	int (*dnld_fw) (struct mwifiex_adapter *, struct mwifiex_fw_image *);
	void (*card_reset) (struct mwifiex_adapter *);
	int (*reg_dump)(struct mwifiex_adapter *, char *);
	void (*device_dump)(struct mwifiex_adapter *);
	int (*clean_pcie_ring) (struct mwifiex_adapter *adapter);
	void (*iface_work)(struct work_struct *work);
	void (*submit_rem_rx_urbs)(struct mwifiex_adapter *adapter);
	void (*deaggr_pkt)(struct mwifiex_adapter *, struct sk_buff *);
	void (*multi_port_resync)(struct mwifiex_adapter *);
	bool (*is_port_ready)(struct mwifiex_private *);
	void (*down_dev)(struct mwifiex_adapter *);
	void (*up_dev)(struct mwifiex_adapter *);
};

struct mwifiex_adapter {
	u8 iface_type;
	unsigned int debug_mask;
	struct mwifiex_iface_comb iface_limit;
	struct mwifiex_iface_comb curr_iface_comb;
	struct mwifiex_private *priv[MWIFIEX_MAX_BSS_NUM];
	u8 priv_num;
	const struct firmware *firmware;
	char fw_name[32];
	int winner;
	struct device *dev;
	struct wiphy *wiphy;
	u8 perm_addr[ETH_ALEN];
	unsigned long work_flags;
	u32 fw_release_number;
	u8 intf_hdr_len;
	u16 init_wait_q_woken;
	wait_queue_head_t init_wait_q;
	void *card;
	struct mwifiex_if_ops if_ops;
	atomic_t bypass_tx_pending;
	atomic_t rx_pending;
	atomic_t tx_pending;
	atomic_t cmd_pending;
	atomic_t tx_hw_pending;
	struct workqueue_struct *workqueue;
	struct work_struct main_work;
	struct workqueue_struct *rx_workqueue;
	struct work_struct rx_work;
	struct workqueue_struct *dfs_workqueue;
	struct work_struct dfs_work;
	bool rx_work_enabled;
	bool rx_processing;
	bool delay_main_work;
	bool rx_locked;
	bool main_locked;
	struct mwifiex_bss_prio_tbl bss_prio_tbl[MWIFIEX_MAX_BSS_NUM];
	/* spin lock for main process */
	spinlock_t main_proc_lock;
	u32 mwifiex_processing;
	u8 more_task_flag;
	u16 tx_buf_size;
	u16 curr_tx_buf_size;
	/* sdio single port rx aggregation capability */
	bool host_disable_sdio_rx_aggr;
	bool sdio_rx_aggr_enable;
	u16 sdio_rx_block_size;
	u32 ioport;
	enum MWIFIEX_HARDWARE_STATUS hw_status;
	u16 number_of_antenna;
	u32 fw_cap_info;
	/* spin lock for interrupt handling */
	spinlock_t int_lock;
	u8 int_status;
	u32 event_cause;
	struct sk_buff *event_skb;
	u8 upld_buf[MWIFIEX_UPLD_SIZE];
	u8 data_sent;
	u8 cmd_sent;
	u8 cmd_resp_received;
	u8 event_received;
	u8 data_received;
	u16 seq_num;
	struct cmd_ctrl_node *cmd_pool;
	struct cmd_ctrl_node *curr_cmd;
	/* spin lock for command */
	spinlock_t mwifiex_cmd_lock;
	u16 last_init_cmd;
	struct timer_list cmd_timer;
	struct list_head cmd_free_q;
	/* spin lock for cmd_free_q */
	spinlock_t cmd_free_q_lock;
	struct list_head cmd_pending_q;
	/* spin lock for cmd_pending_q */
	spinlock_t cmd_pending_q_lock;
	struct list_head scan_pending_q;
	/* spin lock for scan_pending_q */
	spinlock_t scan_pending_q_lock;
	/* spin lock for RX processing routine */
	spinlock_t rx_proc_lock;
	struct sk_buff_head tx_data_q;
	atomic_t tx_queued;
	u32 scan_processing;
	u16 region_code;
	struct mwifiex_802_11d_domain_reg domain_reg;
	u16 scan_probes;
	u32 scan_mode;
	u16 specific_scan_time;
	u16 active_scan_time;
	u16 passive_scan_time;
	u16 scan_chan_gap_time;
	u8 fw_bands;
	u8 adhoc_start_band;
	u8 config_bands;
	struct mwifiex_chan_scan_param_set *scan_channels;
	u8 tx_lock_flag;
	struct mwifiex_sleep_params sleep_params;
	struct mwifiex_sleep_period sleep_period;
	u16 ps_mode;
	u32 ps_state;
	u8 need_to_wakeup;
	u16 multiple_dtim;
	u16 local_listen_interval;
	u16 null_pkt_interval;
	struct sk_buff *sleep_cfm;
	u16 bcn_miss_time_out;
	u16 adhoc_awake_period;
	u8 is_deep_sleep;
	u8 delay_null_pkt;
	u16 delay_to_ps;
	u16 enhanced_ps_mode;
	u8 pm_wakeup_card_req;
	u16 gen_null_pkt;
	u16 pps_uapsd_mode;
	u32 pm_wakeup_fw_try;
	struct timer_list wakeup_timer;
	struct mwifiex_hs_config_param hs_cfg;
	u8 hs_activated;
	u16 hs_activate_wait_q_woken;
	wait_queue_head_t hs_activate_wait_q;
	u8 event_body[MAX_EVENT_SIZE];
	u32 hw_dot_11n_dev_cap;
	u8 hw_dev_mcs_support;
	u8 user_dev_mcs_support;
	u8 adhoc_11n_enabled;
	u8 sec_chan_offset;
	struct mwifiex_dbg dbg;
	u8 arp_filter[ARP_FILTER_MAX_BUF_SIZE];
	u32 arp_filter_size;
	struct mwifiex_wait_queue cmd_wait_q;
	u8 scan_wait_q_woken;
	spinlock_t queue_lock;		/* lock for tx queues */
	u8 country_code[IEEE80211_COUNTRY_STRING_LEN];
	u16 max_mgmt_ie_index;
	const struct firmware *cal_data;
	struct device_node *dt_node;

	/* 11AC */
	u32 is_hw_11ac_capable;
	u32 hw_dot_11ac_dev_cap;
	u32 hw_dot_11ac_mcs_support;
	u32 usr_dot_11ac_dev_cap_bg;
	u32 usr_dot_11ac_dev_cap_a;
	u32 usr_dot_11ac_mcs_support;

	atomic_t pending_bridged_pkts;

	/* For synchronizing FW initialization with device lifecycle. */
	struct completion *fw_done;

	bool ext_scan;
	u8 fw_api_ver;
	u8 key_api_major_ver, key_api_minor_ver;
	struct memory_type_mapping *mem_type_mapping_tbl;
	u8 num_mem_types;
	bool scan_chan_gap_enabled;
	struct sk_buff_head rx_data_q;
	bool mfg_mode;
	struct mwifiex_chan_stats *chan_stats;
	u32 num_in_chan_stats;
	int survey_idx;
	bool auto_tdls;
	u8 coex_scan;
	u8 coex_min_scan_time;
	u8 coex_max_scan_time;
	u8 coex_win_size;
	u8 coex_tx_win_size;
	u8 coex_rx_win_size;
	bool drcs_enabled;
	u8 active_scan_triggered;
	bool usb_mc_status;
	bool usb_mc_setup;
	struct cfg80211_wowlan_nd_info *nd_info;
	struct ieee80211_regdomain *regd;

	/* Wake-on-WLAN (WoWLAN) */
	int irq_wakeup;
	bool wake_by_wifi;
	/* Aggregation parameters*/
	struct bus_aggr_params bus_aggr;
	/* Device dump data/length */
	void *devdump_data;
	int devdump_len;
	struct timer_list devdump_timer;
};

static int (*klpe_mwifiex_send_cmd)(struct mwifiex_private *priv, u16 cmd_no,
		     u16 cmd_action, u32 cmd_oid, void *data_buf, bool sync);

static u8 (*klpe_mwifiex_band_to_radio_type)(u8 band);

int klpp_mwifiex_cmd_802_11_ad_hoc_start(struct mwifiex_private *priv,
				    struct host_cmd_ds_command *cmd,
				    struct cfg80211_ssid *req_ssid);

static struct mwifiex_chan_freq_power *(*klpe_mwifiex_get_cfp)(struct mwifiex_private *priv,
						u8 band, u16 channel, u32 freq);

static int (*klpe_mwifiex_cmd_append_vsie_tlv)(struct mwifiex_private *priv, u16 vsie_mask,
				u8 **buffer);
static u32 (*klpe_mwifiex_get_active_data_rates)(struct mwifiex_private *priv,
				    u8 *rates);

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/11n.h */
static int (*klpe_mwifiex_fill_cap_info)(struct mwifiex_private *, u8 radio_type,
			  struct ieee80211_ht_cap *);

/* klp-ccp: from drivers/net/wireless/marvell/mwifiex/join.c */
static int (*klpe_mwifiex_append_rsn_ie_wpa_wpa2)(struct mwifiex_private *priv,
					  u8 **buffer);

int
klpp_mwifiex_cmd_802_11_ad_hoc_start(struct mwifiex_private *priv,
				struct host_cmd_ds_command *cmd,
				struct cfg80211_ssid *req_ssid)
{
	int rsn_ie_len = 0;
	struct mwifiex_adapter *adapter = priv->adapter;
	struct host_cmd_ds_802_11_ad_hoc_start *adhoc_start =
		&cmd->params.adhoc_start;
	struct mwifiex_bssdescriptor *bss_desc;
	u32 cmd_append_size = 0;
	u32 i;
	u16 tmp_cap;
	struct mwifiex_ie_types_chan_list_param_set *chan_tlv;
	u8 radio_type;

	struct mwifiex_ie_types_htcap *ht_cap;
	struct mwifiex_ie_types_htinfo *ht_info;
	u8 *pos = (u8 *) adhoc_start +
			sizeof(struct host_cmd_ds_802_11_ad_hoc_start);

	if (!adapter)
		return -1;

	cmd->command = cpu_to_le16(HostCmd_CMD_802_11_AD_HOC_START);

	bss_desc = &priv->curr_bss_params.bss_descriptor;
	priv->attempted_bss_desc = bss_desc;

	/*
	 * Fill in the parameters for 2 data structures:
	 *   1. struct host_cmd_ds_802_11_ad_hoc_start command
	 *   2. bss_desc
	 * Driver will fill up SSID, bss_mode,IBSS param, Physical Param,
	 * probe delay, and Cap info.
	 * Firmware will fill up beacon period, Basic rates
	 * and operational rates.
	 */

	memset(adhoc_start->ssid, 0, IEEE80211_MAX_SSID_LEN);

	/*
	 * Fix CVE-2020-36158
	 *  +2 lines
	 */
	if (req_ssid->ssid_len > IEEE80211_MAX_SSID_LEN)
		req_ssid->ssid_len = IEEE80211_MAX_SSID_LEN;
	memcpy(adhoc_start->ssid, req_ssid->ssid, req_ssid->ssid_len);

	klpr_mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: SSID = %s\n",
		    adhoc_start->ssid);

	memset(bss_desc->ssid.ssid, 0, IEEE80211_MAX_SSID_LEN);
	memcpy(bss_desc->ssid.ssid, req_ssid->ssid, req_ssid->ssid_len);

	bss_desc->ssid.ssid_len = req_ssid->ssid_len;

	/* Set the BSS mode */
	adhoc_start->bss_mode = HostCmd_BSS_MODE_IBSS;
	bss_desc->bss_mode = NL80211_IFTYPE_ADHOC;
	adhoc_start->beacon_period = cpu_to_le16(priv->beacon_period);
	bss_desc->beacon_period = priv->beacon_period;

#define DS_PARA_IE_ID   3

#define DS_PARA_IE_LEN  1
	adhoc_start->phy_param_set.ds_param_set.element_id = DS_PARA_IE_ID;
	adhoc_start->phy_param_set.ds_param_set.len = DS_PARA_IE_LEN;

	if (!(*klpe_mwifiex_get_cfp)(priv, adapter->adhoc_start_band,
			     (u16) priv->adhoc_channel, 0)) {
		struct mwifiex_chan_freq_power *cfp;
		cfp = (*klpe_mwifiex_get_cfp)(priv, adapter->adhoc_start_band,
				      FIRST_VALID_CHANNEL, 0);
		if (cfp)
			priv->adhoc_channel = (u8) cfp->channel;
	}

	if (!priv->adhoc_channel) {
		klpr_mwifiex_dbg(adapter, ERROR,
			    "ADHOC_S_CMD: adhoc_channel cannot be 0\n");
		return -1;
	}

	klpr_mwifiex_dbg(adapter, INFO,
		    "info: ADHOC_S_CMD: creating ADHOC on channel %d\n",
		    priv->adhoc_channel);

	priv->curr_bss_params.bss_descriptor.channel = priv->adhoc_channel;
	priv->curr_bss_params.band = adapter->adhoc_start_band;

	bss_desc->channel = priv->adhoc_channel;
	adhoc_start->phy_param_set.ds_param_set.current_chan =
		priv->adhoc_channel;

	memcpy(&bss_desc->phy_param_set, &adhoc_start->phy_param_set,
	       sizeof(union ieee_types_phy_param_set));

#define IBSS_PARA_IE_ID   6

#define IBSS_PARA_IE_LEN  2
	adhoc_start->ss_param_set.ibss_param_set.element_id = IBSS_PARA_IE_ID;
	adhoc_start->ss_param_set.ibss_param_set.len = IBSS_PARA_IE_LEN;
	adhoc_start->ss_param_set.ibss_param_set.atim_window
					= cpu_to_le16(priv->atim_window);
	memcpy(&bss_desc->ss_param_set, &adhoc_start->ss_param_set,
	       sizeof(union ieee_types_ss_param_set));

	/* Set Capability info */
	bss_desc->cap_info_bitmap |= WLAN_CAPABILITY_IBSS;
	tmp_cap = WLAN_CAPABILITY_IBSS;

	/* Set up privacy in bss_desc */
	if (priv->sec_info.encryption_mode) {
		/* Ad-Hoc capability privacy on */
		klpr_mwifiex_dbg(adapter, INFO,
			    "info: ADHOC_S_CMD: wep_status set privacy to WEP\n");
		bss_desc->privacy = MWIFIEX_802_11_PRIV_FILTER_8021X_WEP;
		tmp_cap |= WLAN_CAPABILITY_PRIVACY;
	} else {
		klpr_mwifiex_dbg(adapter, INFO,
			    "info: ADHOC_S_CMD: wep_status NOT set,\t"
			    "setting privacy to ACCEPT ALL\n");
		bss_desc->privacy = MWIFIEX_802_11_PRIV_FILTER_ACCEPT_ALL;
	}

	memset(adhoc_start->data_rate, 0, sizeof(adhoc_start->data_rate));
	(*klpe_mwifiex_get_active_data_rates)(priv, adhoc_start->data_rate);
	if ((adapter->adhoc_start_band & BAND_G) &&
	    (priv->curr_pkt_filter & HostCmd_ACT_MAC_ADHOC_G_PROTECTION_ON)) {
		if ((*klpe_mwifiex_send_cmd)(priv, HostCmd_CMD_MAC_CONTROL,
				     HostCmd_ACT_GEN_SET, 0,
				     &priv->curr_pkt_filter, false)) {
			klpr_mwifiex_dbg(adapter, ERROR,
				    "ADHOC_S_CMD: G Protection config failed\n");
			return -1;
		}
	}
	/* Find the last non zero */
	for (i = 0; i < sizeof(adhoc_start->data_rate); i++)
		if (!adhoc_start->data_rate[i])
			break;

	priv->curr_bss_params.num_of_rates = i;

	/* Copy the ad-hoc creating rates into Current BSS rate structure */
	memcpy(&priv->curr_bss_params.data_rates,
	       &adhoc_start->data_rate, priv->curr_bss_params.num_of_rates);

	klpr_mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: rates=%4ph\n",
		    adhoc_start->data_rate);

	klpr_mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: AD-HOC Start command is ready\n");

	if (IS_SUPPORT_MULTI_BANDS(adapter)) {
		/* Append a channel TLV */
		chan_tlv = (struct mwifiex_ie_types_chan_list_param_set *) pos;
		chan_tlv->header.type = cpu_to_le16(TLV_TYPE_CHANLIST);
		chan_tlv->header.len =
			cpu_to_le16(sizeof(struct mwifiex_chan_scan_param_set));

		memset(chan_tlv->chan_scan_param, 0x00,
		       sizeof(struct mwifiex_chan_scan_param_set));
		chan_tlv->chan_scan_param[0].chan_number =
			(u8) priv->curr_bss_params.bss_descriptor.channel;

		klpr_mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: TLV Chan = %d\n",
			    chan_tlv->chan_scan_param[0].chan_number);

		chan_tlv->chan_scan_param[0].radio_type
		       = (*klpe_mwifiex_band_to_radio_type)(priv->curr_bss_params.band);
		if (adapter->adhoc_start_band & BAND_GN ||
		    adapter->adhoc_start_band & BAND_AN) {
			if (adapter->sec_chan_offset ==
					    IEEE80211_HT_PARAM_CHA_SEC_ABOVE)
				chan_tlv->chan_scan_param[0].radio_type |=
					(IEEE80211_HT_PARAM_CHA_SEC_ABOVE << 4);
			else if (adapter->sec_chan_offset ==
					    IEEE80211_HT_PARAM_CHA_SEC_BELOW)
				chan_tlv->chan_scan_param[0].radio_type |=
					(IEEE80211_HT_PARAM_CHA_SEC_BELOW << 4);
		}
		klpr_mwifiex_dbg(adapter, INFO, "info: ADHOC_S_CMD: TLV Band = %d\n",
			    chan_tlv->chan_scan_param[0].radio_type);
		pos += sizeof(chan_tlv->header) +
			sizeof(struct mwifiex_chan_scan_param_set);
		cmd_append_size +=
			sizeof(chan_tlv->header) +
			sizeof(struct mwifiex_chan_scan_param_set);
	}

	/* Append vendor specific IE TLV */
	cmd_append_size += (*klpe_mwifiex_cmd_append_vsie_tlv)(priv,
				MWIFIEX_VSIE_MASK_ADHOC, &pos);

	if (priv->sec_info.wpa_enabled) {
		rsn_ie_len = (*klpe_mwifiex_append_rsn_ie_wpa_wpa2)(priv, &pos);
		if (rsn_ie_len == -1)
			return -1;
		cmd_append_size += rsn_ie_len;
	}

	if (adapter->adhoc_11n_enabled) {
		/* Fill HT CAPABILITY */
		ht_cap = (struct mwifiex_ie_types_htcap *) pos;
		memset(ht_cap, 0, sizeof(struct mwifiex_ie_types_htcap));
		ht_cap->header.type = cpu_to_le16(WLAN_EID_HT_CAPABILITY);
		ht_cap->header.len =
		       cpu_to_le16(sizeof(struct ieee80211_ht_cap));
		radio_type = (*klpe_mwifiex_band_to_radio_type)(
					priv->adapter->config_bands);
		(*klpe_mwifiex_fill_cap_info)(priv, radio_type, &ht_cap->ht_cap);

		if (adapter->sec_chan_offset ==
					IEEE80211_HT_PARAM_CHA_SEC_NONE) {
			u16 tmp_ht_cap;

			tmp_ht_cap = le16_to_cpu(ht_cap->ht_cap.cap_info);
			tmp_ht_cap &= ~IEEE80211_HT_CAP_SUP_WIDTH_20_40;
			tmp_ht_cap &= ~IEEE80211_HT_CAP_SGI_40;
			ht_cap->ht_cap.cap_info = cpu_to_le16(tmp_ht_cap);
		}

		pos += sizeof(struct mwifiex_ie_types_htcap);
		cmd_append_size += sizeof(struct mwifiex_ie_types_htcap);

		/* Fill HT INFORMATION */
		ht_info = (struct mwifiex_ie_types_htinfo *) pos;
		memset(ht_info, 0, sizeof(struct mwifiex_ie_types_htinfo));
		ht_info->header.type = cpu_to_le16(WLAN_EID_HT_OPERATION);
		ht_info->header.len =
			cpu_to_le16(sizeof(struct ieee80211_ht_operation));

		ht_info->ht_oper.primary_chan =
			(u8) priv->curr_bss_params.bss_descriptor.channel;
		if (adapter->sec_chan_offset) {
			ht_info->ht_oper.ht_param = adapter->sec_chan_offset;
			ht_info->ht_oper.ht_param |=
					IEEE80211_HT_PARAM_CHAN_WIDTH_ANY;
		}
		ht_info->ht_oper.operation_mode =
		     cpu_to_le16(IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT);
		ht_info->ht_oper.basic_set[0] = 0xff;
		pos += sizeof(struct mwifiex_ie_types_htinfo);
		cmd_append_size +=
				sizeof(struct mwifiex_ie_types_htinfo);
	}

	cmd->size =
		cpu_to_le16((u16)(sizeof(struct host_cmd_ds_802_11_ad_hoc_start)
				  + S_DS_GEN + cmd_append_size));

	if (adapter->adhoc_start_band == BAND_B)
		tmp_cap &= ~WLAN_CAPABILITY_SHORT_SLOT_TIME;
	else
		tmp_cap |= WLAN_CAPABILITY_SHORT_SLOT_TIME;

	adhoc_start->cap_info_bitmap = cpu_to_le16(tmp_cap);

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1180562.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "mwifiex"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "_mwifiex_dbg", (void *)&klpe__mwifiex_dbg, "mwifiex" },
	{ "mwifiex_send_cmd", (void *)&klpe_mwifiex_send_cmd, "mwifiex" },
	{ "mwifiex_band_to_radio_type",
	  (void *)&klpe_mwifiex_band_to_radio_type, "mwifiex" },
	{ "mwifiex_get_cfp", (void *)&klpe_mwifiex_get_cfp, "mwifiex" },
	{ "mwifiex_cmd_append_vsie_tlv",
	  (void *)&klpe_mwifiex_cmd_append_vsie_tlv, "mwifiex" },
	{ "mwifiex_get_active_data_rates",
	  (void *)&klpe_mwifiex_get_active_data_rates, "mwifiex" },
	{ "mwifiex_fill_cap_info", (void *)&klpe_mwifiex_fill_cap_info,
	  "mwifiex" },
	{ "mwifiex_append_rsn_ie_wpa_wpa2",
	  (void *)&klpe_mwifiex_append_rsn_ie_wpa_wpa2, "mwifiex" },
};

static int livepatch_bsc1180562_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1180562_module_nb = {
	.notifier_call = livepatch_bsc1180562_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1180562_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1180562_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1180562_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1180562_module_nb);
}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
