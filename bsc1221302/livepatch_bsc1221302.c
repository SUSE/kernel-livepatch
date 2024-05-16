/*
 * livepatch_bsc1221302
 *
 * Fix for CVE-2024-26610, bsc#1221302
 *
 *  Upstream commit:
 *  cf4a0d840ecc ("wifi: iwlwifi: fix a memory corruption")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  e7967c5d006ee9712c52279f1c0d04a77bb5988e
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

#if IS_ENABLED(CONFIG_IWLWIFI)

#if !IS_MODULE(CONFIG_IWLWIFI)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-drv.h */
#include <linux/export.h>

struct iwl_trans;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-trans.h */
#include <linux/ieee80211.h>
#include <linux/mm.h> /* for page_address */
#include <linux/lockdep.h>
#include <linux/kernel.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-modparams.h */
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/gfp.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-debug.h */
enum iwl_err_mode {
	IWL_ERR_MODE_REGULAR,
	IWL_ERR_MODE_RFKILL,
	IWL_ERR_MODE_TRACE_ONLY,
	IWL_ERR_MODE_RATELIMIT,
};

static void (*klpe___iwl_err)(struct device *dev, enum iwl_err_mode mode, const char *fmt, ...)
	__printf(3, 4);
static void (*klpe___iwl_warn)(struct device *dev, const char *fmt, ...) __printf(2, 3);

#if defined(CONFIG_IWLWIFI_DEBUG) || defined(CONFIG_IWLWIFI_DEVICE_TRACING)
static void (*klpe___iwl_dbg)(struct device *dev,
	       u32 level, bool limit, const char *function,
	       const char *fmt, ...) __printf(5, 6);
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-config.h */
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/ieee80211.h>

/* klp-ccp: from include/uapi/linux/nl80211.h */
#define __LINUX_NL80211_H

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-config.h */
enum iwl_device_family {
	IWL_DEVICE_FAMILY_UNDEFINED,
	IWL_DEVICE_FAMILY_1000,
	IWL_DEVICE_FAMILY_100,
	IWL_DEVICE_FAMILY_2000,
	IWL_DEVICE_FAMILY_2030,
	IWL_DEVICE_FAMILY_105,
	IWL_DEVICE_FAMILY_135,
	IWL_DEVICE_FAMILY_5000,
	IWL_DEVICE_FAMILY_5150,
	IWL_DEVICE_FAMILY_6000,
	IWL_DEVICE_FAMILY_6000i,
	IWL_DEVICE_FAMILY_6005,
	IWL_DEVICE_FAMILY_6030,
	IWL_DEVICE_FAMILY_6050,
	IWL_DEVICE_FAMILY_6150,
	IWL_DEVICE_FAMILY_7000,
	IWL_DEVICE_FAMILY_8000,
	IWL_DEVICE_FAMILY_9000,
	IWL_DEVICE_FAMILY_22000,
	IWL_DEVICE_FAMILY_AX210,
	IWL_DEVICE_FAMILY_BZ,
};

struct iwl_cfg_trans_params {
	const struct iwl_base_params *base_params;
	enum iwl_device_family device_family;
	u32 umac_prph_offset;
	u32 xtal_latency;
	u32 extra_phy_cfg_flags;
	u32 rf_id:1,
	    use_tfh:1,
	    gen2:1,
	    mq_rx_supported:1,
	    integrated:1,
	    low_latency_xtal:1,
	    bisr_workaround:1,
	    ltr_delay:2,
	    imr_enabled:1;
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/img.h */
#include <linux/types.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/dbg-tlv.h */
#include <linux/bitops.h>

#define IWL_FW_INI_MAX_REGION_ID		64
#define IWL_FW_INI_MAX_NAME			32

struct iwl_fw_ini_hcmd {
	u8 id;
	u8 group;
	__le16 reserved;
	u8 data[0];
} __packed;

struct iwl_fw_ini_header {
	__le32 version;
	__le32 domain;
	/* followed by the data */
} __packed;

struct iwl_fw_ini_region_dev_addr {
	__le32 size;
	__le32 offset;
} __packed;

struct iwl_fw_ini_region_fifos {
	__le32 fid[2];
	__le32 hdr_only;
	__le32 offset;
} __packed;

struct iwl_fw_ini_region_err_table {
	__le32 version;
	__le32 base_addr;
	__le32 size;
	__le32 offset;
} __packed;

struct iwl_fw_ini_region_special_device_memory {
	__le16 type;
	__le16 version;
	__le32 base_addr;
	__le32 size;
	__le32 offset;
} __packed;

struct iwl_fw_ini_region_internal_buffer {
	__le32 alloc_id;
	__le32 base_addr;
	__le32 size;
} __packed;

struct iwl_fw_ini_region_tlv {
	struct iwl_fw_ini_header hdr;
	__le32 id;
	u8 type;
	u8 sub_type;
	u8 sub_type_ver;
	u8 reserved;
	u8 name[IWL_FW_INI_MAX_NAME];
	union {
		struct iwl_fw_ini_region_dev_addr dev_addr;
		struct iwl_fw_ini_region_fifos fifos;
		struct iwl_fw_ini_region_err_table err_table;
		struct iwl_fw_ini_region_internal_buffer internal_buffer;
		struct iwl_fw_ini_region_special_device_memory special_mem;
		__le32 dram_alloc_id;
		__le32 tlv_mask;
	}; /* FW_TLV_DEBUG_REGION_CONF_PARAMS_API_U_VER_1 */
	__le32 addrs[];
} __packed;

struct iwl_fw_ini_allocation_tlv {
	struct iwl_fw_ini_header hdr;
	__le32 alloc_id;
	__le32 buf_location;
	__le32 req_size;
	__le32 max_frags_num;
	__le32 min_size;
} __packed;

struct iwl_fw_ini_trigger_tlv {
	struct iwl_fw_ini_header hdr;
	__le32 time_point;
	__le32 trigger_reason;
	__le32 apply_policy;
	__le32 dump_delay;
	__le32 occurrences;
	__le32 reserved;
	__le32 ignore_consec;
	__le32 reset_fw;
	__le32 multi_dut;
	__le64 regions_mask;
	__le32 data[];
} __packed;

struct iwl_fw_ini_hcmd_tlv {
	struct iwl_fw_ini_header hdr;
	__le32 time_point;
	__le32 period_msec;
	struct iwl_fw_ini_hcmd hcmd;
} __packed;

struct iwl_fw_ini_addr_val {
	__le32 address;
	__le32 value;
} __packed;

struct iwl_fw_ini_conf_set_tlv {
	struct iwl_fw_ini_header hdr;
	__le32 time_point;
	__le32 set_type;
	__le32 addr_offset;
	struct iwl_fw_ini_addr_val addr_val[0];
} __packed;

enum iwl_fw_ini_config_set_type {
	IWL_FW_INI_CONFIG_SET_TYPE_INVALID = 0,
	IWL_FW_INI_CONFIG_SET_TYPE_DEVICE_PERIPHERY_MAC,
	IWL_FW_INI_CONFIG_SET_TYPE_DEVICE_PERIPHERY_PHY,
	IWL_FW_INI_CONFIG_SET_TYPE_DEVICE_PERIPHERY_AUX,
	IWL_FW_INI_CONFIG_SET_TYPE_DEVICE_MEMORY,
	IWL_FW_INI_CONFIG_SET_TYPE_CSR,
	IWL_FW_INI_CONFIG_SET_TYPE_DBGC_DRAM_ADDR,
	IWL_FW_INI_CONFIG_SET_TYPE_PERIPH_SCRATCH_HWM,
	IWL_FW_INI_CONFIG_SET_TYPE_MAX_NUM,
} __packed;

enum iwl_fw_ini_allocation_id {
	IWL_FW_INI_ALLOCATION_INVALID,
	IWL_FW_INI_ALLOCATION_ID_DBGC1,
	IWL_FW_INI_ALLOCATION_ID_DBGC2,
	IWL_FW_INI_ALLOCATION_ID_DBGC3,
	IWL_FW_INI_ALLOCATION_ID_DBGC4,
	IWL_FW_INI_ALLOCATION_NUM,
};

enum iwl_fw_ini_buffer_location {
	IWL_FW_INI_LOCATION_INVALID,
	IWL_FW_INI_LOCATION_SRAM_PATH,
	IWL_FW_INI_LOCATION_DRAM_PATH,
	IWL_FW_INI_LOCATION_NPK_PATH,
	IWL_FW_INI_LOCATION_NUM,
};

enum iwl_fw_ini_region_type {
	IWL_FW_INI_REGION_INVALID,
	IWL_FW_INI_REGION_TLV,
	IWL_FW_INI_REGION_INTERNAL_BUFFER,
	IWL_FW_INI_REGION_DRAM_BUFFER,
	IWL_FW_INI_REGION_TXF,
	IWL_FW_INI_REGION_RXF,
	IWL_FW_INI_REGION_LMAC_ERROR_TABLE,
	IWL_FW_INI_REGION_UMAC_ERROR_TABLE,
	IWL_FW_INI_REGION_RSP_OR_NOTIF,
	IWL_FW_INI_REGION_DEVICE_MEMORY,
	IWL_FW_INI_REGION_PERIPHERY_MAC,
	IWL_FW_INI_REGION_PERIPHERY_PHY,
	IWL_FW_INI_REGION_PERIPHERY_AUX,
	IWL_FW_INI_REGION_PAGING,
	IWL_FW_INI_REGION_CSR,
	IWL_FW_INI_REGION_DRAM_IMR,
	IWL_FW_INI_REGION_PCI_IOSF_CONFIG,
	IWL_FW_INI_REGION_SPECIAL_DEVICE_MEMORY,
	IWL_FW_INI_REGION_DBGI_SRAM,
	IWL_FW_INI_REGION_NUM
};

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

enum iwl_fw_ini_trigger_apply_policy {
	IWL_FW_INI_APPLY_POLICY_MATCH_TIME_POINT	= BIT(0),
	IWL_FW_INI_APPLY_POLICY_MATCH_DATA		= BIT(1),
	IWL_FW_INI_APPLY_POLICY_OVERRIDE_REGIONS	= BIT(8),
	IWL_FW_INI_APPLY_POLICY_OVERRIDE_CFG		= BIT(9),
	IWL_FW_INI_APPLY_POLICY_OVERRIDE_DATA		= BIT(10),
	IWL_FW_INI_APPLY_POLICY_DUMP_COMPLETE_CMD	= BIT(16),
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/file.h */
#include <linux/netdevice.h>
#include <linux/nl80211.h>

struct iwl_ucode_tlv {
	__le32 type;		/* see above */
	__le32 length;		/* not including type/length fields */
	u8 data[];
};

#define FW_VER_HUMAN_READABLE_SZ	64

typedef unsigned int __bitwise iwl_ucode_tlv_api_t;

enum iwl_ucode_tlv_api {
	/* API Set 0 */
	IWL_UCODE_TLV_API_FRAGMENTED_SCAN	= (__force iwl_ucode_tlv_api_t)8,
	IWL_UCODE_TLV_API_WIFI_MCC_UPDATE	= (__force iwl_ucode_tlv_api_t)9,
	IWL_UCODE_TLV_API_LQ_SS_PARAMS		= (__force iwl_ucode_tlv_api_t)18,
	IWL_UCODE_TLV_API_NEW_VERSION		= (__force iwl_ucode_tlv_api_t)20,
	IWL_UCODE_TLV_API_SCAN_TSF_REPORT	= (__force iwl_ucode_tlv_api_t)28,
	IWL_UCODE_TLV_API_TKIP_MIC_KEYS		= (__force iwl_ucode_tlv_api_t)29,
	IWL_UCODE_TLV_API_STA_TYPE		= (__force iwl_ucode_tlv_api_t)30,
	IWL_UCODE_TLV_API_NAN2_VER2		= (__force iwl_ucode_tlv_api_t)31,
	/* API Set 1 */
	IWL_UCODE_TLV_API_ADAPTIVE_DWELL	= (__force iwl_ucode_tlv_api_t)32,
	IWL_UCODE_TLV_API_OCE			= (__force iwl_ucode_tlv_api_t)33,
	IWL_UCODE_TLV_API_NEW_BEACON_TEMPLATE	= (__force iwl_ucode_tlv_api_t)34,
	IWL_UCODE_TLV_API_NEW_RX_STATS		= (__force iwl_ucode_tlv_api_t)35,
	IWL_UCODE_TLV_API_WOWLAN_KEY_MATERIAL	= (__force iwl_ucode_tlv_api_t)36,
	IWL_UCODE_TLV_API_QUOTA_LOW_LATENCY	= (__force iwl_ucode_tlv_api_t)38,
	IWL_UCODE_TLV_API_DEPRECATE_TTAK	= (__force iwl_ucode_tlv_api_t)41,
	IWL_UCODE_TLV_API_ADAPTIVE_DWELL_V2	= (__force iwl_ucode_tlv_api_t)42,
	IWL_UCODE_TLV_API_FRAG_EBS		= (__force iwl_ucode_tlv_api_t)44,
	IWL_UCODE_TLV_API_REDUCE_TX_POWER	= (__force iwl_ucode_tlv_api_t)45,
	IWL_UCODE_TLV_API_SHORT_BEACON_NOTIF	= (__force iwl_ucode_tlv_api_t)46,
	IWL_UCODE_TLV_API_BEACON_FILTER_V4      = (__force iwl_ucode_tlv_api_t)47,
	IWL_UCODE_TLV_API_REGULATORY_NVM_INFO   = (__force iwl_ucode_tlv_api_t)48,
	IWL_UCODE_TLV_API_FTM_NEW_RANGE_REQ     = (__force iwl_ucode_tlv_api_t)49,
	IWL_UCODE_TLV_API_SCAN_OFFLOAD_CHANS    = (__force iwl_ucode_tlv_api_t)50,
	IWL_UCODE_TLV_API_MBSSID_HE		= (__force iwl_ucode_tlv_api_t)52,
	IWL_UCODE_TLV_API_WOWLAN_TCP_SYN_WAKE	= (__force iwl_ucode_tlv_api_t)53,
	IWL_UCODE_TLV_API_FTM_RTT_ACCURACY      = (__force iwl_ucode_tlv_api_t)54,
	IWL_UCODE_TLV_API_SAR_TABLE_VER         = (__force iwl_ucode_tlv_api_t)55,
	IWL_UCODE_TLV_API_REDUCED_SCAN_CONFIG   = (__force iwl_ucode_tlv_api_t)56,
	IWL_UCODE_TLV_API_ADWELL_HB_DEF_N_AP	= (__force iwl_ucode_tlv_api_t)57,
	IWL_UCODE_TLV_API_SCAN_EXT_CHAN_VER	= (__force iwl_ucode_tlv_api_t)58,
	IWL_UCODE_TLV_API_BAND_IN_RX_DATA	= (__force iwl_ucode_tlv_api_t)59,

#ifdef __CHECKER__
#error "klp-ccp: non-taken branch"
#else
	NUM_IWL_UCODE_TLV_API
#endif
};

typedef unsigned int __bitwise iwl_ucode_tlv_capa_t;

enum iwl_ucode_tlv_capa {
	/* set 0 */
	IWL_UCODE_TLV_CAPA_D0I3_SUPPORT			= (__force iwl_ucode_tlv_capa_t)0,
	IWL_UCODE_TLV_CAPA_LAR_SUPPORT			= (__force iwl_ucode_tlv_capa_t)1,
	IWL_UCODE_TLV_CAPA_UMAC_SCAN			= (__force iwl_ucode_tlv_capa_t)2,
	IWL_UCODE_TLV_CAPA_BEAMFORMER			= (__force iwl_ucode_tlv_capa_t)3,
	IWL_UCODE_TLV_CAPA_TDLS_SUPPORT			= (__force iwl_ucode_tlv_capa_t)6,
	IWL_UCODE_TLV_CAPA_TXPOWER_INSERTION_SUPPORT	= (__force iwl_ucode_tlv_capa_t)8,
	IWL_UCODE_TLV_CAPA_DS_PARAM_SET_IE_SUPPORT	= (__force iwl_ucode_tlv_capa_t)9,
	IWL_UCODE_TLV_CAPA_WFA_TPC_REP_IE_SUPPORT	= (__force iwl_ucode_tlv_capa_t)10,
	IWL_UCODE_TLV_CAPA_QUIET_PERIOD_SUPPORT		= (__force iwl_ucode_tlv_capa_t)11,
	IWL_UCODE_TLV_CAPA_DQA_SUPPORT			= (__force iwl_ucode_tlv_capa_t)12,
	IWL_UCODE_TLV_CAPA_TDLS_CHANNEL_SWITCH		= (__force iwl_ucode_tlv_capa_t)13,
	IWL_UCODE_TLV_CAPA_CNSLDTD_D3_D0_IMG		= (__force iwl_ucode_tlv_capa_t)17,
	IWL_UCODE_TLV_CAPA_HOTSPOT_SUPPORT		= (__force iwl_ucode_tlv_capa_t)18,
	IWL_UCODE_TLV_CAPA_CSUM_SUPPORT			= (__force iwl_ucode_tlv_capa_t)21,
	IWL_UCODE_TLV_CAPA_RADIO_BEACON_STATS		= (__force iwl_ucode_tlv_capa_t)22,
	IWL_UCODE_TLV_CAPA_P2P_SCM_UAPSD		= (__force iwl_ucode_tlv_capa_t)26,
	IWL_UCODE_TLV_CAPA_BT_COEX_PLCR			= (__force iwl_ucode_tlv_capa_t)28,
	IWL_UCODE_TLV_CAPA_LAR_MULTI_MCC		= (__force iwl_ucode_tlv_capa_t)29,
	IWL_UCODE_TLV_CAPA_BT_COEX_RRC			= (__force iwl_ucode_tlv_capa_t)30,
	IWL_UCODE_TLV_CAPA_GSCAN_SUPPORT		= (__force iwl_ucode_tlv_capa_t)31,

	/* set 1 */
	IWL_UCODE_TLV_CAPA_SOC_LATENCY_SUPPORT		= (__force iwl_ucode_tlv_capa_t)37,
	IWL_UCODE_TLV_CAPA_STA_PM_NOTIF			= (__force iwl_ucode_tlv_capa_t)38,
	IWL_UCODE_TLV_CAPA_BINDING_CDB_SUPPORT		= (__force iwl_ucode_tlv_capa_t)39,
	IWL_UCODE_TLV_CAPA_CDB_SUPPORT			= (__force iwl_ucode_tlv_capa_t)40,
	IWL_UCODE_TLV_CAPA_D0I3_END_FIRST		= (__force iwl_ucode_tlv_capa_t)41,
	IWL_UCODE_TLV_CAPA_TLC_OFFLOAD                  = (__force iwl_ucode_tlv_capa_t)43,
	IWL_UCODE_TLV_CAPA_DYNAMIC_QUOTA                = (__force iwl_ucode_tlv_capa_t)44,
	IWL_UCODE_TLV_CAPA_COEX_SCHEMA_2		= (__force iwl_ucode_tlv_capa_t)45,
	IWL_UCODE_TLV_CAPA_CHANNEL_SWITCH_CMD		= (__force iwl_ucode_tlv_capa_t)46,
	IWL_UCODE_TLV_CAPA_FTM_CALIBRATED		= (__force iwl_ucode_tlv_capa_t)47,
	IWL_UCODE_TLV_CAPA_ULTRA_HB_CHANNELS		= (__force iwl_ucode_tlv_capa_t)48,
	IWL_UCODE_TLV_CAPA_CS_MODIFY			= (__force iwl_ucode_tlv_capa_t)49,
	IWL_UCODE_TLV_CAPA_SET_LTR_GEN2			= (__force iwl_ucode_tlv_capa_t)50,
	IWL_UCODE_TLV_CAPA_SET_PPAG			= (__force iwl_ucode_tlv_capa_t)52,
	IWL_UCODE_TLV_CAPA_TAS_CFG			= (__force iwl_ucode_tlv_capa_t)53,
	IWL_UCODE_TLV_CAPA_SESSION_PROT_CMD		= (__force iwl_ucode_tlv_capa_t)54,
	IWL_UCODE_TLV_CAPA_PROTECTED_TWT		= (__force iwl_ucode_tlv_capa_t)56,
	IWL_UCODE_TLV_CAPA_FW_RESET_HANDSHAKE		= (__force iwl_ucode_tlv_capa_t)57,
	IWL_UCODE_TLV_CAPA_PASSIVE_6GHZ_SCAN		= (__force iwl_ucode_tlv_capa_t)58,
	IWL_UCODE_TLV_CAPA_HIDDEN_6GHZ_SCAN		= (__force iwl_ucode_tlv_capa_t)59,
	IWL_UCODE_TLV_CAPA_BROADCAST_TWT		= (__force iwl_ucode_tlv_capa_t)60,
	IWL_UCODE_TLV_CAPA_COEX_HIGH_PRIO		= (__force iwl_ucode_tlv_capa_t)61,
	IWL_UCODE_TLV_CAPA_RFIM_SUPPORT			= (__force iwl_ucode_tlv_capa_t)62,
	IWL_UCODE_TLV_CAPA_BAID_ML_SUPPORT		= (__force iwl_ucode_tlv_capa_t)63,

	/* set 2 */
	IWL_UCODE_TLV_CAPA_EXTENDED_DTS_MEASURE		= (__force iwl_ucode_tlv_capa_t)64,
	IWL_UCODE_TLV_CAPA_SHORT_PM_TIMEOUTS		= (__force iwl_ucode_tlv_capa_t)65,
	IWL_UCODE_TLV_CAPA_BT_MPLUT_SUPPORT		= (__force iwl_ucode_tlv_capa_t)67,
	IWL_UCODE_TLV_CAPA_MULTI_QUEUE_RX_SUPPORT	= (__force iwl_ucode_tlv_capa_t)68,
	IWL_UCODE_TLV_CAPA_CSA_AND_TBTT_OFFLOAD		= (__force iwl_ucode_tlv_capa_t)70,
	IWL_UCODE_TLV_CAPA_BEACON_ANT_SELECTION		= (__force iwl_ucode_tlv_capa_t)71,
	IWL_UCODE_TLV_CAPA_BEACON_STORING		= (__force iwl_ucode_tlv_capa_t)72,
	IWL_UCODE_TLV_CAPA_LAR_SUPPORT_V3		= (__force iwl_ucode_tlv_capa_t)73,
	IWL_UCODE_TLV_CAPA_CT_KILL_BY_FW		= (__force iwl_ucode_tlv_capa_t)74,
	IWL_UCODE_TLV_CAPA_TEMP_THS_REPORT_SUPPORT	= (__force iwl_ucode_tlv_capa_t)75,
	IWL_UCODE_TLV_CAPA_CTDP_SUPPORT			= (__force iwl_ucode_tlv_capa_t)76,
	IWL_UCODE_TLV_CAPA_USNIFFER_UNIFIED		= (__force iwl_ucode_tlv_capa_t)77,
	IWL_UCODE_TLV_CAPA_EXTEND_SHARED_MEM_CFG	= (__force iwl_ucode_tlv_capa_t)80,
	IWL_UCODE_TLV_CAPA_LQM_SUPPORT			= (__force iwl_ucode_tlv_capa_t)81,
	IWL_UCODE_TLV_CAPA_TX_POWER_ACK			= (__force iwl_ucode_tlv_capa_t)84,
	IWL_UCODE_TLV_CAPA_D3_DEBUG			= (__force iwl_ucode_tlv_capa_t)87,
	IWL_UCODE_TLV_CAPA_LED_CMD_SUPPORT		= (__force iwl_ucode_tlv_capa_t)88,
	IWL_UCODE_TLV_CAPA_MCC_UPDATE_11AX_SUPPORT	= (__force iwl_ucode_tlv_capa_t)89,
	IWL_UCODE_TLV_CAPA_CSI_REPORTING		= (__force iwl_ucode_tlv_capa_t)90,
	IWL_UCODE_TLV_CAPA_DBG_SUSPEND_RESUME_CMD_SUPP	= (__force iwl_ucode_tlv_capa_t)92,
	IWL_UCODE_TLV_CAPA_DBG_BUF_ALLOC_CMD_SUPP	= (__force iwl_ucode_tlv_capa_t)93,

	/* set 3 */
	IWL_UCODE_TLV_CAPA_MLME_OFFLOAD			= (__force iwl_ucode_tlv_capa_t)96,

	/*
	 * @IWL_UCODE_TLV_CAPA_PSC_CHAN_SUPPORT: supports PSC channels
	 */
	IWL_UCODE_TLV_CAPA_PSC_CHAN_SUPPORT		= (__force iwl_ucode_tlv_capa_t)98,

	IWL_UCODE_TLV_CAPA_BIGTK_SUPPORT		= (__force iwl_ucode_tlv_capa_t)100,
	IWL_UCODE_TLV_CAPA_DRAM_FRAG_SUPPORT		= (__force iwl_ucode_tlv_capa_t)104,
	IWL_UCODE_TLV_CAPA_DUMP_COMPLETE_SUPPORT	= (__force iwl_ucode_tlv_capa_t)105,

#ifdef __CHECKER__
#error "klp-ccp: non-taken branch"
#else
	NUM_IWL_UCODE_TLV_CAPA
#endif
};

struct iwl_tlv_calib_ctrl {
	__le32 flow_trigger;
	__le32 event_trigger;
} __packed;

#define FW_DBG_CONF_MAX		32

static inline size_t _iwl_tlv_array_len(const struct iwl_ucode_tlv *tlv,
					size_t fixed_size, size_t var_size)
{
	size_t var_len = le32_to_cpu(tlv->length) - fixed_size;

	if (WARN_ON(var_len % var_size))
		return 0;

	return var_len / var_size;
}

#define iwl_tlv_array_len(_tlv_ptr, _struct_ptr, _memb)			\
	_iwl_tlv_array_len((_tlv_ptr), sizeof(*(_struct_ptr)),		\
			   sizeof(_struct_ptr->_memb[0]))

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/error-dump.h */
#include <linux/types.h>

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/cmdhdr.h */
#define WIDE_ID(grp, opcode) (((grp) << 8) | (opcode))

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/error-dump.h */
#define MAX_NUM_LMAC 2

#define TX_FIFO_INTERNAL_MAX_NUM	6
#define TX_FIFO_MAX_NUM			15

enum iwl_fw_dbg_trigger {
	FW_DBG_TRIGGER_INVALID = 0,
	FW_DBG_TRIGGER_USER,
	FW_DBG_TRIGGER_FW_ASSERT,
	FW_DBG_TRIGGER_MISSED_BEACONS,
	FW_DBG_TRIGGER_CHANNEL_SWITCH,
	FW_DBG_TRIGGER_FW_NOTIF,
	FW_DBG_TRIGGER_MLME,
	FW_DBG_TRIGGER_STATS,
	FW_DBG_TRIGGER_RSSI,
	FW_DBG_TRIGGER_TXQ_TIMERS,
	FW_DBG_TRIGGER_TIME_EVENT,
	FW_DBG_TRIGGER_BA,
	FW_DBG_TRIGGER_TX_LATENCY,
	FW_DBG_TRIGGER_TDLS,
	FW_DBG_TRIGGER_TX_STATUS,
	FW_DBG_TRIGGER_ALIVE_TIMEOUT,
	FW_DBG_TRIGGER_DRIVER,

	/* must be last */
	FW_DBG_TRIGGER_MAX,
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/img.h */
enum iwl_ucode_type {
	IWL_UCODE_REGULAR,
	IWL_UCODE_INIT,
	IWL_UCODE_WOWLAN,
	IWL_UCODE_REGULAR_USNIFFER,
	IWL_UCODE_TYPE_MAX,
};

struct iwl_ucode_capabilities {
	u32 max_probe_length;
	u32 n_scan_channels;
	u32 standard_phy_calibration_size;
	u32 flags;
	u32 error_log_addr;
	u32 error_log_size;
	u32 num_stations;
	unsigned long _api[BITS_TO_LONGS(NUM_IWL_UCODE_TLV_API)];
	unsigned long _capa[BITS_TO_LONGS(NUM_IWL_UCODE_TLV_CAPA)];

	const struct iwl_fw_cmd_version *cmd_versions;
	u32 n_cmd_versions;
};

static inline bool
fw_has_capa(const struct iwl_ucode_capabilities *capabilities,
	    iwl_ucode_tlv_capa_t capa)
{
	return test_bit((__force long)capa, capabilities->_capa);
}

struct fw_img {
	struct fw_desc *sec;
	int num_sec;
	bool is_dual_cpus;
	u32 paging_mem_size;
};

struct iwl_fw_paging {
	dma_addr_t fw_paging_phys;
	struct page *fw_paging_block;
	u32 fw_paging_size;
	u32 fw_offs;
};

enum iwl_fw_type {
	IWL_FW_DVM,
	IWL_FW_MVM,
};

struct iwl_fw_dbg {
	struct iwl_fw_dbg_dest_tlv_v1 *dest_tlv;
	u8 n_dest_reg;
	struct iwl_fw_dbg_conf_tlv *conf_tlv[FW_DBG_CONF_MAX];
	struct iwl_fw_dbg_trigger_tlv *trigger_tlv[FW_DBG_TRIGGER_MAX];
	size_t trigger_tlv_len[FW_DBG_TRIGGER_MAX];
	struct iwl_fw_dbg_mem_seg_tlv *mem_tlv;
	size_t n_mem_tlv;
	u32 dump_mask;
};

struct iwl_dump_exclude {
	u32 addr, size;
};

struct iwl_fw {
	u32 ucode_ver;

	char fw_version[64];

	/* ucode images */
	struct fw_img img[IWL_UCODE_TYPE_MAX];
	size_t iml_len;
	u8 *iml;

	struct iwl_ucode_capabilities ucode_capa;
	bool enhance_sensitivity_table;

	u32 init_evtlog_ptr, init_evtlog_size, init_errlog_ptr;
	u32 inst_evtlog_ptr, inst_evtlog_size, inst_errlog_ptr;

	struct iwl_tlv_calib_ctrl default_calib[IWL_UCODE_TYPE_MAX];
	u32 phy_config;
	u8 valid_tx_ant;
	u8 valid_rx_ant;

	enum iwl_fw_type type;

	u8 human_readable[FW_VER_HUMAN_READABLE_SZ];

	struct iwl_fw_dbg dbg;

	u8 *phy_integration_ver;
	u32 phy_integration_ver_len;

	struct iwl_dump_exclude dump_excl[2], dump_excl_wowlan[2];
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-op-mode.h */
#include <linux/netdevice.h>
/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-dbg-tlv.h */
#include <linux/device.h>
#include <linux/types.h>

struct iwl_dbg_tlv_node {
	struct list_head list;
	struct iwl_ucode_tlv tlv;
};

union iwl_dbg_tlv_tp_data;

struct iwl_dbg_tlv_time_point_data {
	struct list_head trig_list;
	struct list_head active_trig_list;
	struct list_head hcmd_list;
	struct list_head config_list;
};

struct iwl_fw_runtime;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-trans.h */
#include <linux/firmware.h>

struct iwl_device_tx_cmd;

#define IWL_MAX_CMD_TBS_PER_TFD	2

struct iwl_host_cmd {
	const void *data[IWL_MAX_CMD_TBS_PER_TFD];
	struct iwl_rx_packet *resp_pkt;
	unsigned long _rx_page_addr;
	u32 _rx_page_order;

	u32 flags;
	u32 id;
	u16 len[IWL_MAX_CMD_TBS_PER_TFD];
	u8 dataflags[IWL_MAX_CMD_TBS_PER_TFD];
};

#define IWL_MAX_TVQM_QUEUES		512

enum iwl_d3_status;

struct iwl_dump_sanitize_ops;

struct iwl_trans_config;

struct iwl_trans_txq_scd_cfg;

struct iwl_trans_rxq_dma_data;

struct iwl_trans_ops {

	int (*start_hw)(struct iwl_trans *iwl_trans);
	void (*op_mode_leave)(struct iwl_trans *iwl_trans);
	int (*start_fw)(struct iwl_trans *trans, const struct fw_img *fw,
			bool run_in_rfkill);
	void (*fw_alive)(struct iwl_trans *trans, u32 scd_addr);
	void (*stop_device)(struct iwl_trans *trans);

	int (*d3_suspend)(struct iwl_trans *trans, bool test, bool reset);
	int (*d3_resume)(struct iwl_trans *trans, enum iwl_d3_status *status,
			 bool test, bool reset);

	int (*send_cmd)(struct iwl_trans *trans, struct iwl_host_cmd *cmd);

	int (*tx)(struct iwl_trans *trans, struct sk_buff *skb,
		  struct iwl_device_tx_cmd *dev_cmd, int queue);
	void (*reclaim)(struct iwl_trans *trans, int queue, int ssn,
			struct sk_buff_head *skbs);

	void (*set_q_ptrs)(struct iwl_trans *trans, int queue, int ptr);

	bool (*txq_enable)(struct iwl_trans *trans, int queue, u16 ssn,
			   const struct iwl_trans_txq_scd_cfg *cfg,
			   unsigned int queue_wdg_timeout);
	void (*txq_disable)(struct iwl_trans *trans, int queue,
			    bool configure_scd);
	/* 22000 functions */
	int (*txq_alloc)(struct iwl_trans *trans, u32 flags,
			 u32 sta_mask, u8 tid,
			 int size, unsigned int queue_wdg_timeout);
	void (*txq_free)(struct iwl_trans *trans, int queue);
	int (*rxq_dma_data)(struct iwl_trans *trans, int queue,
			    struct iwl_trans_rxq_dma_data *data);

	void (*txq_set_shared_mode)(struct iwl_trans *trans, u32 txq_id,
				    bool shared);

	int (*wait_tx_queues_empty)(struct iwl_trans *trans, u32 txq_bm);
	int (*wait_txq_empty)(struct iwl_trans *trans, int queue);
	void (*freeze_txq_timer)(struct iwl_trans *trans, unsigned long txqs,
				 bool freeze);
	void (*block_txq_ptrs)(struct iwl_trans *trans, bool block);

	void (*write8)(struct iwl_trans *trans, u32 ofs, u8 val);
	void (*write32)(struct iwl_trans *trans, u32 ofs, u32 val);
	u32 (*read32)(struct iwl_trans *trans, u32 ofs);
	u32 (*read_prph)(struct iwl_trans *trans, u32 ofs);
	void (*write_prph)(struct iwl_trans *trans, u32 ofs, u32 val);
	int (*read_mem)(struct iwl_trans *trans, u32 addr,
			void *buf, int dwords);
	int (*write_mem)(struct iwl_trans *trans, u32 addr,
			 const void *buf, int dwords);
	int (*read_config32)(struct iwl_trans *trans, u32 ofs, u32 *val);
	void (*configure)(struct iwl_trans *trans,
			  const struct iwl_trans_config *trans_cfg);
	void (*set_pmi)(struct iwl_trans *trans, bool state);
	int (*sw_reset)(struct iwl_trans *trans, bool retake_ownership);
	bool (*grab_nic_access)(struct iwl_trans *trans);
	void (*release_nic_access)(struct iwl_trans *trans);
	void (*set_bits_mask)(struct iwl_trans *trans, u32 reg, u32 mask,
			      u32 value);

	struct iwl_trans_dump_data *(*dump_data)(struct iwl_trans *trans,
						 u32 dump_mask,
						 const struct iwl_dump_sanitize_ops *sanitize_ops,
						 void *sanitize_ctx);
	void (*debugfs_cleanup)(struct iwl_trans *trans);
	void (*sync_nmi)(struct iwl_trans *trans);
	int (*set_pnvm)(struct iwl_trans *trans, const void *data, u32 len);
	int (*set_reduce_power)(struct iwl_trans *trans,
				const void *data, u32 len);
	void (*interrupts)(struct iwl_trans *trans, bool enable);
	int (*imr_dma_data)(struct iwl_trans *trans,
			    u32 dst_addr, u64 src_addr,
			    u32 byte_cnt);

};

enum iwl_trans_state {
	IWL_TRANS_NO_FW,
	IWL_TRANS_FW_STARTED,
	IWL_TRANS_FW_ALIVE,
};

enum iwl_plat_pm_mode {
	IWL_PLAT_PM_MODE_DISABLED,
	IWL_PLAT_PM_MODE_D3,
};

enum iwl_ini_cfg_state {
	IWL_INI_CFG_STATE_NOT_LOADED,
	IWL_INI_CFG_STATE_LOADED,
	IWL_INI_CFG_STATE_CORRUPTED,
};

struct iwl_dram_data {
	dma_addr_t physical;
	void *block;
	int size;
};

struct iwl_fw_mon {
	u32 num_frags;
	struct iwl_dram_data *frags;
};

struct iwl_self_init_dram {
	struct iwl_dram_data *fw;
	int fw_cnt;
	struct iwl_dram_data *paging;
	int paging_cnt;
};

struct iwl_imr_data {
	u32 imr_enable;
	u32 imr_size;
	u32 sram_addr;
	u32 sram_size;
	u32 imr2sram_remainbyte;
	u64 imr_curr_addr;
	__le64 imr_base_addr;
};

struct iwl_trans_debug {
	u8 n_dest_reg;
	bool rec_on;

	const struct iwl_fw_dbg_dest_tlv_v1 *dest_tlv;
	const struct iwl_fw_dbg_conf_tlv *conf_tlv[FW_DBG_CONF_MAX];
	struct iwl_fw_dbg_trigger_tlv * const *trigger_tlv;

	u32 lmac_error_event_table[2];
	u32 umac_error_event_table;
	u32 tcm_error_event_table[2];
	u32 rcm_error_event_table[2];
	unsigned int error_event_table_tlv_status;

	enum iwl_ini_cfg_state internal_ini_cfg;
	enum iwl_ini_cfg_state external_ini_cfg;

	struct iwl_fw_ini_allocation_tlv fw_mon_cfg[IWL_FW_INI_ALLOCATION_NUM];
	struct iwl_fw_mon fw_mon_ini[IWL_FW_INI_ALLOCATION_NUM];

	struct iwl_dram_data fw_mon;

	bool hw_error;
	enum iwl_fw_ini_buffer_location ini_dest;

	u64 unsupported_region_msk;
	struct iwl_ucode_tlv *active_regions[IWL_FW_INI_MAX_REGION_ID];
	struct list_head debug_info_tlv_list;
	struct iwl_dbg_tlv_time_point_data
		time_point[IWL_FW_INI_TIME_POINT_NUM];
	struct list_head periodic_trig_list;

	u32 domains_bitmap;
	u32 ucode_preset;
	bool restart_required;
	u32 last_tp_resetfw;
	struct iwl_imr_data imr_data;
};

struct iwl_dma_ptr {
	dma_addr_t dma;
	void *addr;
	size_t size;
};

struct iwl_trans_txqs {
	unsigned long queue_used[BITS_TO_LONGS(IWL_MAX_TVQM_QUEUES)];
	unsigned long queue_stopped[BITS_TO_LONGS(IWL_MAX_TVQM_QUEUES)];
	struct iwl_txq *txq[IWL_MAX_TVQM_QUEUES];
	struct dma_pool *bc_pool;
	size_t bc_tbl_size;
	bool bc_table_dword;
	u8 page_offs;
	u8 dev_cmd_offs;
	struct iwl_tso_hdr_page __percpu *tso_hdr_page;

	struct {
		u8 fifo;
		u8 q_id;
		unsigned int wdg_timeout;
	} cmd;

	struct {
		u8 max_tbs;
		u16 size;
		u8 addr_size;
	} tfd;

	struct iwl_dma_ptr scd_bc_tbls;

	u8 queue_alloc_cmd_ver;
};

struct iwl_trans {
	const struct iwl_trans_ops *ops;
	struct iwl_op_mode *op_mode;
	const struct iwl_cfg_trans_params *trans_cfg;
	const struct iwl_cfg *cfg;
	struct iwl_drv *drv;
	enum iwl_trans_state state;
	unsigned long status;

	struct device *dev;
	u32 max_skb_frags;
	u32 hw_rev;
	u32 hw_rev_step;
	u32 hw_rf_id;
	u32 hw_id;
	char hw_id_str[52];
	u32 sku_id[3];

	u8 rx_mpdu_cmd, rx_mpdu_cmd_hdr_size;

	bool pm_support;
	bool ltr_enabled;
	u8 pnvm_loaded:1;
	u8 reduce_power_loaded:1;

	const struct iwl_hcmd_arr *command_groups;
	int command_groups_size;
	bool wide_cmd_header;

	wait_queue_head_t wait_command_queue;
	u8 num_rx_queues;

	size_t iml_len;
	u8 *iml;

	/* The following fields are internal only */
	struct kmem_cache *dev_cmd_pool;
	char dev_cmd_pool_name[50];

	struct dentry *dbgfs_dir;

#ifdef CONFIG_LOCKDEP
#error "klp-ccp: non-taken branch"
#endif
	struct iwl_trans_debug dbg;
	struct iwl_self_init_dram init_dram;

	enum iwl_plat_pm_mode system_pm_mode;

	const char *name;
	struct iwl_trans_txqs txqs;

	/* pointer to trans specific struct */
	/*Ensure that this pointer will always be aligned to sizeof pointer */
	char trans_specific[] __aligned(sizeof(void *));
};

static int (*klpe_iwl_trans_send_cmd)(struct iwl_trans *trans, struct iwl_host_cmd *cmd);

static inline void iwl_trans_write_prph(struct iwl_trans *trans, u32 ofs,
					u32 val)
{
	return trans->ops->write_prph(trans, ofs, val);
}

static inline int iwl_trans_write_mem(struct iwl_trans *trans, u32 addr,
				      const void *buf, int dwords)
{
	return trans->ops->write_mem(trans, addr, buf, dwords);
}

static inline u32 iwl_trans_write_mem32(struct iwl_trans *trans, u32 addr,
					u32 val)
{
	return iwl_trans_write_mem(trans, addr, &val, 1);
}

#define iwl_trans_grab_nic_access(trans)		\
	__cond_lock(nic_access,				\
		    likely((trans)->ops->grab_nic_access(trans)))

static inline void __releases(nic_access)
iwl_trans_release_nic_access(struct iwl_trans *trans)
{
	trans->ops->release_nic_access(trans);
	__release(nic_access);
}

static inline bool iwl_trans_dbg_ini_valid(struct iwl_trans *trans)
{
	return trans->dbg.internal_ini_cfg != IWL_INI_CFG_STATE_NOT_LOADED ||
		trans->dbg.external_ini_cfg != IWL_INI_CFG_STATE_NOT_LOADED;
}

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/dbg.h */
#include <linux/workqueue.h>

/* klp-ccp: from include/net/cfg80211.h */
#define __NET_CFG80211_H

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/debug.h */
#define BUF_ALLOC_MAX_NUM_FRAGS 16

struct iwl_buf_alloc_frag {
	__le64 addr;
	__le32 size;
} __packed;

struct iwl_buf_alloc_cmd {
	__le32 alloc_id;
	__le32 buf_location;
	__le32 num_frags;
	struct iwl_buf_alloc_frag frags[BUF_ALLOC_MAX_NUM_FRAGS];
} __packed;

#define DRAM_INFO_FIRST_MAGIC_WORD 0x76543210
#define DRAM_INFO_SECOND_MAGIC_WORD 0x89ABCDEF

struct iwl_dram_info {
	__le32 first_word;
	__le32 second_word;
	struct iwl_buf_alloc_cmd dram_frags[IWL_FW_INI_ALLOCATION_NUM - 1];
} __packed;

struct iwl_dbgc1_info {
	__le32 first_word;
	__le32 dbgc1_add_lsb;
	__le32 dbgc1_add_msb;
	__le32 dbgc1_size;
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/paging.h */
#define NUM_OF_FW_PAGING_BLOCKS	33 /* 32 for data and 1 block for CSS */

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/fw/api/power.h */
#define IWL_NUM_CHAIN_LIMITS	2

#define MCC_TO_SAR_OFFSET_TABLE_ROW_SIZE	26
#define MCC_TO_SAR_OFFSET_TABLE_COL_SIZE	13

struct iwl_sar_offset_mapping_cmd {
	u8 offset_map[MCC_TO_SAR_OFFSET_TABLE_ROW_SIZE]
		[MCC_TO_SAR_OFFSET_TABLE_COL_SIZE];
	u16 reserved;
} __packed;

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-eeprom-parse.h */
#include <linux/types.h>
#include <linux/if_ether.h>
#include <net/cfg80211.h>

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
#ifdef CONFIG_IWLWIFI_DEBUGFS
	struct {
		struct delayed_work wk;
		u32 delay;
		u64 seq;
	} timestamp;
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
	struct iwl_sar_offset_mapping_cmd sgom_table;
	bool sgom_enabled;
	u8 reduced_power_flags;
#endif
};

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-io.h */
static void (*klpe_iwl_write32)(struct iwl_trans *trans, u32 ofs, u32 val);

/* klp-ccp: from drivers/net/wireless/intel/iwlwifi/iwl-dbg-tlv.c */
struct iwl_dbg_tlv_timer_node {
	struct list_head list;
	struct timer_list timer;
	struct iwl_fw_runtime *fwrt;
	struct iwl_ucode_tlv *tlv;
};

static int (*klpe_iwl_dbg_tlv_add)(const struct iwl_ucode_tlv *tlv,
			   struct list_head *list);

static void iwl_dbg_tlv_fragments_free(struct iwl_trans *trans,
				       enum iwl_fw_ini_allocation_id alloc_id)
{
	struct iwl_fw_mon *fw_mon;
	int i;

	if (alloc_id <= IWL_FW_INI_ALLOCATION_INVALID ||
	    alloc_id >= IWL_FW_INI_ALLOCATION_NUM)
		return;

	fw_mon = &trans->dbg.fw_mon_ini[alloc_id];

	for (i = 0; i < fw_mon->num_frags; i++) {
		struct iwl_dram_data *frag = &fw_mon->frags[i];

		dma_free_coherent(trans->dev, frag->size, frag->block,
				  frag->physical);

		frag->physical = 0;
		frag->block = NULL;
		frag->size = 0;
	}

	kfree(fw_mon->frags);
	fw_mon->frags = NULL;
	fw_mon->num_frags = 0;
}

#define CHECK_FOR_NEWLINE(f) BUILD_BUG_ON(f[sizeof(f) - 2] != '\n')

#define KLPR___IWL_ERR_DEV(d, mode, f, a...)					\
	do {									\
		CHECK_FOR_NEWLINE(f);						\
		(*klpe___iwl_err)((d), mode, f, ## a);				\
	} while (0)

#define KLPR_IWL_ERR_DEV(d, f, a...)						\
	KLPR___IWL_ERR_DEV(d, IWL_ERR_MODE_REGULAR, f, ## a)

#define KLPR_IWL_ERR(m, f, a...)						\
	KLPR_IWL_ERR_DEV((m)->dev, f, ## a)

#define KLPR_IWL_WARN(m, f, a...)						\
	do {									\
		CHECK_FOR_NEWLINE(f);						\
		(*klpe___iwl_warn)((m)->dev, f, ## a);				\
	} while (0)


#define KLPR___IWL_DEBUG_DEV(dev, level, limit, fmt, args...)			\
	do {									\
		CHECK_FOR_NEWLINE(fmt);						\
		(*klpe___iwl_dbg)(dev, level, limit, __func__, fmt, ##args);	\
	} while (0)

#define KLPR_IWL_DEBUG(m, level, fmt, args...)					\
	KLPR___IWL_DEBUG_DEV((m)->dev, level, false, fmt, ##args)

#define IWL_DL_FW	0x00010000

#define KLPR_IWL_DEBUG_FW(p, f, a...)						\
	KLPR_IWL_DEBUG(p, IWL_DL_FW, f, ## a)

static int klpr_iwl_dbg_tlv_alloc_fragment(struct iwl_fw_runtime *fwrt,
				      struct iwl_dram_data *frag, u32 pages)
{
	void *block = NULL;
	dma_addr_t physical;

	if (!frag || frag->size || !pages)
		return -EIO;

	/*
	 * We try to allocate as many pages as we can, starting with
	 * the requested amount and going down until we can allocate
	 * something.  Because of DIV_ROUND_UP(), pages will never go
	 * down to 0 and stop the loop, so stop when pages reaches 1,
	 * which is too small anyway.
	 */
	while (pages > 1) {
		block = dma_alloc_coherent(fwrt->dev, pages * PAGE_SIZE,
					   &physical,
					   GFP_KERNEL | __GFP_NOWARN);
		if (block)
			break;

		KLPR_IWL_WARN(fwrt, "WRT: Failed to allocate fragment size %lu\n",
			 pages * PAGE_SIZE);

		pages = DIV_ROUND_UP(pages, 2);
	}

	if (!block)
		return -ENOMEM;

	frag->physical = physical;
	frag->block = block;
	frag->size = pages * PAGE_SIZE;

	return pages;
}

static int klpr_iwl_dbg_tlv_alloc_fragments(struct iwl_fw_runtime *fwrt,
				       enum iwl_fw_ini_allocation_id alloc_id)
{
	struct iwl_fw_mon *fw_mon;
	struct iwl_fw_ini_allocation_tlv *fw_mon_cfg;
	u32 num_frags, remain_pages, frag_pages;
	int i;

	if (alloc_id < IWL_FW_INI_ALLOCATION_INVALID ||
	    alloc_id >= IWL_FW_INI_ALLOCATION_NUM)
		return -EIO;

	fw_mon_cfg = &fwrt->trans->dbg.fw_mon_cfg[alloc_id];
	fw_mon = &fwrt->trans->dbg.fw_mon_ini[alloc_id];

	if (fw_mon->num_frags ||
	    fw_mon_cfg->buf_location !=
	    cpu_to_le32(IWL_FW_INI_LOCATION_DRAM_PATH))
		return 0;

	num_frags = le32_to_cpu(fw_mon_cfg->max_frags_num);
	if (fwrt->trans->trans_cfg->device_family < IWL_DEVICE_FAMILY_AX210) {
		if (alloc_id != IWL_FW_INI_ALLOCATION_ID_DBGC1)
			return -EIO;
		num_frags = 1;
	}

	remain_pages = DIV_ROUND_UP(le32_to_cpu(fw_mon_cfg->req_size),
				    PAGE_SIZE);
	num_frags = min_t(u32, num_frags, BUF_ALLOC_MAX_NUM_FRAGS);
	num_frags = min_t(u32, num_frags, remain_pages);
	frag_pages = DIV_ROUND_UP(remain_pages, num_frags);

	fw_mon->frags = kcalloc(num_frags, sizeof(*fw_mon->frags), GFP_KERNEL);
	if (!fw_mon->frags)
		return -ENOMEM;

	for (i = 0; i < num_frags; i++) {
		int pages = min_t(u32, frag_pages, remain_pages);

		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: Allocating DRAM buffer (alloc_id=%u, fragment=%u, size=0x%lx)\n",
			     alloc_id, i, pages * PAGE_SIZE);

		pages = klpr_iwl_dbg_tlv_alloc_fragment(fwrt, &fw_mon->frags[i],
						   pages);
		if (pages < 0) {
			u32 alloc_size = le32_to_cpu(fw_mon_cfg->req_size) -
				(remain_pages * PAGE_SIZE);

			if (alloc_size < le32_to_cpu(fw_mon_cfg->min_size)) {
				iwl_dbg_tlv_fragments_free(fwrt->trans,
							   alloc_id);
				return pages;
			}
			break;
		}

		remain_pages -= pages;
		fw_mon->num_frags++;
	}

	return 0;
}

static int (*klpe_iwl_dbg_tlv_apply_buffer)(struct iwl_fw_runtime *fwrt,
				    enum iwl_fw_ini_allocation_id alloc_id);

static void klpr_iwl_dbg_tlv_apply_buffers(struct iwl_fw_runtime *fwrt)
{
	int ret, i;

	if (fw_has_capa(&fwrt->fw->ucode_capa,
			IWL_UCODE_TLV_CAPA_DRAM_FRAG_SUPPORT))
		return;

	for (i = 0; i < IWL_FW_INI_ALLOCATION_NUM; i++) {
		ret = (*klpe_iwl_dbg_tlv_apply_buffer)(fwrt, i);
		if (ret)
			KLPR_IWL_WARN(fwrt,
				 "WRT: Failed to apply DRAM buffer for allocation id %d, ret=%d\n",
				 i, ret);
	}
}

static int klpr_iwl_dbg_tlv_update_dram(struct iwl_fw_runtime *fwrt,
				   enum iwl_fw_ini_allocation_id alloc_id,
				   struct iwl_dram_info *dram_info)
{
	struct iwl_fw_mon *fw_mon;
	u32 remain_frags, num_frags;
	int j, fw_mon_idx = 0;
	struct iwl_buf_alloc_cmd *data;

	if (le32_to_cpu(fwrt->trans->dbg.fw_mon_cfg[alloc_id].buf_location) !=
			IWL_FW_INI_LOCATION_DRAM_PATH) {
		KLPR_IWL_DEBUG_FW(fwrt, "DRAM_PATH is not supported alloc_id %u\n", alloc_id);
		return -1;
	}

	fw_mon = &fwrt->trans->dbg.fw_mon_ini[alloc_id];

	/* the first fragment of DBGC1 is given to the FW via register
	 * or context info
	 */
	if (alloc_id == IWL_FW_INI_ALLOCATION_ID_DBGC1)
		fw_mon_idx++;

	remain_frags = fw_mon->num_frags - fw_mon_idx;
	if (!remain_frags)
		return -1;

	num_frags = min_t(u32, remain_frags, BUF_ALLOC_MAX_NUM_FRAGS);
	data = &dram_info->dram_frags[alloc_id - 1];
	data->alloc_id = cpu_to_le32(alloc_id);
	data->num_frags = cpu_to_le32(num_frags);
	data->buf_location = cpu_to_le32(IWL_FW_INI_LOCATION_DRAM_PATH);

	KLPR_IWL_DEBUG_FW(fwrt, "WRT: DRAM buffer details alloc_id=%u, num_frags=%u\n",
		     cpu_to_le32(alloc_id), cpu_to_le32(num_frags));

	for (j = 0; j < num_frags; j++) {
		struct iwl_buf_alloc_frag *frag = &data->frags[j];
		struct iwl_dram_data *fw_mon_frag = &fw_mon->frags[fw_mon_idx++];

		frag->addr = cpu_to_le64(fw_mon_frag->physical);
		frag->size = cpu_to_le32(fw_mon_frag->size);
		KLPR_IWL_DEBUG_FW(fwrt, "WRT: DRAM fragment details\n");
		KLPR_IWL_DEBUG_FW(fwrt, "frag=%u, addr=0x%016llx, size=0x%x)\n",
			     j, cpu_to_le64(fw_mon_frag->physical),
			     cpu_to_le32(fw_mon_frag->size));
	}
	return 0;
}

static void klpr_iwl_dbg_tlv_update_drams(struct iwl_fw_runtime *fwrt)
{
	int ret, i;
	bool dram_alloc = false;
	struct iwl_dram_data *frags =
		&fwrt->trans->dbg.fw_mon_ini[IWL_FW_INI_ALLOCATION_ID_DBGC1].frags[0];
	struct iwl_dram_info *dram_info;

	if (!frags || !frags->block)
		return;

	dram_info = frags->block;

	if (!fw_has_capa(&fwrt->fw->ucode_capa,
			 IWL_UCODE_TLV_CAPA_DRAM_FRAG_SUPPORT))
		return;

	dram_info->first_word = cpu_to_le32(DRAM_INFO_FIRST_MAGIC_WORD);
	dram_info->second_word = cpu_to_le32(DRAM_INFO_SECOND_MAGIC_WORD);

	for (i = IWL_FW_INI_ALLOCATION_ID_DBGC1;
	     i <= IWL_FW_INI_ALLOCATION_ID_DBGC3; i++) {
		ret = klpr_iwl_dbg_tlv_update_dram(fwrt, i, dram_info);
		if (!ret)
			dram_alloc = true;
		else
			KLPR_IWL_WARN(fwrt,
				 "WRT: Failed to set DRAM buffer for alloc id %d, ret=%d\n",
				 i, ret);
	}

	if (dram_alloc)
		KLPR_IWL_DEBUG_FW(fwrt, "block data after  %08x\n",
			     dram_info->first_word);
	else
		memset(frags->block, 0, sizeof(*dram_info));
}

static void klpr_iwl_dbg_tlv_send_hcmds(struct iwl_fw_runtime *fwrt,
				   struct list_head *hcmd_list)
{
	struct iwl_dbg_tlv_node *node;

	list_for_each_entry(node, hcmd_list, list) {
		struct iwl_fw_ini_hcmd_tlv *hcmd = (void *)node->tlv.data;
		struct iwl_fw_ini_hcmd *hcmd_data = &hcmd->hcmd;
		u16 hcmd_len = le32_to_cpu(node->tlv.length) - sizeof(*hcmd);
		struct iwl_host_cmd cmd = {
			.id = WIDE_ID(hcmd_data->group, hcmd_data->id),
			.len = { hcmd_len, },
			.data = { hcmd_data->data, },
		};

		(*klpe_iwl_trans_send_cmd)(fwrt->trans, &cmd);
	}
}

static void klpr_iwl_dbg_tlv_apply_config(struct iwl_fw_runtime *fwrt,
				     struct list_head *conf_list)
{
	struct iwl_dbg_tlv_node *node;

	list_for_each_entry(node, conf_list, list) {
		struct iwl_fw_ini_conf_set_tlv *config_list = (void *)node->tlv.data;
		u32 count, address, value;
		u32 len = (le32_to_cpu(node->tlv.length) - sizeof(*config_list)) / 8;
		u32 type = le32_to_cpu(config_list->set_type);
		u32 offset = le32_to_cpu(config_list->addr_offset);

		switch (type) {
		case IWL_FW_INI_CONFIG_SET_TYPE_DEVICE_PERIPHERY_MAC: {
			if (!iwl_trans_grab_nic_access(fwrt->trans)) {
				KLPR_IWL_DEBUG_FW(fwrt, "WRT: failed to get nic access\n");
				KLPR_IWL_DEBUG_FW(fwrt, "WRT: skipping MAC PERIPHERY config\n");
				continue;
			}
			KLPR_IWL_DEBUG_FW(fwrt, "WRT:  MAC PERIPHERY config len: len %u\n", len);
			for (count = 0; count < len; count++) {
				address = le32_to_cpu(config_list->addr_val[count].address);
				value = le32_to_cpu(config_list->addr_val[count].value);
				iwl_trans_write_prph(fwrt->trans, address + offset, value);
			}
			iwl_trans_release_nic_access(fwrt->trans);
		break;
		}
		case IWL_FW_INI_CONFIG_SET_TYPE_DEVICE_MEMORY: {
			for (count = 0; count < len; count++) {
				address = le32_to_cpu(config_list->addr_val[count].address);
				value = le32_to_cpu(config_list->addr_val[count].value);
				iwl_trans_write_mem32(fwrt->trans, address + offset, value);
				KLPR_IWL_DEBUG_FW(fwrt, "WRT: DEV_MEM: count %u, add: %u val: %u\n",
					     count, address, value);
			}
		break;
		}
		case IWL_FW_INI_CONFIG_SET_TYPE_CSR: {
			for (count = 0; count < len; count++) {
				address = le32_to_cpu(config_list->addr_val[count].address);
				value = le32_to_cpu(config_list->addr_val[count].value);
				(*klpe_iwl_write32)(fwrt->trans, address + offset, value);
				KLPR_IWL_DEBUG_FW(fwrt, "WRT: CSR: count %u, add: %u val: %u\n",
					     count, address, value);
			}
		break;
		}
		case IWL_FW_INI_CONFIG_SET_TYPE_DBGC_DRAM_ADDR: {
			struct iwl_dbgc1_info dram_info = {};
			struct iwl_dram_data *frags = &fwrt->trans->dbg.fw_mon_ini[1].frags[0];
			__le64 dram_base_addr;
			__le32 dram_size;
			u64 dram_addr;
			u32 ret;

			if (!frags)
				break;

			dram_base_addr = cpu_to_le64(frags->physical);
			dram_size = cpu_to_le32(frags->size);
			dram_addr = le64_to_cpu(dram_base_addr);

			KLPR_IWL_DEBUG_FW(fwrt, "WRT: dram_base_addr 0x%016llx, dram_size 0x%x\n",
				     dram_base_addr, dram_size);
			KLPR_IWL_DEBUG_FW(fwrt, "WRT: config_list->addr_offset: %u\n",
				     le32_to_cpu(config_list->addr_offset));
			for (count = 0; count < len; count++) {
				address = le32_to_cpu(config_list->addr_val[count].address);
				dram_info.dbgc1_add_lsb =
					cpu_to_le32((dram_addr & 0x00000000FFFFFFFFULL) + 0x400);
				dram_info.dbgc1_add_msb =
					cpu_to_le32((dram_addr & 0xFFFFFFFF00000000ULL) >> 32);
				dram_info.dbgc1_size = cpu_to_le32(le32_to_cpu(dram_size) - 0x400);
				ret = iwl_trans_write_mem(fwrt->trans,
							  address + offset, &dram_info, 4);
				if (ret) {
					KLPR_IWL_ERR(fwrt, "Failed to write dram_info to HW_SMEM\n");
					break;
				}
			}
			break;
		}
		case IWL_FW_INI_CONFIG_SET_TYPE_PERIPH_SCRATCH_HWM: {
			u32 debug_token_config =
				le32_to_cpu(config_list->addr_val[0].value);

			KLPR_IWL_DEBUG_FW(fwrt, "WRT: Setting HWM debug token config: %u\n",
				     debug_token_config);
			fwrt->trans->dbg.ucode_preset = debug_token_config;
			break;
		}
		default:
			break;
		}
	}
}

static void (*klpe_iwl_dbg_tlv_periodic_trig_handler)(struct timer_list *t);

static void klpr_iwl_dbg_tlv_set_periodic_trigs(struct iwl_fw_runtime *fwrt)
{
	struct iwl_dbg_tlv_node *node;
	struct list_head *trig_list =
		&fwrt->trans->dbg.time_point[IWL_FW_INI_TIME_POINT_PERIODIC].active_trig_list;

	list_for_each_entry(node, trig_list, list) {
		struct iwl_fw_ini_trigger_tlv *trig = (void *)node->tlv.data;
		struct iwl_dbg_tlv_timer_node *timer_node;
		u32 occur = le32_to_cpu(trig->occurrences), collect_interval;
		u32 min_interval = 100;

		if (!occur)
			continue;

		/* make sure there is at least one dword of data for the
		 * interval value
		 */
		if (le32_to_cpu(node->tlv.length) <
		    sizeof(*trig) + sizeof(__le32)) {
			KLPR_IWL_ERR(fwrt,
				"WRT: Invalid periodic trigger data was not given\n");
			continue;
		}

		if (le32_to_cpu(trig->data[0]) < min_interval) {
			KLPR_IWL_WARN(fwrt,
				 "WRT: Override min interval from %u to %u msec\n",
				 le32_to_cpu(trig->data[0]), min_interval);
			trig->data[0] = cpu_to_le32(min_interval);
		}

		collect_interval = le32_to_cpu(trig->data[0]);

		timer_node = kzalloc(sizeof(*timer_node), GFP_KERNEL);
		if (!timer_node) {
			KLPR_IWL_ERR(fwrt,
				"WRT: Failed to allocate periodic trigger\n");
			continue;
		}

		timer_node->fwrt = fwrt;
		timer_node->tlv = &node->tlv;
		timer_setup(&timer_node->timer,
			    (*klpe_iwl_dbg_tlv_periodic_trig_handler), 0);

		list_add_tail(&timer_node->list,
			      &fwrt->trans->dbg.periodic_trig_list);

		KLPR_IWL_DEBUG_FW(fwrt, "WRT: Enabling periodic trigger\n");

		mod_timer(&timer_node->timer,
			  jiffies + msecs_to_jiffies(collect_interval));
	}
}

static bool is_trig_data_contained(const struct iwl_ucode_tlv *new,
				   const struct iwl_ucode_tlv *old)
{
	const struct iwl_fw_ini_trigger_tlv *new_trig = (const void *)new->data;
	const struct iwl_fw_ini_trigger_tlv *old_trig = (const void *)old->data;
	const __le32 *new_data = new_trig->data, *old_data = old_trig->data;
	u32 new_dwords_num = iwl_tlv_array_len(new, new_trig, data);
	u32 old_dwords_num = iwl_tlv_array_len(old, old_trig, data);
	int i, j;

	for (i = 0; i < new_dwords_num; i++) {
		bool match = false;

		for (j = 0; j < old_dwords_num; j++) {
			if (new_data[i] == old_data[j]) {
				match = true;
				break;
			}
		}
		if (!match)
			return false;
	}

	return true;
}

static int klpr_iwl_dbg_tlv_override_trig_node(struct iwl_fw_runtime *fwrt,
					  struct iwl_ucode_tlv *trig_tlv,
					  struct iwl_dbg_tlv_node *node)
{
	struct iwl_ucode_tlv *node_tlv = &node->tlv;
	struct iwl_fw_ini_trigger_tlv *node_trig = (void *)node_tlv->data;
	struct iwl_fw_ini_trigger_tlv *trig = (void *)trig_tlv->data;
	u32 policy = le32_to_cpu(trig->apply_policy);
	u32 size = le32_to_cpu(trig_tlv->length);
	u32 trig_data_len = size - sizeof(*trig);
	u32 offset = 0;

	if (!(policy & IWL_FW_INI_APPLY_POLICY_OVERRIDE_DATA)) {
		u32 data_len = le32_to_cpu(node_tlv->length) -
			sizeof(*node_trig);

		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: Appending trigger data (time point %u)\n",
			     le32_to_cpu(trig->time_point));

		offset += data_len;
		size += data_len;
	} else {
		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: Overriding trigger data (time point %u)\n",
			     le32_to_cpu(trig->time_point));
	}

	if (size != le32_to_cpu(node_tlv->length)) {
		struct list_head *prev = node->list.prev;
		struct iwl_dbg_tlv_node *tmp;

		list_del(&node->list);

		tmp = krealloc(node, sizeof(*node) + size, GFP_KERNEL);
		if (!tmp) {
			KLPR_IWL_WARN(fwrt,
				 "WRT: No memory to override trigger (time point %u)\n",
				 le32_to_cpu(trig->time_point));

			list_add(&node->list, prev);

			return -ENOMEM;
		}

		list_add(&tmp->list, prev);
		node_tlv = &tmp->tlv;
		node_trig = (void *)node_tlv->data;
	}

	memcpy((u8 *)node_trig->data + offset, trig->data, trig_data_len);
	node_tlv->length = cpu_to_le32(size);

	if (policy & IWL_FW_INI_APPLY_POLICY_OVERRIDE_CFG) {
		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: Overriding trigger configuration (time point %u)\n",
			     le32_to_cpu(trig->time_point));

		/* the first 11 dwords are configuration related */
		memcpy(node_trig, trig, sizeof(__le32) * 11);
	}

	if (policy & IWL_FW_INI_APPLY_POLICY_OVERRIDE_REGIONS) {
		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: Overriding trigger regions (time point %u)\n",
			     le32_to_cpu(trig->time_point));

		node_trig->regions_mask = trig->regions_mask;
	} else {
		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: Appending trigger regions (time point %u)\n",
			     le32_to_cpu(trig->time_point));

		node_trig->regions_mask |= trig->regions_mask;
	}

	return 0;
}

static int
klpr_iwl_dbg_tlv_add_active_trigger(struct iwl_fw_runtime *fwrt,
			       struct list_head *trig_list,
			       struct iwl_ucode_tlv *trig_tlv)
{
	struct iwl_fw_ini_trigger_tlv *trig = (void *)trig_tlv->data;
	struct iwl_dbg_tlv_node *node, *match = NULL;
	u32 policy = le32_to_cpu(trig->apply_policy);

	list_for_each_entry(node, trig_list, list) {
		if (!(policy & IWL_FW_INI_APPLY_POLICY_MATCH_TIME_POINT))
			break;

		if (!(policy & IWL_FW_INI_APPLY_POLICY_MATCH_DATA) ||
		    is_trig_data_contained(trig_tlv, &node->tlv)) {
			match = node;
			break;
		}
	}

	if (!match) {
		KLPR_IWL_DEBUG_FW(fwrt, "WRT: Enabling trigger (time point %u)\n",
			     le32_to_cpu(trig->time_point));
		return (*klpe_iwl_dbg_tlv_add)(trig_tlv, trig_list);
	}

	return klpr_iwl_dbg_tlv_override_trig_node(fwrt, trig_tlv, match);
}

static void
klpr_iwl_dbg_tlv_gen_active_trig_list(struct iwl_fw_runtime *fwrt,
				 struct iwl_dbg_tlv_time_point_data *tp)
{
	struct iwl_dbg_tlv_node *node;
	struct list_head *trig_list = &tp->trig_list;
	struct list_head *active_trig_list = &tp->active_trig_list;

	list_for_each_entry(node, trig_list, list) {
		struct iwl_ucode_tlv *tlv = &node->tlv;

		klpr_iwl_dbg_tlv_add_active_trigger(fwrt, active_trig_list, tlv);
	}
}

static bool (*klpe_iwl_dbg_tlv_check_fw_pkt)(struct iwl_fw_runtime *fwrt,
				     struct iwl_fwrt_dump_data *dump_data,
				     union iwl_dbg_tlv_tp_data *tp_data,
				     u32 trig_data);

static int
(*klpe_iwl_dbg_tlv_tp_trigger)(struct iwl_fw_runtime *fwrt, bool sync,
		       struct list_head *active_trig_list,
		       union iwl_dbg_tlv_tp_data *tp_data,
		       bool (*data_check)(struct iwl_fw_runtime *fwrt,
					  struct iwl_fwrt_dump_data *dump_data,
					  union iwl_dbg_tlv_tp_data *tp_data,
					  u32 trig_data));

static void klpr_iwl_dbg_tlv_init_cfg(struct iwl_fw_runtime *fwrt)
{
	enum iwl_fw_ini_buffer_location *ini_dest = &fwrt->trans->dbg.ini_dest;
	int ret, i;
	u32 failed_alloc = 0;

	if (*ini_dest != IWL_FW_INI_LOCATION_INVALID)
		return;

	KLPR_IWL_DEBUG_FW(fwrt,
		     "WRT: Generating active triggers list, domain 0x%x\n",
		     fwrt->trans->dbg.domains_bitmap);

	for (i = 0; i < ARRAY_SIZE(fwrt->trans->dbg.time_point); i++) {
		struct iwl_dbg_tlv_time_point_data *tp =
			&fwrt->trans->dbg.time_point[i];

		klpr_iwl_dbg_tlv_gen_active_trig_list(fwrt, tp);
	}

	*ini_dest = IWL_FW_INI_LOCATION_INVALID;
	for (i = 0; i < IWL_FW_INI_ALLOCATION_NUM; i++) {
		struct iwl_fw_ini_allocation_tlv *fw_mon_cfg =
			&fwrt->trans->dbg.fw_mon_cfg[i];
		u32 dest = le32_to_cpu(fw_mon_cfg->buf_location);

		if (dest == IWL_FW_INI_LOCATION_INVALID) {
			failed_alloc |= BIT(i);
			continue;
		}

		if (*ini_dest == IWL_FW_INI_LOCATION_INVALID)
			*ini_dest = dest;

		if (dest != *ini_dest)
			continue;

		ret = klpr_iwl_dbg_tlv_alloc_fragments(fwrt, i);

		if (ret) {
			KLPR_IWL_WARN(fwrt,
				 "WRT: Failed to allocate DRAM buffer for allocation id %d, ret=%d\n",
				 i, ret);
			failed_alloc |= BIT(i);
		}
	}

	if (!failed_alloc)
		return;

	for (i = 0; i < ARRAY_SIZE(fwrt->trans->dbg.active_regions) && failed_alloc; i++) {
		struct iwl_fw_ini_region_tlv *reg;
		struct iwl_ucode_tlv **active_reg =
			&fwrt->trans->dbg.active_regions[i];
		u32 reg_type;

		if (!*active_reg) {
			fwrt->trans->dbg.unsupported_region_msk |= BIT(i);
			continue;
		}

		reg = (void *)(*active_reg)->data;
		reg_type = reg->type;

		if (reg_type != IWL_FW_INI_REGION_DRAM_BUFFER ||
		    !(BIT(le32_to_cpu(reg->dram_alloc_id)) & failed_alloc))
			continue;

		KLPR_IWL_DEBUG_FW(fwrt,
			     "WRT: removing allocation id %d from region id %d\n",
			     le32_to_cpu(reg->dram_alloc_id), i);

		failed_alloc &= ~le32_to_cpu(reg->dram_alloc_id);
		fwrt->trans->dbg.unsupported_region_msk |= BIT(i);

		kfree(*active_reg);
		*active_reg = NULL;
	}
}

void klpp__iwl_dbg_tlv_time_point(struct iwl_fw_runtime *fwrt,
			     enum iwl_fw_ini_time_point tp_id,
			     union iwl_dbg_tlv_tp_data *tp_data,
			     bool sync)
{
	struct list_head *hcmd_list, *trig_list, *conf_list;

	if (!iwl_trans_dbg_ini_valid(fwrt->trans) ||
	    tp_id == IWL_FW_INI_TIME_POINT_INVALID ||
	    tp_id >= IWL_FW_INI_TIME_POINT_NUM)
		return;

	hcmd_list = &fwrt->trans->dbg.time_point[tp_id].hcmd_list;
	trig_list = &fwrt->trans->dbg.time_point[tp_id].active_trig_list;
	conf_list = &fwrt->trans->dbg.time_point[tp_id].config_list;

	switch (tp_id) {
	case IWL_FW_INI_TIME_POINT_EARLY:
		klpr_iwl_dbg_tlv_init_cfg(fwrt);
		klpr_iwl_dbg_tlv_apply_config(fwrt, conf_list);
		klpr_iwl_dbg_tlv_update_drams(fwrt);
		(*klpe_iwl_dbg_tlv_tp_trigger)(fwrt, sync, trig_list, tp_data, NULL);
		break;
	case IWL_FW_INI_TIME_POINT_AFTER_ALIVE:
		klpr_iwl_dbg_tlv_apply_buffers(fwrt);
		klpr_iwl_dbg_tlv_send_hcmds(fwrt, hcmd_list);
		klpr_iwl_dbg_tlv_apply_config(fwrt, conf_list);
		(*klpe_iwl_dbg_tlv_tp_trigger)(fwrt, sync, trig_list, tp_data, NULL);
		break;
	case IWL_FW_INI_TIME_POINT_PERIODIC:
		klpr_iwl_dbg_tlv_set_periodic_trigs(fwrt);
		klpr_iwl_dbg_tlv_send_hcmds(fwrt, hcmd_list);
		break;
	case IWL_FW_INI_TIME_POINT_FW_RSP_OR_NOTIF:
	case IWL_FW_INI_TIME_POINT_MISSED_BEACONS:
	case IWL_FW_INI_TIME_POINT_FW_DHC_NOTIFICATION:
		klpr_iwl_dbg_tlv_send_hcmds(fwrt, hcmd_list);
		klpr_iwl_dbg_tlv_apply_config(fwrt, conf_list);
		(*klpe_iwl_dbg_tlv_tp_trigger)(fwrt, sync, trig_list, tp_data,
				       (*klpe_iwl_dbg_tlv_check_fw_pkt));
		break;
	default:
		klpr_iwl_dbg_tlv_send_hcmds(fwrt, hcmd_list);
		klpr_iwl_dbg_tlv_apply_config(fwrt, conf_list);
		(*klpe_iwl_dbg_tlv_tp_trigger)(fwrt, sync, trig_list, tp_data, NULL);
		break;
	}
}



#include "livepatch_bsc1221302.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "iwlwifi"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__iwl_dbg", (void *)&klpe___iwl_dbg, "iwlwifi" },
	{ "__iwl_err", (void *)&klpe___iwl_err, "iwlwifi" },
	{ "__iwl_warn", (void *)&klpe___iwl_warn, "iwlwifi" },
	{ "iwl_dbg_tlv_add", (void *)&klpe_iwl_dbg_tlv_add, "iwlwifi" },
	{ "iwl_dbg_tlv_apply_buffer", (void *)&klpe_iwl_dbg_tlv_apply_buffer,
	  "iwlwifi" },
	{ "iwl_dbg_tlv_check_fw_pkt", (void *)&klpe_iwl_dbg_tlv_check_fw_pkt,
	  "iwlwifi" },
	{ "iwl_dbg_tlv_periodic_trig_handler",
	  (void *)&klpe_iwl_dbg_tlv_periodic_trig_handler, "iwlwifi" },
	{ "iwl_dbg_tlv_tp_trigger", (void *)&klpe_iwl_dbg_tlv_tp_trigger,
	  "iwlwifi" },
	{ "iwl_trans_send_cmd", (void *)&klpe_iwl_trans_send_cmd, "iwlwifi" },
	{ "iwl_write32", (void *)&klpe_iwl_write32, "iwlwifi" },
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

int livepatch_bsc1221302_init(void)
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

void livepatch_bsc1221302_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_IWLWIFI) */
