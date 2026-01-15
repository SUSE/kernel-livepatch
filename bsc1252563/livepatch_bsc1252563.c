/*
 * livepatch_bsc1252563
 *
 * Fix for CVE-2023-53717, bsc#1252563
 *
 *  Copyright (c) 2025 SUSE
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

#if IS_ENABLED(CONFIG_ATH9K_HTC)

#if !IS_MODULE(CONFIG_ATH9K_HTC)
#error "Live patch supports only CONFIG=m"
#endif


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc.h */
#include <linux/module.h>
#include <linux/usb.h>
#include <linux/firmware.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/leds.h>
#include <linux/slab.h>
#include <net/mac80211.h>
/* klp-ccp: from drivers/net/wireless/ath/ath9k/common.h */
#include <net/mac80211.h>
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

struct ath_ops {
	unsigned int (*read)(void *, u32 reg_offset);
	void (*multi_read)(void *, u32 *addr, u32 *val, u16 count);
	void (*write)(void *, u32 val, u32 reg_offset);
	void (*enable_write_buffer)(void *);
	void (*write_flush) (void *);
	u32 (*rmw)(void *, u32 reg_offset, u32 set, u32 clr);
	void (*enable_rmw_buffer)(void *);
	void (*rmw_flush) (void *);

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

enum ATH_DEBUG {
	ATH_DBG_RESET		= 0x00000001,
	ATH_DBG_QUEUE		= 0x00000002,
	ATH_DBG_EEPROM		= 0x00000004,
	ATH_DBG_CALIBRATE	= 0x00000008,
	ATH_DBG_INTERRUPT	= 0x00000010,
	ATH_DBG_REGULATORY	= 0x00000020,
	ATH_DBG_ANI		= 0x00000040,
	ATH_DBG_XMIT		= 0x00000080,
	ATH_DBG_BEACON		= 0x00000100,
	ATH_DBG_CONFIG		= 0x00000200,
	ATH_DBG_FATAL		= 0x00000400,
	ATH_DBG_PS		= 0x00000800,
	ATH_DBG_BTCOEX		= 0x00001000,
	ATH_DBG_WMI		= 0x00002000,
	ATH_DBG_BSTUCK		= 0x00004000,
	ATH_DBG_MCI		= 0x00008000,
	ATH_DBG_DFS		= 0x00010000,
	ATH_DBG_WOW		= 0x00020000,
	ATH_DBG_CHAN_CTX	= 0x00040000,
	ATH_DBG_DYNACK		= 0x00080000,
	ATH_DBG_SPECTRAL_SCAN	= 0x00100000,
	ATH_DBG_ANY		= 0xffffffff
};

#ifdef CONFIG_ATH_DEBUG
#error "klp-ccp: non-taken branch"
#else

static inline  __attribute__ ((format (printf, 3, 4)))
void _ath_dbg(struct ath_common *common, enum ATH_DEBUG dbg_mask,
	     const char *fmt, ...)
{
}
#define ath_dbg(common, dbg_mask, fmt, ...)				\
	_ath_dbg(common, ATH_DBG_##dbg_mask, fmt, ##__VA_ARGS__)

#endif /* CONFIG_ATH_DEBUG */

/* klp-ccp: from drivers/net/wireless/ath/ath9k/hw.h */
#include <linux/if_ether.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/firmware.h>
/* klp-ccp: from drivers/net/wireless/ath/ath9k/mac.h */
#include <net/cfg80211.h>

struct ath_tx_status;

enum ath9k_tx_queue {
	ATH9K_TX_QUEUE_INACTIVE = 0,
	ATH9K_TX_QUEUE_DATA,
	ATH9K_TX_QUEUE_BEACON,
	ATH9K_TX_QUEUE_CAB,
	ATH9K_TX_QUEUE_UAPSD,
	ATH9K_TX_QUEUE_PSPOLL
};

#define	ATH9K_NUM_TX_QUEUES 10

enum ath9k_tx_queue_flags {
	TXQ_FLAG_TXINT_ENABLE = 0x0001,
	TXQ_FLAG_TXDESCINT_ENABLE = 0x0002,
	TXQ_FLAG_TXEOLINT_ENABLE = 0x0004,
	TXQ_FLAG_TXURNINT_ENABLE = 0x0008,
	TXQ_FLAG_BACKOFF_DISABLE = 0x0010,
	TXQ_FLAG_COMPRESSION_ENABLE = 0x0020,
	TXQ_FLAG_RDYTIME_EXP_POLICY_ENABLE = 0x0040,
	TXQ_FLAG_FRAG_BURST_BACKOFF_ENABLE = 0x0080,
};

struct ath9k_tx_queue_info {
	u32 tqi_ver;
	enum ath9k_tx_queue tqi_type;
	int tqi_subtype;
	enum ath9k_tx_queue_flags tqi_qflags;
	u32 tqi_priority;
	u32 tqi_aifs;
	u32 tqi_cwmin;
	u32 tqi_cwmax;
	u16 tqi_shretry;
	u16 tqi_lgretry;
	u32 tqi_cbrPeriod;
	u32 tqi_cbrOverflowLimit;
	u32 tqi_burstTime;
	u32 tqi_readyTime;
	u32 tqi_physCompBuf;
	u32 tqi_intFlags;
};

struct ath_tx_info;

struct ath_hw;

/* klp-ccp: from drivers/net/wireless/ath/ath9k/ani.h */
enum ath9k_ani_cmd {
	ATH9K_ANI_OFDM_WEAK_SIGNAL_DETECTION = 0x1,
	ATH9K_ANI_FIRSTEP_LEVEL = 0x2,
	ATH9K_ANI_SPUR_IMMUNITY_LEVEL = 0x4,
	ATH9K_ANI_MRC_CCK = 0x8,
	ATH9K_ANI_ALL = 0xfff
};

struct ath9k_mib_stats {
	u32 ackrcv_bad;
	u32 rts_bad;
	u32 rts_good;
	u32 fcs_bad;
	u32 beacons;
};

struct ath9k_ani_default {
	u16 m1ThreshLow;
	u16 m2ThreshLow;
	u16 m1Thresh;
	u16 m2Thresh;
	u16 m2CountThr;
	u16 m2CountThrLow;
	u16 m1ThreshLowExt;
	u16 m2ThreshLowExt;
	u16 m1ThreshExt;
	u16 m2ThreshExt;
	u16 firstep;
	u16 firstepLow;
	u16 cycpwrThr1;
	u16 cycpwrThr1Ext;
};

struct ar5416AniState {
	u8 noiseImmunityLevel;
	u8 ofdmNoiseImmunityLevel;
	u8 cckNoiseImmunityLevel;
	bool ofdmsTurn;
	u8 mrcCCK;
	u8 spurImmunityLevel;
	u8 firstepLevel;
	bool ofdmWeakSigDetect;
	u32 listenTime;
	u32 ofdmPhyErrCount;
	u32 cckPhyErrCount;
	struct ath9k_ani_default iniDef;
};

struct ar5416Stats {
	u32 ast_ani_spurup;
	u32 ast_ani_spurdown;
	u32 ast_ani_ofdmon;
	u32 ast_ani_ofdmoff;
	u32 ast_ani_cckhigh;
	u32 ast_ani_ccklow;
	u32 ast_ani_stepup;
	u32 ast_ani_stepdown;
	u32 ast_ani_ofdmerrs;
	u32 ast_ani_cckerrs;
	u32 ast_ani_reset;
	u32 ast_ani_lneg_or_lzero;
	u32 avgbrssi;
	struct ath9k_mib_stats ast_mibstats;
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/eeprom.h */
#define AR_EEPROM_MODAL_SPURS   5

#include <net/cfg80211.h>
/* klp-ccp: from drivers/net/wireless/ath/ath9k/ar9003_eeprom.h */
#include <linux/types.h>

#define AR9300_NUM_5G_CAL_PIERS      8
#define AR9300_NUM_2G_CAL_PIERS      3
#define AR9300_NUM_5G_20_TARGET_POWERS  8
#define AR9300_NUM_5G_40_TARGET_POWERS  8
#define AR9300_NUM_2G_CCK_TARGET_POWERS 2
#define AR9300_NUM_2G_20_TARGET_POWERS  3
#define AR9300_NUM_2G_40_TARGET_POWERS  3

#define AR9300_NUM_CTLS_5G           9
#define AR9300_NUM_CTLS_2G           12
#define AR9300_NUM_BAND_EDGES_5G     8
#define AR9300_NUM_BAND_EDGES_2G     4

#define AR9300_CUSTOMER_DATA_SIZE    20

#define AR9300_MAX_CHAINS            3

struct eepFlags {
	u8 opFlags;
	u8 eepMisc;
} __packed;

struct ar9300_base_eep_hdr {
	__le16 regDmn[2];
	/* 4 bits tx and 4 bits rx */
	u8 txrxMask;
	struct eepFlags opCapFlags;
	u8 rfSilent;
	u8 blueToothOptions;
	u8 deviceCap;
	/* takes lower byte in eeprom location */
	u8 deviceType;
	/* offset in dB to be added to beginning
	 * of pdadc table in calibration
	 */
	int8_t pwrTableOffset;
	u8 params_for_tuning_caps[2];
	/*
	 * bit0 - enable tx temp comp
	 * bit1 - enable tx volt comp
	 * bit2 - enable fastClock - default to 1
	 * bit3 - enable doubling - default to 1
	 * bit4 - enable internal regulator - default to 1
	 */
	u8 featureEnable;
	/* misc flags: bit0 - turn down drivestrength */
	u8 miscConfiguration;
	u8 eepromWriteEnableGpio;
	u8 wlanDisableGpio;
	u8 wlanLedGpio;
	u8 rxBandSelectGpio;
	u8 txrxgain;
	/* SW controlled internal regulator fields */
	__le32 swreg;
} __packed;

struct ar9300_modal_eep_header {
	/* 4 idle, t1, t2, b (4 bits per setting) */
	__le32 antCtrlCommon;
	/* 4 ra1l1, ra2l1, ra1l2, ra2l2, ra12 */
	__le32 antCtrlCommon2;
	/* 6 idle, t, r, rx1, rx12, b (2 bits each) */
	__le16 antCtrlChain[AR9300_MAX_CHAINS];
	/* 3 xatten1_db for AR9280 (0xa20c/b20c 5:0) */
	u8 xatten1DB[AR9300_MAX_CHAINS];
	/* 3  xatten1_margin for merlin (0xa20c/b20c 16:12 */
	u8 xatten1Margin[AR9300_MAX_CHAINS];
	int8_t tempSlope;
	int8_t voltSlope;
	/* spur channels in usual fbin coding format */
	u8 spurChans[AR_EEPROM_MODAL_SPURS];
	/* 3  Check if the register is per chain */
	int8_t noiseFloorThreshCh[AR9300_MAX_CHAINS];
	u8 reserved[11];
	int8_t quick_drop;
	u8 xpaBiasLvl;
	u8 txFrameToDataStart;
	u8 txFrameToPaOn;
	u8 txClip;
	int8_t antennaGain;
	u8 switchSettling;
	int8_t adcDesiredSize;
	u8 txEndToXpaOff;
	u8 txEndToRxOn;
	u8 txFrameToXpaOn;
	u8 thresh62;
	__le32 papdRateMaskHt20;
	__le32 papdRateMaskHt40;
	__le16 switchcomspdt;
	u8 xlna_bias_strength;
	u8 futureModal[7];
} __packed;

struct ar9300_cal_data_per_freq_op_loop {
	int8_t refPower;
	/* pdadc voltage at power measurement */
	u8 voltMeas;
	/* pcdac used for power measurement   */
	u8 tempMeas;
	/* range is -60 to -127 create a mapping equation 1db resolution */
	int8_t rxNoisefloorCal;
	/*range is same as noisefloor */
	int8_t rxNoisefloorPower;
	/* temp measured when noisefloor cal was performed */
	u8 rxTempMeas;
} __packed;

struct cal_tgt_pow_legacy {
	u8 tPow2x[4];
} __packed;

struct cal_tgt_pow_ht {
	u8 tPow2x[14];
} __packed;

struct cal_ctl_data_2g {
	u8 ctlEdges[AR9300_NUM_BAND_EDGES_2G];
} __packed;

struct cal_ctl_data_5g {
	u8 ctlEdges[AR9300_NUM_BAND_EDGES_5G];
} __packed;

#define MAX_BASE_EXTENSION_FUTURE 2

struct ar9300_BaseExtension_1 {
	u8 ant_div_control;
	u8 future[MAX_BASE_EXTENSION_FUTURE];
	/*
	 * misc_enable:
	 *
	 * BIT 0   - TX Gain Cap enable.
	 * BIT 1   - Uncompressed Checksum enable.
	 * BIT 2/3 - MinCCApwr enable 2g/5g.
	 */
	u8 misc_enable;
	int8_t tempslopextension[8];
	int8_t quick_drop_low;
	int8_t quick_drop_high;
} __packed;

struct ar9300_BaseExtension_2 {
	int8_t    tempSlopeLow;
	int8_t    tempSlopeHigh;
	u8   xatten1DBLow[AR9300_MAX_CHAINS];
	u8   xatten1MarginLow[AR9300_MAX_CHAINS];
	u8   xatten1DBHigh[AR9300_MAX_CHAINS];
	u8   xatten1MarginHigh[AR9300_MAX_CHAINS];
} __packed;

struct ar9300_eeprom {
	u8 eepromVersion;
	u8 templateVersion;
	u8 macAddr[6];
	u8 custData[AR9300_CUSTOMER_DATA_SIZE];

	struct ar9300_base_eep_hdr baseEepHeader;

	struct ar9300_modal_eep_header modalHeader2G;
	struct ar9300_BaseExtension_1 base_ext1;
	u8 calFreqPier2G[AR9300_NUM_2G_CAL_PIERS];
	struct ar9300_cal_data_per_freq_op_loop
	 calPierData2G[AR9300_MAX_CHAINS][AR9300_NUM_2G_CAL_PIERS];
	u8 calTarget_freqbin_Cck[AR9300_NUM_2G_CCK_TARGET_POWERS];
	u8 calTarget_freqbin_2G[AR9300_NUM_2G_20_TARGET_POWERS];
	u8 calTarget_freqbin_2GHT20[AR9300_NUM_2G_20_TARGET_POWERS];
	u8 calTarget_freqbin_2GHT40[AR9300_NUM_2G_40_TARGET_POWERS];
	struct cal_tgt_pow_legacy
	 calTargetPowerCck[AR9300_NUM_2G_CCK_TARGET_POWERS];
	struct cal_tgt_pow_legacy
	 calTargetPower2G[AR9300_NUM_2G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower2GHT20[AR9300_NUM_2G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower2GHT40[AR9300_NUM_2G_40_TARGET_POWERS];
	u8 ctlIndex_2G[AR9300_NUM_CTLS_2G];
	u8 ctl_freqbin_2G[AR9300_NUM_CTLS_2G][AR9300_NUM_BAND_EDGES_2G];
	struct cal_ctl_data_2g ctlPowerData_2G[AR9300_NUM_CTLS_2G];
	struct ar9300_modal_eep_header modalHeader5G;
	struct ar9300_BaseExtension_2 base_ext2;
	u8 calFreqPier5G[AR9300_NUM_5G_CAL_PIERS];
	struct ar9300_cal_data_per_freq_op_loop
	 calPierData5G[AR9300_MAX_CHAINS][AR9300_NUM_5G_CAL_PIERS];
	u8 calTarget_freqbin_5G[AR9300_NUM_5G_20_TARGET_POWERS];
	u8 calTarget_freqbin_5GHT20[AR9300_NUM_5G_20_TARGET_POWERS];
	u8 calTarget_freqbin_5GHT40[AR9300_NUM_5G_40_TARGET_POWERS];
	struct cal_tgt_pow_legacy
	 calTargetPower5G[AR9300_NUM_5G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower5GHT20[AR9300_NUM_5G_20_TARGET_POWERS];
	struct cal_tgt_pow_ht
	 calTargetPower5GHT40[AR9300_NUM_5G_40_TARGET_POWERS];
	u8 ctlIndex_5G[AR9300_NUM_CTLS_5G];
	u8 ctl_freqbin_5G[AR9300_NUM_CTLS_5G][AR9300_NUM_BAND_EDGES_5G];
	struct cal_ctl_data_5g ctlPowerData_5G[AR9300_NUM_CTLS_5G];
} __packed;

/* klp-ccp: from drivers/net/wireless/ath/ath9k/eeprom.h */
#define AR5416_NUM_5G_CAL_PIERS         8
#define AR5416_NUM_2G_CAL_PIERS         4
#define AR5416_NUM_5G_20_TARGET_POWERS  8
#define AR5416_NUM_5G_40_TARGET_POWERS  8
#define AR5416_NUM_2G_CCK_TARGET_POWERS 3
#define AR5416_NUM_2G_20_TARGET_POWERS  4
#define AR5416_NUM_2G_40_TARGET_POWERS  4
#define AR5416_NUM_CTLS                 24
#define AR5416_NUM_BAND_EDGES           8
#define AR5416_NUM_PD_GAINS             4

#define AR5416_PD_GAIN_ICEPTS           5

#define AR5416_MAX_CHAINS               3

#define AR5416_EEP4K_NUM_2G_CAL_PIERS         3
#define AR5416_EEP4K_NUM_2G_CCK_TARGET_POWERS 3
#define AR5416_EEP4K_NUM_2G_20_TARGET_POWERS  3
#define AR5416_EEP4K_NUM_2G_40_TARGET_POWERS  3
#define AR5416_EEP4K_NUM_CTLS                 12
#define AR5416_EEP4K_NUM_BAND_EDGES           4
#define AR5416_EEP4K_NUM_PD_GAINS             2
#define AR5416_EEP4K_MAX_CHAINS               1

#define AR9287_NUM_2G_CAL_PIERS         3
#define AR9287_NUM_2G_CCK_TARGET_POWERS 3
#define AR9287_NUM_2G_20_TARGET_POWERS  3
#define AR9287_NUM_2G_40_TARGET_POWERS  3
#define AR9287_NUM_CTLS              	12
#define AR9287_NUM_BAND_EDGES        	4
#define AR9287_PD_GAIN_ICEPTS           1

#define AR9287_MAX_CHAINS               2

#define AR9287_DATA_SZ                  32

enum ar5416_rates {
	rate6mb, rate9mb, rate12mb, rate18mb,
	rate24mb, rate36mb, rate48mb, rate54mb,
	rate1l, rate2l, rate2s, rate5_5l,
	rate5_5s, rate11l, rate11s, rateXr,
	rateHt20_0, rateHt20_1, rateHt20_2, rateHt20_3,
	rateHt20_4, rateHt20_5, rateHt20_6, rateHt20_7,
	rateHt40_0, rateHt40_1, rateHt40_2, rateHt40_3,
	rateHt40_4, rateHt40_5, rateHt40_6, rateHt40_7,
	rateDupCck, rateDupOfdm, rateExtCck, rateExtOfdm,
	Ar5416RateSize
};

struct base_eep_header {
	__le16 length;
	__le16 checksum;
	__le16 version;
	u8 opCapFlags;
	u8 eepMisc;
	__le16 regDmn[2];
	u8 macAddr[6];
	u8 rxMask;
	u8 txMask;
	__le16 rfSilent;
	__le16 blueToothOptions;
	__le16 deviceCap;
	__le32 binBuildNumber;
	u8 deviceType;
	u8 pwdclkind;
	u8 fastClk5g;
	u8 divChain;
	u8 rxGainType;
	u8 dacHiPwrMode_5G;
	u8 openLoopPwrCntl;
	u8 dacLpMode;
	u8 txGainType;
	u8 rcChainMask;
	u8 desiredScaleCCK;
	u8 pwr_table_offset;
	u8 frac_n_5g;
	u8 futureBase_3[21];
} __packed;

struct base_eep_header_4k {
	__le16 length;
	__le16 checksum;
	__le16 version;
	u8 opCapFlags;
	u8 eepMisc;
	__le16 regDmn[2];
	u8 macAddr[6];
	u8 rxMask;
	u8 txMask;
	__le16 rfSilent;
	__le16 blueToothOptions;
	__le16 deviceCap;
	__le32 binBuildNumber;
	u8 deviceType;
	u8 txGainType;
} __packed;

struct spur_chan {
	__le16 spurChan;
	u8 spurRangeLow;
	u8 spurRangeHigh;
} __packed;

struct modal_eep_header {
	__le32 antCtrlChain[AR5416_MAX_CHAINS];
	__le32 antCtrlCommon;
	u8 antennaGainCh[AR5416_MAX_CHAINS];
	u8 switchSettling;
	u8 txRxAttenCh[AR5416_MAX_CHAINS];
	u8 rxTxMarginCh[AR5416_MAX_CHAINS];
	u8 adcDesiredSize;
	u8 pgaDesiredSize;
	u8 xlnaGainCh[AR5416_MAX_CHAINS];
	u8 txEndToXpaOff;
	u8 txEndToRxOn;
	u8 txFrameToXpaOn;
	u8 thresh62;
	u8 noiseFloorThreshCh[AR5416_MAX_CHAINS];
	u8 xpdGain;
	u8 xpd;
	u8 iqCalICh[AR5416_MAX_CHAINS];
	u8 iqCalQCh[AR5416_MAX_CHAINS];
	u8 pdGainOverlap;
	u8 ob;
	u8 db;
	u8 xpaBiasLvl;
	u8 pwrDecreaseFor2Chain;
	u8 pwrDecreaseFor3Chain;
	u8 txFrameToDataStart;
	u8 txFrameToPaOn;
	u8 ht40PowerIncForPdadc;
	u8 bswAtten[AR5416_MAX_CHAINS];
	u8 bswMargin[AR5416_MAX_CHAINS];
	u8 swSettleHt40;
	u8 xatten2Db[AR5416_MAX_CHAINS];
	u8 xatten2Margin[AR5416_MAX_CHAINS];
	u8 ob_ch1;
	u8 db_ch1;
	u8 lna_ctl;
	u8 miscBits;
	__le16 xpaBiasLvlFreq[3];
	u8 futureModal[6];

	struct spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __packed;

struct modal_eep_4k_header {
	__le32 antCtrlChain[AR5416_EEP4K_MAX_CHAINS];
	__le32 antCtrlCommon;
	u8 antennaGainCh[AR5416_EEP4K_MAX_CHAINS];
	u8 switchSettling;
	u8 txRxAttenCh[AR5416_EEP4K_MAX_CHAINS];
	u8 rxTxMarginCh[AR5416_EEP4K_MAX_CHAINS];
	u8 adcDesiredSize;
	u8 pgaDesiredSize;
	u8 xlnaGainCh[AR5416_EEP4K_MAX_CHAINS];
	u8 txEndToXpaOff;
	u8 txEndToRxOn;
	u8 txFrameToXpaOn;
	u8 thresh62;
	u8 noiseFloorThreshCh[AR5416_EEP4K_MAX_CHAINS];
	u8 xpdGain;
	u8 xpd;
	u8 iqCalICh[AR5416_EEP4K_MAX_CHAINS];
	u8 iqCalQCh[AR5416_EEP4K_MAX_CHAINS];
	u8 pdGainOverlap;
#ifdef __BIG_ENDIAN_BITFIELD
#error "klp-ccp: non-taken branch"
#else
	u8 ob_0:4, ob_1:4;
	u8 db1_0:4, db1_1:4;
#endif
	u8 xpaBiasLvl;
	u8 txFrameToDataStart;
	u8 txFrameToPaOn;
	u8 ht40PowerIncForPdadc;
	u8 bswAtten[AR5416_EEP4K_MAX_CHAINS];
	u8 bswMargin[AR5416_EEP4K_MAX_CHAINS];
	u8 swSettleHt40;
	u8 xatten2Db[AR5416_EEP4K_MAX_CHAINS];
	u8 xatten2Margin[AR5416_EEP4K_MAX_CHAINS];
#ifdef __BIG_ENDIAN_BITFIELD
#error "klp-ccp: non-taken branch"
#else
	u8 db2_0:4, db2_1:4;
#endif
	u8 version;
#ifdef __BIG_ENDIAN_BITFIELD
#error "klp-ccp: non-taken branch"
#else
	u8 ob_2:4, ob_3:4;
	u8 ob_4:4, antdiv_ctl1:4;
	u8 db1_2:4, db1_3:4;
	u8 db1_4:4, antdiv_ctl2:4;
	u8 db2_2:4, db2_3:4;
	u8 db2_4:4, reserved:4;
#endif
	u8 tx_diversity;
	u8 flc_pwr_thresh;
	u8 bb_scale_smrt_antenna;
	u8 futureModal[1];
	struct spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __packed;

struct base_eep_ar9287_header {
	__le16 length;
	__le16 checksum;
	__le16 version;
	u8 opCapFlags;
	u8 eepMisc;
	__le16 regDmn[2];
	u8 macAddr[6];
	u8 rxMask;
	u8 txMask;
	__le16 rfSilent;
	__le16 blueToothOptions;
	__le16 deviceCap;
	__le32 binBuildNumber;
	u8 deviceType;
	u8 openLoopPwrCntl;
	int8_t pwrTableOffset;
	int8_t tempSensSlope;
	int8_t tempSensSlopePalOn;
	u8 futureBase[29];
} __packed;

struct modal_eep_ar9287_header {
	__le32 antCtrlChain[AR9287_MAX_CHAINS];
	__le32 antCtrlCommon;
	int8_t antennaGainCh[AR9287_MAX_CHAINS];
	u8 switchSettling;
	u8 txRxAttenCh[AR9287_MAX_CHAINS];
	u8 rxTxMarginCh[AR9287_MAX_CHAINS];
	int8_t adcDesiredSize;
	u8 txEndToXpaOff;
	u8 txEndToRxOn;
	u8 txFrameToXpaOn;
	u8 thresh62;
	int8_t noiseFloorThreshCh[AR9287_MAX_CHAINS];
	u8 xpdGain;
	u8 xpd;
	int8_t iqCalICh[AR9287_MAX_CHAINS];
	int8_t iqCalQCh[AR9287_MAX_CHAINS];
	u8 pdGainOverlap;
	u8 xpaBiasLvl;
	u8 txFrameToDataStart;
	u8 txFrameToPaOn;
	u8 ht40PowerIncForPdadc;
	u8 bswAtten[AR9287_MAX_CHAINS];
	u8 bswMargin[AR9287_MAX_CHAINS];
	u8 swSettleHt40;
	u8 version;
	u8 db1;
	u8 db2;
	u8 ob_cck;
	u8 ob_psk;
	u8 ob_qam;
	u8 ob_pal_off;
	u8 futureModal[30];
	struct spur_chan spurChans[AR_EEPROM_MODAL_SPURS];
} __packed;

struct cal_data_per_freq {
	u8 pwrPdg[AR5416_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
	u8 vpdPdg[AR5416_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
} __packed;

struct cal_data_per_freq_4k {
	u8 pwrPdg[AR5416_EEP4K_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
	u8 vpdPdg[AR5416_EEP4K_NUM_PD_GAINS][AR5416_PD_GAIN_ICEPTS];
} __packed;

struct cal_target_power_leg {
	u8 bChannel;
	u8 tPow2x[4];
} __packed;

struct cal_target_power_ht {
	u8 bChannel;
	u8 tPow2x[8];
} __packed;

struct cal_ctl_edges {
	u8 bChannel;
	u8 ctl;
} __packed;

struct cal_data_op_loop_ar9287 {
	u8 pwrPdg[2][5];
	u8 vpdPdg[2][5];
	u8 pcdac[2][5];
	u8 empty[2][5];
} __packed;

struct cal_data_per_freq_ar9287 {
	u8 pwrPdg[AR5416_NUM_PD_GAINS][AR9287_PD_GAIN_ICEPTS];
	u8 vpdPdg[AR5416_NUM_PD_GAINS][AR9287_PD_GAIN_ICEPTS];
} __packed;

union cal_data_per_freq_ar9287_u {
	struct cal_data_op_loop_ar9287 calDataOpen;
	struct cal_data_per_freq_ar9287 calDataClose;
} __packed;

struct cal_ctl_data_ar9287 {
	struct cal_ctl_edges
	ctlEdges[AR9287_MAX_CHAINS][AR9287_NUM_BAND_EDGES];
} __packed;

struct cal_ctl_data {
	struct cal_ctl_edges
	ctlEdges[AR5416_MAX_CHAINS][AR5416_NUM_BAND_EDGES];
} __packed;

struct cal_ctl_data_4k {
	struct cal_ctl_edges
	ctlEdges[AR5416_EEP4K_MAX_CHAINS][AR5416_EEP4K_NUM_BAND_EDGES];
} __packed;

struct ar5416_eeprom_def {
	struct base_eep_header baseEepHeader;
	u8 custData[64];
	struct modal_eep_header modalHeader[2];
	u8 calFreqPier5G[AR5416_NUM_5G_CAL_PIERS];
	u8 calFreqPier2G[AR5416_NUM_2G_CAL_PIERS];
	struct cal_data_per_freq
	 calPierData5G[AR5416_MAX_CHAINS][AR5416_NUM_5G_CAL_PIERS];
	struct cal_data_per_freq
	 calPierData2G[AR5416_MAX_CHAINS][AR5416_NUM_2G_CAL_PIERS];
	struct cal_target_power_leg
	 calTargetPower5G[AR5416_NUM_5G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower5GHT20[AR5416_NUM_5G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower5GHT40[AR5416_NUM_5G_40_TARGET_POWERS];
	struct cal_target_power_leg
	 calTargetPowerCck[AR5416_NUM_2G_CCK_TARGET_POWERS];
	struct cal_target_power_leg
	 calTargetPower2G[AR5416_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower2GHT20[AR5416_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	 calTargetPower2GHT40[AR5416_NUM_2G_40_TARGET_POWERS];
	u8 ctlIndex[AR5416_NUM_CTLS];
	struct cal_ctl_data ctlData[AR5416_NUM_CTLS];
	u8 padding;
} __packed;

struct ar5416_eeprom_4k {
	struct base_eep_header_4k baseEepHeader;
	u8 custData[20];
	struct modal_eep_4k_header modalHeader;
	u8 calFreqPier2G[AR5416_EEP4K_NUM_2G_CAL_PIERS];
	struct cal_data_per_freq_4k
	calPierData2G[AR5416_EEP4K_MAX_CHAINS][AR5416_EEP4K_NUM_2G_CAL_PIERS];
	struct cal_target_power_leg
	calTargetPowerCck[AR5416_EEP4K_NUM_2G_CCK_TARGET_POWERS];
	struct cal_target_power_leg
	calTargetPower2G[AR5416_EEP4K_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT20[AR5416_EEP4K_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT40[AR5416_EEP4K_NUM_2G_40_TARGET_POWERS];
	u8 ctlIndex[AR5416_EEP4K_NUM_CTLS];
	struct cal_ctl_data_4k ctlData[AR5416_EEP4K_NUM_CTLS];
	u8 padding;
} __packed;

struct ar9287_eeprom {
	struct base_eep_ar9287_header baseEepHeader;
	u8 custData[AR9287_DATA_SZ];
	struct modal_eep_ar9287_header modalHeader;
	u8 calFreqPier2G[AR9287_NUM_2G_CAL_PIERS];
	union cal_data_per_freq_ar9287_u
	calPierData2G[AR9287_MAX_CHAINS][AR9287_NUM_2G_CAL_PIERS];
	struct cal_target_power_leg
	calTargetPowerCck[AR9287_NUM_2G_CCK_TARGET_POWERS];
	struct cal_target_power_leg
	calTargetPower2G[AR9287_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT20[AR9287_NUM_2G_20_TARGET_POWERS];
	struct cal_target_power_ht
	calTargetPower2GHT40[AR9287_NUM_2G_40_TARGET_POWERS];
	u8 ctlIndex[AR9287_NUM_CTLS];
	struct cal_ctl_data_ar9287 ctlData[AR9287_NUM_CTLS];
	u8 padding;
} __packed;

/* klp-ccp: from drivers/net/wireless/ath/ath9k/calib.h */
#define NUM_NF_READINGS       6
#define ATH9K_NF_CAL_HIST_MAX 5

struct ar5416IniArray {
	u32 *ia_array;
	u32 ia_rows;
	u32 ia_columns;
};

enum ath9k_cal_state {
	CAL_INACTIVE,
	CAL_WAITING,
	CAL_RUNNING,
	CAL_DONE
};

struct ath9k_cal_list {
	const struct ath9k_percal_data *calData;
	enum ath9k_cal_state calState;
	struct ath9k_cal_list *calNext;
};

struct ath9k_nfcal_hist {
	int16_t nfCalBuffer[ATH9K_NF_CAL_HIST_MAX];
	u8 currIndex;
	int16_t privNF;
	u8 invalidNFcount;
};

struct ath9k_pacal_info{
	int32_t prev_offset;	/* Previous value of PA offset value */
	int8_t max_skipcount;	/* Max No. of times PACAL can be skipped */
	int8_t skipcount;	/* No. of times the PACAL to be skipped */
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/reg.h */
enum ath_usb_dev {
	AR9280_USB = 1, /* AR7010 + AR9280, UB94 */
	AR9287_USB = 2, /* AR7010 + AR9287, UB95 */
	STORAGE_DEVICE = 3,
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/btcoex.h */
#define AR9300_NUM_BT_WEIGHTS   4
#define AR9300_NUM_WLAN_WEIGHTS 4

#define ATH_AIC_MAX_BT_CHANNEL  79

enum ath_stomp_type {
	ATH_BTCOEX_STOMP_ALL,
	ATH_BTCOEX_STOMP_LOW,
	ATH_BTCOEX_STOMP_NONE,
	ATH_BTCOEX_STOMP_LOW_FTP,
	ATH_BTCOEX_STOMP_AUDIO,
	ATH_BTCOEX_STOMP_MAX
};

enum ath_btcoex_scheme {
	ATH_BTCOEX_CFG_NONE,
	ATH_BTCOEX_CFG_2WIRE,
	ATH_BTCOEX_CFG_3WIRE,
	ATH_BTCOEX_CFG_MCI,
};

struct ath9k_hw_mci {
	u32 raw_intr;
	u32 rx_msg_intr;
	u32 cont_status;
	u32 gpm_addr;
	u32 gpm_len;
	u32 gpm_idx;
	u32 sched_addr;
	u32 wlan_channels[4];
	u32 wlan_cal_seq;
	u32 wlan_cal_done;
	u32 config;
	u8 *gpm_buf;
	bool ready;
	bool update_2g5g;
	bool is_2g;
	bool query_bt;
	bool unhalt_bt_gpm; /* need send UNHALT */
	bool halted_bt_gpm; /* HALT sent */
	bool need_flush_btinfo;
	bool bt_version_known;
	bool wlan_channels_update;
	u8 wlan_ver_major;
	u8 wlan_ver_minor;
	u8 bt_ver_major;
	u8 bt_ver_minor;
	u8 bt_state;
	u8 stomp_ftp;
	bool concur_tx;
	u32 last_recovery;
};

struct ath9k_hw_aic {
	bool aic_enabled;
	u8 aic_cal_state;
	u8 aic_caled_chan;
	u32 aic_sram[ATH_AIC_MAX_BT_CHANNEL];
	u32 aic_cal_start_time;
};

struct ath_btcoex_hw {
	enum ath_btcoex_scheme scheme;
	struct ath9k_hw_mci mci;
	struct ath9k_hw_aic aic;
	bool enabled;
	u8 wlanactive_gpio;
	u8 btactive_gpio;
	u8 btpriority_gpio;
	u32 bt_coex_mode; 	/* Register setting for AR_BT_COEX_MODE */
	u32 bt_coex_weights; 	/* Register setting for AR_BT_COEX_WEIGHT */
	u32 bt_coex_mode2; 	/* Register setting for AR_BT_COEX_MODE2 */
	u32 bt_coex_mode3;	/* Register setting for AR_BT_COEX_MODE3 */
	u32 bt_weight[AR9300_NUM_BT_WEIGHTS];
	u32 wlan_weight[AR9300_NUM_WLAN_WEIGHTS];
	u8 tx_prio[ATH_BTCOEX_STOMP_MAX];
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/dynack.h */
#define ATH_DYN_BUF	64

struct ath_dyn_rxbuf {
	u16 h_rb, t_rb;
	u32 tstamp[ATH_DYN_BUF];
};

struct ts_info {
	u32 tstamp;
	u32 dur;
};

struct haddr_pair {
	u8 h_dest[ETH_ALEN];
	u8 h_src[ETH_ALEN];
};

struct ath_dyn_txbuf {
	u16 h_rb, t_rb;
	struct haddr_pair addr[ATH_DYN_BUF];
	struct ts_info ts[ATH_DYN_BUF];
};

struct ath_dynack {
	bool enabled;
	int ackto;
	unsigned long lto;

	struct list_head nodes;

	/* protect timestamp queue access */
	spinlock_t qlock;
	struct ath_dyn_rxbuf ack_rbf;
	struct ath_dyn_txbuf st_rbf;
};

/* klp-ccp: from drivers/net/wireless/ath/regd.h */
#include <linux/nl80211.h>
#include <net/cfg80211.h>

/* klp-ccp: from drivers/net/wireless/ath/ath9k/hw.h */
#define ATH9K_NUM_CHANNELS	38

#define PAPRD_GAIN_TABLE_ENTRIES	32
#define PAPRD_TABLE_SZ			24

enum ath_ini_subsys {
	ATH_INI_PRE = 0,
	ATH_INI_CORE,
	ATH_INI_POST,
	ATH_INI_NUM_SPLIT,
};

struct ath9k_hw_wow {
	u32 wow_event_mask;
	u32 wow_event_mask2;
	u8 max_patterns;
};

struct ath9k_hw_capabilities {
	u32 hw_caps; /* ATH9K_HW_CAP_* from ath9k_hw_caps */
	u16 rts_aggr_limit;
	u8 tx_chainmask;
	u8 rx_chainmask;
	u8 chip_chainmask;
	u8 max_txchains;
	u8 max_rxchains;
	u8 num_gpio_pins;
	u32 gpio_mask;
	u32 gpio_requested;
	u8 rx_hp_qdepth;
	u8 rx_lp_qdepth;
	u8 rx_status_len;
	u8 tx_desc_len;
	u8 txs_len;
};

struct ath9k_ops_config {
	int dma_beacon_response_time;
	int sw_beacon_response_time;
	bool cwm_ignore_extcca;
	u32 pcie_waen;
	u8 analog_shiftreg;
	u32 ofdm_trig_low;
	u32 ofdm_trig_high;
	u32 cck_trig_high;
	u32 cck_trig_low;
	bool enable_paprd;
	int serialize_regmode;
	bool rx_intr_mitigation;
	bool tx_intr_mitigation;
	u8 max_txtrig_level;
	u16 ani_poll_interval; /* ANI poll interval in ms */
	u16 hw_hang_checks;
	u16 rimt_first;
	u16 rimt_last;

	/* Platform specific config */
	u32 aspm_l1_fix;
	u32 xlna_gpio;
	u32 ant_ctrl_comm2g_switch_enable;
	bool xatten_margin_cfg;
	bool alt_mingainidx;
	u8 pll_pwrsave;
	bool tx_gain_buffalo;
	bool led_active_high;
};

enum ath9k_int {
	ATH9K_INT_RX = 0x00000001,
	ATH9K_INT_RXDESC = 0x00000002,
	ATH9K_INT_RXHP = 0x00000001,
	ATH9K_INT_RXLP = 0x00000002,
	ATH9K_INT_RXNOFRM = 0x00000008,
	ATH9K_INT_RXEOL = 0x00000010,
	ATH9K_INT_RXORN = 0x00000020,
	ATH9K_INT_TX = 0x00000040,
	ATH9K_INT_TXDESC = 0x00000080,
	ATH9K_INT_TIM_TIMER = 0x00000100,
	ATH9K_INT_MCI = 0x00000200,
	ATH9K_INT_BB_WATCHDOG = 0x00000400,
	ATH9K_INT_TXURN = 0x00000800,
	ATH9K_INT_MIB = 0x00001000,
	ATH9K_INT_RXPHY = 0x00004000,
	ATH9K_INT_RXKCM = 0x00008000,
	ATH9K_INT_SWBA = 0x00010000,
	ATH9K_INT_BMISS = 0x00040000,
	ATH9K_INT_BNR = 0x00100000,
	ATH9K_INT_TIM = 0x00200000,
	ATH9K_INT_DTIM = 0x00400000,
	ATH9K_INT_DTIMSYNC = 0x00800000,
	ATH9K_INT_GPIO = 0x01000000,
	ATH9K_INT_CABEND = 0x02000000,
	ATH9K_INT_TSFOOR = 0x04000000,
	ATH9K_INT_GENTIMER = 0x08000000,
	ATH9K_INT_CST = 0x10000000,
	ATH9K_INT_GTT = 0x20000000,
	ATH9K_INT_FATAL = 0x40000000,
	ATH9K_INT_GLOBAL = 0x80000000,
	ATH9K_INT_BMISC = ATH9K_INT_TIM |
		ATH9K_INT_DTIM |
		ATH9K_INT_DTIMSYNC |
		ATH9K_INT_TSFOOR |
		ATH9K_INT_CABEND,
	ATH9K_INT_COMMON = ATH9K_INT_RXNOFRM |
		ATH9K_INT_RXDESC |
		ATH9K_INT_RXEOL |
		ATH9K_INT_RXORN |
		ATH9K_INT_TXURN |
		ATH9K_INT_TXDESC |
		ATH9K_INT_MIB |
		ATH9K_INT_RXPHY |
		ATH9K_INT_RXKCM |
		ATH9K_INT_SWBA |
		ATH9K_INT_BMISS |
		ATH9K_INT_GPIO,
	ATH9K_INT_NOCARD = 0xffffffff
};

#define MAX_RTT_TABLE_ENTRY     6
#define MAX_IQCAL_MEASUREMENT	8
#define MAX_CL_TAB_ENTRY	16

struct ath9k_hw_cal_data {
	u16 channel;
	u16 channelFlags;
	unsigned long cal_flags;
	int32_t CalValid;
	int8_t iCoff;
	int8_t qCoff;
	u8 caldac[2];
	u16 small_signal_gain[AR9300_MAX_CHAINS];
	u32 pa_table[AR9300_MAX_CHAINS][PAPRD_TABLE_SZ];
	u32 num_measures[AR9300_MAX_CHAINS];
	int tx_corr_coeff[MAX_IQCAL_MEASUREMENT][AR9300_MAX_CHAINS];
	u32 tx_clcal[AR9300_MAX_CHAINS][MAX_CL_TAB_ENTRY];
	u32 rtt_table[AR9300_MAX_CHAINS][MAX_RTT_TABLE_ENTRY];
	struct ath9k_nfcal_hist nfCalHist[NUM_NF_READINGS];
};

struct ath9k_channel {
	struct ieee80211_channel *chan;
	u16 channel;
	u16 channelFlags;
	s16 noisefloor;
};

enum ath9k_power_mode {
	ATH9K_PM_AWAKE = 0,
	ATH9K_PM_FULL_SLEEP,
	ATH9K_PM_NETWORK_SLEEP,
	ATH9K_PM_UNDEFINED
};

struct ath9k_hw_version {
	u32 magic;
	u16 devid;
	u16 subvendorid;
	u32 macVersion;
	u16 macRev;
	u16 phyRev;
	u16 analog5GhzRev;
	u16 analog2GhzRev;
	enum ath_usb_dev usbdev;
};

#define ATH_MAX_GEN_TIMER	16

struct ath_gen_timer_table {
	struct ath_gen_timer *timers[ATH_MAX_GEN_TIMER];
	u16 timer_mask;
	bool tsf2_enabled;
};

struct ath_hw_antcomb_conf;

struct ath_hw_radar_conf {
	unsigned int pulse_inband;
	unsigned int pulse_inband_step;
	unsigned int pulse_height;
	unsigned int pulse_rssi;
	unsigned int pulse_maxlen;

	unsigned int radar_rssi;
	unsigned int radar_inband;
	int fir_power;

	bool ext_channel;
};

struct ath_hw_private_ops {
	void (*init_hang_checks)(struct ath_hw *ah);
	bool (*detect_mac_hang)(struct ath_hw *ah);
	bool (*detect_bb_hang)(struct ath_hw *ah);

	/* Calibration ops */
	void (*init_cal_settings)(struct ath_hw *ah);
	bool (*init_cal)(struct ath_hw *ah, struct ath9k_channel *chan);

	void (*init_mode_gain_regs)(struct ath_hw *ah);
	void (*setup_calibration)(struct ath_hw *ah,
				  struct ath9k_cal_list *currCal);

	/* PHY ops */
	int (*rf_set_freq)(struct ath_hw *ah,
			   struct ath9k_channel *chan);
	void (*spur_mitigate_freq)(struct ath_hw *ah,
				   struct ath9k_channel *chan);
	bool (*set_rf_regs)(struct ath_hw *ah,
			    struct ath9k_channel *chan,
			    u16 modesIndex);
	void (*set_channel_regs)(struct ath_hw *ah, struct ath9k_channel *chan);
	void (*init_bb)(struct ath_hw *ah,
			struct ath9k_channel *chan);
	int (*process_ini)(struct ath_hw *ah, struct ath9k_channel *chan);
	void (*olc_init)(struct ath_hw *ah);
	void (*set_rfmode)(struct ath_hw *ah, struct ath9k_channel *chan);
	void (*mark_phy_inactive)(struct ath_hw *ah);
	void (*set_delta_slope)(struct ath_hw *ah, struct ath9k_channel *chan);
	bool (*rfbus_req)(struct ath_hw *ah);
	void (*rfbus_done)(struct ath_hw *ah);
	void (*restore_chainmask)(struct ath_hw *ah);
	u32 (*compute_pll_control)(struct ath_hw *ah,
				   struct ath9k_channel *chan);
	bool (*ani_control)(struct ath_hw *ah, enum ath9k_ani_cmd cmd,
			    int param);
	void (*do_getnf)(struct ath_hw *ah, int16_t nfarray[NUM_NF_READINGS]);
	void (*set_radar_params)(struct ath_hw *ah,
				 struct ath_hw_radar_conf *conf);
	int (*fast_chan_change)(struct ath_hw *ah, struct ath9k_channel *chan,
				u8 *ini_reloaded);

	/* ANI */
	void (*ani_cache_ini_regs)(struct ath_hw *ah);

#ifdef CONFIG_ATH9K_BTCOEX_SUPPORT
	bool (*is_aic_enabled)(struct ath_hw *ah);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_ATH9K_BTCOEX_SUPPORT */
};

struct ath_spec_scan {
	bool enabled;
	bool short_repeat;
	bool endless;
	u8 count;
	u8 period;
	u8 fft_period;
};

struct ath_hw_ops {
	void (*config_pci_powersave)(struct ath_hw *ah,
				     bool power_off);
	void (*rx_enable)(struct ath_hw *ah);
	void (*set_desc_link)(void *ds, u32 link);
	int (*calibrate)(struct ath_hw *ah, struct ath9k_channel *chan,
			 u8 rxchainmask, bool longcal);
	bool (*get_isr)(struct ath_hw *ah, enum ath9k_int *masked,
			u32 *sync_cause_p);
	void (*set_txdesc)(struct ath_hw *ah, void *ds,
			   struct ath_tx_info *i);
	int (*proc_txdesc)(struct ath_hw *ah, void *ds,
			   struct ath_tx_status *ts);
	int (*get_duration)(struct ath_hw *ah, const void *ds, int index);
	void (*antdiv_comb_conf_get)(struct ath_hw *ah,
			struct ath_hw_antcomb_conf *antconf);
	void (*antdiv_comb_conf_set)(struct ath_hw *ah,
			struct ath_hw_antcomb_conf *antconf);
	void (*spectral_scan_config)(struct ath_hw *ah,
				     struct ath_spec_scan *param);
	void (*spectral_scan_trigger)(struct ath_hw *ah);
	void (*spectral_scan_wait)(struct ath_hw *ah);

	void (*tx99_start)(struct ath_hw *ah, u32 qnum);
	void (*tx99_stop)(struct ath_hw *ah);
	void (*tx99_set_txpower)(struct ath_hw *ah, u8 power);

#ifdef CONFIG_ATH9K_BTCOEX_SUPPORT
	void (*set_bt_ant_diversity)(struct ath_hw *hw, bool enable);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct ath_nf_limits {
	s16 max;
	s16 min;
	s16 nominal;
	s16 cal[AR5416_MAX_CHAINS];
	s16 pwr[AR5416_MAX_CHAINS];
};

#define AH_UNPLUGGED    0x2 /* The card has been physically removed. */

struct ath_hw {
	struct ath_ops reg_ops;

	struct device *dev;
	struct ieee80211_hw *hw;
	struct ath_common common;
	struct ath9k_hw_version hw_version;
	struct ath9k_ops_config config;
	struct ath9k_hw_capabilities caps;
	struct ath9k_channel channels[ATH9K_NUM_CHANNELS];
	struct ath9k_channel *curchan;

	union {
		struct ar5416_eeprom_def def;
		struct ar5416_eeprom_4k map4k;
		struct ar9287_eeprom map9287;
		struct ar9300_eeprom ar9300_eep;
	} eeprom;
	const struct eeprom_ops *eep_ops;

	bool sw_mgmt_crypto_tx;
	bool sw_mgmt_crypto_rx;
	bool is_pciexpress;
	bool aspm_enabled;
	bool is_monitoring;
	bool need_an_top2_fixup;
	u16 tx_trig_level;

	u32 nf_regs[6];
	struct ath_nf_limits nf_2g;
	struct ath_nf_limits nf_5g;
	u16 rfsilent;
	u32 rfkill_gpio;
	u32 rfkill_polarity;
	u32 ah_flags;
	s16 nf_override;

	bool reset_power_on;
	bool htc_reset_init;

	enum nl80211_iftype opmode;
	enum ath9k_power_mode power_mode;

	s8 noise;
	struct ath9k_hw_cal_data *caldata;
	struct ath9k_pacal_info pacal_info;
	struct ar5416Stats stats;
	struct ath9k_tx_queue_info txq[ATH9K_NUM_TX_QUEUES];
	DECLARE_BITMAP(pending_del_keymap, ATH_KEYMAX);

	enum ath9k_int imask;
	u32 imrs2_reg;
	u32 txok_interrupt_mask;
	u32 txerr_interrupt_mask;
	u32 txdesc_interrupt_mask;
	u32 txeol_interrupt_mask;
	u32 txurn_interrupt_mask;
	atomic_t intr_ref_cnt;
	bool chip_fullsleep;
	u32 modes_index;

	/* Calibration */
	u32 supp_cals;
	struct ath9k_cal_list iq_caldata;
	struct ath9k_cal_list adcgain_caldata;
	struct ath9k_cal_list adcdc_caldata;
	struct ath9k_cal_list *cal_list;
	struct ath9k_cal_list *cal_list_last;
	struct ath9k_cal_list *cal_list_curr;
	union {
		u32 unsign[AR5416_MAX_CHAINS];
		int32_t sign[AR5416_MAX_CHAINS];
	} meas0;
	union {
		u32 unsign[AR5416_MAX_CHAINS];
		int32_t sign[AR5416_MAX_CHAINS];
	} meas1;
	union {
		u32 unsign[AR5416_MAX_CHAINS];
		int32_t sign[AR5416_MAX_CHAINS];
	} meas2;
	union {
		u32 unsign[AR5416_MAX_CHAINS];
		int32_t sign[AR5416_MAX_CHAINS];
	} meas3;
	u16 cal_samples;
	u8 enabled_cals;

	u32 sta_id1_defaults;
	u32 misc_mode;

	/* Private to hardware code */
	struct ath_hw_private_ops private_ops;
	/* Accessed by the lower level driver */
	struct ath_hw_ops ops;

	/* Used to program the radio on non single-chip devices */
	u32 *analogBank6Data;

	int coverage_class;
	u32 slottime;
	u32 globaltxtimeout;

	/* ANI */
	u32 aniperiod;
	enum ath9k_ani_cmd ani_function;
	u32 ani_skip_count;
	struct ar5416AniState ani;

#ifdef CONFIG_ATH9K_BTCOEX_SUPPORT
	struct ath_btcoex_hw btcoex_hw;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u32 intr_txqs;
	u8 txchainmask;
	u8 rxchainmask;

	struct ath_hw_radar_conf radar_conf;

	u32 originalGain[22];
	int initPDADC;
	int PDADCdelta;
	int led_pin;
	u32 gpio_mask;
	u32 gpio_val;

	struct ar5416IniArray ini_dfs;
	struct ar5416IniArray iniModes;
	struct ar5416IniArray iniCommon;
	struct ar5416IniArray iniBB_RfGain;
	struct ar5416IniArray iniBank6;
	struct ar5416IniArray iniAddac;
	struct ar5416IniArray iniPcieSerdes;
	struct ar5416IniArray iniPcieSerdesLowPower;
	struct ar5416IniArray iniModesFastClock;
	struct ar5416IniArray iniAdditional;
	struct ar5416IniArray iniModesRxGain;
	struct ar5416IniArray ini_modes_rx_gain_bounds;
	struct ar5416IniArray iniModesTxGain;
	struct ar5416IniArray iniCckfirNormal;
	struct ar5416IniArray iniCckfirJapan2484;
	struct ar5416IniArray iniModes_9271_ANI_reg;
	struct ar5416IniArray ini_radio_post_sys2ant;
	struct ar5416IniArray ini_modes_rxgain_xlna;
	struct ar5416IniArray ini_modes_rxgain_bb_core;
	struct ar5416IniArray ini_modes_rxgain_bb_postamble;

	struct ar5416IniArray iniMac[ATH_INI_NUM_SPLIT];
	struct ar5416IniArray iniBB[ATH_INI_NUM_SPLIT];
	struct ar5416IniArray iniRadio[ATH_INI_NUM_SPLIT];
	struct ar5416IniArray iniSOC[ATH_INI_NUM_SPLIT];

	u32 intr_gen_timer_trigger;
	u32 intr_gen_timer_thresh;
	struct ath_gen_timer_table hw_gen_timers;

	struct ar9003_txs *ts_ring;
	u32 ts_paddr_start;
	u32 ts_paddr_end;
	u16 ts_tail;
	u16 ts_size;

	u32 bb_watchdog_last_status;
	u32 bb_watchdog_timeout_ms; /* in ms, 0 to disable */
	u8 bb_hang_rx_ofdm; /* true if bb hang due to rx_ofdm */

	unsigned int paprd_target_power;
	unsigned int paprd_training_power;
	unsigned int paprd_ratemask;
	unsigned int paprd_ratemask_ht40;
	bool paprd_table_write_done;
	u32 paprd_gain_table_entries[PAPRD_GAIN_TABLE_ENTRIES];
	u8 paprd_gain_table_index[PAPRD_GAIN_TABLE_ENTRIES];
	/*
	 * Store the permanent value of Reg 0x4004in WARegVal
	 * so we dont have to R/M/W. We should not be reading
	 * this register when in sleep states.
	 */
	u32 WARegVal;

	/* Enterprise mode cap */
	u32 ent_mode;

#ifdef CONFIG_ATH9K_WOW
	struct ath9k_hw_wow wow;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	bool is_clk_25mhz;
	int (*get_mac_revision)(void);
	int (*external_reset)(void);
	bool disable_2ghz;
	bool disable_5ghz;

	const struct firmware *eeprom_blob;

	struct ath_dynack dynack;

	bool tpc_enabled;
	u8 tx_power[Ar5416RateSize];
	u8 tx_power_stbc[Ar5416RateSize];
	bool msi_enabled;
	u32 msi_mask;
	u32 msi_reg;
};

static inline struct ath_common *ath9k_hw_common(struct ath_hw *ah)
{
	return &ah->common;
}

/* klp-ccp: from drivers/net/wireless/ath/ath9k/common-spectral.h */
enum spectral_mode {
	SPECTRAL_DISABLED = 0,
	SPECTRAL_BACKGROUND,
	SPECTRAL_MANUAL,
	SPECTRAL_CHANSCAN,
};

struct ath_spec_scan_priv {
	struct ath_hw *ah;
	/* relay(fs) channel for spectral scan */
	struct rchan *rfs_chan_spec_scan;
	enum spectral_mode spectral_mode;
	struct ath_spec_scan spec_config;
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/common.h */
struct ath_beacon_config {
	struct ieee80211_vif *main_vif;
	int beacon_interval;
	u16 dtim_period;
	u16 bmiss_timeout;
	u8 dtim_count;
	u8 enable_beacon;
	bool ibss_creator;
	u32 nexttbtt;
	u32 intval;
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc_hst.h */
struct htc_target;

enum htc_endpoint_id {
	ENDPOINT_UNUSED = -1,
	ENDPOINT0 = 0,
	ENDPOINT1 = 1,
	ENDPOINT2 = 2,
	ENDPOINT3 = 3,
	ENDPOINT4 = 4,
	ENDPOINT5 = 5,
	ENDPOINT6 = 6,
	ENDPOINT7 = 7,
	ENDPOINT8 = 8,
	ENDPOINT_MAX = 22
};

struct htc_frame_hdr {
	u8 endpoint_id;
	u8 flags;
	__be16 payload_len;
	u8 control[4];
} __packed;

static int (*klpe_htc_send_epid)(struct htc_target *target, struct sk_buff *skb,
		  enum htc_endpoint_id epid);

/* klp-ccp: from drivers/net/wireless/ath/ath9k/hif_usb.h */
#define MAX_TX_BUF_NUM  256

/* klp-ccp: from drivers/net/wireless/ath/ath9k/wmi.h */
struct wmi_cmd_hdr {
	__be16 command_id;
	__be16 seq_no;
} __packed;

enum wmi_cmd_id {
	WMI_ECHO_CMDID = 0x0001,
	WMI_ACCESS_MEMORY_CMDID,

	/* Commands to Target */
	WMI_GET_FW_VERSION,
	WMI_DISABLE_INTR_CMDID,
	WMI_ENABLE_INTR_CMDID,
	WMI_ATH_INIT_CMDID,
	WMI_ABORT_TXQ_CMDID,
	WMI_STOP_TX_DMA_CMDID,
	WMI_ABORT_TX_DMA_CMDID,
	WMI_DRAIN_TXQ_CMDID,
	WMI_DRAIN_TXQ_ALL_CMDID,
	WMI_START_RECV_CMDID,
	WMI_STOP_RECV_CMDID,
	WMI_FLUSH_RECV_CMDID,
	WMI_SET_MODE_CMDID,
	WMI_NODE_CREATE_CMDID,
	WMI_NODE_REMOVE_CMDID,
	WMI_VAP_REMOVE_CMDID,
	WMI_VAP_CREATE_CMDID,
	WMI_REG_READ_CMDID,
	WMI_REG_WRITE_CMDID,
	WMI_RC_STATE_CHANGE_CMDID,
	WMI_RC_RATE_UPDATE_CMDID,
	WMI_TARGET_IC_UPDATE_CMDID,
	WMI_TX_AGGR_ENABLE_CMDID,
	WMI_TGT_DETACH_CMDID,
	WMI_NODE_UPDATE_CMDID,
	WMI_INT_STATS_CMDID,
	WMI_TX_STATS_CMDID,
	WMI_RX_STATS_CMDID,
	WMI_BITRATE_MASK_CMDID,
	WMI_REG_RMW_CMDID,
};

#define MAX_CMD_NUMBER 62
#define MAX_RMW_CMD_NUMBER 15

struct register_write {
	__be32 reg;
	__be32 val;
};

struct register_rmw {
	__be32 reg;
	__be32 set;
	__be32 clr;
} __packed;

struct wmi {
	struct ath9k_htc_priv *drv_priv;
	struct htc_target *htc;
	enum htc_endpoint_id ctrl_epid;
	struct mutex op_mutex;
	struct completion cmd_wait;
	u16 last_seq_id;
	struct sk_buff_head wmi_event_queue;
	struct tasklet_struct wmi_event_tasklet;
	u16 tx_seq_id;
	u8 *cmd_rsp_buf;
	u32 cmd_rsp_len;
	bool stopped;

	struct list_head pending_tx_events;
	spinlock_t event_lock;

	spinlock_t wmi_lock;

	/* multi write section */
	atomic_t mwrite_cnt;
	struct register_write multi_write[MAX_CMD_NUMBER];
	u32 multi_write_idx;
	struct mutex multi_write_mutex;

	/* multi rmw section */
	atomic_t m_rmw_cnt;
	struct register_rmw multi_rmw[MAX_RMW_CMD_NUMBER];
	u32 multi_rmw_idx;
	struct mutex multi_rmw_mutex;

};

int klpp_ath9k_wmi_cmd(struct wmi *wmi, enum wmi_cmd_id cmd_id,
		  u8 *cmd_buf, u32 cmd_len,
		  u8 *rsp_buf, u32 rsp_len,
		  u32 timeout);

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc.h */
#define ATH9K_HTC_MAX_VIF 2
#define ATH9K_HTC_MAX_BCN_VIF 2

struct ath9k_htc_rx {
	struct list_head rxbuf;
	spinlock_t rxbuflock;
};

struct ath9k_htc_tx {
	u8 flags;
	int queued_cnt;
	struct sk_buff_head mgmt_ep_queue;
	struct sk_buff_head cab_ep_queue;
	struct sk_buff_head data_be_queue;
	struct sk_buff_head data_bk_queue;
	struct sk_buff_head data_vi_queue;
	struct sk_buff_head data_vo_queue;
	struct sk_buff_head tx_failed;
	DECLARE_BITMAP(tx_slot, MAX_TX_BUF_NUM);
	struct timer_list cleanup_timer;
	spinlock_t tx_lock;
};

struct htc_beacon {
	enum {
		OK,		/* no change needed */
		UPDATE,		/* update pending */
		COMMIT		/* beacon sent, commit change */
	} updateslot;		/* slot time update fsm */

	struct ieee80211_vif *bslot[ATH9K_HTC_MAX_BCN_VIF];
	u32 bmisscnt;
	u32 beaconq;
	int slottime;
	int slotupdate;
};

struct ath_btcoex {
	u32 bt_priority_cnt;
	unsigned long bt_priority_time;
	int bt_stomp_type; /* Types of BT stomping */
	u32 btcoex_no_stomp;
	u32 btcoex_period;
	u32 btscan_no_stomp;
};

struct ath9k_htc_priv {
	struct device *dev;
	struct ieee80211_hw *hw;
	struct ath_hw *ah;
	struct htc_target *htc;
	struct wmi *wmi;

	u16 fw_version_major;
	u16 fw_version_minor;

	enum htc_endpoint_id wmi_cmd_ep;
	enum htc_endpoint_id beacon_ep;
	enum htc_endpoint_id cab_ep;
	enum htc_endpoint_id uapsd_ep;
	enum htc_endpoint_id mgmt_ep;
	enum htc_endpoint_id data_be_ep;
	enum htc_endpoint_id data_bk_ep;
	enum htc_endpoint_id data_vi_ep;
	enum htc_endpoint_id data_vo_ep;

	u8 vif_slot;
	u8 mon_vif_idx;
	u8 sta_slot;
	u8 vif_sta_pos[ATH9K_HTC_MAX_VIF];
	u8 num_ibss_vif;
	u8 num_mbss_vif;
	u8 num_sta_vif;
	u8 num_sta_assoc_vif;
	u8 num_ap_vif;

	u16 curtxpow;
	u16 txpowlimit;
	u16 nvifs;
	u16 nstations;
	bool rearm_ani;
	bool reconfig_beacon;
	unsigned int rxfilter;
	unsigned long op_flags;
	unsigned long fw_flags;

	struct ath9k_hw_cal_data caldata;
	struct ath_spec_scan_priv spec_priv;

	spinlock_t beacon_lock;
	struct ath_beacon_config cur_beacon_conf;
	struct htc_beacon beacon;

	struct ath9k_htc_rx rx;
	struct ath9k_htc_tx tx;

	struct tasklet_struct swba_tasklet;
	struct tasklet_struct rx_tasklet;
	struct delayed_work ani_work;
	struct tasklet_struct tx_failed_tasklet;
	struct work_struct ps_work;
	struct work_struct fatal_work;

	struct mutex htc_pm_lock;
	unsigned long ps_usecount;
	bool ps_enabled;
	bool ps_idle;

#ifdef CONFIG_MAC80211_LEDS
	enum led_brightness brightness;
	bool led_registered;
	char led_name[32];
	struct led_classdev led_cdev;
	struct work_struct led_work;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	int cabq;
	int hwq_map[IEEE80211_NUM_ACS];

#ifdef CONFIG_ATH9K_BTCOEX_SUPPORT
	struct ath_btcoex btcoex;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct delayed_work coex_period_work;
	struct delayed_work duty_cycle_work;
#ifdef CONFIG_ATH9K_HTC_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	struct mutex mutex;
	struct ieee80211_vif *csa_vif;
};

/* klp-ccp: from drivers/net/wireless/ath/ath9k/wmi.c */
static const char *wmi_cmd_to_name(enum wmi_cmd_id wmi_cmd)
{
	switch (wmi_cmd) {
	case WMI_ECHO_CMDID:
		return "WMI_ECHO_CMDID";
	case WMI_ACCESS_MEMORY_CMDID:
		return "WMI_ACCESS_MEMORY_CMDID";
	case WMI_GET_FW_VERSION:
		return "WMI_GET_FW_VERSION";
	case WMI_DISABLE_INTR_CMDID:
		return "WMI_DISABLE_INTR_CMDID";
	case WMI_ENABLE_INTR_CMDID:
		return "WMI_ENABLE_INTR_CMDID";
	case WMI_ATH_INIT_CMDID:
		return "WMI_ATH_INIT_CMDID";
	case WMI_ABORT_TXQ_CMDID:
		return "WMI_ABORT_TXQ_CMDID";
	case WMI_STOP_TX_DMA_CMDID:
		return "WMI_STOP_TX_DMA_CMDID";
	case WMI_ABORT_TX_DMA_CMDID:
		return "WMI_ABORT_TX_DMA_CMDID";
	case WMI_DRAIN_TXQ_CMDID:
		return "WMI_DRAIN_TXQ_CMDID";
	case WMI_DRAIN_TXQ_ALL_CMDID:
		return "WMI_DRAIN_TXQ_ALL_CMDID";
	case WMI_START_RECV_CMDID:
		return "WMI_START_RECV_CMDID";
	case WMI_STOP_RECV_CMDID:
		return "WMI_STOP_RECV_CMDID";
	case WMI_FLUSH_RECV_CMDID:
		return "WMI_FLUSH_RECV_CMDID";
	case WMI_SET_MODE_CMDID:
		return "WMI_SET_MODE_CMDID";
	case WMI_NODE_CREATE_CMDID:
		return "WMI_NODE_CREATE_CMDID";
	case WMI_NODE_REMOVE_CMDID:
		return "WMI_NODE_REMOVE_CMDID";
	case WMI_VAP_REMOVE_CMDID:
		return "WMI_VAP_REMOVE_CMDID";
	case WMI_VAP_CREATE_CMDID:
		return "WMI_VAP_CREATE_CMDID";
	case WMI_REG_READ_CMDID:
		return "WMI_REG_READ_CMDID";
	case WMI_REG_WRITE_CMDID:
		return "WMI_REG_WRITE_CMDID";
	case WMI_REG_RMW_CMDID:
		return "WMI_REG_RMW_CMDID";
	case WMI_RC_STATE_CHANGE_CMDID:
		return "WMI_RC_STATE_CHANGE_CMDID";
	case WMI_RC_RATE_UPDATE_CMDID:
		return "WMI_RC_RATE_UPDATE_CMDID";
	case WMI_TARGET_IC_UPDATE_CMDID:
		return "WMI_TARGET_IC_UPDATE_CMDID";
	case WMI_TX_AGGR_ENABLE_CMDID:
		return "WMI_TX_AGGR_ENABLE_CMDID";
	case WMI_TGT_DETACH_CMDID:
		return "WMI_TGT_DETACH_CMDID";
	case WMI_NODE_UPDATE_CMDID:
		return "WMI_NODE_UPDATE_CMDID";
	case WMI_INT_STATS_CMDID:
		return "WMI_INT_STATS_CMDID";
	case WMI_TX_STATS_CMDID:
		return "WMI_TX_STATS_CMDID";
	case WMI_RX_STATS_CMDID:
		return "WMI_RX_STATS_CMDID";
	case WMI_BITRATE_MASK_CMDID:
		return "WMI_BITRATE_MASK_CMDID";
	}

	return "Bogus";
}

static int klpr_ath9k_wmi_cmd_issue(struct wmi *wmi,
			       struct sk_buff *skb,
			       enum wmi_cmd_id cmd, u16 len)
{
	struct wmi_cmd_hdr *hdr;
	unsigned long flags;

	hdr = skb_push(skb, sizeof(struct wmi_cmd_hdr));
	hdr->command_id = cpu_to_be16(cmd);
	hdr->seq_no = cpu_to_be16(++wmi->tx_seq_id);

	spin_lock_irqsave(&wmi->wmi_lock, flags);
	wmi->last_seq_id = wmi->tx_seq_id;
	spin_unlock_irqrestore(&wmi->wmi_lock, flags);

	return (*klpe_htc_send_epid)(wmi->htc, skb, wmi->ctrl_epid);
}

int klpp_ath9k_wmi_cmd(struct wmi *wmi, enum wmi_cmd_id cmd_id,
		  u8 *cmd_buf, u32 cmd_len,
		  u8 *rsp_buf, u32 rsp_len,
		  u32 timeout)
{
	struct ath_hw *ah = wmi->drv_priv->ah;
	struct ath_common *common = ath9k_hw_common(ah);
	u16 headroom = sizeof(struct htc_frame_hdr) +
		       sizeof(struct wmi_cmd_hdr);
	struct sk_buff *skb;
	unsigned long time_left;
	int ret = 0;

	if (ah->ah_flags & AH_UNPLUGGED)
		return 0;

	skb = alloc_skb(headroom + cmd_len, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, headroom);

	if (cmd_len != 0 && cmd_buf != NULL) {
		skb_put_data(skb, cmd_buf, cmd_len);
	}

	mutex_lock(&wmi->op_mutex);

	/* check if wmi stopped flag is set */
	if (unlikely(wmi->stopped)) {
		ret = -EPROTO;
		goto out;
	}

	/* record the rsp buffer and length */
	wmi->cmd_rsp_buf = rsp_buf;
	wmi->cmd_rsp_len = rsp_len;

	ret = klpr_ath9k_wmi_cmd_issue(wmi, skb, cmd_id, cmd_len);
	if (ret)
		goto out;

	time_left = wait_for_completion_timeout(&wmi->cmd_wait, timeout);
	if (!time_left) {
		ath_dbg(common, WMI, "Timeout waiting for WMI command: %s\n",
			wmi_cmd_to_name(cmd_id));
		wmi->last_seq_id = 0;
		mutex_unlock(&wmi->op_mutex);
		kfree_skb(skb);
		return -ETIMEDOUT;
	}

	mutex_unlock(&wmi->op_mutex);

	return 0;

out:
	ath_dbg(common, WMI, "WMI failure for: %s\n", wmi_cmd_to_name(cmd_id));
	mutex_unlock(&wmi->op_mutex);
	kfree_skb(skb);

	return ret;
}


#include "livepatch_bsc1252563.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ath9k_htc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "htc_send_epid", (void *)&klpe_htc_send_epid, "ath9k_htc" },
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

int livepatch_bsc1252563_init(void)
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

void livepatch_bsc1252563_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_ATH9K_HTC) */
