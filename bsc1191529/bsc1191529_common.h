#ifndef BSC1191529_COMMON_H
#define BSC1191529_COMMON_H

int livepatch_bsc1191529_ath_key_init(void);
void livepatch_bsc1191529_ath_key_cleanup(void);

int livepatch_bsc1191529_ath9k_main_init(void);
void livepatch_bsc1191529_ath9k_main_cleanup(void);

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

enum ath_op_flags {
	ATH_OP_INVALID,
	ATH_OP_BEACONS,
	ATH_OP_ANI_RUN,
	ATH_OP_PRIM_STA_VIF,
	ATH_OP_HW_RESET,
	ATH_OP_SCANNING,
	ATH_OP_MULTI_CHANNEL,
	ATH_OP_WOW_ENABLED,
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

#endif
