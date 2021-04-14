/*
 * livepatch_bsc1183658
 *
 * Fix for CVE-2021-28660, bsc#1183658
 *
 *  Upstream commit:
 *  74b6b20df8cf ("staging: rtl8188eu: prevent ->ssid overflow in
 *                 rtw_wx_set_scan()")
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP and SLE15 commit:
 *  not affected
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  5b4b262fad45a717765d9829ee33c74994d44cd0
 *
 *  SLE15-SP2 commit:
 *  bdb8cee56b35daeaced46f945494024e3fa74b4d
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

#if IS_ENABLED(CONFIG_R8188EU)

#if !IS_MODULE(CONFIG_R8188EU)
#error "Live patch supports only CONFIG_R8188EU=m"
#endif

/* klp-ccp: from drivers/staging/rtl8188eu/os_dep/ioctl_linux.c */
#include <linux/ieee80211.h>
/* klp-ccp: from drivers/staging/rtl8188eu/include/basic_types.h */
#include <linux/types.h>

/* klp-ccp: from drivers/staging/rtl8188eu/include/osdep_service.h */
#define _FAIL		0

#include <linux/spinlock.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kref.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>
#include <linux/atomic.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/sem.h>
#include <linux/etherdevice.h>
#include <linux/wireless.h>

/* klp-ccp: from include/net/iw_handler.h */
struct iw_request_info;

/* klp-ccp: from drivers/staging/rtl8188eu/include/osdep_service.h */
#include <linux/delay.h>
#include <linux/interrupt.h>	/*  for struct tasklet_struct */

/* klp-ccp: from drivers/staging/rtl8188eu/include/osdep_service.h */
#include <linux/usb/ch9.h>

struct	__queue	{
	struct	list_head	queue;
	spinlock_t lock;
};

struct rtw_netdev_priv_indicator {
	void *priv;
};

#define rtw_netdev_priv(netdev)					\
	(((struct rtw_netdev_priv_indicator *)netdev_priv(netdev))->priv)

/* klp-ccp: from drivers/staging/rtl8188eu/include/wlan_bssdef.h */
#define MAX_IE_SZ			768

#define NDIS_802_11_LENGTH_RATES_EX     16

#define NDIS_802_11_RSSI long           /*  in dBm */

struct ndis_802_11_ssid {
	u32  SsidLength;
	u8  Ssid[32];
};

enum NDIS_802_11_NETWORK_TYPE {
	Ndis802_11FH,
	Ndis802_11DS,
	Ndis802_11OFDM5,
	Ndis802_11OFDM24,
	Ndis802_11NetworkTypeMax    /*  dummy upper bound */
};

struct ndis_802_11_config_fh {
	u32           Length;		/*  Length of structure */
	u32           HopPattern;	/*  As defined by 802.11, MSB set */
	u32           HopSet;		/*  to one if non-802.11 */
	u32           DwellTime;	/*  units are Kusec */
};

struct ndis_802_11_config {
	u32           Length;             /*  Length of structure */
	u32           BeaconPeriod;       /*  units are Kusec */
	u32           ATIMWindow;         /*  units are Kusec */
	u32           DSConfig;           /*  Frequency, units are kHz */
	struct ndis_802_11_config_fh    FHConfig;
};

enum ndis_802_11_network_infra {
	Ndis802_11IBSS,
	Ndis802_11Infrastructure,
	Ndis802_11AutoUnknown,
	Ndis802_11InfrastructureMax,     /*  dummy upper bound */
	Ndis802_11APMode
};

struct ndis_802_11_wep {
	u32     Length;        /*  Length of this structure */
	u32     KeyIndex;      /*  0 is the per-client key,
				* 1-N are the global keys
				*/
	u32     KeyLength;     /*  length of key in bytes */
	u8     KeyMaterial[16];/*  variable len depending on above field */
};

struct wlan_phy_info {
	u8	SignalStrength;/* in percentage) */
	u8	SignalQuality;/* in percentage) */
	u8	Optimum_antenna;  /* for Antenna diversity */
	u8	Reserved_0;
};

struct wlan_bcn_info {
	/* these infor get from rtw_get_encrypt_info when
	 *	 * translate scan to UI
	 */
	u8 encryp_protocol;/* ENCRYP_PROTOCOL_E: OPEN/WEP/WPA/WPA2/WAPI */
	int group_cipher; /* WPA/WPA2 group cipher */
	int pairwise_cipher;/* WPA/WPA2/WEP pairwise cipher */
	int is_8021x;

	/* bwmode 20/40 and ch_offset UP/LOW */
	unsigned short	ht_cap_info;
	unsigned char	ht_info_infos_0;
};

struct wlan_bssid_ex {
	u32  Length;
	unsigned char MacAddress[ETH_ALEN];
	u8  Reserved[2];/* 0]: IS beacon frame */
	struct ndis_802_11_ssid  Ssid;
	u32  Privacy;
	NDIS_802_11_RSSI  Rssi;/* in dBM,raw data ,get from PHY) */
	enum  NDIS_802_11_NETWORK_TYPE  NetworkTypeInUse;
	struct ndis_802_11_config  Configuration;
	enum ndis_802_11_network_infra  InfrastructureMode;
	unsigned char SupportedRates[NDIS_802_11_LENGTH_RATES_EX];
	struct wlan_phy_info	PhyInfo;
	u32  ie_length;
	u8  ies[MAX_IE_SZ];	/* timestamp, beacon interval, and
				 * capability information)
				 */
} __packed;

struct	wlan_network {
	struct list_head list;
	int	network_type;	/* refer to ieee80211.h for WIRELESS_11A/B/G */
	int	fixed;		/*  set fixed when not to be removed
				 *  in site-surveying
				 */
	unsigned long	last_scanned; /* timestamp for the network */
	int	aid;		/* will only be valid when a BSS is joinned. */
	int	join_res;
	struct wlan_bssid_ex	network; /* must be the last item */
	struct wlan_bcn_info	BcnInfo;
};

#define NUM_PRE_AUTH_KEY 16
#define NUM_PMKID_CACHE NUM_PRE_AUTH_KEY

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_ht.h */
#include <linux/ieee80211.h>

struct ht_priv {
	u32	ht_option;
	u32	ampdu_enable;/* for enable Tx A-MPDU */
	u8	bwmode;/*  */
	u8	ch_offset;/* PRIME_CHNL_OFFSET */
	u8	sgi;/* short GI */

	/* for processing Tx A-MPDU */
	u8	agg_enable_bitmap;
	u8	candidate_tid_bitmap;

	struct ieee80211_ht_cap ht_cap;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_rf.h */
#define NumRates	(13)

#define	MAX_CHANNEL_NUM			14	/* 2.4 GHz only */

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_led.h */
enum LED_STATE_871x {
	LED_UNKNOWN,
	RTW_LED_ON,
	RTW_LED_OFF,
	LED_BLINK_NORMAL,
	LED_BLINK_SLOWLY,
	LED_BLINK_POWER_ON,
	LED_BLINK_SCAN,
	LED_BLINK_TXRX,
	LED_BLINK_WPS,
	LED_BLINK_WPS_STOP
};

struct LED_871x {
	struct adapter *padapter;

	enum LED_STATE_871x	CurrLedState; /*  Current LED state. */
	enum LED_STATE_871x	BlinkingLedState; /*  Next state for blinking,
						   * either RTW_LED_ON or RTW_LED_OFF are.
						   */

	u8 bLedOn; /*  true if LED is ON, false if LED is OFF. */

	u8 bLedBlinkInProgress; /*  true if it is blinking, false o.w.. */

	u8 bLedWPSBlinkInProgress;

	u32 BlinkTimes; /*  Number of times to toggle led state for blinking. */

	struct timer_list BlinkTimer; /*  Timer object for led blinking. */

	/*  ALPHA, added by chiyoko, 20090106 */
	u8 bLedNoLinkBlinkInProgress;
	u8 bLedLinkBlinkInProgress;
	u8 bLedScanBlinkInProgress;
	struct work_struct BlinkWorkItem; /* Workitem used by BlinkTimer to
					   * manipulate H/W to blink LED.
					   */
};

struct led_priv {
	/* add for led control */
	struct LED_871x			SwLed0;
	/* add for led control */
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/wifi.h */
struct HT_info_element {
	unsigned char	primary_channel;
	unsigned char	infos[5];
	unsigned char	MCS_rate[16];
} __packed;

struct AC_param {
	unsigned char		ACI_AIFSN;
	unsigned char		CW;
	__le16	TXOP_limit;
} __packed;

struct WMM_para_element {
	unsigned char		QoS_info;
	unsigned char		reserved;
	struct AC_param	ac_param[4];
} __packed;

struct ADDBA_request {
	unsigned char	dialog_token;
	__le16		BA_para_set;
	unsigned short	BA_timeout_value;
	unsigned short	BA_starting_seqctrl;
} __packed;

/* klp-ccp: from drivers/staging/rtl8188eu/include/ieee80211.h */
#include <linux/wireless.h>

#define MAX_WPS_IE_LEN (512)

struct rtw_ieee80211_channel {
	u16 hw_value;
	u32 flags;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_cmd.h */
struct cmd_priv {
	struct completion cmd_queue_comp;
	struct completion terminate_cmdthread_comp;
	struct __queue cmd_queue;
	u8 cmdthd_running;
	struct adapter *padapter;
};

#define RTW_SSID_SCAN_AMOUNT 9 /*  for WEXT_CSCAN_AMOUNT 9 */
#define RTW_CHANNEL_SCAN_AMOUNT (14+37)

static u8 (*klpe_rtw_sitesurvey_cmd)(struct adapter *padapter, struct ndis_802_11_ssid *ssid,
		      int ssid_num, struct rtw_ieee80211_channel *ch,
		      int ch_num);

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_xmit.h */
struct  submit_ctx {
	u32 submit_time; /* */
	u32 timeout_ms; /* <0: not synchronous, 0: wait forever, >0: up to ms waiting */
	int status; /* status for operation */
	struct completion done;
};

struct	xmit_priv {
	spinlock_t lock;
	struct __queue be_pending;
	struct __queue bk_pending;
	struct __queue vi_pending;
	struct __queue vo_pending;
	struct __queue bm_pending;
	u8 *pallocated_frame_buf;
	u8 *pxmit_frame_buf;
	uint free_xmitframe_cnt;
	struct __queue free_xmit_queue;
	uint	frag_len;
	struct adapter	*adapter;
	u8   vcs_setting;
	u8	vcs;
	u8	vcs_type;
	u64	tx_bytes;
	u64	tx_pkts;
	u64	tx_drop;
	u64	last_tx_bytes;
	u64	last_tx_pkts;
	struct hw_xmit *hwxmits;
	u8	hwxmit_entry;
	u8	wmm_para_seq[4];/* sequence for wmm ac parameter strength
				 * from large to small. it's value is 0->vo,
				 * 1->vi, 2->be, 3->bk.
				 */
	u8		txirp_cnt;/*  */
	struct tasklet_struct xmit_tasklet;
	/* per AC pending irp */
	int beq_cnt;
	int bkq_cnt;
	int viq_cnt;
	int voq_cnt;
	struct __queue free_xmitbuf_queue;
	struct __queue pending_xmitbuf_queue;
	u8 *pallocated_xmitbuf;
	u8 *pxmitbuf;
	uint free_xmitbuf_cnt;
	struct __queue free_xmit_extbuf_queue;
	u8 *pallocated_xmit_extbuf;
	u8 *pxmit_extbuf;
	uint free_xmit_extbuf_cnt;
	u16	nqos_ssn;
	int	ack_tx;
	struct mutex ack_tx_mutex;
	struct submit_ctx ack_tx_ops;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_recv.h */
struct signal_stat {
	u8	update_req;		/* used to indicate */
	u8	avg_val;		/* avg of valid elements */
	u32	total_num;		/* num of valid elements */
	u32	total_val;		/* sum of valid elements */
};

struct recv_priv {
	struct __queue free_recv_queue;
	struct __queue recv_pending_queue;
	struct __queue uc_swdec_pending_queue;
	void *pallocated_frame_buf;
	struct adapter	*adapter;
	u32	bIsAnyNonBEPkts;
	u64	rx_bytes;
	u64	rx_pkts;
	u64	rx_drop;
	u64	last_rx_bytes;

	struct tasklet_struct irq_prepare_beacon_tasklet;
	struct tasklet_struct recv_tasklet;
	struct sk_buff_head free_recv_skb_queue;
	struct sk_buff_head rx_skb_queue;
	struct recv_buf *precv_buf;    /*  4 alignment */
	struct __queue free_recv_buf_queue;
	/* For display the phy information */
	s8 rssi;
	s8 rxpwdb;
	u8 signal_strength;
	u8 signal_qual;
	u8 noise;
	s8 RxRssi[2];

	struct timer_list signal_stat_timer;
	u32 signal_stat_sampling_interval;
	struct signal_stat signal_qual_data;
	struct signal_stat signal_strength_data;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/hal_intf.h */
static void (*klpe_indicate_wx_scan_complete_event)(struct adapter *padapter);

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_security.h */
union pn48	{
	u64	val;

#ifdef __LITTLE_ENDIAN
	struct {
		u8 TSC0;
		u8 TSC1;
		u8 TSC2;
		u8 TSC3;
		u8 TSC4;
		u8 TSC5;
		u8 TSC6;
		u8 TSC7;
	} _byte_;

#elif defined(__BIG_ENDIAN)
#error "klp-ccp: non-taken branch"
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

union Keytype {
	u8   skey[16];
	u32    lkey[4];
};

struct rt_pmkid_list {
	u8	bUsed;
	u8	Bssid[6];
	u8	PMKID[16];
	u8	SsidBuf[33];
	u8	*ssid_octet;
	u16	ssid_length;
};

struct security_priv {
	u32	  dot11AuthAlgrthm;	/*  802.11 auth, could be open,
					 * shared, 8021x and authswitch
					 */
	u32	  dot11PrivacyAlgrthm;	/*  This specify the privacy for
					 * shared auth. algorithm.
					 */
	/* WEP */
	u32	  dot11PrivacyKeyIndex;	/*  this is only valid for legendary
					 * wep, 0~3 for key id.(tx key index)
					 */
	union Keytype dot11DefKey[4];	/*  this is only valid for def. key */
	u32	dot11DefKeylen[4];
	u32 dot118021XGrpPrivacy;	/*  This specify the privacy algthm.
					 * used for Grp key
					 */
	u32	dot118021XGrpKeyid;	/*  key id used for Grp Key
					 * ( tx key index)
					 */
	union Keytype	dot118021XGrpKey[4];	/*  802.1x Group Key,
						 * for inx0 and inx1
						 */
	union Keytype	dot118021XGrptxmickey[4];
	union Keytype	dot118021XGrprxmickey[4];
	union pn48	dot11Grptxpn;		/* PN48 used for Grp Key xmit.*/
	union pn48	dot11Grprxpn;		/* PN48 used for Grp Key recv.*/
#ifdef CONFIG_88EU_AP_MODE
	unsigned int dot8021xalg;/* 0:disable, 1:psk, 2:802.1x */
	unsigned int wpa_psk;/* 0:disable, bit(0): WPA, bit(1):WPA2 */
	unsigned int wpa_group_cipher;
	unsigned int wpa2_group_cipher;
	unsigned int wpa_pairwise_cipher;
	unsigned int wpa2_pairwise_cipher;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u8 wps_ie[MAX_WPS_IE_LEN];/* added in assoc req */
	int wps_ie_len;
	u8	binstallGrpkey;
	u8	busetkipkey;
	u8	bcheck_grpkey;
	u8	bgrpkey_handshake;
	s32	hw_decrypted;/* if the rx packets is hw_decrypted==false,i
			      * it means the hw has not been ready.
			      */

	/* keeps the auth_type & enc_status from upper layer
	 * ioctl(wpa_supplicant or wzc)
	 */
	u32 ndisauthtype;	/*  NDIS_802_11_AUTHENTICATION_MODE */
	u32 ndisencryptstatus;	/*  NDIS_802_11_ENCRYPTION_STATUS */
	struct wlan_bssid_ex sec_bss;  /* for joinbss (h2c buffer) usage */
	struct ndis_802_11_wep ndiswep;
	u8 assoc_info[600];
	u8 szofcapability[256]; /* for wpa2 usage */
	u8 oidassociation[512]; /* for wpa/wpa2 usage */
	u8 authenticator_ie[256];  /* store ap security information element */
	u8 supplicant_ie[256];  /* store sta security information element */

	/* for tkip countermeasure */
	u32 last_mic_err_time;
	u8	btkip_countermeasure;
	u8	btkip_wait_report;
	u32 btkip_countermeasure_time;

	/*  */
	/*  For WPA2 Pre-Authentication. */
	/*  */
	struct rt_pmkid_list PMKIDList[NUM_PMKID_CACHE];
	u8	PMKIDIndex;
	u8 bWepDefaultKeyIdxSet;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_pwrctrl.h */
enum rt_rf_power_state {
	rf_on,		/*  RF is on after RFSleep or RFOff */
	rf_sleep,	/*  802.11 Power Save mode */
	rf_off,		/*  HW/SW Radio OFF or Inactive Power Save */
	/* Add the new RF state above this line===== */
	rf_max
};

enum _PS_BBRegBackup_ {
	PSBBREG_RF0 = 0,
	PSBBREG_RF1,
	PSBBREG_RF2,
	PSBBREG_AFE0,
	PSBBREG_TOTALCNT
};

struct pwrctrl_priv {
	struct mutex mutex_lock;
	volatile u8 rpwm; /*  requested power state for fw */
	volatile u8 cpwm; /*  fw current power state. updated when
			   * 1. read from HCPWM 2. driver lowers power level
			   */
	volatile u8 tog; /*  toggling */
	volatile u8 cpwm_tog; /*  toggling */

	u8	pwr_mode;
	u8	smart_ps;
	u8	bcn_ant_mode;

	u32	alives;
	struct work_struct cpwm_event;
	u8	bpower_saving;

	u8	b_hw_radio_off;
	u8	reg_rfoff;
	u8	reg_pdnmode; /* powerdown mode */
	u32	rfoff_reason;

	/* RF OFF Level */
	u32	cur_ps_level;
	u32	reg_rfps_level;
	uint	ips_enter_cnts;
	uint	ips_leave_cnts;

	u8	ips_mode;
	u8	ips_mode_req;	/*  used to accept the mode setting request,
				 *  will update to ipsmode later
				 */
	uint bips_processing;
	unsigned long ips_deny_time; /* will deny IPS when system time less than this */
	u8 ps_processing; /* temp used to mark whether in rtw_ps_processor */

	u8	bLeisurePs;
	u8	LpsIdleCount;
	u8	power_mgnt;
	u8	bFwCurrentInPSMode;
	u32	DelayLPSLastTimeStamp;
	u8	btcoex_rfon;
	s32		pnp_current_pwr_state;
	u8		pnp_bstop_trx;

	u8		bInternalAutoSuspend;
	u8		bInSuspend;
	u8		bSupportRemoteWakeup;
	struct timer_list pwr_state_check_timer;
	int		pwr_state_check_interval;
	u8		pwr_state_check_cnts;

	int		ps_flag;

	enum rt_rf_power_state	rf_pwrstate;/* cur power state */
	enum rt_rf_power_state	change_rfpwrstate;

	u8		wepkeymask;
	u8		bHWPowerdown;/* if support hw power down */
	u8		bHWPwrPindetect;
	u8		bkeepfwalive;
	u8		brfoffbyhw;
	unsigned long PS_BBRegBackup[PSBBREG_TOTALCNT];
};

static int (*klpe__rtw_pwr_wakeup)(struct adapter *adapter, u32 ips_defer_ms,
		    const char *caller);

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_eeprom.h */
#define	HWSET_MAX_SIZE_512		512

struct eeprom_priv {
	u8		bautoload_fail_flag;
	u8		bloadfile_fail_flag;
	u8		bloadmac_fail_flag;
	u8		mac_addr[6];	/* PermanentAddress */
	u16		channel_plan;
	u8		EepromOrEfuse;
	u8		efuse_eeprom_data[HWSET_MAX_SIZE_512];
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/sta_info.h */
#define NUM_STA 32
#define NUM_ACL 16

struct rtw_wlan_acl_node {
	struct list_head list;
	u8       addr[ETH_ALEN];
	u8       valid;
};

struct wlan_acl_pool {
	int mode;
	int num;
	struct rtw_wlan_acl_node aclnode[NUM_ACL];
	struct __queue acl_node_q;
};

struct	sta_priv {
	u8 *pallocated_stainfo_buf;
	u8 *pstainfo_buf;
	struct __queue free_sta_queue;

	spinlock_t sta_hash_lock;
	struct list_head sta_hash[NUM_STA];
	int asoc_sta_count;
	struct __queue sleep_q;
	struct __queue wakeup_q;

	struct adapter *padapter;

	spinlock_t asoc_list_lock;
	struct list_head asoc_list;

#ifdef CONFIG_88EU_AP_MODE
	struct list_head auth_list;
	spinlock_t auth_list_lock;
	u8 asoc_list_cnt;
	u8 auth_list_cnt;

	unsigned int auth_to;  /* sec, time to expire in authenticating. */
	unsigned int assoc_to; /* sec, time to expire before associating. */
	unsigned int expire_to; /* sec , time to expire after associated. */

	/* pointers to STA info; based on allocated AID or NULL if AID free
	 * AID is in the range 1-2007, so sta_aid[0] corresponders to AID 1
	 * and so on
	 */
	struct sta_info *sta_aid[NUM_STA];

	u16 sta_dz_bitmap;/* only support 15 stations, station aid bitmap
			   * for sleeping sta.
			   */
	u16 tim_bitmap;	/* only support 15 stations, aid=0~15 mapping
			 * bit0~bit15
			 */

	u16 max_num_sta;

	struct wlan_acl_pool acl_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/drv_types.h */
struct qos_priv {
	/* bit mask option: u-apsd, s-apsd, ts, block ack... */
	unsigned int qos_option;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_mlme.h */
#define WIFI_UNDER_LINKING		0x00000080

#define	WIFI_SITE_MONITOR		0x00000800	/* to indicate the station is under site surveying */

#define _FW_UNDER_LINKING	WIFI_UNDER_LINKING

#define _FW_UNDER_SURVEY	WIFI_SITE_MONITOR

enum rt_scan_type {
	SCAN_PASSIVE,
	SCAN_ACTIVE,
	SCAN_MIX,
};

struct rt_link_detect {
	u32	NumTxOkInPeriod;
	u32	NumRxOkInPeriod;
	u32	NumRxUnicastOkInPeriod;
	bool	bBusyTraffic;
	bool	bTxBusyTraffic;
	bool	bRxBusyTraffic;
	bool	bHigherBusyTraffic; /*  For interrupt migration purpose. */
	bool	bHigherBusyRxTraffic; /* We may disable Tx interrupt according
				       * to Rx traffic.
				       */
	bool	bHigherBusyTxTraffic; /* We may disable Tx interrupt according
				       * to Tx traffic.
				       */
};

struct mlme_priv {
	spinlock_t lock;
	int fw_state;	/* shall we protect this variable? maybe not necessarily... */
	u8 bScanInProcess;
	u8 to_join; /* flag */
	u8 to_roaming; /*  roaming trying times */

	u8 *nic_hdl;

	struct list_head *pscanned;
	struct __queue free_bss_pool;
	struct __queue scanned_queue;
	u8 *free_bss_buf;

	struct ndis_802_11_ssid	assoc_ssid;
	u8	assoc_bssid[6];

	struct wlan_network	cur_network;

	u32	scan_interval;

	struct timer_list assoc_timer;

	uint assoc_by_bssid;

	struct timer_list scan_to_timer; /*  driver itself handles scan_timeout status. */

	struct qos_priv qospriv;

	/* Number of non-HT AP/stations */
	int num_sta_no_ht;

	/* Number of HT AP/stations 20 MHz */
	/* int num_sta_ht_20mhz; */

	int num_FortyMHzIntolerant;
	struct ht_priv	htpriv;
	struct rt_link_detect LinkDetectInfo;
	struct timer_list dynamic_chk_timer; /* dynamic/periodic check timer */

	u8	key_mask; /* use for ips to set wep key after ips_leave */
	u8	acm_mask; /*  for wmm acm mask */
	u8	ChannelPlan;
	enum rt_scan_type scan_mode; /*  active: 1, passive: 0 */

	/* u8 probereq_wpsie[MAX_WPS_IE_LEN];added in probe req */
	/* int probereq_wpsie_len; */
	u8 *wps_probe_req_ie;
	u32 wps_probe_req_ie_len;

	u8 *assoc_req;
	u32 assoc_req_len;
	u8 *assoc_rsp;
	u32 assoc_rsp_len;

#if defined(CONFIG_88EU_AP_MODE)
	int num_sta_non_erp;

	/* Number of associated stations that do not support Short Slot Time */
	int num_sta_no_short_slot_time;

	/* Number of associated stations that do not support Short Preamble */
	int num_sta_no_short_preamble;

	int olbc; /* Overlapping Legacy BSS Condition */

	/* Number of HT assoc sta that do not support greenfield */
	int num_sta_ht_no_gf;

	/* Number of associated non-HT stations */
	/* int num_sta_no_ht; */

	/* Number of HT associated stations 20 MHz */
	int num_sta_ht_20mhz;

	/* Overlapping BSS information */
	int olbc_ht;

	u16 ht_op_mode;

	u8 *wps_beacon_ie;
	/* u8 *wps_probe_req_ie; */
	u8 *wps_probe_resp_ie;
	u8 *wps_assoc_resp_ie;

	u32 wps_beacon_ie_len;
	u32 wps_probe_resp_ie_len;
	u32 wps_assoc_resp_ie_len;

	spinlock_t bcn_update_lock;
	u8		update_bcn;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* if defined (CONFIG_88EU_AP_MODE) */
};

static inline int check_fwstate(struct mlme_priv *pmlmepriv, int state)
{
	if (pmlmepriv->fw_state & state)
		return true;

	return false;
}

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_debug.h */
#define _drv_err_			5
#define _drv_info_			8

#define _module_rtl871x_mlme_c_		BIT(4)

#define DRIVER_PREFIX	"R8188EU: "

static u32 (*klpe_GlobalDebugLevel);

#define KLPR_DBG_88E(...)						\
	do {								\
		if (_drv_err_ <= (*klpe_GlobalDebugLevel))		\
			pr_info(DRIVER_PREFIX __VA_ARGS__);		\
	} while (0)

#define KLPR_RT_TRACE(_comp, _level, fmt)				\
	do {								\
		if (_level <= (*klpe_GlobalDebugLevel)) {		\
			pr_info("%s [0x%08x,%d]", DRIVER_PREFIX,	\
				 (unsigned int)_comp, _level);		\
			pr_info fmt;					\
		}							\
	} while (0)

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_event.h */
#include <linux/mutex.h>
#include <linux/sem.h>

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_mlme_ext.h */
struct ss_res {
	int state;
	int bss_cnt;
	int channel_idx;
	int scan_mode;
	u8 ssid_num;
	u8 ch_num;
	struct ndis_802_11_ssid ssid[RTW_SSID_SCAN_AMOUNT];
	struct rtw_ieee80211_channel ch[RTW_CHANNEL_SCAN_AMOUNT];
};

struct FW_Sta_Info {
	struct sta_info	*psta;
	u32	status;
	u32	rx_pkt;
	u32	retry;
	unsigned char SupportedRates[NDIS_802_11_LENGTH_RATES_EX];
};

struct mlme_ext_info {
	u32	state;
	u32	reauth_count;
	u32	reassoc_count;
	u32	link_count;
	u32	auth_seq;
	u32	auth_algo;	/*  802.11 auth, could be open, shared, auto */
	u32	authModeToggle;
	u32	enc_algo;/* encrypt algorithm; */
	u32	key_index;	/*  this is only valid for legacy wep,
				 *  0~3 for key id.
				 */
	u32	iv;
	u8	chg_txt[128];
	u16	aid;
	u16	bcn_interval;
	u16	capability;
	u8	assoc_AP_vendor;
	u8	slotTime;
	u8	preamble_mode;
	u8	WMM_enable;
	u8	ERP_enable;
	u8	ERP_IE;
	u8	HT_enable;
	u8	HT_caps_enable;
	u8	HT_info_enable;
	u8	HT_protection;
	u8	turboMode_cts2self;
	u8	turboMode_rtsen;
	u8	SM_PS;
	u8	agg_enable_bitmap;
	u8	ADDBA_retry_count;
	u8	candidate_tid_bitmap;
	u8	dialogToken;
	/*  Accept ADDBA Request */
	bool accept_addba_req;
	u8	bwmode_updated;
	u8	hidden_ssid_mode;

	struct ADDBA_request	ADDBA_req;
	struct WMM_para_element	WMM_param;
	struct ieee80211_ht_cap HT_caps;
	struct HT_info_element	HT_info;
	struct wlan_bssid_ex	network;/* join network or bss_network,
					 * if in ap mode, it is the same
					 * as cur_network.network
					 */
	struct FW_Sta_Info	FW_sta_info[NUM_STA];
};

struct rt_channel_info {
	u8	ChannelNum;	/*  The channel number. */
	enum rt_scan_type ScanType;	/*  Scan type such as passive
					 *  or active scan.
					 */
	u32	rx_count;
};

#define P2P_MAX_REG_CLASSES 10

#define P2P_MAX_REG_CLASS_CHANNELS 20

struct p2p_channels {
	/*  struct p2p_reg_class - Supported regulatory class */
	struct p2p_reg_class {
		/*  reg_class - Regulatory class (IEEE 802.11-2007, Annex J) */
		u8 reg_class;

		/*  channel - Supported channels */
		u8 channel[P2P_MAX_REG_CLASS_CHANNELS];

		/*  channels - Number of channel entries in use */
		size_t channels;
	} reg_class[P2P_MAX_REG_CLASSES];

	/*  reg_classes - Number of reg_class entries in use */
	size_t reg_classes;
};

struct mlme_ext_priv {
	struct adapter	*padapter;
	u8	mlmeext_init;
	atomic_t	event_seq;
	u16	mgnt_seq;

	unsigned char	cur_channel;
	unsigned char	cur_bwmode;
	unsigned char	cur_ch_offset;/* PRIME_CHNL_OFFSET */
	unsigned char	cur_wireless_mode;	/*  NETWORK_TYPE */

	unsigned char	oper_channel; /* saved chan info when call
				       * set_channel_bw
				       */
	unsigned char	oper_bwmode;
	unsigned char	oper_ch_offset;/* PRIME_CHNL_OFFSET */

	unsigned char	max_chan_nums;
	struct rt_channel_info channel_set[MAX_CHANNEL_NUM];
	struct p2p_channels channel_list;
	unsigned char	basicrate[NumRates];
	unsigned char	datarate[NumRates];

	struct ss_res		sitesurvey_res;
	struct mlme_ext_info	mlmext_info;/* for sta/adhoc mode, including
					     * current scan/connecting/connected
					     * related info. For ap mode,
					     * network includes ap's cap_info
					     */
	struct timer_list survey_timer;
	struct timer_list link_timer;
	u16	chan_scan_time;

	u8	scan_abort;
	u8	tx_rate; /*  TXRATE when USERATE is set. */

	u32	retry; /* retry for issue probereq */

	u64 TSFValue;

#ifdef CONFIG_88EU_AP_MODE
	unsigned char bstart_bss;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u8 update_channel_plan_by_ap_done;
	/* recv_decache check for Action_public frame */
	u8 action_public_dialog_token;
	u16	 action_public_rxseq;
	u8 active_keep_alive_check;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/drv_types.h */
struct registry_priv {
	struct ndis_802_11_ssid	ssid;
	u8	channel;/* ad-hoc support requirement */
	u8	wireless_mode;/* A, B, G, auto */
	u8	preamble;/* long, short, auto */
	u8	vrtl_carrier_sense;/* Enable, Disable, Auto */
	u8	vcs_type;/* RTS/CTS, CTS-to-self */
	u16	rts_thresh;
	u16	frag_thresh;
	u8	power_mgnt;
	u8	ips_mode;
	u8	smart_ps;
	u8	mp_mode;
	u8	acm_method;
	  /* UAPSD */
	u8	wmm_enable;
	u8	uapsd_enable;

	struct wlan_bssid_ex    dev_network;

	u8	ht_enable;
	u8	cbw40_enable;
	u8	ampdu_enable;/* for tx */
	u8	rx_stbc;
	u8	ampdu_amsdu;/* A-MPDU Supports A-MSDU is permitted */

	u8	wifi_spec;/*  !turbo_mode */

	u8	channel_plan;
	bool	accept_addba_req; /* true = accept AP's Add BA req */

	u8	antdiv_cfg;
	u8	antdiv_type;

	u8	usbss_enable;/* 0:disable,1:enable */
	u8	hwpdn_mode;/* 0:disable,1:enable,2:decide by EFUSE config */

	u8	max_roaming_times; /*  the max number driver will try */

	u8	fw_iol; /* enable iol without other concern */

	u8	enable80211d;

	u8	ifname[16];
	u8	if2name[16];

	u8	notch_filter;
	bool	monitor_enable;
};

struct adapter {
	struct dvobj_priv *dvobj;
	struct	mlme_priv mlmepriv;
	struct	mlme_ext_priv mlmeextpriv;
	struct	cmd_priv	cmdpriv;
	struct	xmit_priv	xmitpriv;
	struct	recv_priv	recvpriv;
	struct	sta_priv	stapriv;
	struct	security_priv	securitypriv;
	struct	registry_priv	registrypriv;
	struct	pwrctrl_priv	pwrctrlpriv;
	struct	eeprom_priv eeprompriv;
	struct	led_priv	ledpriv;

	struct hal_data_8188e *HalData;

	s32	bDriverStopped;
	s32	bSurpriseRemoved;

	u8	hw_init_completed;

	void *cmdThread;
	struct  net_device *pnetdev;
	struct  net_device *pmondev;

	int bup;
	struct net_device_stats stats;
	struct iw_statistics iwstats;
	struct proc_dir_entry *dir_dev;/*  for proc directory */

	int net_closed;
	u8 bFWReady;
	u8 bReadPortCancel;
	u8 bWritePortCancel;

	struct mutex hw_init_mutex;
};

/* klp-ccp: from drivers/staging/rtl8188eu/include/rtw_ioctl_set.h */
static u8 (*klpe_rtw_set_802_11_bssid_list_scan)(struct adapter *adapter,
				  struct ndis_802_11_ssid *pssid,
				  int ssid_max_num);

/* klp-ccp: from drivers/staging/rtl8188eu/os_dep/ioctl_linux.c */
#include <linux/vmalloc.h>
#include <linux/etherdevice.h>

#define WEXT_CSCAN_HEADER		"CSCAN S\x01\x00\x00S\x00"
#define WEXT_CSCAN_HEADER_SIZE		12
#define WEXT_CSCAN_SSID_SECTION		'S'
#define WEXT_CSCAN_CHANNEL_SECTION	'C'

#define WEXT_CSCAN_ACTV_DWELL_SECTION	'A'
#define WEXT_CSCAN_PASV_DWELL_SECTION	'P'
#define WEXT_CSCAN_HOME_DWELL_SECTION	'H'
#define WEXT_CSCAN_TYPE_SECTION		'T'

int klpp_rtw_wx_set_scan(struct net_device *dev, struct iw_request_info *a,
			     union iwreq_data *wrqu, char *extra)
{
	u8 _status = false;
	int ret = 0;
	struct adapter *padapter = (struct adapter *)rtw_netdev_priv(dev);
	struct mlme_priv *pmlmepriv = &padapter->mlmepriv;
	struct ndis_802_11_ssid ssid[RTW_SSID_SCAN_AMOUNT];

	KLPR_RT_TRACE(_module_rtl871x_mlme_c_, _drv_info_, ("rtw_wx_set_scan\n"));

	if (_FAIL == (*klpe__rtw_pwr_wakeup)(padapter, 2000, __func__)) {
		ret = -1;
		goto exit;
	}

	if (padapter->bDriverStopped) {
		KLPR_DBG_88E("bDriverStopped =%d\n", padapter->bDriverStopped);
		ret = -1;
		goto exit;
	}

	if (!padapter->bup) {
		ret = -1;
		goto exit;
	}

	if (!padapter->hw_init_completed) {
		ret = -1;
		goto exit;
	}

	/*  When Busy Traffic, driver do not site survey. So driver return success. */
	/*  wpa_supplicant will not issue SIOCSIWSCAN cmd again after scan timeout. */
	/*  modify by thomas 2011-02-22. */
	if (pmlmepriv->LinkDetectInfo.bBusyTraffic) {
		(*klpe_indicate_wx_scan_complete_event)(padapter);
		goto exit;
	}

	if (check_fwstate(pmlmepriv, _FW_UNDER_SURVEY|_FW_UNDER_LINKING)) {
		(*klpe_indicate_wx_scan_complete_event)(padapter);
		goto exit;
	}

/*	For the DMP WiFi Display project, the driver won't to scan because */
/*	the pmlmepriv->scan_interval is always equal to 3. */
/*	So, the wpa_supplicant won't find out the WPS SoftAP. */

	memset(ssid, 0, sizeof(struct ndis_802_11_ssid)*RTW_SSID_SCAN_AMOUNT);

	if (wrqu->data.length == sizeof(struct iw_scan_req)) {
		struct iw_scan_req *req = (struct iw_scan_req *)extra;

		if (wrqu->data.flags & IW_SCAN_THIS_ESSID) {
			int len = min_t(int, req->essid_len,
					IW_ESSID_MAX_SIZE);

			memcpy(ssid[0].Ssid, req->essid, len);
			ssid[0].SsidLength = len;

			KLPR_DBG_88E("IW_SCAN_THIS_ESSID, ssid =%s, len =%d\n", req->essid, req->essid_len);

			spin_lock_bh(&pmlmepriv->lock);

			_status = (*klpe_rtw_sitesurvey_cmd)(padapter, ssid, 1, NULL, 0);

			spin_unlock_bh(&pmlmepriv->lock);
		} else if (req->scan_type == IW_SCAN_TYPE_PASSIVE) {
			KLPR_DBG_88E("rtw_wx_set_scan, req->scan_type == IW_SCAN_TYPE_PASSIVE\n");
		}
	} else {
		if (wrqu->data.length >= WEXT_CSCAN_HEADER_SIZE &&
		    !memcmp(extra, WEXT_CSCAN_HEADER, WEXT_CSCAN_HEADER_SIZE)) {
			int len = wrqu->data.length - WEXT_CSCAN_HEADER_SIZE;
			char *pos = extra+WEXT_CSCAN_HEADER_SIZE;
			char section;
			char sec_len;
			int ssid_index = 0;

			while (len >= 1) {
				section = *(pos++);
				len -= 1;

				switch (section) {
				case WEXT_CSCAN_SSID_SECTION:
					if (len < 1) {
						len = 0;
						break;
					}
					sec_len = *(pos++); len -= 1;
					/*
					 * Fix CVE-2021-28660
					 *  -1 line, +3 lines
					 */
					if (sec_len > 0 &&
					    sec_len <= len &&
					    sec_len <= 32) {
						ssid[ssid_index].SsidLength = sec_len;
						/*
						 * Fix CVE-2021-28660
						 *  -1 line, +1 line
						 */
						memcpy(ssid[ssid_index].Ssid, pos, sec_len);
						ssid_index++;
					}
					pos += sec_len;
					len -= sec_len;
					break;
				case WEXT_CSCAN_TYPE_SECTION:
				case WEXT_CSCAN_CHANNEL_SECTION:
					pos += 1;
					len -= 1;
					break;
				case WEXT_CSCAN_PASV_DWELL_SECTION:
				case WEXT_CSCAN_HOME_DWELL_SECTION:
				case WEXT_CSCAN_ACTV_DWELL_SECTION:
					pos += 2;
					len -= 2;
					break;
				default:
					len = 0; /*  stop parsing */
				}
			}

			/* it has still some scan parameter to parse, we only do this now... */
			_status = (*klpe_rtw_set_802_11_bssid_list_scan)(padapter, ssid, RTW_SSID_SCAN_AMOUNT);
		} else {
			_status = (*klpe_rtw_set_802_11_bssid_list_scan)(padapter, NULL, 0);
		}
	}

	if (!_status)
		ret = -1;

exit:

	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1183658.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "r8188eu"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "GlobalDebugLevel", (void *)&klpe_GlobalDebugLevel, "r8188eu" },
	{ "rtw_sitesurvey_cmd", (void *)&klpe_rtw_sitesurvey_cmd, "r8188eu" },
	{ "indicate_wx_scan_complete_event",
	  (void *)&klpe_indicate_wx_scan_complete_event, "r8188eu" },
	{ "_rtw_pwr_wakeup", (void *)&klpe__rtw_pwr_wakeup, "r8188eu" },
	{ "rtw_set_802_11_bssid_list_scan",
	  (void *)&klpe_rtw_set_802_11_bssid_list_scan, "r8188eu" },};

static int livepatch_bsc1183658_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1183658_module_nb = {
	.notifier_call = livepatch_bsc1183658_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1183658_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1183658_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1183658_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1183658_module_nb);
}

#endif /* IS_ENABLED(CONFIG_R8188EU) */
