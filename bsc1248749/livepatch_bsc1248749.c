/*
 * livepatch_bsc1248749
 *
 * Fix for CVE-2025-38644, bsc#1248749
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

#if IS_ENABLED(CONFIG_MAC80211)

#if !IS_MODULE(CONFIG_MAC80211)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/mac80211/tdls.c */
#include <linux/ieee80211.h>
#include <linux/log2.h>
#include <net/cfg80211.h>

/* klp-ccp: from net/mac80211/ieee80211_i.h */
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/etherdevice.h>
#include <linux/leds.h>
#include <linux/idr.h>

/* klp-ccp: from include/linux/rhashtable.h */
#define _LINUX_RHASHTABLE_H

/* klp-ccp: from net/mac80211/ieee80211_i.h */
#include <linux/rbtree.h>
#include <kunit/visibility.h>

/* klp-ccp: from include/net/ieee80211_radiotap.h */
#define __RADIOTAP_H

/* klp-ccp: from net/mac80211/ieee80211_i.h */
#include <net/cfg80211.h>
#include <net/mac80211.h>
#include <net/fq.h>

/* klp-ccp: from net/mac80211/key.h */
#include <linux/types.h>
#include <linux/list.h>

#include <linux/rcupdate.h>
#include <crypto/arc4.h>
#include <net/mac80211.h>

#define NUM_DEFAULT_KEYS 4
#define NUM_DEFAULT_MGMT_KEYS 2
#define NUM_DEFAULT_BEACON_KEYS 2

/* klp-ccp: from net/mac80211/sta_info.h */
#include <linux/list.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/workqueue.h>
#include <linux/average.h>
#include <linux/bitfield.h>
#include <linux/etherdevice.h>
#include <linux/rhashtable.h>
#include <linux/u64_stats_sync.h>

enum ieee80211_sta_info_flags {
	WLAN_STA_AUTH,
	WLAN_STA_ASSOC,
	WLAN_STA_PS_STA,
	WLAN_STA_AUTHORIZED,
	WLAN_STA_SHORT_PREAMBLE,
	WLAN_STA_WDS,
	WLAN_STA_CLEAR_PS_FILT,
	WLAN_STA_MFP,
	WLAN_STA_BLOCK_BA,
	WLAN_STA_PS_DRIVER,
	WLAN_STA_PSPOLL,
	WLAN_STA_TDLS_PEER,
	WLAN_STA_TDLS_PEER_AUTH,
	WLAN_STA_TDLS_INITIATOR,
	WLAN_STA_TDLS_CHAN_SWITCH,
	WLAN_STA_TDLS_OFF_CHANNEL,
	WLAN_STA_TDLS_WIDER_BW,
	WLAN_STA_UAPSD,
	WLAN_STA_SP,
	WLAN_STA_4ADDR_EVENT,
	WLAN_STA_INSERTED,
	WLAN_STA_RATE_CONTROL,
	WLAN_STA_TOFFSET_KNOWN,
	WLAN_STA_MPSP_OWNER,
	WLAN_STA_MPSP_RECIPIENT,
	WLAN_STA_PS_DELIVER,
	WLAN_STA_USES_ENCRYPTION,
	WLAN_STA_DECAP_OFFLOAD,

	NUM_WLAN_STA_FLAGS,
};

struct ewma_avg_signal { unsigned long internal; };

struct airtime_info {
	u64 rx_airtime;
	u64 tx_airtime;
	unsigned long last_active;
	s32 deficit;
	atomic_t aql_tx_pending; /* Estimated airtime for frames pending */
	u32 aql_limit_low;
	u32 aql_limit_high;
};

struct sta_ampdu_mlme {
	/* rx */
	struct tid_ampdu_rx __rcu *tid_rx[IEEE80211_NUM_TIDS];
	u8 tid_rx_token[IEEE80211_NUM_TIDS];
	unsigned long tid_rx_timer_expired[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long tid_rx_stop_requested[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long tid_rx_manage_offl[BITS_TO_LONGS(2 * IEEE80211_NUM_TIDS)];
	unsigned long agg_session_valid[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long unexpected_agg[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	/* tx */
	struct wiphy_work work;
	struct tid_ampdu_tx __rcu *tid_tx[IEEE80211_NUM_TIDS];
	struct tid_ampdu_tx *tid_start_tx[IEEE80211_NUM_TIDS];
	unsigned long last_addba_req_time[IEEE80211_NUM_TIDS];
	u8 addba_req_num[IEEE80211_NUM_TIDS];
	u8 dialog_token_allocator;
};

struct ewma_signal { unsigned long internal; };

struct ieee80211_sta_rx_stats {
	unsigned long packets;
	unsigned long last_rx;
	unsigned long num_duplicates;
	unsigned long fragments;
	unsigned long dropped;
	int last_signal;
	u8 chains;
	s8 chain_signal_last[IEEE80211_MAX_CHAINS];
	u32 last_rate;
	struct u64_stats_sync syncp;
	u64 bytes;
	u64 msdu[IEEE80211_NUM_TIDS + 1];
};

#define IEEE80211_FRAGMENT_MAX 4

struct ieee80211_fragment_entry {
	struct sk_buff_head skb_list;
	unsigned long first_frag_time;
	u16 seq;
	u16 extra_len;
	u16 last_frag;
	u8 rx_queue;
	u8 check_sequential_pn:1, /* needed for CCMP/GCMP */
	   is_protected:1;
	u8 last_pn[6]; /* PN of the last fragment if CCMP was used */
	unsigned int key_color;
};

struct ieee80211_fragment_cache {
	struct ieee80211_fragment_entry	entries[IEEE80211_FRAGMENT_MAX];
	unsigned int next;
};

struct link_sta_info {
	u8 addr[ETH_ALEN];
	u8 link_id;

	u8 op_mode_nss, capa_nss;

	struct rhlist_head link_hash_node;

	struct sta_info *sta;
	struct ieee80211_key __rcu *gtk[NUM_DEFAULT_KEYS +
					NUM_DEFAULT_MGMT_KEYS +
					NUM_DEFAULT_BEACON_KEYS];
	struct ieee80211_sta_rx_stats __percpu *pcpu_rx_stats;

	/* Updated from RX path only, no locking requirements */
	struct ieee80211_sta_rx_stats rx_stats;
	struct {
		struct ewma_signal signal;
		struct ewma_signal chain_signal[IEEE80211_MAX_CHAINS];
	} rx_stats_avg;

	/* Updated from TX status path only, no locking requirements */
	struct {
		unsigned long filtered;
		unsigned long retry_failed, retry_count;
		unsigned int lost_packets;
		unsigned long last_pkt_time;
		u64 msdu_retries[IEEE80211_NUM_TIDS + 1];
		u64 msdu_failed[IEEE80211_NUM_TIDS + 1];
		unsigned long last_ack;
		s8 last_ack_signal;
		bool ack_signal_filled;
		struct ewma_avg_signal avg_ack_signal;
	} status_stats;

	/* Updated from TX path only, no locking requirements */
	struct {
		u64 packets[IEEE80211_NUM_ACS];
		u64 bytes[IEEE80211_NUM_ACS];
		struct ieee80211_tx_rate last_rate;
		struct rate_info last_rate_info;
		u64 msdu[IEEE80211_NUM_TIDS + 1];
	} tx_stats;

	enum ieee80211_sta_rx_bandwidth cur_max_bandwidth;

#ifdef CONFIG_MAC80211_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	struct ieee80211_link_sta *pub;
};

struct sta_info {
	/* General information, mostly static */
	struct list_head list, free_list;
	struct rcu_head rcu_head;
	struct rhlist_head hash_node;
	u8 addr[ETH_ALEN];
	struct ieee80211_local *local;
	struct ieee80211_sub_if_data *sdata;
	struct ieee80211_key __rcu *ptk[NUM_DEFAULT_KEYS];
	u8 ptk_idx;
	struct rate_control_ref *rate_ctrl;
	void *rate_ctrl_priv;
	spinlock_t rate_ctrl_lock;
	spinlock_t lock;

	struct ieee80211_fast_tx __rcu *fast_tx;
	struct ieee80211_fast_rx __rcu *fast_rx;

#ifdef CONFIG_MAC80211_MESH
	struct mesh_sta *mesh;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct work_struct drv_deliver_wk;

	u16 listen_interval;

	bool dead;
	bool removed;

	bool uploaded;

	enum ieee80211_sta_state sta_state;

	/* use the accessors defined below */
	unsigned long _flags;

	/* STA powersave lock and frame queues */
	spinlock_t ps_lock;
	struct sk_buff_head ps_tx_buf[IEEE80211_NUM_ACS];
	struct sk_buff_head tx_filtered[IEEE80211_NUM_ACS];
	unsigned long driver_buffered_tids;
	unsigned long txq_buffered_tids;

	u64 assoc_at;
	long last_connected;

	/* Plus 1 for non-QoS frames */
	__le16 last_seq_ctrl[IEEE80211_NUM_TIDS + 1];

	u16 tid_seq[IEEE80211_QOS_CTL_TID_MASK + 1];

	struct airtime_info airtime[IEEE80211_NUM_ACS];
	u16 airtime_weight;

	/*
	 * Aggregation information, locked with lock.
	 */
	struct sta_ampdu_mlme ampdu_mlme;

#ifdef CONFIG_MAC80211_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	struct codel_params cparams;

	u8 reserved_tid;
	s8 amsdu_mesh_control;

	struct cfg80211_chan_def tdls_chandef;

	struct ieee80211_fragment_cache frags;

	struct ieee80211_sta_aggregates cur;
	struct link_sta_info deflink;
	struct link_sta_info __rcu *link[IEEE80211_MLD_MAX_NUM_LINKS];

	/* keep last! */
	struct ieee80211_sta sta;
};

static inline void set_sta_flag(struct sta_info *sta,
				enum ieee80211_sta_info_flags flag)
{
	WARN_ON(flag == WLAN_STA_AUTH ||
		flag == WLAN_STA_ASSOC ||
		flag == WLAN_STA_AUTHORIZED);
	set_bit(flag, &sta->_flags);
}

static inline int test_sta_flag(struct sta_info *sta,
				enum ieee80211_sta_info_flags flag)
{
	return test_bit(flag, &sta->_flags);
}

struct sta_info *sta_info_get(struct ieee80211_sub_if_data *sdata,
			      const u8 *addr);

int sta_info_destroy_addr(struct ieee80211_sub_if_data *sdata,
			  const u8 *addr);

/* klp-ccp: from net/mac80211/debug.h */
#include <net/cfg80211.h>

#define MAC80211_TDLS_DEBUG 0

#define _sdata_dbg(print, sdata, fmt, ...)				\
do {									\
	if (print)							\
		pr_debug("%s: " fmt,					\
			 (sdata)->name, ##__VA_ARGS__);			\
} while (0)

#define tdls_dbg(sdata, fmt, ...)					\
	_sdata_dbg(MAC80211_TDLS_DEBUG,					\
		   sdata, fmt, ##__VA_ARGS__)

/* klp-ccp: from net/mac80211/ieee80211_i.h */
struct ps_data {
	/* yes, this looks ugly, but guarantees that we can later use
	 * bitmap_empty :)
	 * NB: don't touch this bitmap, use sta_info_{set,clear}_tim_bit */
	u8 tim[sizeof(unsigned long) * BITS_TO_LONGS(IEEE80211_MAX_AID + 1)]
			__aligned(__alignof__(unsigned long));
	struct sk_buff_head bc_buf;
	atomic_t num_sta_ps; /* number of stations in PS mode */
	int dtim_count;
	bool dtim_bc_mc;
};

struct ieee80211_if_ap {
	struct list_head vlans; /* write-protected with RTNL and local->mtx */

	struct ps_data ps;
	atomic_t num_mcast_sta; /* number of stations receiving multicast */

	bool multicast_to_unicast;
	bool active;
};

struct ieee80211_if_vlan {
	struct list_head list; /* write-protected with RTNL and local->mtx */

	/* used for all tx if the VLAN is configured to 4-addr mode */
	struct sta_info __rcu *sta;
	atomic_t num_mcast_sta; /* number of stations receiving multicast */
};

struct mesh_stats {
	__u32 fwded_mcast;		/* Mesh forwarded multicast frames */
	__u32 fwded_unicast;		/* Mesh forwarded unicast frames */
	__u32 fwded_frames;		/* Mesh total forwarded frames */
	__u32 dropped_frames_ttl;	/* Not transmitted since mesh_ttl == 0*/
	__u32 dropped_frames_no_route;	/* Not transmitted, no route found */
};

struct mesh_preq_queue {
	struct list_head list;
	u8 dst[ETH_ALEN];
	u8 flags;
};

enum ieee80211_conn_mode {
	IEEE80211_CONN_MODE_S1G,
	IEEE80211_CONN_MODE_LEGACY,
	IEEE80211_CONN_MODE_HT,
	IEEE80211_CONN_MODE_VHT,
	IEEE80211_CONN_MODE_HE,
	IEEE80211_CONN_MODE_EHT,
};

enum ieee80211_conn_bw_limit {
	IEEE80211_CONN_BW_LIMIT_20,
	IEEE80211_CONN_BW_LIMIT_40,
	IEEE80211_CONN_BW_LIMIT_80,
	IEEE80211_CONN_BW_LIMIT_160, /* also 80+80 */
	IEEE80211_CONN_BW_LIMIT_320,
};

struct ieee80211_conn_settings {
	enum ieee80211_conn_mode mode;
	enum ieee80211_conn_bw_limit bw_limit;
};

struct ieee80211_sta_tx_tspec {
	/* timestamp of the first packet in the time slice */
	unsigned long time_slice_start;

	u32 admitted_time; /* in usecs, unlike over the air */
	u8 tsid;
	s8 up; /* signed to be able to invalidate with -1 during teardown */

	/* consumed TX time in microseconds in the time slice */
	u32 consumed_tx_time;
	enum {
		TX_TSPEC_ACTION_NONE = 0,
		TX_TSPEC_ACTION_DOWNGRADE,
		TX_TSPEC_ACTION_STOP_DOWNGRADE,
	} action;
	bool downgraded;
};

struct ieee80211_adv_ttlm_info {
	/* time in TUs at which the new mapping is established, or 0 if there is
	 * no planned advertised TID-to-link mapping
	 */
	u16 switch_time;
	u32 duration; /* duration of the planned T2L map in TUs */
	u16 map; /* map of usable links for all TIDs */
	bool active; /* whether the advertised mapping is active or not */
};

struct ewma_beacon_signal { unsigned long internal; };

struct ieee80211_if_managed {
	struct timer_list timer;
	struct timer_list conn_mon_timer;
	struct timer_list bcn_mon_timer;
	struct wiphy_work monitor_work;
	struct wiphy_work beacon_connection_loss_work;
	struct wiphy_work csa_connection_drop_work;

	unsigned long beacon_timeout;
	unsigned long probe_timeout;
	int probe_send_count;
	bool nullfunc_failed;
	u8 connection_loss:1,
	   driver_disconnect:1,
	   reconnect:1,
	   associated:1;

	struct ieee80211_mgd_auth_data *auth_data;
	struct ieee80211_mgd_assoc_data *assoc_data;

	bool powersave; /* powersave requested for this iface */
	bool broken_ap; /* AP is broken -- turn off powersave */

	unsigned int flags;

	u16 mcast_seq_last;

	bool status_acked;
	bool status_received;
	__le16 status_fc;

	enum {
		IEEE80211_MFP_DISABLED,
		IEEE80211_MFP_OPTIONAL,
		IEEE80211_MFP_REQUIRED
	} mfp; /* management frame protection */

	/*
	 * Bitmask of enabled u-apsd queues,
	 * IEEE80211_WMM_IE_STA_QOSINFO_AC_BE & co. Needs a new association
	 * to take effect.
	 */
	unsigned int uapsd_queues;

	/*
	 * Maximum number of buffered frames AP can deliver during a
	 * service period, IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL or similar.
	 * Needs a new association to take effect.
	 */
	unsigned int uapsd_max_sp_len;

	u8 use_4addr;

	/*
	 * State variables for keeping track of RSSI of the AP currently
	 * connected to and informing driver when RSSI has gone
	 * below/above a certain threshold.
	 */
	int rssi_min_thold, rssi_max_thold;

	struct ieee80211_ht_cap ht_capa; /* configured ht-cap over-rides */
	struct ieee80211_ht_cap ht_capa_mask; /* Valid parts of ht_capa */
	struct ieee80211_vht_cap vht_capa; /* configured VHT overrides */
	struct ieee80211_vht_cap vht_capa_mask; /* Valid parts of vht_capa */
	struct ieee80211_s1g_cap s1g_capa; /* configured S1G overrides */
	struct ieee80211_s1g_cap s1g_capa_mask; /* valid s1g_capa bits */

	/* TDLS support */
	u8 tdls_peer[ETH_ALEN] __aligned(2);
	struct wiphy_delayed_work tdls_peer_del_work;
	struct sk_buff *orig_teardown_skb; /* The original teardown skb */
	struct sk_buff *teardown_skb; /* A copy to send through the AP */
	spinlock_t teardown_lock; /* To lock changing teardown_skb */
	bool tdls_wider_bw_prohibited;

	/* WMM-AC TSPEC support */
	struct ieee80211_sta_tx_tspec tx_tspec[IEEE80211_NUM_ACS];
	/* Use a separate work struct so that we can do something here
	 * while the sdata->work is flushing the queues, for example.
	 * otherwise, in scenarios where we hardly get any traffic out
	 * on the BE queue, but there's a lot of VO traffic, we might
	 * get stuck in a downgraded situation and flush takes forever.
	 */
	struct wiphy_delayed_work tx_tspec_wk;

	/* Information elements from the last transmitted (Re)Association
	 * Request frame.
	 */
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;

	struct wiphy_delayed_work ml_reconf_work;
	u16 removed_links;

	/* TID-to-link mapping support */
	struct wiphy_delayed_work ttlm_work;
	struct ieee80211_adv_ttlm_info ttlm_info;
	struct wiphy_work teardown_ttlm_work;

	/* dialog token enumerator for neg TTLM request */
	u8 dialog_token_alloc;
	struct wiphy_delayed_work neg_ttlm_timeout_work;

	void *suse_kabi_padding;	/* XXX SLE-specific kABI placeholder */
};

struct ieee80211_if_ibss {
	struct timer_list timer;
	struct wiphy_work csa_connection_drop_work;

	unsigned long last_scan_completed;

	u32 basic_rates;

	bool fixed_bssid;
	bool fixed_channel;
	bool privacy;

	bool control_port;
	bool userspace_handles_dfs;

	u8 bssid[ETH_ALEN] __aligned(2);
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len, ie_len;
	u8 *ie;
	struct cfg80211_chan_def chandef;

	unsigned long ibss_join_req;
	/* probe response/beacon for IBSS */
	struct beacon_data __rcu *presp;

	struct ieee80211_ht_cap ht_capa; /* configured ht-cap over-rides */
	struct ieee80211_ht_cap ht_capa_mask; /* Valid parts of ht_capa */

	spinlock_t incomplete_lock;
	struct list_head incomplete_stations;

	enum {
		IEEE80211_IBSS_MLME_SEARCH,
		IEEE80211_IBSS_MLME_JOINED,
	} state;
};

struct ieee80211_if_ocb {
	struct timer_list housekeeping_timer;
	unsigned long wrkq_flags;

	spinlock_t incomplete_lock;
	struct list_head incomplete_stations;

	bool joined;
};

struct mesh_table {
	struct hlist_head known_gates;
	spinlock_t gates_lock;
	struct rhashtable rhead;
	struct hlist_head walk_head;
	spinlock_t walk_lock;
	atomic_t entries;		/* Up to MAX_MESH_NEIGHBOURS */
};

struct mesh_tx_cache {
	struct rhashtable rht;
	struct hlist_head walk_head;
	spinlock_t walk_lock;
};

struct ieee80211_if_mesh {
	struct timer_list housekeeping_timer;
	struct timer_list mesh_path_timer;
	struct timer_list mesh_path_root_timer;

	unsigned long wrkq_flags;
	unsigned long mbss_changed[64 / BITS_PER_LONG];

	bool userspace_handles_dfs;

	u8 mesh_id[IEEE80211_MAX_MESH_ID_LEN];
	size_t mesh_id_len;
	/* Active Path Selection Protocol Identifier */
	u8 mesh_pp_id;
	/* Active Path Selection Metric Identifier */
	u8 mesh_pm_id;
	/* Congestion Control Mode Identifier */
	u8 mesh_cc_id;
	/* Synchronization Protocol Identifier */
	u8 mesh_sp_id;
	/* Authentication Protocol Identifier */
	u8 mesh_auth_id;
	/* Local mesh Sequence Number */
	u32 sn;
	/* Last used PREQ ID */
	u32 preq_id;
	atomic_t mpaths;
	/* Timestamp of last SN update */
	unsigned long last_sn_update;
	/* Time when it's ok to send next PERR */
	unsigned long next_perr;
	/* Timestamp of last PREQ sent */
	unsigned long last_preq;
	struct mesh_rmc *rmc;
	spinlock_t mesh_preq_queue_lock;
	struct mesh_preq_queue preq_queue;
	int preq_queue_len;
	struct mesh_stats mshstats;
	struct mesh_config mshcfg;
	atomic_t estab_plinks;
	atomic_t mesh_seqnum;
	bool accepting_plinks;
	int num_gates;
	struct beacon_data __rcu *beacon;
	const u8 *ie;
	u8 ie_len;
	enum {
		IEEE80211_MESH_SEC_NONE = 0x0,
		IEEE80211_MESH_SEC_AUTHED = 0x1,
		IEEE80211_MESH_SEC_SECURED = 0x2,
	} security;
	bool user_mpm;
	/* Extensible Synchronization Framework */
	const struct ieee80211_mesh_sync_ops *sync_ops;
	s64 sync_offset_clockdrift_max;
	spinlock_t sync_offset_lock;
	/* mesh power save */
	enum nl80211_mesh_power_mode nonpeer_pm;
	int ps_peers_light_sleep;
	int ps_peers_deep_sleep;
	struct ps_data ps;
	/* Channel Switching Support */
	struct mesh_csa_settings __rcu *csa;
	enum {
		IEEE80211_MESH_CSA_ROLE_NONE,
		IEEE80211_MESH_CSA_ROLE_INIT,
		IEEE80211_MESH_CSA_ROLE_REPEATER,
	} csa_role;
	u8 chsw_ttl;
	u16 pre_value;

	/* offset from skb->data while building IE */
	int meshconf_offset;

	struct mesh_table mesh_paths;
	struct mesh_table mpp_paths; /* Store paths for MPP&MAP */
	int mesh_paths_generation;
	int mpp_paths_generation;
	struct mesh_tx_cache tx_cache;
};

struct ieee80211_if_mntr {
	u32 flags;
	u8 mu_follow_addr[ETH_ALEN] __aligned(2);

	struct list_head list;
};

struct ieee80211_if_nan {
	struct cfg80211_nan_conf conf;

	/* protects function_inst_ids */
	spinlock_t func_lock;
	struct idr function_inst_ids;
};

struct ieee80211_link_data_managed {
	u8 bssid[ETH_ALEN] __aligned(2);

	u8 dtim_period;
	enum ieee80211_smps_mode req_smps, /* requested smps mode */
				 driver_smps_mode; /* smps mode request */

	struct ieee80211_conn_settings conn;

	s16 p2p_noa_index;

	bool tdls_chan_switch_prohibited;

	bool have_beacon;
	bool tracking_signal_avg;
	bool disable_wmm_tracking;
	bool operating_11g_mode;

	struct {
		struct wiphy_delayed_work switch_work;
		struct cfg80211_chan_def ap_chandef;
		struct ieee80211_parsed_tpe tpe;
		unsigned long time;
		bool waiting_bcn;
		bool ignored_same_chan;
		bool blocked_tx;
	} csa;

	struct wiphy_work request_smps_work;
	/* used to reconfigure hardware SM PS */
	struct wiphy_work recalc_smps;

	bool beacon_crc_valid;
	u32 beacon_crc;
	struct ewma_beacon_signal ave_beacon_signal;
	int last_ave_beacon_signal;

	/*
	 * Number of Beacon frames used in ave_beacon_signal. This can be used
	 * to avoid generating less reliable cqm events that would be based
	 * only on couple of received frames.
	 */
	unsigned int count_beacon_signal;

	/* Number of times beacon loss was invoked. */
	unsigned int beacon_loss_count;

	/*
	 * Last Beacon frame signal strength average (ave_beacon_signal / 16)
	 * that triggered a cqm event. 0 indicates that no event has been
	 * generated for the current association.
	 */
	int last_cqm_event_signal;

	int wmm_last_param_set;
	int mu_edca_last_param_set;

	u8 bss_param_ch_cnt;
};

struct ieee80211_link_data_ap {
	struct beacon_data __rcu *beacon;
	struct probe_resp __rcu *probe_resp;
	struct fils_discovery_data __rcu *fils_discovery;
	struct unsol_bcast_probe_resp_data __rcu *unsol_bcast_probe_resp;

	/* to be used after channel switch. */
	struct cfg80211_beacon_data *next_beacon;
};

struct ieee80211_link_data {
	struct ieee80211_sub_if_data *sdata;
	unsigned int link_id;

	struct list_head assigned_chanctx_list; /* protected by wiphy mutex */
	struct list_head reserved_chanctx_list; /* protected by wiphy mutex */

	/* multicast keys only */
	struct ieee80211_key __rcu *gtk[NUM_DEFAULT_KEYS +
					NUM_DEFAULT_MGMT_KEYS +
					NUM_DEFAULT_BEACON_KEYS];
	struct ieee80211_key __rcu *default_multicast_key;
	struct ieee80211_key __rcu *default_mgmt_key;
	struct ieee80211_key __rcu *default_beacon_key;


	bool operating_11g_mode;

	struct {
		struct wiphy_work finalize_work;
		struct ieee80211_chan_req chanreq;
	} csa;

	struct wiphy_work color_change_finalize_work;
	struct wiphy_delayed_work color_collision_detect_work;
	u64 color_bitmap;

	/* context reservation -- protected with wiphy mutex */
	struct ieee80211_chanctx *reserved_chanctx;
	struct ieee80211_chan_req reserved;
	bool reserved_radar_required;
	bool reserved_ready;

	u8 needed_rx_chains;
	enum ieee80211_smps_mode smps_mode;

	int user_power_level; /* in dBm */
	int ap_power_level; /* in dBm */

	bool radar_required;
	struct wiphy_delayed_work dfs_cac_timer_work;

	union {
		struct ieee80211_link_data_managed mgd;
		struct ieee80211_link_data_ap ap;
	} u;

	struct ieee80211_tx_queue_params tx_conf[IEEE80211_NUM_ACS];

	struct ieee80211_bss_conf *conf;

#ifdef CONFIG_MAC80211_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	void *suse_kabi_padding;	/* XXX SLE-specific kABI placeholder */
};

struct ieee80211_sub_if_data {
	struct list_head list;

	struct wireless_dev wdev;

	/* keys */
	struct list_head key_list;

	/* count for keys needing tailroom space allocation */
	int crypto_tx_tailroom_needed_cnt;
	int crypto_tx_tailroom_pending_dec;
	struct wiphy_delayed_work dec_tailroom_needed_wk;

	struct net_device *dev;
	struct ieee80211_local *local;

	unsigned int flags;

	unsigned long state;

	char name[IFNAMSIZ];

	struct ieee80211_fragment_cache frags;

	/* TID bitmap for NoAck policy */
	u16 noack_map;

	/* bit field of ACM bits (BIT(802.1D tag)) */
	u8 wmm_acm;

	struct ieee80211_key __rcu *keys[NUM_DEFAULT_KEYS];
	struct ieee80211_key __rcu *default_unicast_key;

	u16 sequence_number;
	u16 mld_mcast_seq;
	__be16 control_port_protocol;
	bool control_port_no_encrypt;
	bool control_port_no_preauth;
	bool control_port_over_nl80211;

	atomic_t num_tx_queued;
	struct mac80211_qos_map __rcu *qos_map;

	struct wiphy_work work;
	struct sk_buff_head skb_queue;
	struct sk_buff_head status_queue;

	/*
	 * AP this belongs to: self in AP mode and
	 * corresponding AP in VLAN mode, NULL for
	 * all others (might be needed later in IBSS)
	 */
	struct ieee80211_if_ap *bss;

	/* bitmap of allowed (non-MCS) rate indexes for rate control */
	u32 rc_rateidx_mask[NUM_NL80211_BANDS];

	bool rc_has_mcs_mask[NUM_NL80211_BANDS];
	u8  rc_rateidx_mcs_mask[NUM_NL80211_BANDS][IEEE80211_HT_MCS_MASK_LEN];

	bool rc_has_vht_mcs_mask[NUM_NL80211_BANDS];
	u16 rc_rateidx_vht_mcs_mask[NUM_NL80211_BANDS][NL80211_VHT_NSS_MAX];

	/* Beacon frame (non-MCS) rate (as a bitmap) */
	u32 beacon_rateidx_mask[NUM_NL80211_BANDS];
	bool beacon_rate_set;

	union {
		struct ieee80211_if_ap ap;
		struct ieee80211_if_vlan vlan;
		struct ieee80211_if_managed mgd;
		struct ieee80211_if_ibss ibss;
		struct ieee80211_if_mesh mesh;
		struct ieee80211_if_ocb ocb;
		struct ieee80211_if_mntr mntr;
		struct ieee80211_if_nan nan;
	} u;

	struct ieee80211_link_data deflink;
	struct ieee80211_link_data __rcu *link[IEEE80211_MLD_MAX_NUM_LINKS];

	/* for ieee80211_set_active_links_async() */
	struct wiphy_work activate_links_work;
	u16 desired_active_links;

	u16 restart_active_links;

#ifdef CONFIG_MAC80211_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	void *suse_kabi_padding;	/* XXX SLE-specific kABI placeholder */

	/* must be last, dynamically sized area in this! */
	struct ieee80211_vif vif;
};

enum queue_stop_reason {
	IEEE80211_QUEUE_STOP_REASON_DRIVER,
	IEEE80211_QUEUE_STOP_REASON_PS,
	IEEE80211_QUEUE_STOP_REASON_CSA,
	IEEE80211_QUEUE_STOP_REASON_AGGREGATION,
	IEEE80211_QUEUE_STOP_REASON_SUSPEND,
	IEEE80211_QUEUE_STOP_REASON_SKB_ADD,
	IEEE80211_QUEUE_STOP_REASON_OFFCHANNEL,
	IEEE80211_QUEUE_STOP_REASON_FLUSH,
	IEEE80211_QUEUE_STOP_REASON_TDLS_TEARDOWN,
	IEEE80211_QUEUE_STOP_REASON_RESERVE_TID,
	IEEE80211_QUEUE_STOP_REASON_IFTYPE_CHANGE,

	IEEE80211_QUEUE_STOP_REASONS,
};

enum mac80211_scan_state {
	SCAN_DECISION,
	SCAN_SET_CHANNEL,
	SCAN_SEND_PROBE,
	SCAN_SUSPEND,
	SCAN_RESUME,
	SCAN_ABORT,
};

struct ieee80211_local {
	/* embed the driver visible part.
	 * don't cast (use the static inlines below), but we keep
	 * it first anyway so they become a no-op */
	struct ieee80211_hw hw;

	struct fq fq;
	struct codel_vars *cvars;
	struct codel_params cparams;

	/* protects active_txqs and txqi->schedule_order */
	spinlock_t active_txq_lock[IEEE80211_NUM_ACS];
	struct list_head active_txqs[IEEE80211_NUM_ACS];
	u16 schedule_round[IEEE80211_NUM_ACS];

	/* serializes ieee80211_handle_wake_tx_queue */
	spinlock_t handle_wake_tx_queue_lock;

	u16 airtime_flags;
	u32 aql_txq_limit_low[IEEE80211_NUM_ACS];
	u32 aql_txq_limit_high[IEEE80211_NUM_ACS];
	u32 aql_threshold;
	atomic_t aql_total_pending_airtime;
	atomic_t aql_ac_pending_airtime[IEEE80211_NUM_ACS];

	const struct ieee80211_ops *ops;

	/*
	 * private workqueue to mac80211. mac80211 makes this accessible
	 * via ieee80211_queue_work()
	 */
	struct workqueue_struct *workqueue;

	unsigned long queue_stop_reasons[IEEE80211_MAX_QUEUES];
	int q_stop_reasons[IEEE80211_MAX_QUEUES][IEEE80211_QUEUE_STOP_REASONS];
	/* also used to protect ampdu_ac_queue and amdpu_ac_stop_refcnt */
	spinlock_t queue_stop_reason_lock;

	int open_count;
	int monitors, cooked_mntrs;
	/* number of interfaces with corresponding FIF_ flags */
	int fif_fcsfail, fif_plcpfail, fif_control, fif_other_bss, fif_pspoll,
	    fif_probe_req;
	bool probe_req_reg;
	bool rx_mcast_action_reg;
	unsigned int filter_flags; /* FIF_* */

	bool wiphy_ciphers_allocated;

	struct cfg80211_chan_def dflt_chandef;
	bool emulate_chanctx;

	/* protects the aggregated multicast list and filter calls */
	spinlock_t filter_lock;

	/* used for uploading changed mc list */
	struct wiphy_work reconfig_filter;

	/* aggregated multicast list */
	struct netdev_hw_addr_list mc_list;

	bool tim_in_locked_section; /* see ieee80211_beacon_get() */

	/*
	 * suspended is true if we finished all the suspend _and_ we have
	 * not yet come up from resume. This is to be used by mac80211
	 * to ensure driver sanity during suspend and mac80211's own
	 * sanity. It can eventually be used for WoW as well.
	 */
	bool suspended;

	/* suspending is true during the whole suspend process */
	bool suspending;

	/*
	 * Resuming is true while suspended, but when we're reprogramming the
	 * hardware -- at that time it's allowed to use ieee80211_queue_work()
	 * again even though some other parts of the stack are still suspended
	 * and we still drop received frames to avoid waking the stack.
	 */
	bool resuming;

	/*
	 * quiescing is true during the suspend process _only_ to
	 * ease timer cancelling etc.
	 */
	bool quiescing;

	/* device is started */
	bool started;

	/* device is during a HW reconfig */
	bool in_reconfig;

	/* reconfiguration failed ... suppress some warnings etc. */
	bool reconfig_failure;

	/* wowlan is enabled -- don't reconfig on resume */
	bool wowlan;

	struct wiphy_work radar_detected_work;

	/* number of RX chains the hardware has */
	u8 rx_chains;

	/* bitmap of which sbands were copied */
	u8 sband_allocated;

	int tx_headroom; /* required headroom for hardware/radiotap */

	/* Tasklet and skb queue to process calls from IRQ mode. All frames
	 * added to skb_queue will be processed, but frames in
	 * skb_queue_unreliable may be dropped if the total length of these
	 * queues increases over the limit. */
	struct tasklet_struct tasklet;
	struct sk_buff_head skb_queue;
	struct sk_buff_head skb_queue_unreliable;

	spinlock_t rx_path_lock;

	/* Station data */
	/*
	 * The list, hash table and counter are protected
	 * by the wiphy mutex, reads are done with RCU.
	 */
	spinlock_t tim_lock;
	unsigned long num_sta;
	struct list_head sta_list;
	struct rhltable sta_hash;
	struct rhltable link_sta_hash;
	struct timer_list sta_cleanup;
	int sta_generation;

	struct sk_buff_head pending[IEEE80211_MAX_QUEUES];
	struct tasklet_struct tx_pending_tasklet;
	struct tasklet_struct wake_txqs_tasklet;

	atomic_t agg_queue_stop[IEEE80211_MAX_QUEUES];

	/* number of interfaces with allmulti RX */
	atomic_t iff_allmultis;

	struct rate_control_ref *rate_ctrl;

	struct arc4_ctx wep_tx_ctx;
	struct arc4_ctx wep_rx_ctx;
	u32 wep_iv;

	/* see iface.c */
	struct list_head interfaces;
	struct list_head mon_list; /* only that are IFF_UP && !cooked */
	struct mutex iflist_mtx;

	/* Scanning and BSS list */
	unsigned long scanning;
	struct cfg80211_ssid scan_ssid;
	struct cfg80211_scan_request *int_scan_req;
	struct cfg80211_scan_request __rcu *scan_req;
	struct ieee80211_scan_request *hw_scan_req;
	struct cfg80211_chan_def scan_chandef;
	enum nl80211_band hw_scan_band;
	int scan_channel_idx;
	int scan_ies_len;
	int hw_scan_ies_bufsize;
	struct cfg80211_scan_info scan_info;

	struct wiphy_work sched_scan_stopped_work;
	struct ieee80211_sub_if_data __rcu *sched_scan_sdata;
	struct cfg80211_sched_scan_request __rcu *sched_scan_req;
	u8 scan_addr[ETH_ALEN];

	unsigned long leave_oper_channel_time;
	enum mac80211_scan_state next_scan_state;
	struct wiphy_delayed_work scan_work;
	struct ieee80211_sub_if_data __rcu *scan_sdata;

	/* Temporary remain-on-channel for off-channel operations */
	struct ieee80211_channel *tmp_channel;

	/* channel contexts */
	struct list_head chanctx_list;

#ifdef CONFIG_MAC80211_LEDS
	struct led_trigger tx_led, rx_led, assoc_led, radio_led;
	struct led_trigger tpt_led;
	atomic_t tx_led_active, rx_led_active, assoc_led_active;
	atomic_t radio_led_active, tpt_led_active;
	struct tpt_led_trigger *tpt_led_trigger;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_MAC80211_DEBUG_COUNTERS
#error "klp-ccp: non-taken branch"
#else /* CONFIG_MAC80211_DEBUG_COUNTERS */

#endif /* CONFIG_MAC80211_DEBUG_COUNTERS */
	int total_ps_buffered; /* total number of all buffered unicast and
				* multicast packets for power saving stations
				*/

	bool pspolling;
	/*
	 * PS can only be enabled when we have exactly one managed
	 * interface (and monitors) in PS, this then points there.
	 */
	struct ieee80211_sub_if_data *ps_sdata;
	struct wiphy_work dynamic_ps_enable_work;
	struct wiphy_work dynamic_ps_disable_work;
	struct timer_list dynamic_ps_timer;
	struct notifier_block ifa_notifier;
	struct notifier_block ifa6_notifier;

	/*
	 * The dynamic ps timeout configured from user space via WEXT -
	 * this will override whatever chosen by mac80211 internally.
	 */
	int dynamic_ps_forced_timeout;

	int user_power_level; /* in dBm, for all interfaces */

	struct work_struct restart_work;

#ifdef CONFIG_MAC80211_DEBUGFS
#error "klp-ccp: non-taken branch"
#endif
	struct wiphy_delayed_work roc_work;
	struct list_head roc_list;
	struct wiphy_work hw_roc_start, hw_roc_done;
	unsigned long hw_roc_start_time;
	u64 roc_cookie_counter;

	struct idr ack_status_frames;
	spinlock_t ack_status_lock;

	struct ieee80211_sub_if_data __rcu *p2p_sdata;

	/* virtual monitor interface */
	struct ieee80211_sub_if_data __rcu *monitor_sdata;
	struct ieee80211_chan_req monitor_chanreq;

	/* extended capabilities provided by mac80211 */
	u8 ext_capa[8];

	bool wbrf_supported;

	void *suse_kabi_padding;	/* XXX SLE-specific kABI placeholder */
};

static inline struct ieee80211_sub_if_data *
IEEE80211_DEV_TO_SUB_IF(const struct net_device *dev)
{
	return netdev_priv(dev);
}

void ieee80211_link_info_change_notify(struct ieee80211_sub_if_data *sdata,
				       struct ieee80211_link_data *link,
				       u64 changed);

void ieee80211_flush_queues(struct ieee80211_local *local,
			    struct ieee80211_sub_if_data *sdata, bool drop);

/* klp-ccp: from net/mac80211/driver-ops.h */
#include <net/mac80211.h>

/* klp-ccp: from net/mac80211/trace.h */
#if !defined(__MAC80211_DRIVER_TRACE) || defined(TRACE_HEADER_MULTI_READ)

#include <net/mac80211.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* !__MAC80211_DRIVER_TRACE || TRACE_HEADER_MULTI_READ */

#include <trace/define_trace.h>

/* klp-ccp: from net/mac80211/rate.h */
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/mac80211.h>

/* klp-ccp: from net/mac80211/wme.h */
#include <linux/netdevice.h>

/* klp-ccp: from net/mac80211/tdls.c */
extern void iee80211_tdls_recalc_chanctx(struct ieee80211_sub_if_data *sdata,
					 struct sta_info *sta);

static int iee80211_tdls_have_ht_peers(struct ieee80211_sub_if_data *sdata)
{
	struct sta_info *sta;
	bool result = false;

	rcu_read_lock();
	list_for_each_entry_rcu(sta, &sdata->local->sta_list, list) {
		if (!sta->sta.tdls || sta->sdata != sdata || !sta->uploaded ||
		    !test_sta_flag(sta, WLAN_STA_AUTHORIZED) ||
		    !test_sta_flag(sta, WLAN_STA_TDLS_PEER_AUTH) ||
		    !sta->sta.deflink.ht_cap.ht_supported)
			continue;
		result = true;
		break;
	}
	rcu_read_unlock();

	return result;
}

static void
iee80211_tdls_recalc_ht_protection(struct ieee80211_sub_if_data *sdata,
				   struct sta_info *sta)
{
	bool tdls_ht;
	u16 protection = IEEE80211_HT_OP_MODE_PROTECTION_NONHT_MIXED |
			 IEEE80211_HT_OP_MODE_NON_GF_STA_PRSNT |
			 IEEE80211_HT_OP_MODE_NON_HT_STA_PRSNT;
	u16 opmode;

	/* Nothing to do if the BSS connection uses (at least) HT */
	if (sdata->deflink.u.mgd.conn.mode >= IEEE80211_CONN_MODE_HT)
		return;

	tdls_ht = (sta && sta->sta.deflink.ht_cap.ht_supported) ||
		  iee80211_tdls_have_ht_peers(sdata);

	opmode = sdata->vif.bss_conf.ht_operation_mode;

	if (tdls_ht)
		opmode |= protection;
	else
		opmode &= ~protection;

	if (opmode == sdata->vif.bss_conf.ht_operation_mode)
		return;

	sdata->vif.bss_conf.ht_operation_mode = opmode;
	ieee80211_link_info_change_notify(sdata, &sdata->deflink,
					  BSS_CHANGED_HT);
}

int klpp_ieee80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
			const u8 *peer, enum nl80211_tdls_operation oper)
{
	struct sta_info *sta;
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = sdata->local;
	int ret;

	lockdep_assert_wiphy(local->hw.wiphy);

	if (!(wiphy->flags & WIPHY_FLAG_SUPPORTS_TDLS))
		return -EOPNOTSUPP;

	if (sdata->vif.type != NL80211_IFTYPE_STATION || !sdata->vif.cfg.assoc)
		return -EINVAL;

	switch (oper) {
	case NL80211_TDLS_ENABLE_LINK:
	case NL80211_TDLS_DISABLE_LINK:
		break;
	case NL80211_TDLS_TEARDOWN:
	case NL80211_TDLS_SETUP:
	case NL80211_TDLS_DISCOVERY_REQ:
		/* We don't support in-driver setup/teardown/discovery */
		return -EOPNOTSUPP;
	}

	/* protect possible bss_conf changes and avoid concurrency in
	 * ieee80211_bss_info_change_notify()
	 */
	tdls_dbg(sdata, "TDLS oper %d peer %pM\n", oper, peer);

	switch (oper) {
	case NL80211_TDLS_ENABLE_LINK:
		if (sdata->vif.bss_conf.csa_active) {
			tdls_dbg(sdata, "TDLS: disallow link during CSA\n");
			return -EBUSY;
		}

		sta = sta_info_get(sdata, peer);
		if (!sta)
			return -ENOLINK;

		iee80211_tdls_recalc_chanctx(sdata, sta);
		iee80211_tdls_recalc_ht_protection(sdata, sta);

		set_sta_flag(sta, WLAN_STA_TDLS_PEER_AUTH);

		WARN_ON_ONCE(is_zero_ether_addr(sdata->u.mgd.tdls_peer) ||
			     !ether_addr_equal(sdata->u.mgd.tdls_peer, peer));
		break;
	case NL80211_TDLS_DISABLE_LINK:
		/*
		 * The teardown message in ieee80211_tdls_mgmt_teardown() was
		 * created while the queues were stopped, so it might still be
		 * pending. Before flushing the queues we need to be sure the
		 * message is handled by the tasklet handling pending messages,
		 * otherwise we might start destroying the station before
		 * sending the teardown packet.
		 * Note that this only forces the tasklet to flush pendings -
		 * not to stop the tasklet from rescheduling itself.
		 */
		tasklet_kill(&local->tx_pending_tasklet);
		/* flush a potentially queued teardown packet */
		ieee80211_flush_queues(local, sdata, false);

		ret = sta_info_destroy_addr(sdata, peer);

		iee80211_tdls_recalc_ht_protection(sdata, NULL);

		iee80211_tdls_recalc_chanctx(sdata, NULL);
		if (ret)
			return ret;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ether_addr_equal(sdata->u.mgd.tdls_peer, peer)) {
		wiphy_delayed_work_cancel(sdata->local->hw.wiphy,
					  &sdata->u.mgd.tdls_peer_del_work);
		eth_zero_addr(sdata->u.mgd.tdls_peer);
	}

	wiphy_work_queue(sdata->local->hw.wiphy,
			 &sdata->deflink.u.mgd.request_smps_work);

	return 0;
}


#include "livepatch_bsc1248749.h"

#include <linux/livepatch.h>

extern typeof(iee80211_tdls_recalc_chanctx) iee80211_tdls_recalc_chanctx
	 KLP_RELOC_SYMBOL(mac80211, mac80211, iee80211_tdls_recalc_chanctx);
extern typeof(ieee80211_flush_queues) ieee80211_flush_queues
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_flush_queues);
extern typeof(ieee80211_link_info_change_notify)
	 ieee80211_link_info_change_notify
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_link_info_change_notify);
extern typeof(sta_info_destroy_addr) sta_info_destroy_addr
	 KLP_RELOC_SYMBOL(mac80211, mac80211, sta_info_destroy_addr);
extern typeof(sta_info_get) sta_info_get
	 KLP_RELOC_SYMBOL(mac80211, mac80211, sta_info_get);
extern typeof(wiphy_delayed_work_cancel) wiphy_delayed_work_cancel
	 KLP_RELOC_SYMBOL(mac80211, cfg80211, wiphy_delayed_work_cancel);
extern typeof(wiphy_work_queue) wiphy_work_queue
	 KLP_RELOC_SYMBOL(mac80211, cfg80211, wiphy_work_queue);

#endif /* IS_ENABLED(CONFIG_MAC80211) */
