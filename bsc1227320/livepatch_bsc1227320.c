/*
 * livepatch_bsc1227320
 *
 * Fix for CVE-2024-35789, bsc#1227320
 *
 *  Upstream commit:
 *  4f2bdb3c5e31 ("wifi: mac80211: check/clear fast rx for non-4addr sta VLAN changes")
 *
 *  SLE12-SP5 commit:
 *  4495db1f68d30d8afc42111bef51d532b4ec0928
 *
 *  SLE15-SP3 commit:
 *  7707dc6d22725bdfd58587c0597e82636e643948
 *
 *  SLE15-SP4 and -SP5 commit:
 *  2b6904d2510159094ec6c612a3fd0fcc750f132c
 *
 *  SLE15-SP6 commit:
 *  4be53e7d693c4df101ef0a5c4f05a903e6d16e1d
 *
 *  SLE MICRO-6-0 commit:
 *  4be53e7d693c4df101ef0a5c4f05a903e6d16e1d
 *
 *  Copyright (c) 2025 SUSE
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

#if IS_ENABLED(CONFIG_MAC80211)

#if !IS_MODULE(CONFIG_MAC80211)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/mac80211/cfg.c */
#include <linux/ieee80211.h>
#include <linux/nl80211.h>

#include <linux/slab.h>
#include <net/net_namespace.h>
#include <linux/rcupdate.h>

#include <linux/if_ether.h>
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

/* klp-ccp: from include/linux/jhash.h */
#define _LINUX_JHASH_H

/* klp-ccp: from net/mac80211/ieee80211_i.h */
#include <linux/rbtree.h>

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
	u32 last_active;
	s32 deficit;
	atomic_t aql_tx_pending; /* Estimated airtime for frames pending */
	u32 aql_limit_low;
	u32 aql_limit_high;
};

struct sta_ampdu_mlme {
	struct mutex mtx;
	/* rx */
	struct tid_ampdu_rx __rcu *tid_rx[IEEE80211_NUM_TIDS];
	u8 tid_rx_token[IEEE80211_NUM_TIDS];
	unsigned long tid_rx_timer_expired[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long tid_rx_stop_requested[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long tid_rx_manage_offl[BITS_TO_LONGS(2 * IEEE80211_NUM_TIDS)];
	unsigned long agg_session_valid[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	unsigned long unexpected_agg[BITS_TO_LONGS(IEEE80211_NUM_TIDS)];
	/* tx */
	struct work_struct work;
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
	struct dentry *debugfs_dir;
#else
#error "klp-ccp: a preceeding branch should have been taken"
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
	struct dentry *debugfs_dir;
#else
#error "klp-ccp: a preceeding branch should have been taken"
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

static inline int test_sta_flag(struct sta_info *sta,
				enum ieee80211_sta_info_flags flag)
{
	return test_bit(flag, &sta->_flags);
}

struct sta_info *sta_info_get_bss(struct ieee80211_sub_if_data *sdata,
				  const u8 *addr);

/* klp-ccp: from net/mac80211/debug.h */
#include <net/cfg80211.h>

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

typedef u32 __bitwise ieee80211_conn_flags_t;

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

struct ewma_beacon_signal { unsigned long internal; };

struct ieee80211_if_managed {
	struct timer_list timer;
	struct timer_list conn_mon_timer;
	struct timer_list bcn_mon_timer;
	struct work_struct monitor_work;
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
	struct delayed_work tdls_peer_del_work;
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
	struct delayed_work tx_tspec_wk;

	/* Information elements from the last transmitted (Re)Association
	 * Request frame.
	 */
	u8 *assoc_req_ies;
	size_t assoc_req_ies_len;

	struct wiphy_delayed_work ml_reconf_work;
	u16 removed_links;
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

enum ieee80211_sub_if_data_flags {
	IEEE80211_SDATA_ALLMULTI		= BIT(0),
	IEEE80211_SDATA_DONT_BRIDGE_PACKETS	= BIT(3),
	IEEE80211_SDATA_DISCONNECT_RESUME	= BIT(4),
	IEEE80211_SDATA_IN_DRIVER		= BIT(5),
	IEEE80211_SDATA_DISCONNECT_HW_RESTART	= BIT(6),
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

	ieee80211_conn_flags_t conn_flags;

	s16 p2p_noa_index;

	bool tdls_chan_switch_prohibited;

	bool have_beacon;
	bool tracking_signal_avg;
	bool disable_wmm_tracking;
	bool operating_11g_mode;

	bool csa_waiting_bcn;
	bool csa_ignored_same_chan;
	struct wiphy_delayed_work chswitch_work;

	struct wiphy_work request_smps_work;
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

	struct cfg80211_bss *bss;
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

	struct list_head assigned_chanctx_list; /* protected by chanctx_mtx */
	struct list_head reserved_chanctx_list; /* protected by chanctx_mtx */

	/* multicast keys only */
	struct ieee80211_key __rcu *gtk[NUM_DEFAULT_KEYS +
					NUM_DEFAULT_MGMT_KEYS +
					NUM_DEFAULT_BEACON_KEYS];
	struct ieee80211_key __rcu *default_multicast_key;
	struct ieee80211_key __rcu *default_mgmt_key;
	struct ieee80211_key __rcu *default_beacon_key;

	struct work_struct csa_finalize_work;
	bool csa_block_tx; /* write-protected by sdata_lock and local->mtx */

	bool operating_11g_mode;

	struct cfg80211_chan_def csa_chandef;

	struct work_struct color_change_finalize_work;
	struct delayed_work color_collision_detect_work;
	u64 color_bitmap;

	/* context reservation -- protected with chanctx_mtx */
	struct ieee80211_chanctx *reserved_chanctx;
	struct cfg80211_chan_def reserved_chandef;
	bool reserved_radar_required;
	bool reserved_ready;

	u8 needed_rx_chains;
	enum ieee80211_smps_mode smps_mode;

	int user_power_level; /* in dBm */
	int ap_power_level; /* in dBm */

	bool radar_required;
	struct delayed_work dfs_cac_timer_work;

	union {
		struct ieee80211_link_data_managed mgd;
		struct ieee80211_link_data_ap ap;
	} u;

	struct ieee80211_tx_queue_params tx_conf[IEEE80211_NUM_ACS];

	struct ieee80211_bss_conf *conf;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct dentry *debugfs_dir;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct ieee80211_sub_if_data {
	struct list_head list;

	struct wireless_dev wdev;

	/* keys */
	struct list_head key_list;

	/* count for keys needing tailroom space allocation */
	int crypto_tx_tailroom_needed_cnt;
	int crypto_tx_tailroom_pending_dec;
	struct delayed_work dec_tailroom_needed_wk;

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

	/* used to reconfigure hardware SM PS */
	struct work_struct recalc_smps;

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
	struct work_struct activate_links_work;
	u16 desired_active_links;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct {
		struct dentry *subdir_stations;
		struct dentry *default_unicast_key;
		struct dentry *default_multicast_key;
		struct dentry *default_mgmt_key;
		struct dentry *default_beacon_key;
	} debugfs;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
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

	bool use_chanctx;

	/* protects the aggregated multicast list and filter calls */
	spinlock_t filter_lock;

	/* used for uploading changed mc list */
	struct work_struct reconfig_filter;

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
	 * The mutex only protects the list, hash table and
	 * counter, reads are done with RCU.
	 */
	struct mutex sta_mtx;
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

	/*
	 * Key mutex, protects sdata's key_list and sta_info's
	 * key pointers and ptk_idx (write access, they're RCU.)
	 */
	struct mutex key_mtx;

	/* mutex for scan and work locking */
	struct mutex mtx;

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
	/* For backward compatibility only -- do not use */
	struct cfg80211_chan_def _oper_chandef;

	/* Temporary remain-on-channel for off-channel operations */
	struct ieee80211_channel *tmp_channel;

	/* channel contexts */
	struct list_head chanctx_list;
	struct mutex chanctx_mtx;

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
	struct work_struct dynamic_ps_enable_work;
	struct work_struct dynamic_ps_disable_work;
	struct timer_list dynamic_ps_timer;
	struct notifier_block ifa_notifier;
	struct notifier_block ifa6_notifier;

	/*
	 * The dynamic ps timeout configured from user space via WEXT -
	 * this will override whatever chosen by mac80211 internally.
	 */
	int dynamic_ps_forced_timeout;

	int user_power_level; /* in dBm, for all interfaces */

	enum ieee80211_smps_mode smps_mode;

	struct work_struct restart_work;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct local_debugfsdentries {
		struct dentry *rcdir;
		struct dentry *keys;
	} debugfs;
	bool force_tx_status;
#else
#error "klp-ccp: a preceeding branch should have been taken"
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
	struct cfg80211_chan_def monitor_chandef;

	/* extended capabilities provided by mac80211 */
	u8 ext_capa[8];

	void *suse_kabi_padding;	/* XXX SLE-specific kABI placeholder */
};

static inline struct ieee80211_sub_if_data *
IEEE80211_DEV_TO_SUB_IF(const struct net_device *dev)
{
	return netdev_priv(dev);
}

void ieee80211_vif_inc_num_mcast(struct ieee80211_sub_if_data *sdata);
void ieee80211_vif_dec_num_mcast(struct ieee80211_sub_if_data *sdata);

void ieee80211_check_fast_rx(struct sta_info *sta);
void __ieee80211_check_fast_rx_iface(struct ieee80211_sub_if_data *sdata);

void ieee80211_recalc_ps(struct ieee80211_local *local);
void ieee80211_recalc_ps_vif(struct ieee80211_sub_if_data *sdata);

void ieee80211_check_fast_xmit(struct sta_info *sta);

/* klp-ccp: from net/mac80211/driver-ops.h */
#include <net/mac80211.h>

#include <linux/tracepoint.h>
#include <net/mac80211.h>

#include "klp_trace.h"

/* klp-ccp: from net/mac80211/trace.h */
KLPR_TRACE_EVENT(mac80211, drv_return_void,
                 TP_PROTO(struct ieee80211_local *local),
                 TP_ARGS(local));

KLPR_TRACE_EVENT(mac80211, drv_sta_set_4addr,
                 TP_PROTO(struct ieee80211_local *local,
                          struct ieee80211_sub_if_data *sdata,
                          struct ieee80211_sta *sta, bool enabled),
                 TP_ARGS(local, sdata, sta, enabled));

#include <trace/define_trace.h>

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from net/mac80211/driver-ops.h */
#define check_sdata_in_driver(sdata)	({					\
	WARN_ONCE(!sdata->local->reconfig_failure &&				\
		  !(sdata->flags & IEEE80211_SDATA_IN_DRIVER),			\
		  "%s: Failed check-sdata-in-driver check, flags: 0x%x\n",	\
		  sdata->dev ? sdata->dev->name : sdata->name, sdata->flags);	\
	!!(sdata->flags & IEEE80211_SDATA_IN_DRIVER);				\
})

static inline struct ieee80211_sub_if_data *
get_bss_sdata(struct ieee80211_sub_if_data *sdata)
{
	if (sdata && sdata->vif.type == NL80211_IFTYPE_AP_VLAN)
		sdata = container_of(sdata->bss, struct ieee80211_sub_if_data,
				     u.ap);

	return sdata;
}

static inline void drv_sta_set_4addr(struct ieee80211_local *local,
				     struct ieee80211_sub_if_data *sdata,
				     struct ieee80211_sta *sta, bool enabled)
{
	sdata = get_bss_sdata(sdata);
	if (!check_sdata_in_driver(sdata))
		return;

	klpr_trace_drv_sta_set_4addr(local, sdata, sta, enabled);
	if (local->ops->sta_set_4addr)
		local->ops->sta_set_4addr(&local->hw, &sdata->vif, sta, enabled);
	klpr_trace_drv_return_void(local);
}

/* klp-ccp: from net/mac80211/rate.h */
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/types.h>
#include <net/mac80211.h>

/* klp-ccp: from net/mac80211/mesh.h */
#include <linux/types.h>
#include <linux/jhash.h>

/* klp-ccp: from net/mac80211/wme.h */
#include <linux/netdevice.h>

/* klp-ccp: from net/mac80211/cfg.c */
extern int sta_apply_parameters(struct ieee80211_local *local,
				struct sta_info *sta,
				struct station_parameters *params);

int klpp_ieee80211_change_station(struct wiphy *wiphy,
				    struct net_device *dev, const u8 *mac,
				    struct station_parameters *params)
{
	struct ieee80211_sub_if_data *sdata = IEEE80211_DEV_TO_SUB_IF(dev);
	struct ieee80211_local *local = wiphy_priv(wiphy);
	struct sta_info *sta;
	struct ieee80211_sub_if_data *vlansdata;
	enum cfg80211_station_type statype;
	int err;

	mutex_lock(&local->sta_mtx);

	sta = sta_info_get_bss(sdata, mac);
	if (!sta) {
		err = -ENOENT;
		goto out_err;
	}

	switch (sdata->vif.type) {
	case NL80211_IFTYPE_MESH_POINT:
		if (sdata->u.mesh.user_mpm)
			statype = CFG80211_STA_MESH_PEER_USER;
		else
			statype = CFG80211_STA_MESH_PEER_KERNEL;
		break;
	case NL80211_IFTYPE_ADHOC:
		statype = CFG80211_STA_IBSS;
		break;
	case NL80211_IFTYPE_STATION:
		if (!test_sta_flag(sta, WLAN_STA_TDLS_PEER)) {
			statype = CFG80211_STA_AP_STA;
			break;
		}
		if (test_sta_flag(sta, WLAN_STA_AUTHORIZED))
			statype = CFG80211_STA_TDLS_PEER_ACTIVE;
		else
			statype = CFG80211_STA_TDLS_PEER_SETUP;
		break;
	case NL80211_IFTYPE_AP:
	case NL80211_IFTYPE_AP_VLAN:
		if (test_sta_flag(sta, WLAN_STA_ASSOC))
			statype = CFG80211_STA_AP_CLIENT;
		else
			statype = CFG80211_STA_AP_CLIENT_UNASSOC;
		break;
	default:
		err = -EOPNOTSUPP;
		goto out_err;
	}

	err = cfg80211_check_station_change(wiphy, params, statype);
	if (err)
		goto out_err;

	if (params->vlan && params->vlan != sta->sdata->dev) {
		vlansdata = IEEE80211_DEV_TO_SUB_IF(params->vlan);

		if (params->vlan->ieee80211_ptr->use_4addr) {
			if (vlansdata->u.vlan.sta) {
				err = -EBUSY;
				goto out_err;
			}

			rcu_assign_pointer(vlansdata->u.vlan.sta, sta);
			__ieee80211_check_fast_rx_iface(vlansdata);
			drv_sta_set_4addr(local, sta->sdata, &sta->sta, true);
		}

		if (sta->sdata->vif.type == NL80211_IFTYPE_AP_VLAN &&
		    sta->sdata->u.vlan.sta)
			RCU_INIT_POINTER(sta->sdata->u.vlan.sta, NULL);

		if (test_sta_flag(sta, WLAN_STA_AUTHORIZED))
			ieee80211_vif_dec_num_mcast(sta->sdata);

		sta->sdata = vlansdata;
		ieee80211_check_fast_rx(sta);
		ieee80211_check_fast_xmit(sta);

		if (test_sta_flag(sta, WLAN_STA_AUTHORIZED)) {
			ieee80211_vif_inc_num_mcast(sta->sdata);
			cfg80211_send_layer2_update(sta->sdata->dev,
						    sta->sta.addr);
		}
	}

	/* we use sta_info_get_bss() so this might be different */
	if (sdata != sta->sdata) {
		mutex_lock_nested(&sta->sdata->wdev.mtx, 1);
		err = sta_apply_parameters(local, sta, params);
		mutex_unlock(&sta->sdata->wdev.mtx);
	} else {
		err = sta_apply_parameters(local, sta, params);
	}
	if (err)
		goto out_err;

	mutex_unlock(&local->sta_mtx);

	if (sdata->vif.type == NL80211_IFTYPE_STATION &&
	    params->sta_flags_mask & BIT(NL80211_STA_FLAG_AUTHORIZED)) {
		ieee80211_recalc_ps(local);
		ieee80211_recalc_ps_vif(sdata);
	}

	return 0;
out_err:
	mutex_unlock(&local->sta_mtx);
	return err;
}


#include "livepatch_bsc1227320.h"

#include <linux/livepatch.h>

extern typeof(__ieee80211_check_fast_rx_iface) __ieee80211_check_fast_rx_iface
	 KLP_RELOC_SYMBOL(mac80211, mac80211, __ieee80211_check_fast_rx_iface);
extern typeof(ieee80211_check_fast_rx) ieee80211_check_fast_rx
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_check_fast_rx);
extern typeof(ieee80211_check_fast_xmit) ieee80211_check_fast_xmit
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_check_fast_xmit);
extern typeof(ieee80211_recalc_ps) ieee80211_recalc_ps
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_recalc_ps);
extern typeof(ieee80211_recalc_ps_vif) ieee80211_recalc_ps_vif
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_recalc_ps_vif);
extern typeof(ieee80211_vif_dec_num_mcast) ieee80211_vif_dec_num_mcast
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_vif_dec_num_mcast);
extern typeof(ieee80211_vif_inc_num_mcast) ieee80211_vif_inc_num_mcast
	 KLP_RELOC_SYMBOL(mac80211, mac80211, ieee80211_vif_inc_num_mcast);
extern typeof(sta_apply_parameters) sta_apply_parameters
	 KLP_RELOC_SYMBOL(mac80211, mac80211, sta_apply_parameters);
extern typeof(sta_info_get_bss) sta_info_get_bss
	 KLP_RELOC_SYMBOL(mac80211, mac80211, sta_info_get_bss);
extern typeof(cfg80211_check_station_change) cfg80211_check_station_change
	 KLP_RELOC_SYMBOL(mac80211, cfg80211, cfg80211_check_station_change);
extern typeof(cfg80211_send_layer2_update) cfg80211_send_layer2_update
	 KLP_RELOC_SYMBOL(mac80211, cfg80211, cfg80211_send_layer2_update);

#endif /* IS_ENABLED(CONFIG_MAC80211) */
