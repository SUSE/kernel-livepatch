/*
 * livepatch_bsc1264483
 *
 * Fix for CVE-2026-43110, bsc#1264483
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

#if IS_ENABLED(CONFIG_BRCMFMAC)

#if !IS_MODULE(CONFIG_BRCMFMAC)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1264483.h"


/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/fweh.c */
#include <linux/netdevice.h>

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/include/brcmu_wifi.h */
#include <linux/if_ether.h>		/* for ETH_ALEN */
#include <linux/ieee80211.h>		/* for WLAN_PMKID_LEN */

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/include/brcmu_utils.h */
#include <linux/skbuff.h>

#ifdef DEBUG
#error "klp-ccp: non-taken branch"
#else
__printf(3, 4)
static inline
void brcmu_dbg_hex_dump(const void *data, size_t size, const char *fmt, ...)
{
}
#endif

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/core.h */
#include <net/cfg80211.h>

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/fweh.h */
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if.h>

struct brcmf_if;

#define BRCMF_FWEH_EVENT_ENUM_DEFLIST \
	BRCMF_ENUM_DEF(SET_SSID, 0) \
	BRCMF_ENUM_DEF(JOIN, 1) \
	BRCMF_ENUM_DEF(START, 2) \
	BRCMF_ENUM_DEF(AUTH, 3) \
	BRCMF_ENUM_DEF(AUTH_IND, 4) \
	BRCMF_ENUM_DEF(DEAUTH, 5) \
	BRCMF_ENUM_DEF(DEAUTH_IND, 6) \
	BRCMF_ENUM_DEF(ASSOC, 7) \
	BRCMF_ENUM_DEF(ASSOC_IND, 8) \
	BRCMF_ENUM_DEF(REASSOC, 9) \
	BRCMF_ENUM_DEF(REASSOC_IND, 10) \
	BRCMF_ENUM_DEF(DISASSOC, 11) \
	BRCMF_ENUM_DEF(DISASSOC_IND, 12) \
	BRCMF_ENUM_DEF(QUIET_START, 13) \
	BRCMF_ENUM_DEF(QUIET_END, 14) \
	BRCMF_ENUM_DEF(BEACON_RX, 15) \
	BRCMF_ENUM_DEF(LINK, 16) \
	BRCMF_ENUM_DEF(MIC_ERROR, 17) \
	BRCMF_ENUM_DEF(NDIS_LINK, 18) \
	BRCMF_ENUM_DEF(ROAM, 19) \
	BRCMF_ENUM_DEF(TXFAIL, 20) \
	BRCMF_ENUM_DEF(PMKID_CACHE, 21) \
	BRCMF_ENUM_DEF(RETROGRADE_TSF, 22) \
	BRCMF_ENUM_DEF(PRUNE, 23) \
	BRCMF_ENUM_DEF(AUTOAUTH, 24) \
	BRCMF_ENUM_DEF(EAPOL_MSG, 25) \
	BRCMF_ENUM_DEF(SCAN_COMPLETE, 26) \
	BRCMF_ENUM_DEF(ADDTS_IND, 27) \
	BRCMF_ENUM_DEF(DELTS_IND, 28) \
	BRCMF_ENUM_DEF(BCNSENT_IND, 29) \
	BRCMF_ENUM_DEF(BCNRX_MSG, 30) \
	BRCMF_ENUM_DEF(BCNLOST_MSG, 31) \
	BRCMF_ENUM_DEF(ROAM_PREP, 32) \
	BRCMF_ENUM_DEF(PFN_NET_FOUND, 33) \
	BRCMF_ENUM_DEF(PFN_NET_LOST, 34) \
	BRCMF_ENUM_DEF(RESET_COMPLETE, 35) \
	BRCMF_ENUM_DEF(JOIN_START, 36) \
	BRCMF_ENUM_DEF(ROAM_START, 37) \
	BRCMF_ENUM_DEF(ASSOC_START, 38) \
	BRCMF_ENUM_DEF(IBSS_ASSOC, 39) \
	BRCMF_ENUM_DEF(RADIO, 40) \
	BRCMF_ENUM_DEF(PSM_WATCHDOG, 41) \
	BRCMF_ENUM_DEF(PROBREQ_MSG, 44) \
	BRCMF_ENUM_DEF(SCAN_CONFIRM_IND, 45) \
	BRCMF_ENUM_DEF(PSK_SUP, 46) \
	BRCMF_ENUM_DEF(COUNTRY_CODE_CHANGED, 47) \
	BRCMF_ENUM_DEF(EXCEEDED_MEDIUM_TIME, 48) \
	BRCMF_ENUM_DEF(ICV_ERROR, 49) \
	BRCMF_ENUM_DEF(UNICAST_DECODE_ERROR, 50) \
	BRCMF_ENUM_DEF(MULTICAST_DECODE_ERROR, 51) \
	BRCMF_ENUM_DEF(TRACE, 52) \
	BRCMF_ENUM_DEF(IF, 54) \
	BRCMF_ENUM_DEF(P2P_DISC_LISTEN_COMPLETE, 55) \
	BRCMF_ENUM_DEF(RSSI, 56) \
	BRCMF_ENUM_DEF(EXTLOG_MSG, 58) \
	BRCMF_ENUM_DEF(ACTION_FRAME, 59) \
	BRCMF_ENUM_DEF(ACTION_FRAME_COMPLETE, 60) \
	BRCMF_ENUM_DEF(PRE_ASSOC_IND, 61) \
	BRCMF_ENUM_DEF(PRE_REASSOC_IND, 62) \
	BRCMF_ENUM_DEF(CHANNEL_ADOPTED, 63) \
	BRCMF_ENUM_DEF(AP_STARTED, 64) \
	BRCMF_ENUM_DEF(DFS_AP_STOP, 65) \
	BRCMF_ENUM_DEF(DFS_AP_RESUME, 66) \
	BRCMF_ENUM_DEF(ESCAN_RESULT, 69) \
	BRCMF_ENUM_DEF(ACTION_FRAME_OFF_CHAN_COMPLETE, 70) \
	BRCMF_ENUM_DEF(PROBERESP_MSG, 71) \
	BRCMF_ENUM_DEF(P2P_PROBEREQ_MSG, 72) \
	BRCMF_ENUM_DEF(DCS_REQUEST, 73) \
	BRCMF_ENUM_DEF(FIFO_CREDIT_MAP, 74) \
	BRCMF_ENUM_DEF(ACTION_FRAME_RX, 75) \
	BRCMF_ENUM_DEF(TDLS_PEER_EVENT, 92) \
	BRCMF_ENUM_DEF(BCMC_CREDIT_SUPPORT, 127)

#define BRCMF_ENUM_DEF(id, val) \
	BRCMF_E_##id = (val),

enum brcmf_fweh_event_code {
	BRCMF_FWEH_EVENT_ENUM_DEFLIST
};

#define BRCMF_E_IF_ADD				1
#define BRCMF_E_IF_DEL				2
#define BRCMF_E_IF_CHANGE			3

#define BRCMF_E_IF_FLAG_NOIF			1

#define BRCMF_E_IF_ROLE_STA			0

#define BRCMF_E_IF_ROLE_P2P_CLIENT		4

struct brcmf_event_msg_be {
	__be16 version;
	__be16 flags;
	__be32 event_type;
	__be32 status;
	__be32 reason;
	__be32 auth_type;
	__be32 datalen;
	u8 addr[ETH_ALEN];
	char ifname[IFNAMSIZ];
	u8 ifidx;
	u8 bsscfgidx;
} __packed;

struct brcmf_event_msg {
	u16 version;
	u16 flags;
	u32 event_code;
	u32 status;
	u32 reason;
	s32 auth_type;
	u32 datalen;
	u8 addr[ETH_ALEN];
	char ifname[IFNAMSIZ];
	u8 ifidx;
	u8 bsscfgidx;
};

struct brcmf_if_event {
	u8 ifidx;
	u8 action;
	u8 flags;
	u8 bsscfgidx;
	u8 role;
};

typedef int (*brcmf_fweh_handler_t)(struct brcmf_if *ifp,
				    const struct brcmf_event_msg *evtmsg,
				    void *data);

struct brcmf_fweh_event_map_item {
	enum brcmf_fweh_event_code code;
	u32 fwevt_code;
};

struct brcmf_fweh_event_map {
	u32 n_items;
	const struct brcmf_fweh_event_map_item items[] __counted_by(n_items);
};

struct brcmf_fweh_info {
	struct brcmf_pub *drvr;
	bool p2pdev_setup_ongoing;
	struct work_struct event_work;
	spinlock_t evt_q_lock;
	struct list_head event_q;
	uint event_mask_len;
	u8 *event_mask;
	struct brcmf_fweh_event_map *event_map;
	uint num_event_codes;
	brcmf_fweh_handler_t evt_handler[] __counted_by(num_event_codes);
};

const char *brcmf_fweh_event_name(enum brcmf_fweh_event_code code);

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/core.h */
#define BRCMF_MAX_IFS	16

#define BRCMF_DCMD_SMLEN	256

#define BRCMF_DCMD_MAXLEN	8192

#define BRCMF_AMPDU_RX_REORDER_MAXFLOWS		256

#define BRCMF_DRIVER_FIRMWARE_VERSION_LEN	32

#define NDOL_MAX_ENTRIES	8

struct brcmf_rev_info {
	int result;
	u32 vendorid;
	u32 deviceid;
	u32 radiorev;
	u32 corerev;
	u32 boardid;
	u32 boardvendor;
	u32 boardrev;
	u32 driverrev;
	u32 ucoderev;
	u32 bus;
	char chipname[12];
	u32 phytype;
	u32 phyrev;
	u32 anarev;
	u32 chippkg;
	u32 nvramrev;
};

struct brcmf_pub {
	/* Linkage ponters */
	struct brcmf_bus *bus_if;
	struct brcmf_proto *proto;
	struct wiphy *wiphy;
	struct cfg80211_ops *ops;
	struct brcmf_cfg80211_info *config;

	/* Internal brcmf items */
	uint hdrlen;		/* Total BRCMF header length (proto + bus) */

	/* Dongle media info */
	char fwver[BRCMF_DRIVER_FIRMWARE_VERSION_LEN];
	u8 mac[ETH_ALEN];		/* MAC address obtained from dongle */

	struct mac_address addresses[BRCMF_MAX_IFS];

	struct brcmf_if *iflist[BRCMF_MAX_IFS];
	s32 if2bss[BRCMF_MAX_IFS];
	struct brcmf_if *mon_if;

	struct mutex proto_block;
	unsigned char proto_buf[BRCMF_DCMD_MAXLEN];

	struct brcmf_fweh_info *fweh;

	struct brcmf_ampdu_rx_reorder
		*reorder_flows[BRCMF_AMPDU_RX_REORDER_MAXFLOWS];

	u32 feat_flags;
	u32 chip_quirks;

	struct brcmf_rev_info revinfo;
#ifdef DEBUG
#error "klp-ccp: non-taken branch"
#endif
	struct notifier_block inetaddr_notifier;
	struct notifier_block inet6addr_notifier;
	struct brcmf_mp_device *settings;

	struct work_struct bus_reset;

	u8 clmver[BRCMF_DCMD_SMLEN];
	u8 sta_mac_idx;
	const struct brcmf_fwvid_ops *vops;
	void *vdata;
};

struct brcmf_if {
	struct brcmf_pub *drvr;
	struct brcmf_cfg80211_vif *vif;
	struct net_device *ndev;
	struct work_struct multicast_work;
	struct work_struct ndoffload_work;
	struct brcmf_fws_mac_descriptor *fws_desc;
	int ifidx;
	s32 bsscfgidx;
	u8 mac_addr[ETH_ALEN];
	u8 netif_stop;
	spinlock_t netif_stop_lock;
	atomic_t pend_8021x_cnt;
	wait_queue_head_t pend_8021x_wait;
	struct in6_addr ipv6_addr_tbl[NDOL_MAX_ENTRIES];
	u8 ipv6addr_idx;
	bool fwil_fwerr;
};

int brcmf_net_attach(struct brcmf_if *ifp, bool locked);
struct brcmf_if *brcmf_add_if(struct brcmf_pub *drvr, s32 bsscfgidx, s32 ifidx,
			      bool is_p2pdev, const char *name, u8 *mac_addr);
void brcmf_remove_interface(struct brcmf_if *ifp, bool locked);

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/fwil_types.h */
#include <linux/if_ether.h>

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/p2p.h */
#include <net/cfg80211.h>

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.h */
bool brcmf_cfg80211_vif_event_armed(struct brcmf_cfg80211_info *cfg);

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/debug.h */
#include <linux/net.h>	/* net_ratelimit() */

#define bphy_err(drvr, fmt, ...)					\
	do {								\
		if (IS_ENABLED(CONFIG_BRCMDBG) ||			\
		    IS_ENABLED(CONFIG_BRCM_TRACING) ||			\
		    net_ratelimit())					\
			wiphy_err((drvr)->wiphy, "%s: " fmt, __func__,	\
				  ##__VA_ARGS__);			\
	} while (0)

#define brcmf_dbg(level, fmt, ...) no_printk(fmt, ##__VA_ARGS__)

#define BRCMF_EVENT_ON()	0

#define brcmf_dbg_hex_dump(test, data, len, fmt, ...)			\
do {									\
	trace_brcmf_hexdump((void *)data, len);				\
	if (test)							\
		brcmu_dbg_hex_dump(data, len, fmt, ##__VA_ARGS__);	\
} while (0)

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/tracepoint.h */
#if !defined(BRCMF_TRACEPOINT_H_) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/types.h>
#include <linux/tracepoint.h>

#undef TRACE_EVENT
#define TRACE_EVENT(name, proto, ...) \
static inline void trace_ ## name(proto) {}

TRACE_EVENT(brcmf_hexdump,
	TP_PROTO(void *data, size_t len),
	TP_ARGS(data, len),
	TP_STRUCT__entry(
		__field(unsigned long, len)
		__field(unsigned long, addr)
		__dynamic_array(u8, hdata, len)
	),
	TP_fast_assign(
		__entry->len = len;
		__entry->addr = (unsigned long)data;
		memcpy(__get_dynamic_array(hdata), data, len);
	),
	TP_printk("hexdump [addr=%lx, length=%lu]", __entry->addr, __entry->len)
)

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* BRCMF_TRACEPOINT_H_ */

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/proto.h */
enum proto_addr_mode;

struct brcmf_proto {
	int (*hdrpull)(struct brcmf_pub *drvr, bool do_fws,
		       struct sk_buff *skb, struct brcmf_if **ifp);
	int (*query_dcmd)(struct brcmf_pub *drvr, int ifidx, uint cmd,
			  void *buf, uint len, int *fwerr);
	int (*set_dcmd)(struct brcmf_pub *drvr, int ifidx, uint cmd, void *buf,
			uint len, int *fwerr);
	int (*tx_queue_data)(struct brcmf_pub *drvr, int ifidx,
			     struct sk_buff *skb);
	int (*txdata)(struct brcmf_pub *drvr, int ifidx, u8 offset,
		      struct sk_buff *skb);
	void (*configure_addr_mode)(struct brcmf_pub *drvr, int ifidx,
				    enum proto_addr_mode addr_mode);
	void (*delete_peer)(struct brcmf_pub *drvr, int ifidx,
			    u8 peer[ETH_ALEN]);
	void (*add_tdls_peer)(struct brcmf_pub *drvr, int ifidx,
			      u8 peer[ETH_ALEN]);
	void (*rxreorder)(struct brcmf_if *ifp, struct sk_buff *skb);
	void (*add_if)(struct brcmf_if *ifp);
	void (*del_if)(struct brcmf_if *ifp);
	void (*reset_if)(struct brcmf_if *ifp);
	int (*init_done)(struct brcmf_pub *drvr);
	void (*debugfs_create)(struct brcmf_pub *drvr);
	void *pd;
};

static inline void
brcmf_proto_add_if(struct brcmf_pub *drvr, struct brcmf_if *ifp)
{
	if (!drvr->proto->add_if)
		return;
	drvr->proto->add_if(ifp);
}

static inline void
brcmf_proto_reset_if(struct brcmf_pub *drvr, struct brcmf_if *ifp)
{
	if (!drvr->proto->reset_if)
		return;
	drvr->proto->reset_if(ifp);
}

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/bus.h */
#include <linux/kernel.h>
#include <linux/firmware.h>
#include <linux/device.h>

/* klp-ccp: from drivers/net/wireless/broadcom/brcm80211/brcmfmac/fweh.c */
struct brcmf_fweh_queue_item {
	struct list_head q;
	u32 code;
	u8 ifidx;
	u8 ifaddr[ETH_ALEN];
	struct brcmf_event_msg_be emsg;
	u32 datalen;
	u8 data[] __counted_by(datalen);
};

#ifdef DEBUG
#error "klp-ccp: non-taken branch"
#else
const char *brcmf_fweh_event_name(enum brcmf_fweh_event_code code);

#endif

static int brcmf_fweh_call_event_handler(struct brcmf_pub *drvr,
					 struct brcmf_if *ifp,
					 u32 fwcode,
					 struct brcmf_event_msg *emsg,
					 void *data)
{
	struct brcmf_fweh_info *fweh;
	int err = -EINVAL;

	if (ifp) {
		fweh = ifp->drvr->fweh;

		/* handle the event if valid interface and handler */
		if (fweh->evt_handler[fwcode])
			err = fweh->evt_handler[fwcode](ifp, emsg, data);
		else
			bphy_err(drvr, "unhandled fwevt %d ignored\n", fwcode);
	} else {
		bphy_err(drvr, "no interface object\n");
	}
	return err;
}

static void brcmf_fweh_handle_if_event(struct brcmf_pub *drvr,
				       struct brcmf_event_msg *emsg,
				       void *data)
{
	struct brcmf_if_event *ifevent = data;
	struct brcmf_if *ifp;
	bool is_p2pdev;

	brcmf_dbg(EVENT, "action: %u ifidx: %u bsscfgidx: %u flags: %u role: %u\n",
		  ifevent->action, ifevent->ifidx, ifevent->bsscfgidx,
		  ifevent->flags, ifevent->role);

	/* The P2P Device interface event must not be ignored contrary to what
	 * firmware tells us. Older firmware uses p2p noif, with sta role.
	 * This should be accepted when p2pdev_setup is ongoing. TDLS setup will
	 * use the same ifevent and should be ignored.
	 */
	is_p2pdev = ((ifevent->flags & BRCMF_E_IF_FLAG_NOIF) &&
		     (ifevent->role == BRCMF_E_IF_ROLE_P2P_CLIENT ||
		      ((ifevent->role == BRCMF_E_IF_ROLE_STA) &&
		       (drvr->fweh->p2pdev_setup_ongoing))));
	if (!is_p2pdev && (ifevent->flags & BRCMF_E_IF_FLAG_NOIF)) {
		brcmf_dbg(EVENT, "event can be ignored\n");
		return;
	}
	if (ifevent->ifidx >= BRCMF_MAX_IFS) {
		bphy_err(drvr, "invalid interface index: %u\n", ifevent->ifidx);
		return;
	}
	if (ifevent->bsscfgidx >= BRCMF_MAX_IFS) {
		bphy_err(drvr, "invalid bsscfg index: %u\n",
			 ifevent->bsscfgidx);
		return;
	}

	ifp = drvr->iflist[ifevent->bsscfgidx];

	if (ifevent->action == BRCMF_E_IF_ADD) {
		brcmf_dbg(EVENT, "adding %s (%pM)\n", emsg->ifname,
			  emsg->addr);
		ifp = brcmf_add_if(drvr, ifevent->bsscfgidx, ifevent->ifidx,
				   is_p2pdev, emsg->ifname, emsg->addr);
		if (IS_ERR(ifp))
			return;
		if (!is_p2pdev)
			brcmf_proto_add_if(drvr, ifp);
		if (!drvr->fweh->evt_handler[BRCMF_E_IF])
			if (brcmf_net_attach(ifp, false) < 0)
				return;
	}

	if (ifp && ifevent->action == BRCMF_E_IF_CHANGE)
		brcmf_proto_reset_if(drvr, ifp);

	brcmf_fweh_call_event_handler(drvr, ifp, emsg->event_code, emsg,
				      data);

	if (ifp && ifevent->action == BRCMF_E_IF_DEL) {
		bool armed = brcmf_cfg80211_vif_event_armed(drvr->config);

		/* Default handling in case no-one waits for this event */
		if (!armed)
			brcmf_remove_interface(ifp, false);
	}
}

static void brcmf_fweh_map_fwevt_code(struct brcmf_fweh_info *fweh, u32 fw_code,
				      enum brcmf_fweh_event_code *code)
{
	int i;

	if (WARN_ON(!code))
		return;

	*code = fw_code;
	if (fweh->event_map) {
		for (i = 0; i < fweh->event_map->n_items; i++) {
			if (fweh->event_map->items[i].fwevt_code == fw_code) {
				*code = fweh->event_map->items[i].code;
				break;
			}
		}
	}
}

static struct brcmf_fweh_queue_item *
brcmf_fweh_dequeue_event(struct brcmf_fweh_info *fweh)
{
	struct brcmf_fweh_queue_item *event = NULL;
	ulong flags;

	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	if (!list_empty(&fweh->event_q)) {
		event = list_first_entry(&fweh->event_q,
					 struct brcmf_fweh_queue_item, q);
		list_del(&event->q);
	}
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);

	return event;
}

void klpp_brcmf_fweh_event_worker(struct work_struct *work)
{
	struct brcmf_pub *drvr;
	struct brcmf_if *ifp;
	struct brcmf_fweh_info *fweh;
	struct brcmf_fweh_queue_item *event;
	int err = 0;
	struct brcmf_event_msg_be *emsg_be;
	struct brcmf_event_msg emsg;

	fweh = container_of(work, struct brcmf_fweh_info, event_work);
	drvr = fweh->drvr;

	while ((event = brcmf_fweh_dequeue_event(fweh))) {
		enum brcmf_fweh_event_code code;

		brcmf_fweh_map_fwevt_code(fweh, event->code, &code);
		brcmf_dbg(EVENT, "event %s (%u:%u) ifidx %u bsscfg %u addr %pM\n",
			  brcmf_fweh_event_name(code), code, event->code,
			  event->emsg.ifidx, event->emsg.bsscfgidx,
			  event->emsg.addr);
		if (event->emsg.bsscfgidx >= BRCMF_MAX_IFS) {
			bphy_err(drvr, "invalid bsscfg index: %u\n",
				 event->emsg.bsscfgidx);
			goto event_free;
		}

		/* convert event message */
		emsg_be = &event->emsg;
		emsg.version = be16_to_cpu(emsg_be->version);
		emsg.flags = be16_to_cpu(emsg_be->flags);
		emsg.event_code = code;
		emsg.status = be32_to_cpu(emsg_be->status);
		emsg.reason = be32_to_cpu(emsg_be->reason);
		emsg.auth_type = be32_to_cpu(emsg_be->auth_type);
		emsg.datalen = be32_to_cpu(emsg_be->datalen);
		memcpy(emsg.addr, emsg_be->addr, ETH_ALEN);
		memcpy(emsg.ifname, emsg_be->ifname, sizeof(emsg.ifname));
		emsg.ifidx = emsg_be->ifidx;
		emsg.bsscfgidx = emsg_be->bsscfgidx;

		brcmf_dbg(EVENT, "  version %u flags %u status %u reason %u\n",
			  emsg.version, emsg.flags, emsg.status, emsg.reason);
		brcmf_dbg_hex_dump(BRCMF_EVENT_ON(), event->data,
				   min_t(u32, emsg.datalen, 64),
				   "event payload, len=%d\n", emsg.datalen);

		/* special handling of interface event */
		if (event->code == BRCMF_E_IF) {
			brcmf_fweh_handle_if_event(drvr, &emsg, event->data);
			goto event_free;
		}

		if (event->code == BRCMF_E_TDLS_PEER_EVENT)
			ifp = drvr->iflist[0];
		else
			ifp = drvr->iflist[emsg.bsscfgidx];
		err = brcmf_fweh_call_event_handler(drvr, ifp, event->code,
						    &emsg, event->data);
		if (err) {
			bphy_err(drvr, "event handler failed (%d)\n",
				 event->code);
			err = 0;
		}
event_free:
		kfree(event);
	}
}


#include <linux/livepatch.h>

extern typeof(brcmf_add_if) brcmf_add_if
	 KLP_RELOC_SYMBOL(brcmfmac, brcmfmac, brcmf_add_if);
extern typeof(brcmf_cfg80211_vif_event_armed) brcmf_cfg80211_vif_event_armed
	 KLP_RELOC_SYMBOL(brcmfmac, brcmfmac, brcmf_cfg80211_vif_event_armed);
extern typeof(brcmf_fweh_event_name) brcmf_fweh_event_name
	 KLP_RELOC_SYMBOL(brcmfmac, brcmfmac, brcmf_fweh_event_name);
extern typeof(brcmf_net_attach) brcmf_net_attach
	 KLP_RELOC_SYMBOL(brcmfmac, brcmfmac, brcmf_net_attach);
extern typeof(brcmf_remove_interface) brcmf_remove_interface
	 KLP_RELOC_SYMBOL(brcmfmac, brcmfmac, brcmf_remove_interface);

#endif /* IS_ENABLED(CONFIG_BRCMFMAC) */
