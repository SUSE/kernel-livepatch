/*
 * livepatch_bsc1260524
 *
 * Fix for CVE-2026-23393, bsc#1260524
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1260524.h"


/* klp-ccp: from net/bridge/br_cfm.c */
#include <linux/cfm_bridge.h>
#include <uapi/linux/cfm_bridge.h>
/* klp-ccp: from net/bridge/br_private.h */
#include <linux/netdevice.h>
#include <linux/if_bridge.h>
#include <linux/netpoll.h>
#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <net/pkt_cls.h>
#include <linux/if_vlan.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>

typedef struct bridge_id bridge_id;

struct bridge_id {
	unsigned char	prio[2];
	unsigned char	addr[ETH_ALEN];
};

struct mac_addr {
	unsigned char	addr[ETH_ALEN];
};

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING

struct bridge_mcast_own_query {
	struct timer_list	timer;
	u32			startup_sent;
};

struct bridge_mcast_other_query {
	struct timer_list		timer;
	unsigned long			delay_time;
};

struct bridge_mcast_querier {
	struct br_ip addr;
	int port_ifidx;
	seqcount_spinlock_t seq;
};

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

struct net_bridge_mcast {
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	struct net_bridge		*br;
	struct net_bridge_vlan		*vlan;

	u32				multicast_last_member_count;
	u32				multicast_startup_query_count;

	u8				multicast_querier;
	u8				multicast_igmp_version;
	u8				multicast_router;
#if IS_ENABLED(CONFIG_IPV6)
	u8				multicast_mld_version;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	unsigned long			multicast_last_member_interval;
	unsigned long			multicast_membership_interval;
	unsigned long			multicast_querier_interval;
	unsigned long			multicast_query_interval;
	unsigned long			multicast_query_response_interval;
	unsigned long			multicast_startup_query_interval;
	struct hlist_head		ip4_mc_router_list;
	struct timer_list		ip4_mc_router_timer;
	struct bridge_mcast_other_query	ip4_other_query;
	struct bridge_mcast_own_query	ip4_own_query;
	struct bridge_mcast_querier	ip4_querier;
#if IS_ENABLED(CONFIG_IPV6)
	struct hlist_head		ip6_mc_router_list;
	struct timer_list		ip6_mc_router_timer;
	struct bridge_mcast_other_query	ip6_other_query;
	struct bridge_mcast_own_query	ip6_own_query;
	struct bridge_mcast_querier	ip6_querier;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* IS_ENABLED(CONFIG_IPV6) */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_BRIDGE_IGMP_SNOOPING */
};

struct net_bridge_port

#ifdef CONFIG_BRIDGE_VLAN_FILTERING

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SYSFS

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NET_SWITCHDEV

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
;

struct net_bridge {
	spinlock_t			lock;
	spinlock_t			hash_lock;
	struct hlist_head		frame_type_list;
	struct net_device		*dev;
	unsigned long			options;

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	__be16				vlan_proto;
	u16				default_pvid;
	struct net_bridge_vlan_group	__rcu *vlgrp;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct rhashtable		fdb_hash_tbl;
	struct list_head		port_list;
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	union {
		struct rtable		fake_rtable;
		struct rt6_info		fake_rt6_info;
	};
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u16				group_fwd_mask;
	u16				group_fwd_mask_required;

	/* STP */
	bridge_id			designated_root;
	bridge_id			bridge_id;
	unsigned char			topology_change;
	unsigned char			topology_change_detected;
	u16				root_port;
	unsigned long			max_age;
	unsigned long			hello_time;
	unsigned long			forward_delay;
	unsigned long			ageing_time;
	unsigned long			bridge_max_age;
	unsigned long			bridge_hello_time;
	unsigned long			bridge_forward_delay;
	unsigned long			bridge_ageing_time;
	u32				root_path_cost;

	u8				group_addr[ETH_ALEN];

	enum {
		BR_NO_STP, 		/* no spanning tree */
		BR_KERNEL_STP,		/* old STP in kernel */
		BR_USER_STP,		/* new RSTP in userspace */
	} stp_enabled;

	struct net_bridge_mcast		multicast_ctx;

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	struct bridge_mcast_stats	__percpu *mcast_stats;

	u32				hash_max;

	spinlock_t			multicast_lock;

	struct rhashtable		mdb_hash_tbl;
	struct rhashtable		sg_port_tbl;

	struct hlist_head		mcast_gc_list;
	struct hlist_head		mdb_list;

	struct work_struct		mcast_gc_work;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct timer_list		hello_timer;
	struct timer_list		tcn_timer;
	struct timer_list		topology_change_timer;
	struct delayed_work		gc_work;
	struct kobject			*ifobj;
	u32				auto_cnt;

#ifdef CONFIG_NET_SWITCHDEV
	int				last_hwdom;
	/* Bit mask of hardware domain numbers in use */
	unsigned long			busy_hwdoms;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct hlist_head		fdb_list;

#if IS_ENABLED(CONFIG_BRIDGE_MRP)
	struct hlist_head		mrp_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#if IS_ENABLED(CONFIG_BRIDGE_CFM)
	struct hlist_head		mep_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct br_frame_type {
	__be16			type;
	int			(*frame_handler)(struct net_bridge_port *port,
						 struct sk_buff *skb);
	struct hlist_node	list;
};

void br_del_frame(struct net_bridge *br, struct br_frame_type *ft);

/* klp-ccp: from net/bridge/br_private_cfm.h */
#include <uapi/linux/cfm_bridge.h>

struct br_cfm_mep_create {
	enum br_cfm_domain domain; /* Domain for this MEP */
	enum br_cfm_mep_direction direction; /* Up or Down MEP direction */
	u32 ifindex; /* Residence port */
};

struct br_cfm_mep_config {
	u32 mdlevel;
	u32 mepid; /* MEPID for this MEP */
	struct mac_addr unicast_mac; /* The MEP unicast MAC */
};

struct br_cfm_maid {
	u8 data[CFM_MAID_LENGTH];
};

struct br_cfm_cc_config {
	/* Expected received CCM PDU MAID. */
	struct br_cfm_maid exp_maid;

	/* Expected received CCM PDU interval. */
	/* Transmitting CCM PDU interval when CCM tx is enabled. */
	enum br_cfm_ccm_interval exp_interval;

	bool enable; /* Enable/disable CCM PDU handling */
};

int klpp_br_cfm_cc_peer_mep_add(struct net_bridge *br, const u32 instance,
			   u32 peer_mep_id,
			   struct netlink_ext_ack *extack);
int klpp_br_cfm_cc_peer_mep_remove(struct net_bridge *br, const u32 instance,
			      u32 peer_mep_id,
			      struct netlink_ext_ack *extack);

struct br_cfm_cc_ccm_tx_info {
	struct mac_addr dmac;
	/* The CCM will be transmitted for this period in seconds.
	 * Call br_cfm_cc_ccm_tx before timeout to keep transmission alive.
	 * When period is zero any ongoing transmission will be stopped.
	 */
	u32 period;

	bool seq_no_update; /* Update Tx CCM sequence number */
	bool if_tlv; /* Insert Interface Status TLV */
	u8 if_tlv_value; /* Interface Status TLV value */
	bool port_tlv; /* Insert Port Status TLV */
	u8 port_tlv_value; /* Port Status TLV value */
	/* Sender ID TLV ??
	 * Organization-Specific TLV ??
	 */
};

struct br_cfm_mep_status {
	/* Indications that an OAM PDU has been seen. */
	bool opcode_unexp_seen; /* RX of OAM PDU with unexpected opcode */
	bool version_unexp_seen; /* RX of OAM PDU with unexpected version */
	bool rx_level_low_seen; /* Rx of OAM PDU with level low */
};

struct br_cfm_cc_peer_status {
	/* This CCM related status is based on the latest received CCM PDU. */
	u8 port_tlv_value; /* Port Status TLV value */
	u8 if_tlv_value; /* Interface Status TLV value */

	/* CCM has not been received for 3.25 intervals */
	u8 ccm_defect:1;

	/* (RDI == 1) for last received CCM PDU */
	u8 rdi:1;

	/* Indications that a CCM PDU has been seen. */
	u8 seen:1; /* CCM PDU received */
	u8 tlv_seen:1; /* CCM PDU with TLV received */
	/* CCM PDU with unexpected sequence number received */
	u8 seq_unexp_seen:1;
};

struct br_cfm_mep {
	/* list header of MEP instances */
	struct hlist_node		head;
	u32				instance;
	struct br_cfm_mep_create	create;
	struct br_cfm_mep_config	config;
	struct br_cfm_cc_config		cc_config;
	struct br_cfm_cc_ccm_tx_info	cc_ccm_tx_info;
	/* List of multiple peer MEPs */
	struct hlist_head		peer_mep_list;
	struct net_bridge_port __rcu	*b_port;
	unsigned long			ccm_tx_end;
	struct delayed_work		ccm_tx_dwork;
	u32				ccm_tx_snumber;
	u32				ccm_rx_snumber;
	struct br_cfm_mep_status	status;
	bool				rdi;
	struct rcu_head			rcu;
};

struct br_cfm_peer_mep {
	struct hlist_node		head;
	struct br_cfm_mep		*mep;
	struct delayed_work		ccm_rx_dwork;
	u32				mepid;
	struct br_cfm_cc_peer_status	cc_status;
	/* Struct member moved into a hole. */
	bool				ccm_rx_dwork_disabled;
	u32				ccm_rx_count_miss;
	struct rcu_head			rcu;
};

/* klp-ccp: from net/bridge/br_cfm.c */
static struct br_cfm_mep *br_mep_find(struct net_bridge *br, u32 instance)
{
	struct br_cfm_mep *mep;

	hlist_for_each_entry(mep, &br->mep_list, head)
		if (mep->instance == instance)
			return mep;

	return NULL;
}

static struct br_cfm_peer_mep *br_peer_mep_find(struct br_cfm_mep *mep,
						u32 mepid)
{
	struct br_cfm_peer_mep *peer_mep;

	hlist_for_each_entry_rcu(peer_mep, &mep->peer_mep_list, head,
				 lockdep_rtnl_is_held())
		if (peer_mep->mepid == mepid)
			return peer_mep;

	return NULL;
}

static u32 interval_to_us(enum br_cfm_ccm_interval interval)
{
	switch (interval) {
	case BR_CFM_CCM_INTERVAL_NONE:
		return 0;
	case BR_CFM_CCM_INTERVAL_3_3_MS:
		return 3300;
	case BR_CFM_CCM_INTERVAL_10_MS:
		return 10 * 1000;
	case BR_CFM_CCM_INTERVAL_100_MS:
		return 100 * 1000;
	case BR_CFM_CCM_INTERVAL_1_SEC:
		return 1000 * 1000;
	case BR_CFM_CCM_INTERVAL_10_SEC:
		return 10 * 1000 * 1000;
	case BR_CFM_CCM_INTERVAL_1_MIN:
		return 60 * 1000 * 1000;
	case BR_CFM_CCM_INTERVAL_10_MIN:
		return 10 * 60 * 1000 * 1000;
	}
	return 0;
}

void klpp_ccm_rx_timer_start(struct br_cfm_peer_mep *peer_mep)
{
	u32 interval_us;

	interval_us = interval_to_us(peer_mep->mep->cc_config.exp_interval);
	/* Function ccm_rx_dwork must be called with 1/4
	 * of the configured CC 'expected_interval'
	 * in order to detect CCM defect after 3.25 interval.
	 */
	if (!peer_mep->ccm_rx_dwork_disabled)
		queue_delayed_work(system_wq, &peer_mep->ccm_rx_dwork,
				   usecs_to_jiffies(interval_us / 4));
}

extern void cc_peer_enable(struct br_cfm_peer_mep *peer_mep);

extern void ccm_rx_work_expired(struct work_struct *work);

extern struct br_frame_type cfm_frame_type __read_mostly;

void klpp_mep_delete_implementation(struct net_bridge *br,
				      struct br_cfm_mep *mep)
{
	struct br_cfm_peer_mep *peer_mep;
	struct hlist_node *n_store;

	ASSERT_RTNL();

	/* Empty and free peer MEP list */
	hlist_for_each_entry_safe(peer_mep, n_store, &mep->peer_mep_list, head) {
		/* prevent queueing, workaround for missing disable_ */
		peer_mep->ccm_rx_dwork_disabled = true;
		cancel_delayed_work_sync(&peer_mep->ccm_rx_dwork);
		hlist_del_rcu(&peer_mep->head);
		kfree_rcu(peer_mep, rcu);
	}

	cancel_delayed_work_sync(&mep->ccm_tx_dwork);

	RCU_INIT_POINTER(mep->b_port, NULL);
	hlist_del_rcu(&mep->head);
	kfree_rcu(mep, rcu);

	if (hlist_empty(&br->mep_list))
		br_del_frame(br, &cfm_frame_type);
}

int klpp_br_cfm_cc_peer_mep_add(struct net_bridge *br, const u32 instance,
			   u32 mepid,
			   struct netlink_ext_ack *extack)
{
	struct br_cfm_peer_mep *peer_mep;
	struct br_cfm_mep *mep;

	ASSERT_RTNL();

	mep = br_mep_find(br, instance);
	if (!mep) {
		NL_SET_ERR_MSG_MOD(extack,
				   "MEP instance does not exists");
		return -ENOENT;
	}

	peer_mep = br_peer_mep_find(mep, mepid);
	if (peer_mep) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Peer MEP-ID already exists");
		return -EEXIST;
	}

	peer_mep = kzalloc(sizeof(*peer_mep), GFP_KERNEL);
	if (!peer_mep)
		return -ENOMEM;

	peer_mep->mepid = mepid;
	peer_mep->mep = mep;
	peer_mep->ccm_rx_dwork_disabled = false;
	INIT_DELAYED_WORK(&peer_mep->ccm_rx_dwork, ccm_rx_work_expired);

	if (mep->cc_config.enable)
		cc_peer_enable(peer_mep);

	hlist_add_tail_rcu(&peer_mep->head, &mep->peer_mep_list);

	return 0;
}

int klpp_br_cfm_cc_peer_mep_remove(struct net_bridge *br, const u32 instance,
			      u32 mepid,
			      struct netlink_ext_ack *extack)
{
	struct br_cfm_peer_mep *peer_mep;
	struct br_cfm_mep *mep;

	ASSERT_RTNL();

	mep = br_mep_find(br, instance);
	if (!mep) {
		NL_SET_ERR_MSG_MOD(extack,
				   "MEP instance does not exists");
		return -ENOENT;
	}

	peer_mep = br_peer_mep_find(mep, mepid);
	if (!peer_mep) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Peer MEP-ID does not exists");
		return -ENOENT;
	}

	/* prevent queueing, workaround for missing disable_ */
	peer_mep->ccm_rx_dwork_disabled = true;
	cancel_delayed_work_sync(&peer_mep->ccm_rx_dwork);

	hlist_del_rcu(&peer_mep->head);
	kfree_rcu(peer_mep, rcu);

	return 0;
}


#include <linux/livepatch.h>

extern typeof(br_del_frame) br_del_frame
	 KLP_RELOC_SYMBOL(bridge, bridge, br_del_frame);
extern typeof(cc_peer_enable) cc_peer_enable
	 KLP_RELOC_SYMBOL(bridge, bridge, cc_peer_enable);
extern typeof(ccm_rx_work_expired) ccm_rx_work_expired
	 KLP_RELOC_SYMBOL(bridge, bridge, ccm_rx_work_expired);
extern typeof(cfm_frame_type) cfm_frame_type
	 KLP_RELOC_SYMBOL(bridge, bridge, cfm_frame_type);
