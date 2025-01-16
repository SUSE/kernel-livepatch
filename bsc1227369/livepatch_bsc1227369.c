/*
 * livepatch_bsc1227369
 *
 * Fix for CVE-2024-36979, bsc#1227369
 *
 *  Upstream commit:
 *  3a7c1661ae13 ("net: bridge: mst: fix vlan use-after-free")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  be8b71253cd15c3ac2d85a774d37d39a8fd0a147
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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


/* klp-ccp: from net/bridge/br_mst.c */
#include <linux/kernel.h>
#include <net/switchdev.h>

/* klp-ccp: from net/bridge/br_private.h */
#include <linux/netdevice.h>
#include <linux/if_bridge.h>

#include <net/route.h>
#include <net/ip6_fib.h>

/* klp-ccp: from net/bridge/br_private.h */
#include <linux/if_vlan.h>

#include <linux/refcount.h>

typedef struct bridge_id bridge_id;

typedef __u16 port_id;

struct bridge_id {
	unsigned char	prio[2];
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

struct net_bridge_mcast_port {
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	struct net_bridge_port		*port;
	struct net_bridge_vlan		*vlan;

	struct bridge_mcast_own_query	ip4_own_query;
	struct timer_list		ip4_mc_router_timer;
	struct hlist_node		ip4_rlist;
#if IS_ENABLED(CONFIG_IPV6)
	struct bridge_mcast_own_query	ip6_own_query;
	struct timer_list		ip6_mc_router_timer;
	struct hlist_node		ip6_rlist;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* IS_ENABLED(CONFIG_IPV6) */
	unsigned char			multicast_router;
	u32				mdb_n_entries;
	u32				mdb_max_entries;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_BRIDGE_IGMP_SNOOPING */
};

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

struct br_tunnel_info {
	__be64				tunnel_id;
	struct metadata_dst __rcu	*tunnel_dst;
};

struct net_bridge_vlan {
	struct rhash_head		vnode;
	struct rhash_head		tnode;
	u16				vid;
	u16				flags;
	u16				priv_flags;
	u8				state;
	struct pcpu_sw_netstats __percpu *stats;
	union {
		struct net_bridge	*br;
		struct net_bridge_port	*port;
	};
	union {
		refcount_t		refcnt;
		struct net_bridge_vlan	*brvlan;
	};

	struct br_tunnel_info		tinfo;

	union {
		struct net_bridge_mcast		br_mcast_ctx;
		struct net_bridge_mcast_port	port_mcast_ctx;
	};

	u16				msti;

	struct list_head		vlist;

	struct rcu_head			rcu;
};

struct net_bridge_vlan_group {
	struct rhashtable		vlan_hash;
	struct rhashtable		tunnel_hash;
	struct list_head		vlan_list;
	u16				num_vlans;
	u16				pvid;
	u8				pvid_state;
};

struct net_bridge_port {
	struct net_bridge		*br;
	struct net_device		*dev;
	netdevice_tracker		dev_tracker;
	struct list_head		list;

	unsigned long			flags;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	struct net_bridge_vlan_group	__rcu *vlgrp;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct net_bridge_port		__rcu *backup_port;

	/* STP */
	u8				priority;
	u8				state;
	u16				port_no;
	unsigned char			topology_change_ack;
	unsigned char			config_pending;
	port_id				port_id;
	port_id				designated_port;
	bridge_id			designated_root;
	bridge_id			designated_bridge;
	u32				path_cost;
	u32				designated_cost;
	unsigned long			designated_age;

	struct timer_list		forward_delay_timer;
	struct timer_list		hold_timer;
	struct timer_list		message_age_timer;
	struct kobject			kobj;
	struct rcu_head			rcu;

	struct net_bridge_mcast_port	multicast_ctx;

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	struct bridge_mcast_stats	__percpu *mcast_stats;

	u32				multicast_eht_hosts_limit;
	u32				multicast_eht_hosts_cnt;
	struct hlist_head		mglist;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SYSFS
	char				sysfs_name[IFNAMSIZ];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NET_POLL_CONTROLLER
	struct netpoll			*np;
#endif
#ifdef CONFIG_NET_SWITCHDEV
	int				hwdom;
	int				offload_count;
	struct netdev_phys_item_id	ppid;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u16				group_fwd_mask;
	u16				backup_redirected_cnt;

	struct bridge_stp_xstats	stp_xstats;
};

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

#ifdef CONFIG_BRIDGE_VLAN_FILTERING

struct net_bridge_vlan *br_vlan_find(struct net_bridge_vlan_group *vg, u16 vid);

static inline struct net_bridge_vlan_group *nbp_vlan_group(
					const struct net_bridge_port *p)
{
	return rtnl_dereference(p->vlgrp);
}

static inline u8 br_vlan_get_state(const struct net_bridge_vlan *v)
{
	return READ_ONCE(v->state);
}

static inline void br_vlan_set_state(struct net_bridge_vlan *v, u8 state)
{
	WRITE_ONCE(v->state, state);
}

static inline void br_vlan_set_pvid_state(struct net_bridge_vlan_group *vg,
					  u8 state)
{
	WRITE_ONCE(vg->pvid_state, state);
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif


/* klp-ccp: from net/bridge/br_mst.c */
static void klpp_br_mst_vlan_set_state(struct net_bridge_port *p, struct net_bridge_vlan *v,
				  u8 state)
{
	struct net_bridge_vlan_group *vg = nbp_vlan_group(p);

	if (br_vlan_get_state(v) == state)
		return;

	br_vlan_set_state(v, state);

	if (v->vid == vg->pvid)
		br_vlan_set_pvid_state(vg, state);
}

int klpp_br_mst_set_state(struct net_bridge_port *p, u16 msti, u8 state,
		     struct netlink_ext_ack *extack)
{
	struct switchdev_attr attr = {
		.id = SWITCHDEV_ATTR_ID_PORT_MST_STATE,
		.orig_dev = p->dev,
		.u.mst_state = {
			.msti = msti,
			.state = state,
		},
	};
	struct net_bridge_vlan_group *vg;
	struct net_bridge_vlan *v;
	int err = 0;

	rcu_read_lock();
	vg = nbp_vlan_group(p);
	if (!vg)
		goto out;

	/* MSTI 0 (CST) state changes are notified via the regular
	 * SWITCHDEV_ATTR_ID_PORT_STP_STATE.
	 */
	if (msti) {
		err = switchdev_port_attr_set(p->dev, &attr, extack);
		if (err && err != -EOPNOTSUPP)
			goto out;
	}

	err = 0;
	list_for_each_entry_rcu(v, &vg->vlan_list, vlist) {
		if (v->brvlan->msti != msti)
			continue;

		klpp_br_mst_vlan_set_state(p, v, state);
	}

out:
	rcu_read_unlock();
	return err;
}

static void klpp_br_mst_vlan_sync_state(struct net_bridge_vlan *pv, u16 msti)
{
	struct net_bridge_vlan_group *vg = nbp_vlan_group(pv->port);
	struct net_bridge_vlan *v;

	list_for_each_entry(v, &vg->vlan_list, vlist) {
		/* If this port already has a defined state in this
		 * MSTI (through some other VLAN membership), inherit
		 * it.
		 */
		if (v != pv && v->brvlan->msti == msti) {
			klpp_br_mst_vlan_set_state(pv->port, pv, v->state);
			return;
		}
	}

	/* Otherwise, start out in a new MSTI with all ports disabled. */
	return klpp_br_mst_vlan_set_state(pv->port, pv, BR_STATE_DISABLED);
}

int klpp_br_mst_vlan_set_msti(struct net_bridge_vlan *mv, u16 msti)
{
	struct switchdev_attr attr = {
		.id = SWITCHDEV_ATTR_ID_VLAN_MSTI,
		.orig_dev = mv->br->dev,
		.u.vlan_msti = {
			.vid = mv->vid,
			.msti = msti,
		},
	};
	struct net_bridge_vlan_group *vg;
	struct net_bridge_vlan *pv;
	struct net_bridge_port *p;
	int err;

	if (mv->msti == msti)
		return 0;

	err = switchdev_port_attr_set(mv->br->dev, &attr, NULL);
	if (err && err != -EOPNOTSUPP)
		return err;

	mv->msti = msti;

	list_for_each_entry(p, &mv->br->port_list, list) {
		vg = nbp_vlan_group(p);

		pv = br_vlan_find(vg, mv->vid);
		if (pv)
			klpp_br_mst_vlan_sync_state(pv, msti);
	}

	return 0;
}


#include "livepatch_bsc1227369.h"
#include <linux/livepatch.h>

extern typeof(br_vlan_find) br_vlan_find
	 KLP_RELOC_SYMBOL(bridge, bridge, br_vlan_find);
