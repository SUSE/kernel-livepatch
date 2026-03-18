/*
 * livepatch_bsc1255895
 *
 * Fix for CVE-2025-40297, bsc#1255895
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


/* klp-ccp: from net/bridge/br_input.c */
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/etherdevice.h>

#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/random.h>

#include <asm/unaligned.h>
#include <asm/bitsperlong.h>

/* klp-ccp: from net/bridge/br_input.c */
#include <linux/netfilter_bridge.h>

/* klp-ccp: from net/bridge/br_input.c */
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
#include <net/netfilter/nf_queue.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <linux/neighbour.h>
#include <net/arp.h>
#include <net/dsa.h>
#include <linux/export.h>
#include <linux/rculist.h>

/* klp-ccp: from net/bridge/br_private.h */
#include <linux/netdevice.h>
#include <linux/if_bridge.h>

#include <linux/u64_stats_sync.h>
#include <net/route.h>
#include <net/ip6_fib.h>
#include <net/pkt_cls.h>
#include <linux/if_vlan.h>

#include <linux/refcount.h>

typedef struct bridge_id bridge_id;
typedef struct mac_addr mac_addr;
typedef __u16 port_id;

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

struct net_bridge_vlan_group {
	struct rhashtable		vlan_hash;
	struct rhashtable		tunnel_hash;
	struct list_head		vlan_list;
	u16				num_vlans;
	u16				pvid;
	u8				pvid_state;
};

enum {
	BR_FDB_LOCAL,
	BR_FDB_STATIC,
	BR_FDB_STICKY,
	BR_FDB_ADDED_BY_USER,
	BR_FDB_ADDED_BY_EXT_LEARN,
	BR_FDB_OFFLOADED,
	BR_FDB_NOTIFY,
	BR_FDB_NOTIFY_INACTIVE,
	BR_FDB_LOCKED,
};

struct net_bridge_fdb_key {
	mac_addr addr;
	u16 vlan_id;
};

struct net_bridge_fdb_entry {
	struct rhash_head		rhnode;
	struct net_bridge_port		*dst;

	struct net_bridge_fdb_key	key;
	struct hlist_node		fdb_node;
	unsigned long			flags;

	/* write-heavy members should not affect lookups */
	unsigned long			updated ____cacheline_aligned_in_smp;
	unsigned long			used;

	struct rcu_head			rcu;
};

struct net_bridge_mcast_gc {
	struct hlist_node		gc_node;
	void				(*destroy)(struct net_bridge_mcast_gc *gc);
};

struct net_bridge_mdb_entry {
	struct rhash_head		rhnode;
	struct net_bridge		*br;
	struct net_bridge_port_group __rcu *ports;
	struct br_ip			addr;
	bool				host_joined;

	struct timer_list		timer;
	struct hlist_node		mdb_node;

	struct net_bridge_mcast_gc	mcast_gc;
	struct rcu_head			rcu;
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
	u32				backup_nhid;

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

static inline struct net_bridge_port *br_port_get_rcu(const struct net_device *dev)
{
	return rcu_dereference(dev->rx_handler_data);
}

enum net_bridge_opts {
	BROPT_VLAN_ENABLED,
	BROPT_VLAN_STATS_ENABLED,
	BROPT_NF_CALL_IPTABLES,
	BROPT_NF_CALL_IP6TABLES,
	BROPT_NF_CALL_ARPTABLES,
	BROPT_GROUP_ADDR_SET,
	BROPT_MULTICAST_ENABLED,
	BROPT_MULTICAST_QUERY_USE_IFADDR,
	BROPT_MULTICAST_STATS_ENABLED,
	BROPT_HAS_IPV6_ADDR,
	BROPT_NEIGH_SUPPRESS_ENABLED,
	BROPT_MTU_SET_BY_USER,
	BROPT_VLAN_STATS_PER_PORT,
	BROPT_NO_LL_LEARN,
	BROPT_VLAN_BRIDGE_BINDING,
	BROPT_MCAST_VLAN_SNOOPING_ENABLED,
	BROPT_MST_ENABLED,
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

struct br_input_skb_cb {
	struct net_device *brdev;

	u16 frag_max_size;
#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
	u8 igmp;
	u8 mrouters_only:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u8 proxyarp_replied:1;
	u8 src_port_isolated:1;
#ifdef CONFIG_BRIDGE_VLAN_FILTERING
	u8 vlan_filtered:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
	u8 br_netfilter_broute:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_NET_SWITCHDEV
	u8 tx_fwd_offload:1;
	/* The switchdev hardware domain from which this packet was received.
	 * If skb->offload_fwd_mark was set, then this packet was already
	 * forwarded by hardware to the other ports in the source hardware
	 * domain, otherwise it wasn't.
	 */
	int src_hwdom;
	/* Bit mask of hardware domains towards this packet has already been
	 * transmitted using the TX data plane offload.
	 */
	unsigned long fwd_hwdoms;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u32 backup_nhid;
};

#define BR_INPUT_SKB_CB(__skb)	((struct br_input_skb_cb *)(__skb)->cb)

# define BR_INPUT_SKB_CB_MROUTERS_ONLY(__skb)	(BR_INPUT_SKB_CB(__skb)->mrouters_only)

static inline int br_opt_get(const struct net_bridge *br,
			     enum net_bridge_opts opt)
{
	return test_bit(opt, &br->options);
}

#if IS_ENABLED(CONFIG_NET_TC_SKB_EXT)
static inline void br_tc_skb_miss_set(struct sk_buff *skb, bool miss)
{
	struct tc_skb_ext *ext;

	if (!tc_skb_ext_tc_enabled())
		return;

	ext = skb_ext_find(skb, TC_SKB_EXT);
	if (ext) {
		ext->l2_miss = miss;
		return;
	}
	if (!miss)
		return;
	ext = tc_skb_ext_alloc(skb);
	if (!ext)
		return;
	ext->l2_miss = true;
}
#else
#error "klp-ccp: non-taken branch"
#endif

struct net_bridge_fdb_entry *br_fdb_find_rcu(struct net_bridge *br,
					     const unsigned char *addr,
					     __u16 vid);

void br_fdb_update(struct net_bridge *br, struct net_bridge_port *source,
		   const unsigned char *addr, u16 vid, unsigned long flags);

enum br_pkt_type {
	BR_PKT_UNICAST,
	BR_PKT_MULTICAST,
	BR_PKT_BROADCAST
};

void br_forward(const struct net_bridge_port *to, struct sk_buff *skb,
		bool local_rcv, bool local_orig);

void br_flood(struct net_bridge *br, struct sk_buff *skb,
	      enum br_pkt_type pkt_type, bool local_rcv, bool local_orig,
	      u16 vid);

int klpp_br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb);

struct br_frame_type {
	__be16			type;
	int			(*frame_handler)(struct net_bridge_port *port,
						 struct sk_buff *skb);
	struct hlist_node	list;
};

#ifdef CONFIG_BRIDGE_IGMP_SNOOPING
int br_multicast_rcv(struct net_bridge_mcast **brmctx,
		     struct net_bridge_mcast_port **pmctx,
		     struct net_bridge_vlan *vlan,
		     struct sk_buff *skb, u16 vid);
struct net_bridge_mdb_entry *br_mdb_get(struct net_bridge_mcast *brmctx,
					struct sk_buff *skb, u16 vid);

void br_multicast_flood(struct net_bridge_mdb_entry *mdst, struct sk_buff *skb,
			struct net_bridge_mcast *brmctx,
			bool local_rcv, bool local_orig);

static inline bool br_group_is_l2(const struct br_ip *group)
{
	return group->proto == 0;
}

static inline bool br_ip4_multicast_is_router(struct net_bridge_mcast *brmctx)
{
	return timer_pending(&brmctx->ip4_mc_router_timer);
}

static inline bool br_ip6_multicast_is_router(struct net_bridge_mcast *brmctx)
{
#if IS_ENABLED(CONFIG_IPV6)
	return timer_pending(&brmctx->ip6_mc_router_timer);
#else
#error "klp-ccp: non-taken branch"
#endif
}

static inline bool
br_multicast_is_router(struct net_bridge_mcast *brmctx, struct sk_buff *skb)
{
	switch (brmctx->multicast_router) {
	case MDB_RTR_TYPE_PERM:
		return true;
	case MDB_RTR_TYPE_TEMP_QUERY:
		if (skb) {
			if (skb->protocol == htons(ETH_P_IP))
				return br_ip4_multicast_is_router(brmctx);
			else if (skb->protocol == htons(ETH_P_IPV6))
				return br_ip6_multicast_is_router(brmctx);
		} else {
			return br_ip4_multicast_is_router(brmctx) ||
			       br_ip6_multicast_is_router(brmctx);
		}
		fallthrough;
	default:
		return false;
	}
}

static inline bool
__br_multicast_querier_exists(struct net_bridge_mcast *brmctx,
			      struct bridge_mcast_other_query *querier,
			      const bool is_ipv6)
{
	bool own_querier_enabled;

	if (brmctx->multicast_querier) {
		if (is_ipv6 && !br_opt_get(brmctx->br, BROPT_HAS_IPV6_ADDR))
			own_querier_enabled = false;
		else
			own_querier_enabled = true;
	} else {
		own_querier_enabled = false;
	}

	return time_is_before_jiffies(querier->delay_time) &&
	       (own_querier_enabled || timer_pending(&querier->timer));
}

static inline bool br_multicast_querier_exists(struct net_bridge_mcast *brmctx,
					       struct ethhdr *eth,
					       const struct net_bridge_mdb_entry *mdb)
{
	switch (eth->h_proto) {
	case (htons(ETH_P_IP)):
		return __br_multicast_querier_exists(brmctx,
			&brmctx->ip4_other_query, false);
#if IS_ENABLED(CONFIG_IPV6)
	case (htons(ETH_P_IPV6)):
		return __br_multicast_querier_exists(brmctx,
			&brmctx->ip6_other_query, true);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	default:
		return !!mdb && br_group_is_l2(&mdb->addr);
	}
}

#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
bool br_allowed_ingress(const struct net_bridge *br,
			struct net_bridge_vlan_group *vg, struct sk_buff *skb,
			u16 *vid, u8 *state,
			struct net_bridge_vlan **vlan);

static inline struct net_bridge_vlan_group *nbp_vlan_group_rcu(
					const struct net_bridge_port *p)
{
	return rcu_dereference(p->vlgrp);
}

#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_BRIDGE_VLAN_FILTERING
DECLARE_STATIC_KEY_FALSE(br_mst_used);
static inline bool br_mst_is_enabled(const struct net_bridge_port *p)
{
	/* check the port's vlan group to avoid racing with port deletion */
	return static_key_enabled(&br_mst_used) &&
	       br_opt_get(p->br, BROPT_MST_ENABLED) &&
	       rcu_access_pointer(p->vlgrp);
}

#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_NET_SWITCHDEV

void nbp_switchdev_frame_mark(const struct net_bridge_port *p,
			      struct sk_buff *skb);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_NET_SWITCHDEV */

void br_do_proxy_suppress_arp(struct sk_buff *skb, struct net_bridge *br,
			      u16 vid, struct net_bridge_port *p);
void br_do_suppress_nd(struct sk_buff *skb, struct net_bridge *br,
		       u16 vid, struct net_bridge_port *p, struct nd_msg *msg);
struct nd_msg *br_is_nd_neigh_msg(struct sk_buff *skb, struct nd_msg *m);

/* klp-ccp: from net/bridge/br_private_tunnel.h */
#ifdef CONFIG_BRIDGE_VLAN_FILTERING

void br_handle_ingress_vlan_tunnel(struct sk_buff *skb,
				   struct net_bridge_port *p,
				   struct net_bridge_vlan_group *vg);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/bridge/br_input.c */
extern int br_pass_frame_up(struct sk_buff *skb);

int klpp_br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_bridge_port *p = br_port_get_rcu(skb->dev);
	enum br_pkt_type pkt_type = BR_PKT_UNICAST;
	struct net_bridge_fdb_entry *dst = NULL;
	struct net_bridge_mcast_port *pmctx;
	struct net_bridge_mdb_entry *mdst;
	bool local_rcv, mcast_hit = false;
	struct net_bridge_mcast *brmctx;
	struct net_bridge_vlan *vlan;
	struct net_bridge *br;
	u16 vid = 0;
	u8 state;

	if (!p)
		goto drop;

	br = p->br;

	if (br_mst_is_enabled(p)) {
		state = BR_STATE_FORWARDING;
	} else {
		if (p->state == BR_STATE_DISABLED)
			goto drop;

		state = p->state;
	}

	brmctx = &p->br->multicast_ctx;
	pmctx = &p->multicast_ctx;
	if (!br_allowed_ingress(p->br, nbp_vlan_group_rcu(p), skb, &vid,
				&state, &vlan))
		goto out;

	if (p->flags & BR_PORT_LOCKED) {
		struct net_bridge_fdb_entry *fdb_src =
			br_fdb_find_rcu(br, eth_hdr(skb)->h_source, vid);

		if (!fdb_src) {
			/* FDB miss. Create locked FDB entry if MAB is enabled
			 * and drop the packet.
			 */
			if (p->flags & BR_PORT_MAB)
				br_fdb_update(br, p, eth_hdr(skb)->h_source,
					      vid, BIT(BR_FDB_LOCKED));
			goto drop;
		} else if (READ_ONCE(fdb_src->dst) != p ||
			   test_bit(BR_FDB_LOCAL, &fdb_src->flags)) {
			/* FDB mismatch. Drop the packet without roaming. */
			goto drop;
		} else if (test_bit(BR_FDB_LOCKED, &fdb_src->flags)) {
			/* FDB match, but entry is locked. Refresh it and drop
			 * the packet.
			 */
			br_fdb_update(br, p, eth_hdr(skb)->h_source, vid,
				      BIT(BR_FDB_LOCKED));
			goto drop;
		}
	}

	nbp_switchdev_frame_mark(p, skb);

	/* insert into forwarding database after filtering to avoid spoofing */
	if (p->flags & BR_LEARNING)
		br_fdb_update(br, p, eth_hdr(skb)->h_source, vid, 0);

	local_rcv = !!(br->dev->flags & IFF_PROMISC);
	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest)) {
		/* by definition the broadcast is also a multicast address */
		if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)) {
			pkt_type = BR_PKT_BROADCAST;
			local_rcv = true;
		} else {
			pkt_type = BR_PKT_MULTICAST;
			if (br_multicast_rcv(&brmctx, &pmctx, vlan, skb, vid))
				goto drop;
		}
	}

	if (state == BR_STATE_LEARNING)
		goto drop;

	BR_INPUT_SKB_CB(skb)->brdev = br->dev;
	BR_INPUT_SKB_CB(skb)->src_port_isolated = !!(p->flags & BR_ISOLATED);

	if (IS_ENABLED(CONFIG_INET) &&
	    (skb->protocol == htons(ETH_P_ARP) ||
	     skb->protocol == htons(ETH_P_RARP))) {
		br_do_proxy_suppress_arp(skb, br, vid, p);
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   skb->protocol == htons(ETH_P_IPV6) &&
		   br_opt_get(br, BROPT_NEIGH_SUPPRESS_ENABLED) &&
		   pskb_may_pull(skb, sizeof(struct ipv6hdr) +
				 sizeof(struct nd_msg)) &&
		   ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {
			struct nd_msg *msg, _msg;

			msg = br_is_nd_neigh_msg(skb, &_msg);
			if (msg)
				br_do_suppress_nd(skb, br, vid, p, msg);
	}

	switch (pkt_type) {
	case BR_PKT_MULTICAST:
		mdst = br_mdb_get(brmctx, skb, vid);
		if ((mdst || BR_INPUT_SKB_CB_MROUTERS_ONLY(skb)) &&
		    br_multicast_querier_exists(brmctx, eth_hdr(skb), mdst)) {
			if ((mdst && mdst->host_joined) ||
			    br_multicast_is_router(brmctx, skb)) {
				local_rcv = true;
				DEV_STATS_INC(br->dev, multicast);
			}
			mcast_hit = true;
		} else {
			local_rcv = true;
			DEV_STATS_INC(br->dev, multicast);
		}
		break;
	case BR_PKT_UNICAST:
		dst = br_fdb_find_rcu(br, eth_hdr(skb)->h_dest, vid);
		break;
	default:
		break;
	}

	if (dst) {
		unsigned long now = jiffies;

		if (test_bit(BR_FDB_LOCAL, &dst->flags))
			return br_pass_frame_up(skb);

		if (now != dst->used)
			dst->used = now;
		br_forward(dst->dst, skb, local_rcv, false);
	} else {
		if (!mcast_hit)
			br_flood(br, skb, pkt_type, local_rcv, false, vid);
		else
			br_multicast_flood(mdst, skb, brmctx, local_rcv, false);
	}

	if (local_rcv)
		return br_pass_frame_up(skb);

out:
	return 0;
drop:
	kfree_skb(skb);
	goto out;
}

typeof(klpp_br_handle_frame_finish) klpp_br_handle_frame_finish;

extern void __br_handle_local_finish(struct sk_buff *skb);

extern int br_handle_local_finish(struct net *net, struct sock *sk, struct sk_buff *skb);

static int klpr_nf_hook_bridge_pre(struct sk_buff *skb, struct sk_buff **pskb)
{
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
	struct nf_hook_entries *e = NULL;
	struct nf_hook_state state;
	unsigned int verdict, i;
	struct net *net;
	int ret;

	net = dev_net(skb->dev);
#ifdef HAVE_JUMP_LABEL
#error "klp-ccp: non-taken branch"
#endif
	e = rcu_dereference(net->nf.hooks_bridge[NF_BR_PRE_ROUTING]);
	if (!e)
		goto frame_finish;

	nf_hook_state_init(&state, NF_BR_PRE_ROUTING,
			   NFPROTO_BRIDGE, skb->dev, NULL, NULL,
			   net, klpp_br_handle_frame_finish);

	for (i = 0; i < e->num_hook_entries; i++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[i], skb, &state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:
			if (BR_INPUT_SKB_CB(skb)->br_netfilter_broute) {
				*pskb = skb;
				return RX_HANDLER_PASS;
			}
			break;
		case NF_DROP:
			kfree_skb(skb);
			return RX_HANDLER_CONSUMED;
		case NF_QUEUE:
			ret = nf_queue(skb, &state, i, verdict);
			if (ret == 1)
				continue;
			return RX_HANDLER_CONSUMED;
		default: /* STOLEN */
			return RX_HANDLER_CONSUMED;
		}
	}
frame_finish:
	net = dev_net(skb->dev);
	klpp_br_handle_frame_finish(net, NULL, skb);
#else
#error "klp-ccp: non-taken branch"
#endif
	return RX_HANDLER_CONSUMED;
}

static int br_process_frame_type(struct net_bridge_port *p,
				 struct sk_buff *skb)
{
	struct br_frame_type *tmp;

	hlist_for_each_entry_rcu(tmp, &p->br->frame_type_list, list)
		if (unlikely(tmp->type == skb->protocol))
			return tmp->frame_handler(p, skb);

	return 0;
}

rx_handler_result_t klpp_br_handle_frame(struct sk_buff **pskb)
{
	struct net_bridge_port *p;
	struct sk_buff *skb = *pskb;
	const unsigned char *dest = eth_hdr(skb)->h_dest;

	if (unlikely(skb->pkt_type == PACKET_LOOPBACK))
		return RX_HANDLER_PASS;

	if (!is_valid_ether_addr(eth_hdr(skb)->h_source))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return RX_HANDLER_CONSUMED;

	memset(skb->cb, 0, sizeof(struct br_input_skb_cb));
	br_tc_skb_miss_set(skb, false);

	p = br_port_get_rcu(skb->dev);
	if (p->flags & BR_VLAN_TUNNEL)
		br_handle_ingress_vlan_tunnel(skb, p, nbp_vlan_group_rcu(p));

	if (unlikely(is_link_local_ether_addr(dest))) {
		u16 fwd_mask = p->br->group_fwd_mask_required;

		/*
		 * See IEEE 802.1D Table 7-10 Reserved addresses
		 *
		 * Assignment		 		Value
		 * Bridge Group Address		01-80-C2-00-00-00
		 * (MAC Control) 802.3		01-80-C2-00-00-01
		 * (Link Aggregation) 802.3	01-80-C2-00-00-02
		 * 802.1X PAE address		01-80-C2-00-00-03
		 *
		 * 802.1AB LLDP 		01-80-C2-00-00-0E
		 *
		 * Others reserved for future standardization
		 */
		fwd_mask |= p->group_fwd_mask;
		switch (dest[5]) {
		case 0x00:	/* Bridge Group Address */
			/* If STP is turned off,
			   then must forward to keep loop detection */
			if (p->br->stp_enabled == BR_NO_STP ||
			    fwd_mask & (1u << dest[5]))
				goto forward;
			*pskb = skb;
			__br_handle_local_finish(skb);
			return RX_HANDLER_PASS;

		case 0x01:	/* IEEE MAC (Pause) */
			goto drop;

		case 0x0E:	/* 802.1AB LLDP */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
			*pskb = skb;
			__br_handle_local_finish(skb);
			return RX_HANDLER_PASS;

		default:
			/* Allow selective forwarding for most other protocols */
			fwd_mask |= p->br->group_fwd_mask;
			if (fwd_mask & (1u << dest[5]))
				goto forward;
		}

		/* The else clause should be hit when nf_hook():
		 *   - returns < 0 (drop/error)
		 *   - returns = 0 (stolen/nf_queue)
		 * Thus return 1 from the okfn() to signal the skb is ok to pass
		 */
		if (NF_HOOK(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,
			    dev_net(skb->dev), NULL, skb, skb->dev, NULL,
			    br_handle_local_finish) == 1) {
			return RX_HANDLER_PASS;
		} else {
			return RX_HANDLER_CONSUMED;
		}
	}

	if (unlikely(br_process_frame_type(p, skb)))
		return RX_HANDLER_PASS;

forward:
	if (br_mst_is_enabled(p))
		goto defer_stp_filtering;

	switch (p->state) {
	case BR_STATE_FORWARDING:
	case BR_STATE_LEARNING:
defer_stp_filtering:
		if (ether_addr_equal(p->br->dev->dev_addr, dest))
			skb->pkt_type = PACKET_HOST;

		return klpr_nf_hook_bridge_pre(skb, pskb);
	default:
drop:
		kfree_skb(skb);
	}
	return RX_HANDLER_CONSUMED;
}


#include "livepatch_bsc1255895.h"

#include <linux/livepatch.h>

extern typeof(__br_handle_local_finish) __br_handle_local_finish
	 KLP_RELOC_SYMBOL(bridge, bridge, __br_handle_local_finish);
extern typeof(br_allowed_ingress) br_allowed_ingress
	 KLP_RELOC_SYMBOL(bridge, bridge, br_allowed_ingress);
extern typeof(br_do_proxy_suppress_arp) br_do_proxy_suppress_arp
	 KLP_RELOC_SYMBOL(bridge, bridge, br_do_proxy_suppress_arp);
extern typeof(br_do_suppress_nd) br_do_suppress_nd
	 KLP_RELOC_SYMBOL(bridge, bridge, br_do_suppress_nd);
extern typeof(br_fdb_find_rcu) br_fdb_find_rcu
	 KLP_RELOC_SYMBOL(bridge, bridge, br_fdb_find_rcu);
extern typeof(br_fdb_update) br_fdb_update
	 KLP_RELOC_SYMBOL(bridge, bridge, br_fdb_update);
extern typeof(br_flood) br_flood KLP_RELOC_SYMBOL(bridge, bridge, br_flood);
extern typeof(br_forward) br_forward
	 KLP_RELOC_SYMBOL(bridge, bridge, br_forward);
extern typeof(br_handle_ingress_vlan_tunnel) br_handle_ingress_vlan_tunnel
	 KLP_RELOC_SYMBOL(bridge, bridge, br_handle_ingress_vlan_tunnel);
extern typeof(br_handle_local_finish) br_handle_local_finish
	 KLP_RELOC_SYMBOL(bridge, bridge, br_handle_local_finish);
extern typeof(br_is_nd_neigh_msg) br_is_nd_neigh_msg
	 KLP_RELOC_SYMBOL(bridge, bridge, br_is_nd_neigh_msg);
extern typeof(br_mdb_get) br_mdb_get
	 KLP_RELOC_SYMBOL(bridge, bridge, br_mdb_get);
extern typeof(br_mst_used) br_mst_used
	 KLP_RELOC_SYMBOL(bridge, bridge, br_mst_used);
extern typeof(br_multicast_flood) br_multicast_flood
	 KLP_RELOC_SYMBOL(bridge, bridge, br_multicast_flood);
extern typeof(br_multicast_rcv) br_multicast_rcv
	 KLP_RELOC_SYMBOL(bridge, bridge, br_multicast_rcv);
extern typeof(br_pass_frame_up) br_pass_frame_up
	 KLP_RELOC_SYMBOL(bridge, bridge, br_pass_frame_up);
extern typeof(nbp_switchdev_frame_mark) nbp_switchdev_frame_mark
	 KLP_RELOC_SYMBOL(bridge, bridge, nbp_switchdev_frame_mark);
