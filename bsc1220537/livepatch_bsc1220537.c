/*
 * livepatch_bsc1220537
 *
 * Fix for CVE-2021-46955, bsc#1220537
 *
 *  Upstream commit:
 *  7c0ea5930c1c ("openvswitch: fix stack OOB read while fragmenting IPv4 packets")
 *
 *  SLE12-SP5 commit:
 *  1116e19a1a1372d2e810e6cb07ab9ed7fed2ad33
 *
 *  SLE15-SP2 and -SP3 commit:
 *  37faff480a0b06e401708e7622105fbb134aaa0f
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
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

/* klp-ccp: from net/openvswitch/actions.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/openvswitch.h>
#include <linux/netfilter_ipv6.h>
#include <linux/sctp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in6.h>

/* klp-ccp: from include/linux/if_arp.h */
#define _LINUX_IF_ARP_H

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/openvswitch/actions.c */
#include <linux/if_vlan.h>
#include <net/dst.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/mpls.h>
#include <net/sctp/checksum.h>
/* klp-ccp: from net/openvswitch/datapath.h */
#include <asm/page.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/u64_stats_sync.h>
#include <net/ip_tunnels.h>
/* klp-ccp: from net/openvswitch/flow.h */
#include <linux/cache.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>

/* klp-ccp: from include/linux/flex_array.h */
#define _FLEX_ARRAY_H

/* klp-ccp: from include/linux/reciprocal_div.h */
#define _LINUX_RECIPROCAL_DIV_H

/* klp-ccp: from net/openvswitch/flow.h */
#include <net/inet_ecn.h>
#include <net/ip_tunnels.h>

enum sw_flow_mac_proto {
	MAC_PROTO_NONE = 0,
	MAC_PROTO_ETHERNET,
};
#define SW_FLOW_KEY_INVALID	0x80

struct vlan_head {
	__be16 tpid; /* Vlan type. Generally 802.1q or 802.1ad.*/
	__be16 tci;  /* 0 if no VLAN, VLAN_TAG_PRESENT set otherwise. */
};

struct sw_flow_key {
	u8 tun_opts[IP_TUNNEL_OPTS_MAX];
	u8 tun_opts_len;
	struct ip_tunnel_key tun_key;	/* Encapsulating tunnel key. */
	struct {
		u32	priority;	/* Packet QoS priority. */
		u32	skb_mark;	/* SKB mark. */
		u16	in_port;	/* Input switch port (or DP_MAX_PORTS). */
	} __packed phy; /* Safe when right after 'tun_key'. */
	u8 mac_proto;			/* MAC layer protocol (e.g. Ethernet). */
	u8 tun_proto;			/* Protocol of encapsulating tunnel. */
	u32 ovs_flow_hash;		/* Datapath computed hash value.  */
	u32 recirc_id;			/* Recirculation ID.  */
	struct {
		u8     src[ETH_ALEN];	/* Ethernet source address. */
		u8     dst[ETH_ALEN];	/* Ethernet destination address. */
		struct vlan_head vlan;
		struct vlan_head cvlan;
		__be16 type;		/* Ethernet frame type. */
	} eth;
	/* Filling a hole of two bytes. */
	u8 ct_state;
	u8 ct_orig_proto;		/* CT original direction tuple IP
					 * protocol.
					 */
	union {
		struct {
			__be32 top_lse;	/* top label stack entry */
		} mpls;
		struct {
			u8     proto;	/* IP protocol or lower 8 bits of ARP opcode. */
			u8     tos;	    /* IP ToS. */
			u8     ttl;	    /* IP TTL/hop limit. */
			u8     frag;	/* One of OVS_FRAG_TYPE_*. */
		} ip;
	};
	u16 ct_zone;			/* Conntrack zone. */
	struct {
		__be16 src;		/* TCP/UDP/SCTP source port. */
		__be16 dst;		/* TCP/UDP/SCTP destination port. */
		__be16 flags;		/* TCP flags. */
	} tp;
	union {
		struct {
			struct {
				__be32 src;	/* IP source address. */
				__be32 dst;	/* IP destination address. */
			} addr;
			union {
				struct {
					__be32 src;
					__be32 dst;
				} ct_orig;	/* Conntrack original direction fields. */
				struct {
					u8 sha[ETH_ALEN];	/* ARP source hardware address. */
					u8 tha[ETH_ALEN];	/* ARP target hardware address. */
				} arp;
			};
		} ipv4;
		struct {
			struct {
				struct in6_addr src;	/* IPv6 source address. */
				struct in6_addr dst;	/* IPv6 destination address. */
			} addr;
			__be32 label;			/* IPv6 flow label. */
			union {
				struct {
					struct in6_addr src;
					struct in6_addr dst;
				} ct_orig;	/* Conntrack original direction fields. */
				struct {
					struct in6_addr target;	/* ND target address. */
					u8 sll[ETH_ALEN];	/* ND source link layer address. */
					u8 tll[ETH_ALEN];	/* ND target link layer address. */
				} nd;
			};
		} ipv6;
	};
	struct {
		/* Connection tracking fields not packed above. */
		struct {
			__be16 src;	/* CT orig tuple tp src port. */
			__be16 dst;	/* CT orig tuple tp dst port. */
		} orig_tp;
		u32 mark;
		struct ovs_key_ct_labels labels;
	} ct;

} __aligned(BITS_PER_LONG/8);

static inline u8 ovs_key_mac_proto(const struct sw_flow_key *key)
{
	return key->mac_proto & ~SW_FLOW_KEY_INVALID;
}

static inline u16 __ovs_mac_header_len(u8 mac_proto)
{
	return mac_proto == MAC_PROTO_ETHERNET ? ETH_HLEN : 0;
}

static inline u16 ovs_mac_header_len(const struct sw_flow_key *key)
{
	return __ovs_mac_header_len(ovs_key_mac_proto(key));
}

/* klp-ccp: from net/openvswitch/flow_table.h */
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/jiffies.h>
#include <linux/time.h>
#include <linux/flex_array.h>
#include <net/inet_ecn.h>
#include <net/ip_tunnels.h>

struct flow_table {
	struct table_instance __rcu *ti;
	struct table_instance __rcu *ufid_ti;
	struct list_head mask_list;
	unsigned long last_rehash;
	unsigned int count;
	unsigned int ufid_count;
};

/* klp-ccp: from net/openvswitch/datapath.h */
struct datapath {
	struct rcu_head rcu;
	struct list_head list_node;

	/* Flow table. */
	struct flow_table table;

	/* Switch ports. */
	struct hlist_head *ports;

	/* Stats. */
	struct dp_stats_percpu __percpu *stats_percpu;

	/* Network namespace ref. */
	possible_net_t net;

	u32 user_features;

	u32 max_headroom;
};

struct ovs_skb_cb {
	struct vport		*input_vport;
	u16			mru;
	u16			acts_origlen;
	u32			cutlen;
};
#define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)

static struct vport *(*klpe_ovs_lookup_vport)(const struct datapath *dp, u16 port_no);

static inline struct vport *klpr_ovs_vport_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return (*klpe_ovs_lookup_vport)(dp, port_no);
}

#define OVS_NLERR(logging_allowed, fmt, ...)			\
do {								\
	if (logging_allowed && net_ratelimit())			\
		pr_info("netlink: " fmt "\n", ##__VA_ARGS__);	\
} while (0)

/* klp-ccp: from net/openvswitch/vport.h */
#include <linux/if_tunnel.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/reciprocal_div.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/u64_stats_sync.h>

struct vport {
	struct net_device *dev;
	struct datapath	*dp;
	struct vport_portids __rcu *upcall_portids;
	u16 port_no;

	struct hlist_node hash_node;
	struct hlist_node dp_hash_node;
	const struct vport_ops *ops;

	struct list_head detach_list;
	struct rcu_head rcu;
};

static inline const char *ovs_vport_name(struct vport *vport)
{
	return vport->dev->name;
}

static void (*klpe_ovs_vport_send)(struct vport *vport, struct sk_buff *skb, u8 mac_proto);

/* klp-ccp: from net/openvswitch/actions.c */
#define MAX_L2_LEN	(VLAN_ETH_HLEN + 3 * MPLS_HLEN)

static int (*klpe_ovs_vport_output)(struct net *net, struct sock *sk, struct sk_buff *skb);

static struct dst_ops (*klpe_ovs_dst_ops);

static void (*klpe_prepare_frag)(struct vport *vport, struct sk_buff *skb,
			 u16 orig_network_offset, u8 mac_proto);

static void klpr_ovs_fragment(struct net *net, struct vport *vport,
			 struct sk_buff *skb, u16 mru,
			 struct sw_flow_key *key)
{
	u16 orig_network_offset = 0;

	if (eth_p_mpls(skb->protocol)) {
		orig_network_offset = skb_network_offset(skb);
		skb->network_header = skb->inner_network_header;
	}

	if (skb_network_offset(skb) > MAX_L2_LEN) {
		OVS_NLERR(1, "L2 header too long to fragment");
		goto err;
	}

	if (key->eth.type == htons(ETH_P_IP)) {
		struct rtable ovs_rt;
		unsigned long orig_dst;

		memset(&ovs_rt, 0, sizeof(struct rtable));
		(*klpe_prepare_frag)(vport, skb, orig_network_offset,
			     ovs_key_mac_proto(key));
		dst_init(&ovs_rt.dst, &(*klpe_ovs_dst_ops), NULL, 1,
			 DST_OBSOLETE_NONE, DST_NOCOUNT);
		ovs_rt.dst.dev = vport->dev;

		orig_dst = skb->_skb_refdst;
		skb_dst_set_noref(skb, &ovs_rt.dst);
		IPCB(skb)->frag_max_size = mru;

		ip_do_fragment(net, skb->sk, skb, (*klpe_ovs_vport_output));
		refdst_drop(orig_dst);
	} else if (key->eth.type == htons(ETH_P_IPV6)) {
		const struct nf_ipv6_ops *v6ops = nf_get_ipv6_ops();
		unsigned long orig_dst;
		struct rt6_info ovs_rt;

		if (!v6ops)
			goto err;

		(*klpe_prepare_frag)(vport, skb, orig_network_offset,
			     ovs_key_mac_proto(key));
		memset(&ovs_rt, 0, sizeof(ovs_rt));
		dst_init(&ovs_rt.dst, &(*klpe_ovs_dst_ops), NULL, 1,
			 DST_OBSOLETE_NONE, DST_NOCOUNT);
		ovs_rt.dst.dev = vport->dev;

		orig_dst = skb->_skb_refdst;
		skb_dst_set_noref(skb, &ovs_rt.dst);
		IP6CB(skb)->frag_max_size = mru;

		v6ops->fragment(net, skb->sk, skb, (*klpe_ovs_vport_output));
		refdst_drop(orig_dst);
	} else {
		WARN_ONCE(1, "Failed fragment ->%s: eth=%04x, MRU=%d, MTU=%d.",
			  ovs_vport_name(vport), ntohs(key->eth.type), mru,
			  vport->dev->mtu);
		goto err;
	}

	return;
err:
	kfree_skb(skb);
}

void klpp_do_output(struct datapath *dp, struct sk_buff *skb, int out_port,
		      struct sw_flow_key *key)
{
	struct vport *vport = klpr_ovs_vport_rcu(dp, out_port);

	if (likely(vport)) {
		u16 mru = OVS_CB(skb)->mru;
		u32 cutlen = OVS_CB(skb)->cutlen;

		if (unlikely(cutlen > 0)) {
			if (skb->len - cutlen > ovs_mac_header_len(key))
				pskb_trim(skb, skb->len - cutlen);
			else
				pskb_trim(skb, ovs_mac_header_len(key));
		}

		if (likely(!mru ||
		           (skb->len <= mru + vport->dev->hard_header_len))) {
			(*klpe_ovs_vport_send)(vport, skb, ovs_key_mac_proto(key));
		} else if (mru <= vport->dev->mtu) {
			struct net *net = read_pnet(&dp->net);

			klpr_ovs_fragment(net, vport, skb, mru, key);
		} else {
			kfree_skb(skb);
		}
	} else {
		kfree_skb(skb);
	}
}


#include "livepatch_bsc1220537.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "openvswitch"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ovs_dst_ops", (void *)&klpe_ovs_dst_ops, "openvswitch" },
	{ "ovs_lookup_vport", (void *)&klpe_ovs_lookup_vport, "openvswitch" },
	{ "ovs_vport_output", (void *)&klpe_ovs_vport_output, "openvswitch" },
	{ "ovs_vport_send", (void *)&klpe_ovs_vport_send, "openvswitch" },
	{ "prepare_frag", (void *)&klpe_prepare_frag, "openvswitch" },
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

int livepatch_bsc1220537_init(void)
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

void livepatch_bsc1220537_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
