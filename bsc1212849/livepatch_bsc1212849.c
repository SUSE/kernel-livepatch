/*
 * livepatch_bsc1212849
 *
 * Fix for CVE-2023-3090, bsc#1212849 and for CVE-2022-48651, bsc#1223514
 *
 *  Upstream commit:
 *  90cbed524743 ("ipvlan: Fix out-of-bounds caused by unclear skb->cb")
 *  81225b2ea161 ("ipvlan: Fix out-of-bound bugs caused by unset skb->mac_header")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  bd94484cb47717a3a5243a2400ca04df823b2a44
 *  3bb99bc1136fc072f99086334b70444da66cb901
 *
 *  SLE15-SP2 and -SP3 commit:
 *  ddb692240f5be2ac125ddd9870534b8e4a650e73
 *  0325bf2f2c93e1cb6522bcf04ae518ea3ad7b9c5
 *
 *  SLE15-SP4 and -SP5 commit:
 *  7062cceaea4512cb93ea9e24717a6086221e530e
 *  c96a663e04c2b187e2dfe90864330d64ba2e01d6
 *
 *  Copyright (c) 2023-2024 SUSE
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

#if !IS_MODULE(CONFIG_IPVLAN)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/ipvlan/ipvlan.h */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/rculist.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from drivers/net/ipvlan/ipvlan.h */
#include <linux/if_link.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ip6_route.h>
#include <net/rtnetlink.h>
#include <net/route.h>
#include <net/addrconf.h>
#include <net/l3mdev.h>

#define IPVLAN_HASH_SIZE	(1 << BITS_PER_BYTE)

#define IPVLAN_MAC_FILTER_BITS	8
#define IPVLAN_MAC_FILTER_SIZE	(1 << IPVLAN_MAC_FILTER_BITS)

typedef enum {
	IPVL_IPV6 = 0,
	IPVL_ICMPV6,
	IPVL_IPV4,
	IPVL_ARP,
} ipvl_hdr_type;

struct ipvl_dev {
	struct net_device	*dev;
	struct list_head	pnode;
	struct ipvl_port	*port;
	struct net_device	*phy_dev;
	struct list_head	addrs;
	struct ipvl_pcpu_stats	__percpu *pcpu_stats;
	DECLARE_BITMAP(mac_filters, IPVLAN_MAC_FILTER_SIZE);
	netdev_features_t	sfeatures;
	u32			msg_enable;
#ifndef __GENKSYMS__
	spinlock_t              addrs_lock;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct ipvl_addr {
	struct ipvl_dev		*master; /* Back pointer to master */
	union {
		struct in6_addr	ip6;	 /* IPv6 address on logical interface */
		struct in_addr	ip4;	 /* IPv4 address on logical interface */
	} ipu;
	struct hlist_node	hlnode;  /* Hash-table linkage */
	struct list_head	anode;   /* logical-interface linkage */
	ipvl_hdr_type		atype;
	struct rcu_head		rcu;
};

struct ipvl_port {
	struct net_device	*dev;
	possible_net_t		pnet;
	struct hlist_head	hlhead[IPVLAN_HASH_SIZE];
	struct list_head	ipvlans;
	u16			mode;
	u16			dev_id_start;
	struct work_struct	wq;
	struct sk_buff_head	backlog;
	int			count;
	struct ida		ida;
};

static inline struct ipvl_port *ipvlan_port_get_rcu_bh(const struct net_device *d)
{
	return rcu_dereference_bh(d->rx_handler_data);
}

static void (*klpe_ipvlan_count_rx)(const struct ipvl_dev *ipvlan,
		     unsigned int len, bool success, bool mcast);

static void *(*klpe_ipvlan_get_L3_hdr)(struct sk_buff *skb, int *type);

static void ipvlan_skb_crossing_ns(struct sk_buff *skb, struct net_device *dev)
{
	bool xnet = true;

	if (dev)
		xnet = !net_eq(dev_net(skb->dev), dev_net(dev));

	skb_scrub_packet(skb, xnet);
	if (dev)
		skb->dev = dev;
}

static int klpr_ipvlan_rcv_frame(struct ipvl_addr *addr, struct sk_buff **pskb,
			    bool local)
{
	struct ipvl_dev *ipvlan = addr->master;
	struct net_device *dev = ipvlan->dev;
	unsigned int len;
	rx_handler_result_t ret = RX_HANDLER_CONSUMED;
	bool success = false;
	struct sk_buff *skb = *pskb;

	len = skb->len + ETH_HLEN;
	/* Only packets exchanged between two local slaves need to have
	 * device-up check as well as skb-share check.
	 */
	if (local) {
		if (unlikely(!(dev->flags & IFF_UP))) {
			kfree_skb(skb);
			goto out;
		}

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			goto out;

		*pskb = skb;
	}

	if (local) {
		skb->pkt_type = PACKET_HOST;
		if (dev_forward_skb(ipvlan->dev, skb) == NET_RX_SUCCESS)
			success = true;
	} else {
		skb->dev = dev;
		ret = RX_HANDLER_ANOTHER;
		success = true;
	}

out:
	(*klpe_ipvlan_count_rx)(ipvlan, len, success, false);
	return ret;
}

static struct ipvl_addr *(*klpe_ipvlan_addr_lookup)(struct ipvl_port *port,
					    void *lyr3h, int addr_type,
					    bool use_dest);

static int klpp_ipvlan_process_v4_outbound(struct sk_buff *skb)
{
	const struct iphdr *ip4h = ip_hdr(skb);
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	struct rtable *rt;
	int err, ret = NET_XMIT_DROP;
	struct flowi4 fl4 = {
		.flowi4_oif = dev->ifindex,
		.flowi4_tos = RT_TOS(ip4h->tos),
		.flowi4_flags = FLOWI_FLAG_ANYSRC,
		.flowi4_mark = skb->mark,
		.daddr = ip4h->daddr,
		.saddr = ip4h->saddr,
	};

	rt = ip_route_output_flow(net, &fl4, NULL);
	if (IS_ERR(rt))
		goto err;

	if (rt->rt_type != RTN_UNICAST && rt->rt_type != RTN_LOCAL) {
		ip_rt_put(rt);
		goto err;
	}
	skb_dst_set(skb, &rt->dst);

	memset(IPCB(skb), 0, sizeof(*IPCB(skb)));

	err = ip_local_out(net, skb->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		dev->stats.tx_errors++;
	else
		ret = NET_XMIT_SUCCESS;
	goto out;
err:
	dev->stats.tx_errors++;
	kfree_skb(skb);
out:
	return ret;
}

static int klpp_ipvlan_process_v6_outbound(struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct net_device *dev = skb->dev;
	struct net *net = dev_net(dev);
	struct dst_entry *dst;
	int err, ret = NET_XMIT_DROP;
	struct flowi6 fl6 = {
		.flowi6_oif = dev->ifindex,
		.daddr = ip6h->daddr,
		.saddr = ip6h->saddr,
		.flowi6_flags = FLOWI_FLAG_ANYSRC,
		.flowlabel = ip6_flowinfo(ip6h),
		.flowi6_mark = skb->mark,
		.flowi6_proto = ip6h->nexthdr,
	};

	dst = ip6_route_output(net, NULL, &fl6);
	if (dst->error) {
		ret = dst->error;
		dst_release(dst);
		goto err;
	}
	skb_dst_set(skb, dst);

	memset(IP6CB(skb), 0, sizeof(*IP6CB(skb)));

	err = ip6_local_out(net, skb->sk, skb);
	if (unlikely(net_xmit_eval(err)))
		dev->stats.tx_errors++;
	else
		ret = NET_XMIT_SUCCESS;
	goto out;
err:
	dev->stats.tx_errors++;
	kfree_skb(skb);
out:
	return ret;
}

static int klpp_ipvlan_process_outbound(struct sk_buff *skb)
{
	int ret = NET_XMIT_DROP;

	/* The ipvlan is a pseudo-L2 device, so the packets that we receive
	 * will have L2; which need to discarded and processed further
	 * in the net-ns of the main-device.
	 */
	if (skb_mac_header_was_set(skb)) {
		/* In this mode we dont care about
		 * multicast and broadcast traffic */
		struct ethhdr *ethh = eth_hdr(skb);
		if (is_multicast_ether_addr(ethh->h_dest)) {
			pr_warn_ratelimited(
				"Dropped {multi|broad}cast of type=[%x]\n",
				ntohs(skb->protocol));
			kfree_skb(skb);
			goto out;
		}

		skb_pull(skb, sizeof(*ethh));
		skb->mac_header = (typeof(skb->mac_header))~0U;
		skb_reset_network_header(skb);
	}

	if (skb->protocol == htons(ETH_P_IPV6))
		ret = klpp_ipvlan_process_v6_outbound(skb);
	else if (skb->protocol == htons(ETH_P_IP))
		ret = klpp_ipvlan_process_v4_outbound(skb);
	else {
		pr_warn_ratelimited("Dropped outbound packet type=%x\n",
				    ntohs(skb->protocol));
		kfree_skb(skb);
	}
out:
	return ret;
}

static void (*klpe_ipvlan_multicast_enqueue)(struct ipvl_port *port,
				     struct sk_buff *skb, bool tx_pkt);

static int klpr_ipvlan_xmit_mode_l3(struct sk_buff *skb, struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	void *lyr3h;
	struct ipvl_addr *addr;
	int addr_type;

	lyr3h = (*klpe_ipvlan_get_L3_hdr)(skb, &addr_type);
	if (!lyr3h)
		goto out;

	addr = (*klpe_ipvlan_addr_lookup)(ipvlan->port, lyr3h, addr_type, true);
	if (addr)
		return klpr_ipvlan_rcv_frame(addr, &skb, true);

out:
	ipvlan_skb_crossing_ns(skb, ipvlan->phy_dev);
	return klpp_ipvlan_process_outbound(skb);
}

static int klpp_ipvlan_xmit_mode_l2(struct sk_buff *skb, struct net_device *dev)
{
	const struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ethhdr *eth = skb_eth_hdr(skb);
	struct ipvl_addr *addr;
	void *lyr3h;
	int addr_type;

	if (ether_addr_equal(eth->h_dest, eth->h_source)) {
		lyr3h = (*klpe_ipvlan_get_L3_hdr)(skb, &addr_type);
		if (lyr3h) {
			addr = (*klpe_ipvlan_addr_lookup)(ipvlan->port, lyr3h, addr_type, true);
			if (addr)
				return klpr_ipvlan_rcv_frame(addr, &skb, true);
		}
		skb = skb_share_check(skb, GFP_ATOMIC);
		if (!skb)
			return NET_XMIT_DROP;

		/* Packet definitely does not belong to any of the
		 * virtual devices, but the dest is local. So forward
		 * the skb for the main-dev. At the RX side we just return
		 * RX_PASS for it to be processed further on the stack.
		 */
		return dev_forward_skb(ipvlan->phy_dev, skb);

	} else if (is_multicast_ether_addr(eth->h_dest)) {
		skb_reset_mac_header(skb);
		ipvlan_skb_crossing_ns(skb, NULL);
		(*klpe_ipvlan_multicast_enqueue)(ipvlan->port, skb, true);
		return NET_XMIT_SUCCESS;
	}

	skb->dev = ipvlan->phy_dev;
	return dev_queue_xmit(skb);
}

int klpp_ipvlan_queue_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ipvl_dev *ipvlan = netdev_priv(dev);
	struct ipvl_port *port = ipvlan_port_get_rcu_bh(ipvlan->phy_dev);

	if (!port)
		goto out;

	if (unlikely(!pskb_may_pull(skb, sizeof(struct ethhdr))))
		goto out;

	switch(port->mode) {
	case IPVLAN_MODE_L2:
		return klpp_ipvlan_xmit_mode_l2(skb, dev);
	case IPVLAN_MODE_L3:
	case IPVLAN_MODE_L3S:
		return klpr_ipvlan_xmit_mode_l3(skb, dev);
	}

	/* Should not reach here */
	WARN_ONCE(true, "ipvlan_queue_xmit() called for mode = [%hx]\n",
			  port->mode);
out:
	kfree_skb(skb);
	return NET_XMIT_DROP;
}


#include "livepatch_bsc1212849.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ipvlan"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ipvlan_addr_lookup", (void *)&klpe_ipvlan_addr_lookup, "ipvlan" },
	{ "ipvlan_count_rx", (void *)&klpe_ipvlan_count_rx, "ipvlan" },
	{ "ipvlan_get_L3_hdr", (void *)&klpe_ipvlan_get_L3_hdr, "ipvlan" },
	{ "ipvlan_multicast_enqueue", (void *)&klpe_ipvlan_multicast_enqueue,
	  "ipvlan" },
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

int livepatch_bsc1212849_init(void)
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

void livepatch_bsc1212849_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
