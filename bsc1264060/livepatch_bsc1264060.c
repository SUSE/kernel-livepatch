/*
 * livepatch_bsc1264060
 *
 * Fix for CVE-2026-31738, bsc#1264060
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

#include "livepatch_bsc1264060.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <linux/igmp.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include <net/arp.h>
#include <net/ndisc.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/inet_ecn.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/vxlan.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ip6_tunnel.h>
#include <net/ip6_checksum.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static const u8 (*klpe_all_zeros_mac)[ETH_ALEN + 2];

struct vxlan_fdb {
	struct hlist_node hlist;	/* linked list of entries */
	struct rcu_head	  rcu;
	unsigned long	  updated;	/* jiffies */
	unsigned long	  used;
	struct list_head  remotes;
	u8		  eth_addr[ETH_ALEN];
	u16		  state;	/* see ndm_state */
	__be32		  vni;
	u8		  flags;	/* see ndm_flags */
};

static inline struct vxlan_rdst *first_remote_rcu(struct vxlan_fdb *fdb)
{
	return list_entry_rcu(fdb->remotes.next, struct vxlan_rdst, list);
}

static void (*klpe_vxlan_ip_miss)(struct net_device *dev, union vxlan_addr *ipa);

static void (*klpe_vxlan_fdb_miss)(struct vxlan_dev *vxlan, const u8 eth_addr[ETH_ALEN]);

static struct vxlan_fdb *(*klpe___vxlan_find_mac)(struct vxlan_dev *vxlan,
					  const u8 *mac, __be32 vni);

static struct vxlan_fdb *klpr_vxlan_find_mac(struct vxlan_dev *vxlan,
					const u8 *mac, __be32 vni)
{
	struct vxlan_fdb *f;

	f = (*klpe___vxlan_find_mac)(vxlan, mac, vni);
	if (f)
		f->used = jiffies;

	return f;
}

static int klpr_arp_reduce(struct net_device *dev, struct sk_buff *skb, __be32 vni)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct arphdr *parp;
	u8 *arpptr, *sha;
	__be32 sip, tip;
	struct neighbour *n;

	if (dev->flags & IFF_NOARP)
		goto out;

	if (!pskb_may_pull(skb, arp_hdr_len(dev))) {
		dev->stats.tx_dropped++;
		goto out;
	}
	parp = arp_hdr(skb);

	if ((parp->ar_hrd != htons(ARPHRD_ETHER) &&
	     parp->ar_hrd != htons(ARPHRD_IEEE802)) ||
	    parp->ar_pro != htons(ETH_P_IP) ||
	    parp->ar_op != htons(ARPOP_REQUEST) ||
	    parp->ar_hln != dev->addr_len ||
	    parp->ar_pln != 4)
		goto out;
	arpptr = (u8 *)parp + sizeof(struct arphdr);
	sha = arpptr;
	arpptr += dev->addr_len;	/* sha */
	memcpy(&sip, arpptr, sizeof(sip));
	arpptr += sizeof(sip);
	arpptr += dev->addr_len;	/* tha */
	memcpy(&tip, arpptr, sizeof(tip));

	if (ipv4_is_loopback(tip) ||
	    ipv4_is_multicast(tip))
		goto out;

	n = neigh_lookup(&arp_tbl, &tip, dev);

	if (n) {
		struct vxlan_fdb *f;
		struct sk_buff	*reply;

		if (!(n->nud_state & NUD_CONNECTED)) {
			neigh_release(n);
			goto out;
		}

		f = klpr_vxlan_find_mac(vxlan, n->ha, vni);
		if (f && vxlan_addr_any(&(first_remote_rcu(f)->remote_ip))) {
			/* bridge-local neighbor */
			neigh_release(n);
			goto out;
		}

		reply = arp_create(ARPOP_REPLY, ETH_P_ARP, sip, dev, tip, sha,
				n->ha, sha);

		neigh_release(n);

		if (reply == NULL)
			goto out;

		skb_reset_mac_header(reply);
		__skb_pull(reply, skb_network_offset(reply));
		reply->ip_summed = CHECKSUM_UNNECESSARY;
		reply->pkt_type = PACKET_HOST;

		if (netif_rx_ni(reply) == NET_RX_DROP)
			dev->stats.rx_dropped++;
	} else if (vxlan->flags & VXLAN_F_L3MISS) {
		union vxlan_addr ipa = {
			.sin.sin_addr.s_addr = tip,
			.sin.sin_family = AF_INET,
		};

		(*klpe_vxlan_ip_miss)(dev, &ipa);
	}
out:
	consume_skb(skb);
	return NETDEV_TX_OK;
}

#if IS_ENABLED(CONFIG_IPV6)
static struct sk_buff *klpp_vxlan_na_create(struct sk_buff *request,
	struct neighbour *n, bool isrouter)
{
	struct net_device *dev = request->dev;
	struct sk_buff *reply;
	struct nd_msg *ns, *na;
	struct ipv6hdr *pip6;
	u8 *daddr;
	int na_olen = 8; /* opt hdr + ETH_ALEN for target */
	int ns_olen;
	int i, len;

	if (dev == NULL || !pskb_may_pull(request, request->len))
		return NULL;

	len = LL_RESERVED_SPACE(dev) + sizeof(struct ipv6hdr) +
		sizeof(*na) + na_olen + dev->needed_tailroom;
	reply = alloc_skb(len, GFP_ATOMIC);
	if (reply == NULL)
		return NULL;

	reply->protocol = htons(ETH_P_IPV6);
	reply->dev = dev;
	skb_reserve(reply, LL_RESERVED_SPACE(request->dev));
	skb_push(reply, sizeof(struct ethhdr));
	skb_reset_mac_header(reply);

	ns = (struct nd_msg *)(ipv6_hdr(request) + 1);

	daddr = eth_hdr(request)->h_source;
	ns_olen = request->len - skb_network_offset(request) -
		sizeof(struct ipv6hdr) - sizeof(*ns);
	for (i = 0; i < ns_olen-1; i += (ns->opt[i+1]<<3)) {
		if (!ns->opt[i + 1] || i + (ns->opt[i + 1] << 3) > ns_olen) {
			kfree_skb(reply);
			return NULL;
		}
		if (ns->opt[i] == ND_OPT_SOURCE_LL_ADDR) {
			if ((ns->opt[i + 1] << 3) >=
			    sizeof(struct nd_opt_hdr) + ETH_ALEN)
				daddr = ns->opt + i + sizeof(struct nd_opt_hdr);
			break;
		}
	}

	/* Ethernet header */
	ether_addr_copy(eth_hdr(reply)->h_dest, daddr);
	ether_addr_copy(eth_hdr(reply)->h_source, n->ha);
	eth_hdr(reply)->h_proto = htons(ETH_P_IPV6);
	reply->protocol = htons(ETH_P_IPV6);

	skb_pull(reply, sizeof(struct ethhdr));
	skb_reset_network_header(reply);
	skb_put(reply, sizeof(struct ipv6hdr));

	/* IPv6 header */

	pip6 = ipv6_hdr(reply);
	memset(pip6, 0, sizeof(struct ipv6hdr));
	pip6->version = 6;
	pip6->priority = ipv6_hdr(request)->priority;
	pip6->nexthdr = IPPROTO_ICMPV6;
	pip6->hop_limit = 255;
	pip6->daddr = ipv6_hdr(request)->saddr;
	pip6->saddr = *(struct in6_addr *)n->primary_key;

	skb_pull(reply, sizeof(struct ipv6hdr));
	skb_reset_transport_header(reply);

	/* Neighbor Advertisement */
	na = skb_put_zero(reply, sizeof(*na) + na_olen);
	na->icmph.icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
	na->icmph.icmp6_router = isrouter;
	na->icmph.icmp6_override = 1;
	na->icmph.icmp6_solicited = 1;
	na->target = ns->target;
	ether_addr_copy(&na->opt[2], n->ha);
	na->opt[0] = ND_OPT_TARGET_LL_ADDR;
	na->opt[1] = na_olen >> 3;

	na->icmph.icmp6_cksum = csum_ipv6_magic(&pip6->saddr,
		&pip6->daddr, sizeof(*na)+na_olen, IPPROTO_ICMPV6,
		csum_partial(na, sizeof(*na)+na_olen, 0));

	pip6->payload_len = htons(sizeof(*na)+na_olen);

	skb_push(reply, sizeof(struct ipv6hdr));

	reply->ip_summed = CHECKSUM_UNNECESSARY;

	return reply;
}

static int klpp_neigh_reduce(struct net_device *dev, struct sk_buff *skb, __be32 vni)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	const struct in6_addr *daddr;
	const struct ipv6hdr *iphdr;
	struct inet6_dev *in6_dev;
	struct neighbour *n;
	struct nd_msg *msg;

	rcu_read_lock();
	in6_dev = __in6_dev_get(dev);
	if (!in6_dev)
		goto out;

	iphdr = ipv6_hdr(skb);
	daddr = &iphdr->daddr;
	msg = (struct nd_msg *)(iphdr + 1);

	if (ipv6_addr_loopback(daddr) ||
	    ipv6_addr_is_multicast(&msg->target))
		goto out;

	n = neigh_lookup(ipv6_stub->nd_tbl, &msg->target, dev);

	if (n) {
		struct vxlan_fdb *f;
		struct sk_buff *reply;

		if (!(n->nud_state & NUD_CONNECTED)) {
			neigh_release(n);
			goto out;
		}

		f = klpr_vxlan_find_mac(vxlan, n->ha, vni);
		if (f && vxlan_addr_any(&(first_remote_rcu(f)->remote_ip))) {
			/* bridge-local neighbor */
			neigh_release(n);
			goto out;
		}

		reply = klpp_vxlan_na_create(skb, n,
					!!(f ? f->flags & NTF_ROUTER : 0));

		neigh_release(n);

		if (reply == NULL)
			goto out;

		if (netif_rx_ni(reply) == NET_RX_DROP)
			dev->stats.rx_dropped++;

	} else if (vxlan->flags & VXLAN_F_L3MISS) {
		union vxlan_addr ipa = {
			.sin6.sin6_addr = msg->target,
			.sin6.sin6_family = AF_INET6,
		};

		(*klpe_vxlan_ip_miss)(dev, &ipa);
	}

out:
	rcu_read_unlock();
	consume_skb(skb);
	return NETDEV_TX_OK;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static bool klpr_route_shortcircuit(struct net_device *dev, struct sk_buff *skb)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct neighbour *n;

	if (is_multicast_ether_addr(eth_hdr(skb)->h_dest))
		return false;

	n = NULL;
	switch (ntohs(eth_hdr(skb)->h_proto)) {
	case ETH_P_IP:
	{
		struct iphdr *pip;

		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return false;
		pip = ip_hdr(skb);
		n = neigh_lookup(&arp_tbl, &pip->daddr, dev);
		if (!n && (vxlan->flags & VXLAN_F_L3MISS)) {
			union vxlan_addr ipa = {
				.sin.sin_addr.s_addr = pip->daddr,
				.sin.sin_family = AF_INET,
			};

			(*klpe_vxlan_ip_miss)(dev, &ipa);
			return false;
		}

		break;
	}
#if IS_ENABLED(CONFIG_IPV6)
	case ETH_P_IPV6:
	{
		struct ipv6hdr *pip6;

		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return false;
		pip6 = ipv6_hdr(skb);
		n = neigh_lookup(ipv6_stub->nd_tbl, &pip6->daddr, dev);
		if (!n && (vxlan->flags & VXLAN_F_L3MISS)) {
			union vxlan_addr ipa = {
				.sin6.sin6_addr = pip6->daddr,
				.sin6.sin6_family = AF_INET6,
			};

			(*klpe_vxlan_ip_miss)(dev, &ipa);
			return false;
		}

		break;
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	default:
		return false;
	}

	if (n) {
		bool diff;

		diff = !ether_addr_equal(eth_hdr(skb)->h_dest, n->ha);
		if (diff) {
			memcpy(eth_hdr(skb)->h_source, eth_hdr(skb)->h_dest,
				dev->addr_len);
			memcpy(eth_hdr(skb)->h_dest, n->ha, dev->addr_len);
		}
		neigh_release(n);
		return diff;
	}

	return false;
}

static void (*klpe_vxlan_xmit_one)(struct sk_buff *skb, struct net_device *dev,
			   __be32 default_vni, struct vxlan_rdst *rdst,
			   bool did_rsc);

netdev_tx_t klpp_vxlan_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vxlan_dev *vxlan = netdev_priv(dev);
	struct vxlan_rdst *rdst, *fdst = NULL;
	const struct ip_tunnel_info *info;
	bool did_rsc = false;
	struct vxlan_fdb *f;
	struct ethhdr *eth;
	__be32 vni = 0;

	info = skb_tunnel_info(skb);

	skb_reset_mac_header(skb);

	if (vxlan->flags & VXLAN_F_COLLECT_METADATA) {
		if (info && info->mode & IP_TUNNEL_INFO_BRIDGE &&
		    info->mode & IP_TUNNEL_INFO_TX) {
			vni = tunnel_id_to_key32(info->key.tun_id);
		} else {
			if (info && info->mode & IP_TUNNEL_INFO_TX)
				(*klpe_vxlan_xmit_one)(skb, dev, vni, NULL, false);
			else
				kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}

	if (vxlan->flags & VXLAN_F_PROXY) {
		eth = eth_hdr(skb);
		if (ntohs(eth->h_proto) == ETH_P_ARP)
			return klpr_arp_reduce(dev, skb, vni);
#if IS_ENABLED(CONFIG_IPV6)
		else if (ntohs(eth->h_proto) == ETH_P_IPV6 &&
			 pskb_may_pull(skb, sizeof(struct ipv6hdr) +
					    sizeof(struct nd_msg)) &&
			 ipv6_hdr(skb)->nexthdr == IPPROTO_ICMPV6) {
			struct nd_msg *m = (struct nd_msg *)(ipv6_hdr(skb) + 1);

			if (m->icmph.icmp6_code == 0 &&
			    m->icmph.icmp6_type == NDISC_NEIGHBOUR_SOLICITATION)
				return klpp_neigh_reduce(dev, skb, vni);
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	}

	eth = eth_hdr(skb);
	f = klpr_vxlan_find_mac(vxlan, eth->h_dest, vni);
	did_rsc = false;

	if (f && (f->flags & NTF_ROUTER) && (vxlan->flags & VXLAN_F_RSC) &&
	    (ntohs(eth->h_proto) == ETH_P_IP ||
	     ntohs(eth->h_proto) == ETH_P_IPV6)) {
		did_rsc = klpr_route_shortcircuit(dev, skb);
		if (did_rsc)
			f = klpr_vxlan_find_mac(vxlan, eth->h_dest, vni);
	}

	if (f == NULL) {
		f = klpr_vxlan_find_mac(vxlan, (*klpe_all_zeros_mac), vni);
		if (f == NULL) {
			if ((vxlan->flags & VXLAN_F_L2MISS) &&
			    !is_multicast_ether_addr(eth->h_dest))
				(*klpe_vxlan_fdb_miss)(vxlan, eth->h_dest);

			dev->stats.tx_dropped++;
			kfree_skb(skb);
			return NETDEV_TX_OK;
		}
	}

	list_for_each_entry_rcu(rdst, &f->remotes, list) {
		struct sk_buff *skb1;

		if (!fdst) {
			fdst = rdst;
			continue;
		}
		skb1 = skb_clone(skb, GFP_ATOMIC);
		if (skb1)
			(*klpe_vxlan_xmit_one)(skb1, dev, vni, rdst, did_rsc);
	}

	if (fdst)
		(*klpe_vxlan_xmit_one)(skb, dev, vni, fdst, did_rsc);
	else
		kfree_skb(skb);
	return NETDEV_TX_OK;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vxlan"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__vxlan_find_mac", (void *)&klpe___vxlan_find_mac, "vxlan" },
	{ "all_zeros_mac", (void *)&klpe_all_zeros_mac, "vxlan" },
	{ "vxlan_fdb_miss", (void *)&klpe_vxlan_fdb_miss, "vxlan" },
	{ "vxlan_ip_miss", (void *)&klpe_vxlan_ip_miss, "vxlan" },
	{ "vxlan_xmit_one", (void *)&klpe_vxlan_xmit_one, "vxlan" },
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

int livepatch_bsc1264060_init(void)
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

void livepatch_bsc1264060_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
