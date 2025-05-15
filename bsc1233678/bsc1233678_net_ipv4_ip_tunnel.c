/*
 * bsc1233678_net_ipv4_ip_tunnel
 *
 * Fix for CVE-2024-53042, bsc#1233678
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* klp-ccp: from include/linux/if_arp.h */
#define _LINUX_IF_ARP_H

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/

#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/ipv4/ip_tunnel.c */
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>

#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/rculist.h>
#include <linux/err.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>

#include <net/ip_tunnels.h>

/* klp-ccp: from include/net/ip_tunnels.h */
#ifdef CONFIG_INET

static inline void klpp_ip_tunnel_init_flow(struct flowi4 *fl4,
				       int proto,
				       __be32 daddr, __be32 saddr,
				       __be32 key, __u8 tos,
				       struct net *net, int oif,
				       __u32 mark, __u32 tun_inner_hash,
				       __u8 flow_flags)
{
	memset(fl4, 0, sizeof(*fl4));

	if (oif) {
		fl4->flowi4_l3mdev = l3mdev_master_upper_ifindex_by_index(net, oif);
		/* Legacy VRF/l3mdev use case */
		fl4->flowi4_oif = fl4->flowi4_l3mdev ? 0 : oif;
	}

	fl4->daddr = daddr;
	fl4->saddr = saddr;
	fl4->flowi4_tos = tos;
	fl4->flowi4_proto = proto;
	fl4->fl4_gre_key = key;
	fl4->flowi4_mark = mark;
	fl4->flowi4_multipath_hash = tun_inner_hash;
	fl4->flowi4_flags = flow_flags;
}

void klpp_ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev, const
			 struct iphdr *tnl_params, const u8 protocol); void
klpp_ip_md_tunnel_xmit(struct sk_buff *skb, struct net_device *dev, const u8
		       proto, int tunnel_hlen);

#else /* CONFIG_INET */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_INET */

/* klp-ccp: from net/ipv4/ip_tunnel.c */
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>

#include <net/dst_metadata.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

int klpp_ip_tunnel_bind_dev(struct net_device *dev)
{
	struct net_device *tdev = NULL;
	struct ip_tunnel *tunnel = netdev_priv(dev);
	const struct iphdr *iph;
	int hlen = LL_MAX_HEADER;
	int mtu = ETH_DATA_LEN;
	int t_hlen = tunnel->hlen + sizeof(struct iphdr);

	iph = &tunnel->parms.iph;

	/* Guess output device to choose reasonable mtu and needed_headroom */
	if (iph->daddr) {
		struct flowi4 fl4;
		struct rtable *rt;

		klpp_ip_tunnel_init_flow(&fl4, iph->protocol, iph->daddr,
				    iph->saddr, tunnel->parms.o_key,
				    RT_TOS(iph->tos), dev_net(dev),
				    tunnel->parms.link, tunnel->fwmark, 0, 0);
		rt = ip_route_output_key(tunnel->net, &fl4);

		if (!IS_ERR(rt)) {
			tdev = rt->dst.dev;
			ip_rt_put(rt);
		}
		if (dev->type != ARPHRD_ETHER)
			dev->flags |= IFF_POINTOPOINT;

		dst_cache_reset(&tunnel->dst_cache);
	}

	if (!tdev && tunnel->parms.link)
		tdev = __dev_get_by_index(tunnel->net, tunnel->parms.link);

	if (tdev) {
		hlen = tdev->hard_header_len + tdev->needed_headroom;
		mtu = min(tdev->mtu, IP_MAX_MTU);
	}

	dev->needed_headroom = t_hlen + hlen;
	mtu -= t_hlen + (dev->type == ARPHRD_ETHER ? dev->hard_header_len : 0);

	if (mtu < IPV4_MIN_MTU)
		mtu = IPV4_MIN_MTU;

	return mtu;
}

static int tnl_update_pmtu(struct net_device *dev, struct sk_buff *skb,
			    struct rtable *rt, __be16 df,
			    const struct iphdr *inner_iph,
			    int tunnel_hlen, __be32 dst, bool md)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	int pkt_size;
	int mtu;

	tunnel_hlen = md ? tunnel_hlen : tunnel->hlen;
	pkt_size = skb->len - tunnel_hlen;
	pkt_size -= dev->type == ARPHRD_ETHER ? dev->hard_header_len : 0;

	if (df) {
		mtu = dst_mtu(&rt->dst) - (sizeof(struct iphdr) + tunnel_hlen);
		mtu -= dev->type == ARPHRD_ETHER ? dev->hard_header_len : 0;
	} else {
		mtu = skb_valid_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;
	}

	if (skb_valid_dst(skb))
		skb_dst_update_pmtu_no_confirm(skb, mtu);

	if (skb->protocol == htons(ETH_P_IP)) {
		if (!skb_is_gso(skb) &&
		    (inner_iph->frag_off & htons(IP_DF)) &&
		    mtu < pkt_size) {
			icmp_ndo_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
			return -E2BIG;
		}
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct rt6_info *rt6;
		__be32 daddr;

		rt6 = skb_valid_dst(skb) ? (struct rt6_info *)skb_dst(skb) :
					   NULL;
		daddr = md ? dst : tunnel->parms.iph.daddr;

		if (rt6 && mtu < dst_mtu(skb_dst(skb)) &&
			   mtu >= IPV6_MIN_MTU) {
			if ((daddr && !ipv4_is_multicast(daddr)) ||
			    rt6->rt6i_dst.plen == 128) {
				rt6->rt6i_flags |= RTF_MODIFIED;
				dst_metric_set(skb_dst(skb), RTAX_MTU, mtu);
			}
		}

		if (!skb_is_gso(skb) && mtu >= IPV6_MIN_MTU &&
					mtu < pkt_size) {
			icmpv6_ndo_send(skb, ICMPV6_PKT_TOOBIG, 0, mtu);
			return -E2BIG;
		}
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return 0;
}

static void ip_tunnel_adj_headroom(struct net_device *dev, unsigned int headroom)
{
	/* we must cap headroom to some upperlimit, else pskb_expand_head
	 * will overflow header offsets in skb_headers_offset_update().
	 */
	static const unsigned int max_allowed = 512;

	if (headroom > max_allowed)
		headroom = max_allowed;

	if (headroom > READ_ONCE(dev->needed_headroom))
		WRITE_ONCE(dev->needed_headroom, headroom);
}

void klpp_ip_md_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
		       u8 proto, int tunnel_hlen)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	u32 headroom = sizeof(struct iphdr);
	struct ip_tunnel_info *tun_info;
	const struct ip_tunnel_key *key;
	const struct iphdr *inner_iph;
	struct rtable *rt = NULL;
	struct flowi4 fl4;
	__be16 df = 0;
	u8 tos, ttl;
	bool use_cache;

	tun_info = skb_tunnel_info(skb);
	if (unlikely(!tun_info || !(tun_info->mode & IP_TUNNEL_INFO_TX) ||
		     ip_tunnel_info_af(tun_info) != AF_INET))
		goto tx_error;
	key = &tun_info->key;
	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));
	inner_iph = (const struct iphdr *)skb_inner_network_header(skb);
	tos = key->tos;
	if (tos == 1) {
		if (skb->protocol == htons(ETH_P_IP))
			tos = inner_iph->tos;
		else if (skb->protocol == htons(ETH_P_IPV6))
			tos = ipv6_get_dsfield((const struct ipv6hdr *)inner_iph);
	}
	klpp_ip_tunnel_init_flow(&fl4, proto, key->u.ipv4.dst, key->u.ipv4.src,
			    tunnel_id_to_key32(key->tun_id), RT_TOS(tos),
			    dev_net(dev), 0, skb->mark, skb_get_hash(skb),
			    key->flow_flags);

	if (!tunnel_hlen)
		tunnel_hlen = ip_encap_hlen(&tun_info->encap);

	if (ip_tunnel_encap(skb, &tun_info->encap, &proto, &fl4) < 0)
		goto tx_error;

	use_cache = ip_tunnel_dst_cache_usable(skb, tun_info);
	if (use_cache)
		rt = dst_cache_get_ip4(&tun_info->dst_cache, &fl4.saddr);
	if (!rt) {
		rt = ip_route_output_key(tunnel->net, &fl4);
		if (IS_ERR(rt)) {
			DEV_STATS_INC(dev, tx_carrier_errors);
			goto tx_error;
		}
		if (use_cache)
			dst_cache_set_ip4(&tun_info->dst_cache, &rt->dst,
					  fl4.saddr);
	}
	if (rt->dst.dev == dev) {
		ip_rt_put(rt);
		DEV_STATS_INC(dev, collisions);
		goto tx_error;
	}

	if (key->tun_flags & TUNNEL_DONT_FRAGMENT)
		df = htons(IP_DF);
	if (tnl_update_pmtu(dev, skb, rt, df, inner_iph, tunnel_hlen,
			    key->u.ipv4.dst, true)) {
		ip_rt_put(rt);
		goto tx_error;
	}

	tos = ip_tunnel_ecn_encap(tos, inner_iph, skb);
	ttl = key->ttl;
	if (ttl == 0) {
		if (skb->protocol == htons(ETH_P_IP))
			ttl = inner_iph->ttl;
		else if (skb->protocol == htons(ETH_P_IPV6))
			ttl = ((const struct ipv6hdr *)inner_iph)->hop_limit;
		else
			ttl = ip4_dst_hoplimit(&rt->dst);
	}

	headroom += LL_RESERVED_SPACE(rt->dst.dev) + rt->dst.header_len;
	if (skb_cow_head(skb, headroom)) {
		ip_rt_put(rt);
		goto tx_dropped;
	}

	ip_tunnel_adj_headroom(dev, headroom);

	iptunnel_xmit(NULL, rt, skb, fl4.saddr, fl4.daddr, proto, tos, ttl,
		      df, !net_eq(tunnel->net, dev_net(dev)));
	return;
tx_error:
	DEV_STATS_INC(dev, tx_errors);
	goto kfree;
tx_dropped:
	DEV_STATS_INC(dev, tx_dropped);
kfree:
	kfree_skb(skb);
}

typeof(klpp_ip_md_tunnel_xmit) klpp_ip_md_tunnel_xmit;

void klpp_ip_tunnel_xmit(struct sk_buff *skb, struct net_device *dev,
		    const struct iphdr *tnl_params, u8 protocol)
{
	struct ip_tunnel *tunnel = netdev_priv(dev);
	struct ip_tunnel_info *tun_info = NULL;
	const struct iphdr *inner_iph;
	unsigned int max_headroom;	/* The extra header space needed */
	struct rtable *rt = NULL;		/* Route to the other host */
	__be16 payload_protocol;
	bool use_cache = false;
	struct flowi4 fl4;
	bool md = false;
	bool connected;
	u8 tos, ttl;
	__be32 dst;
	__be16 df;

	inner_iph = (const struct iphdr *)skb_inner_network_header(skb);
	connected = (tunnel->parms.iph.daddr != 0);
	payload_protocol = skb_protocol(skb, true);

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	dst = tnl_params->daddr;
	if (dst == 0) {
		/* NBMA tunnel */

		if (!skb_dst(skb)) {
			DEV_STATS_INC(dev, tx_fifo_errors);
			goto tx_error;
		}

		tun_info = skb_tunnel_info(skb);
		if (tun_info && (tun_info->mode & IP_TUNNEL_INFO_TX) &&
		    ip_tunnel_info_af(tun_info) == AF_INET &&
		    tun_info->key.u.ipv4.dst) {
			dst = tun_info->key.u.ipv4.dst;
			md = true;
			connected = true;
		} else if (payload_protocol == htons(ETH_P_IP)) {
			rt = skb_rtable(skb);
			dst = rt_nexthop(rt, inner_iph->daddr);
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (payload_protocol == htons(ETH_P_IPV6)) {
			const struct in6_addr *addr6;
			struct neighbour *neigh;
			bool do_tx_error_icmp;
			int addr_type;

			neigh = dst_neigh_lookup(skb_dst(skb),
						 &ipv6_hdr(skb)->daddr);
			if (!neigh)
				goto tx_error;

			addr6 = (const struct in6_addr *)&neigh->primary_key;
			addr_type = ipv6_addr_type(addr6);

			if (addr_type == IPV6_ADDR_ANY) {
				addr6 = &ipv6_hdr(skb)->daddr;
				addr_type = ipv6_addr_type(addr6);
			}

			if ((addr_type & IPV6_ADDR_COMPATv4) == 0)
				do_tx_error_icmp = true;
			else {
				do_tx_error_icmp = false;
				dst = addr6->s6_addr32[3];
			}
			neigh_release(neigh);
			if (do_tx_error_icmp)
				goto tx_error_icmp;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		else
			goto tx_error;

		if (!md)
			connected = false;
	}

	tos = tnl_params->tos;
	if (tos & 0x1) {
		tos &= ~0x1;
		if (payload_protocol == htons(ETH_P_IP)) {
			tos = inner_iph->tos;
			connected = false;
		} else if (payload_protocol == htons(ETH_P_IPV6)) {
			tos = ipv6_get_dsfield((const struct ipv6hdr *)inner_iph);
			connected = false;
		}
	}

	klpp_ip_tunnel_init_flow(&fl4, protocol, dst, tnl_params->saddr,
			    tunnel->parms.o_key, RT_TOS(tos),
			    dev_net(dev), tunnel->parms.link,
			    tunnel->fwmark, skb_get_hash(skb), 0);

	if (ip_tunnel_encap(skb, &tunnel->encap, &protocol, &fl4) < 0)
		goto tx_error;

	if (connected && md) {
		use_cache = ip_tunnel_dst_cache_usable(skb, tun_info);
		if (use_cache)
			rt = dst_cache_get_ip4(&tun_info->dst_cache,
					       &fl4.saddr);
	} else {
		rt = connected ? dst_cache_get_ip4(&tunnel->dst_cache,
						&fl4.saddr) : NULL;
	}

	if (!rt) {
		rt = ip_route_output_key(tunnel->net, &fl4);

		if (IS_ERR(rt)) {
			DEV_STATS_INC(dev, tx_carrier_errors);
			goto tx_error;
		}
		if (use_cache)
			dst_cache_set_ip4(&tun_info->dst_cache, &rt->dst,
					  fl4.saddr);
		else if (!md && connected)
			dst_cache_set_ip4(&tunnel->dst_cache, &rt->dst,
					  fl4.saddr);
	}

	if (rt->dst.dev == dev) {
		ip_rt_put(rt);
		DEV_STATS_INC(dev, collisions);
		goto tx_error;
	}

	df = tnl_params->frag_off;
	if (payload_protocol == htons(ETH_P_IP) && !tunnel->ignore_df)
		df |= (inner_iph->frag_off & htons(IP_DF));

	if (tnl_update_pmtu(dev, skb, rt, df, inner_iph, 0, 0, false)) {
		ip_rt_put(rt);
		goto tx_error;
	}

	if (tunnel->err_count > 0) {
		if (time_before(jiffies,
				tunnel->err_time + IPTUNNEL_ERR_TIMEO)) {
			tunnel->err_count--;

			dst_link_failure(skb);
		} else
			tunnel->err_count = 0;
	}

	tos = ip_tunnel_ecn_encap(tos, inner_iph, skb);
	ttl = tnl_params->ttl;
	if (ttl == 0) {
		if (payload_protocol == htons(ETH_P_IP))
			ttl = inner_iph->ttl;
#if IS_ENABLED(CONFIG_IPV6)
		else if (payload_protocol == htons(ETH_P_IPV6))
			ttl = ((const struct ipv6hdr *)inner_iph)->hop_limit;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		else
			ttl = ip4_dst_hoplimit(&rt->dst);
	}

	max_headroom = LL_RESERVED_SPACE(rt->dst.dev) + sizeof(struct iphdr)
			+ rt->dst.header_len + ip_encap_hlen(&tunnel->encap);

	if (skb_cow_head(skb, max_headroom)) {
		ip_rt_put(rt);
		DEV_STATS_INC(dev, tx_dropped);
		kfree_skb(skb);
		return;
	}

	ip_tunnel_adj_headroom(dev, max_headroom);

	iptunnel_xmit(NULL, rt, skb, fl4.saddr, fl4.daddr, protocol, tos, ttl,
		      df, !net_eq(tunnel->net, dev_net(dev)));
	return;

#if IS_ENABLED(CONFIG_IPV6)
tx_error_icmp:
	dst_link_failure(skb);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
tx_error:
	DEV_STATS_INC(dev, tx_errors);
	kfree_skb(skb);
}

typeof(klpp_ip_tunnel_xmit) klpp_ip_tunnel_xmit;


#include "livepatch_bsc1233678.h"

