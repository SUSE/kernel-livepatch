/*
 * bsc1233678_net_ipv4_ip_gre
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
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/ipv4/ip_gre.c */
#include <linux/if_vlan.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>

#include <linux/etherdevice.h>
#include <linux/if_ether.h>

#include <net/sock.h>
#include <net/ip.h>

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

#else /* CONFIG_INET */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_INET */

/* klp-ccp: from net/ipv4/ip_gre.c */
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>

#include <net/dst_metadata.h>

int klpp_gre_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct ip_tunnel_info *info = skb_tunnel_info(skb);
	const struct ip_tunnel_key *key;
	struct rtable *rt;
	struct flowi4 fl4;

	if (ip_tunnel_info_af(info) != AF_INET)
		return -EINVAL;

	key = &info->key;
	klpp_ip_tunnel_init_flow(&fl4, IPPROTO_GRE, key->u.ipv4.dst, key->u.ipv4.src,
			    tunnel_id_to_key32(key->tun_id),
			    key->tos & ~INET_ECN_MASK, dev_net(dev), 0,
			    skb->mark, skb_get_hash(skb), key->flow_flags);
	rt = ip_route_output_key(dev_net(dev), &fl4);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	ip_rt_put(rt);
	info->key.u.ipv4.src = fl4.saddr;
	return 0;
}


#include "livepatch_bsc1233678.h"

