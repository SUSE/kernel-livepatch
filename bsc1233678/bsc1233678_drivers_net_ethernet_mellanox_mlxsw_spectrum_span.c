/*
 * bsc1233678_drivers_net_ethernet_mellanox_mlxsw_spectrum_span
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

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum_span.c */
#include <linux/if_bridge.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/rtnetlink.h>
#include <linux/workqueue.h>
#include <net/arp.h>
#include <net/gre.h>

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

/* klp-ccp: from include/net/flow_offload.h */
#define _NET_FLOW_OFFLOAD_H

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum_span.c */
#include <net/ndisc.h>

/* klp-ccp: from include/net/ip6_tunnel.h */
#define _NET_IP6_TUNNEL_H

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum.h */
#include <linux/types.h>
#include <linux/netdevice.h>

#include <linux/bitops.h>
#include <linux/if_bridge.h>
#include <linux/if_vlan.h>
#include <linux/list.h>
#include <linux/dcbnl.h>
#include <linux/in6.h>
#include <linux/notifier.h>

/* klp-ccp: from include/uapi/linux/net_namespace.h */
#define _UAPI_LINUX_NET_NAMESPACE_H_

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum.h */
#include <linux/spinlock.h>

#include <net/flow_offload.h>
#include <net/inet_ecn.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/port.h */
#include <linux/types.h>
/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/core.h */
#include <linux/module.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/net_namespace.h>

/* klp-ccp: from include/net/devlink.h */
#define _NET_DEVLINK_H_

/* klp-ccp: from include/linux/firmware.h */
#define _LINUX_FIRMWARE_H

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/reg.h */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/bitops.h>
#include <linux/if_vlan.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/item.h */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/bitops.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/resources.h */
#include <linux/kernel.h>
#include <linux/types.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxfw/mlxfw.h */
#include <linux/firmware.h>
#include <linux/netlink.h>
#include <linux/device.h>
#include <net/devlink.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/core_acl_flex_keys.h */
#include <linux/types.h>
#include <linux/bitmap.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/core_acl_flex_actions.h */
#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/flow_offload.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum_ipip.h */
#include <net/ip_fib.h>
#include <linux/if_tunnel.h>
#include <net/ip6_tunnel.h>

struct ip_tunnel_parm
mlxsw_sp_ipip_netdev_parms4(const struct net_device *ol_dev);

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum_span.h */
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/refcount.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum_switchdev.h */
#include <linux/netdevice.h>

/* klp-ccp: from drivers/net/ethernet/mellanox/mlxsw/spectrum_span.c */
#if IS_ENABLED(CONFIG_NET_IPGRE)
struct net_device *
klpp_mlxsw_sp_span_gretap4_route(const struct net_device *to_dev,
			    __be32 *saddrp, __be32 *daddrp)
{
	struct ip_tunnel *tun = netdev_priv(to_dev);
	struct net_device *dev = NULL;
	struct ip_tunnel_parm parms;
	struct rtable *rt = NULL;
	struct flowi4 fl4;

	/* We assume "dev" stays valid after rt is put. */
	ASSERT_RTNL();

	parms = mlxsw_sp_ipip_netdev_parms4(to_dev);
	klpp_ip_tunnel_init_flow(&fl4, parms.iph.protocol, *daddrp, *saddrp,
			    0, 0, dev_net(to_dev), parms.link, tun->fwmark, 0,
			    0);

	rt = ip_route_output_key(tun->net, &fl4);
	if (IS_ERR(rt))
		return NULL;

	if (rt->rt_type != RTN_UNICAST)
		goto out;

	dev = rt->dst.dev;
	*saddrp = fl4.saddr;
	if (rt->rt_gw_family == AF_INET)
		*daddrp = rt->rt_gw4;
	/* can not offload if route has an IPv6 gateway */
	else if (rt->rt_gw_family == AF_INET6)
		dev = NULL;

out:
	ip_rt_put(rt);
	return dev;
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif


#include "livepatch_bsc1233678.h"

#include <linux/livepatch.h>

extern typeof(mlxsw_sp_ipip_netdev_parms4) mlxsw_sp_ipip_netdev_parms4
	 KLP_RELOC_SYMBOL(mlxsw_spectrum, mlxsw_spectrum, mlxsw_sp_ipip_netdev_parms4);
