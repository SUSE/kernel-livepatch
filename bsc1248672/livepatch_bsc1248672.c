/*
 * livepatch_bsc1248672
 *
 * Fix for CVE-2025-38500, bsc#1248672
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/xfrm/xfrm_interface_core.c */
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/netdevice.h>
#include <linux/if_link.h>

/* klp-ccp: from include/linux/if_arp.h */
#define _LINUX_IF_ARP_H

/* klp-ccp: from include/uapi/linux/if_arp.h */
#define ARPHRD_INFINIBAND 32		/* InfiniBand			*/

/* klp-ccp: from net/xfrm/xfrm_interface_core.c */
#include <linux/icmpv6.h>
#include <linux/init.h>

/* klp-ccp: from include/uapi/linux/route.h */
#define _LINUX_ROUTE_H

struct rtentry

#ifndef __KERNEL__
#error "klp-ccp: non-taken branch"
#endif
;

/* klp-ccp: from net/xfrm/xfrm_interface_core.c */
#include <linux/rtnetlink.h>
#include <linux/netfilter_ipv6.h>
#include <linux/slab.h>
#include <linux/hash.h>

#include <linux/uaccess.h>
#include <linux/atomic.h>

#include <net/ip.h>
#include <net/ipv6.h>

/* klp-ccp: from include/net/ip6_route.h */
#define _NET_IP6_ROUTE_H

/* klp-ccp: from net/xfrm/xfrm_interface_core.c */
#include <net/ip_tunnels.h>
#include <net/addrconf.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>

#include <net/netns/generic.h>
#include <linux/etherdevice.h>

extern unsigned int xfrmi_net_id __read_mostly;

#define XFRMI_HASH_BITS	8
#define XFRMI_HASH_SIZE	BIT(XFRMI_HASH_BITS)

struct xfrmi_net {
	/* lists for storing interfaces in use */
	struct xfrm_if __rcu *xfrmi[XFRMI_HASH_SIZE];
	struct xfrm_if __rcu *collect_md_xfrmi;
};

static u32 xfrmi_hash(u32 if_id)
{
	return hash_32(if_id, XFRMI_HASH_BITS);
}

static void xfrmi_link(struct xfrmi_net *xfrmn, struct xfrm_if *xi)
{
	struct xfrm_if __rcu **xip = &xfrmn->xfrmi[xfrmi_hash(xi->p.if_id)];

	rcu_assign_pointer(xi->next , rtnl_dereference(*xip));
	rcu_assign_pointer(*xip, xi);
}

static void xfrmi_unlink(struct xfrmi_net *xfrmn, struct xfrm_if *xi)
{
	struct xfrm_if __rcu **xip;
	struct xfrm_if *iter;

	for (xip = &xfrmn->xfrmi[xfrmi_hash(xi->p.if_id)];
	     (iter = rtnl_dereference(*xip)) != NULL;
	     xip = &iter->next) {
		if (xi == iter) {
			rcu_assign_pointer(*xip, xi->next);
			break;
		}
	}
}

static struct xfrm_if *xfrmi_locate(struct net *net, struct xfrm_if_parms *p)
{
	struct xfrm_if __rcu **xip;
	struct xfrm_if *xi;
	struct xfrmi_net *xfrmn = net_generic(net, xfrmi_net_id);

	for (xip = &xfrmn->xfrmi[xfrmi_hash(p->if_id)];
	     (xi = rtnl_dereference(*xip)) != NULL;
	     xip = &xi->next)
		if (xi->p.if_id == p->if_id)
			return xi;

	return NULL;
}

static int xfrmi_change(struct xfrm_if *xi, const struct xfrm_if_parms *p)
{
	if (xi->p.link != p->link)
		return -EINVAL;

	xi->p.if_id = p->if_id;

	return 0;
}

static int xfrmi_update(struct xfrm_if *xi, struct xfrm_if_parms *p)
{
	struct net *net = xi->net;
	struct xfrmi_net *xfrmn = net_generic(net, xfrmi_net_id);
	int err;

	xfrmi_unlink(xfrmn, xi);
	synchronize_net();
	err = xfrmi_change(xi, p);
	xfrmi_link(xfrmn, xi);
	netdev_state_change(xi->dev);
	return err;
}

extern void xfrmi_netlink_parms(struct nlattr *data[],
			       struct xfrm_if_parms *parms);

int klpp_xfrmi_changelink(struct net_device *dev, struct nlattr *tb[],
			  struct nlattr *data[],
			  struct netlink_ext_ack *extack)
{
	struct xfrm_if *xi = netdev_priv(dev);
	struct net *net = xi->net;
	struct xfrm_if_parms p = {};

	xfrmi_netlink_parms(data, &p);
	if (!p.if_id) {
		NL_SET_ERR_MSG(extack, "if_id must be non zero");
		return -EINVAL;
	}

	if (p.collect_md || xi->p.collect_md) {
		NL_SET_ERR_MSG(extack, "collect_md can't be changed");
		return -EINVAL;
	}

	xi = xfrmi_locate(net, &p);
	if (!xi) {
		xi = netdev_priv(dev);
	} else {
		if (xi->dev != dev)
			return -EEXIST;
	}

	return xfrmi_update(xi, &p);
}


#include "livepatch_bsc1248672.h"

#include <linux/livepatch.h>

extern typeof(xfrmi_net_id) xfrmi_net_id
	 KLP_RELOC_SYMBOL(xfrm_interface, xfrm_interface, xfrmi_net_id);
extern typeof(xfrmi_netlink_parms) xfrmi_netlink_parms
	 KLP_RELOC_SYMBOL(xfrm_interface, xfrm_interface, xfrmi_netlink_parms);
