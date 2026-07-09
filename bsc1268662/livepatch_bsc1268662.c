/*
 * livepatch_bsc1268662
 *
 * Fix for CVE-2026-52909, bsc#1268662
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1268662.h"


/* klp-ccp: from net/ipv6/ip6_vti.c */
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
#include <linux/if_arp.h>
#include <linux/icmpv6.h>
#include <linux/init.h>
#include <linux/route.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter_ipv6.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <net/icmp.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/ip6_tunnel.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/etherdevice.h>

#define IP6_VTI_HASH_SIZE_SHIFT  5
#define IP6_VTI_HASH_SIZE (1 << IP6_VTI_HASH_SIZE_SHIFT)

extern void vti6_dev_setup(struct net_device *dev);
extern struct rtnl_link_ops vti6_link_ops __read_mostly;

extern unsigned int vti6_net_id __read_mostly;
struct vti6_net {
	/* the vti6 tunnel fallback device */
	struct net_device *fb_tnl_dev;
	/* lists for storing tunnels in use */
	struct ip6_tnl __rcu *tnls_r_l[IP6_VTI_HASH_SIZE];
	struct ip6_tnl __rcu *tnls_wc[1];
	struct ip6_tnl __rcu **tnls[2];
};

void vti6_dev_setup(struct net_device *dev);

static int __net_init vti6_fb_tnl_dev_init(struct net_device *dev)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = dev_net(dev);
	struct vti6_net *ip6n = net_generic(net, vti6_net_id);

	t->parms.proto = IPPROTO_IPV6;

	rcu_assign_pointer(ip6n->tnls_wc[0], t);
	return 0;
}

extern struct rtnl_link_ops vti6_link_ops __read_mostly;

int klpp_vti6_init_net(struct net *net)
{
	struct vti6_net *ip6n = net_generic(net, vti6_net_id);
	struct ip6_tnl *t = NULL;
	int err;

	ip6n->tnls[0] = ip6n->tnls_wc;
	ip6n->tnls[1] = ip6n->tnls_r_l;

	if (!net_has_fallback_tunnels(net))
		return 0;
	err = -ENOMEM;
	ip6n->fb_tnl_dev = alloc_netdev(sizeof(struct ip6_tnl), "ip6_vti0",
					NET_NAME_UNKNOWN, vti6_dev_setup);

	if (!ip6n->fb_tnl_dev)
		goto err_alloc_dev;
	dev_net_set(ip6n->fb_tnl_dev, net);
	ip6n->fb_tnl_dev->rtnl_link_ops = &vti6_link_ops;
	ip6n->fb_tnl_dev->features |= NETIF_F_NETNS_LOCAL;

	err = vti6_fb_tnl_dev_init(ip6n->fb_tnl_dev);
	if (err < 0)
		goto err_register;

	err = register_netdev(ip6n->fb_tnl_dev);
	if (err < 0)
		goto err_register;

	t = netdev_priv(ip6n->fb_tnl_dev);

	strcpy(t->parms.name, ip6n->fb_tnl_dev->name);
	return 0;

err_register:
	free_netdev(ip6n->fb_tnl_dev);
err_alloc_dev:
	return err;
}


#include <linux/livepatch.h>

extern typeof(vti6_dev_setup) vti6_dev_setup
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_dev_setup);
extern typeof(vti6_link_ops) vti6_link_ops
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_link_ops);
extern typeof(vti6_net_id) vti6_net_id
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_net_id);
