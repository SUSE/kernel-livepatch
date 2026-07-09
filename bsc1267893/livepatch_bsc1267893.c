/*
 * livepatch_bsc1267893
 *
 * Fix for CVE-2026-46120, bsc#1267893
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


#include "livepatch_bsc1267893.h"


/* klp-ccp: from net/ipv6/ip6_gre.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

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
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/hash.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/ip_tunnels.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/addrconf.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>
#include <net/xfrm.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/rtnetlink.h>
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ip6_tunnel.h>
#include <net/gre.h>
#include <net/erspan.h>
#include <net/dst_metadata.h>

#define IP6_GRE_HASH_SIZE_SHIFT  5
#define IP6_GRE_HASH_SIZE (1 << IP6_GRE_HASH_SIZE_SHIFT)

extern unsigned int ip6gre_net_id __read_mostly;
struct ip6gre_net {
	struct ip6_tnl __rcu *tunnels[4][IP6_GRE_HASH_SIZE];

	struct ip6_tnl __rcu *collect_md_tun;
	struct ip6_tnl __rcu *collect_md_tun_erspan;
	struct net_device *fb_tunnel_dev;
};

extern struct rtnl_link_ops ip6gre_link_ops __read_mostly;

extern void ip6gre_tunnel_setup(struct net_device *dev);
static void ip6gre_tunnel_link(struct ip6gre_net *ign, struct ip6_tnl *t);
extern void ip6gre_tnl_link_config(struct ip6_tnl *t, int set_mtu);
extern void ip6erspan_tnl_link_config(struct ip6_tnl *t, int set_mtu);

extern struct ip6_tnl __rcu **__ip6gre_bucket(struct ip6gre_net *ign,
		const struct __ip6_tnl_parm *p);

static void ip6erspan_tunnel_link_md(struct ip6gre_net *ign, struct ip6_tnl *t)
{
	if (t->parms.collect_md)
		rcu_assign_pointer(ign->collect_md_tun_erspan, t);
}

static void ip6gre_tunnel_unlink_md(struct ip6gre_net *ign, struct ip6_tnl *t)
{
	if (t->parms.collect_md)
		rcu_assign_pointer(ign->collect_md_tun, NULL);
}

static inline struct ip6_tnl __rcu **ip6gre_bucket(struct ip6gre_net *ign,
		const struct ip6_tnl *t)
{
	return __ip6gre_bucket(ign, &t->parms);
}

static void ip6gre_tunnel_link(struct ip6gre_net *ign, struct ip6_tnl *t)
{
	struct ip6_tnl __rcu **tp = ip6gre_bucket(ign, t);

	rcu_assign_pointer(t->next, rtnl_dereference(*tp));
	rcu_assign_pointer(*tp, t);
}

extern void ip6gre_tunnel_unlink(struct ip6gre_net *ign, struct ip6_tnl *t);

extern struct ip6_tnl *ip6gre_tunnel_find(struct net *net,
					   const struct __ip6_tnl_parm *parms,
					   int type);

static struct ip6_tnl *ip6gre_tunnel_locate(struct net *net,
		const struct __ip6_tnl_parm *parms, int create)
{
	struct ip6_tnl *t, *nt;
	struct net_device *dev;
	char name[IFNAMSIZ];
	struct ip6gre_net *ign = net_generic(net, ip6gre_net_id);

	t = ip6gre_tunnel_find(net, parms, ARPHRD_IP6GRE);
	if (t && create)
		return NULL;
	if (t || !create)
		return t;

	if (parms->name[0]) {
		if (!dev_valid_name(parms->name))
			return NULL;
		strscpy(name, parms->name, IFNAMSIZ);
	} else {
		strcpy(name, "ip6gre%d");
	}
	dev = alloc_netdev(sizeof(*t), name, NET_NAME_UNKNOWN,
			   ip6gre_tunnel_setup);
	if (!dev)
		return NULL;

	dev_net_set(dev, net);

	nt = netdev_priv(dev);
	nt->parms = *parms;
	dev->rtnl_link_ops = &ip6gre_link_ops;

	nt->dev = dev;
	nt->net = dev_net(dev);

	if (register_netdevice(dev) < 0)
		goto failed_free;

	ip6gre_tnl_link_config(nt, 1);
	ip6gre_tunnel_link(ign, nt);
	return nt;

failed_free:
	free_netdev(dev);
	return NULL;
}

void ip6gre_tnl_link_config(struct ip6_tnl *t, int set_mtu);

extern void ip6gre_tnl_copy_tnl_parm(struct ip6_tnl *t,
				     const struct __ip6_tnl_parm *p);

void ip6gre_tunnel_setup(struct net_device *dev);

extern void ip6erspan_set_version(struct nlattr *data[],
				  struct __ip6_tnl_parm *parms);

extern void ip6gre_netlink_parms(struct nlattr *data[],
				struct __ip6_tnl_parm *parms);

extern bool ip6gre_netlink_encap_parms(struct nlattr *data[],
				       struct ip_tunnel_encap *ipencap);

static struct ip6_tnl *
ip6gre_changelink_common(struct net_device *dev, struct nlattr *tb[],
			 struct nlattr *data[], struct __ip6_tnl_parm *p_p,
			 struct netlink_ext_ack *extack)
{
	struct ip6_tnl *t, *nt = netdev_priv(dev);
	struct net *net = nt->net;
	struct ip6gre_net *ign = net_generic(net, ip6gre_net_id);
	struct ip_tunnel_encap ipencap;

	if (dev == ign->fb_tunnel_dev)
		return ERR_PTR(-EINVAL);

	if (ip6gre_netlink_encap_parms(data, &ipencap)) {
		int err = ip6_tnl_encap_setup(nt, &ipencap);

		if (err < 0)
			return ERR_PTR(err);
	}

	ip6gre_netlink_parms(data, p_p);

	t = ip6gre_tunnel_locate(net, p_p, 0);

	if (t) {
		if (t->dev != dev)
			return ERR_PTR(-EEXIST);
	} else {
		t = nt;
	}

	return t;
}

void ip6erspan_tnl_link_config(struct ip6_tnl *t, int set_mtu);

static int ip6erspan_tnl_change(struct ip6_tnl *t,
				const struct __ip6_tnl_parm *p, int set_mtu)
{
	ip6gre_tnl_copy_tnl_parm(t, p);
	ip6erspan_tnl_link_config(t, set_mtu);
	return 0;
}

int klpp_ip6erspan_changelink(struct net_device *dev, struct nlattr *tb[],
				struct nlattr *data[],
				struct netlink_ext_ack *extack)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct __ip6_tnl_parm p;
	struct ip6gre_net *ign;

	ign = net_generic(t->net, ip6gre_net_id);
	t = ip6gre_changelink_common(dev, tb, data, &p, extack);
	if (IS_ERR(t))
		return PTR_ERR(t);

	ip6erspan_set_version(data, &p);
	ip6gre_tunnel_unlink_md(ign, t);
	ip6gre_tunnel_unlink(ign, t);
	ip6erspan_tnl_change(t, &p, !tb[IFLA_MTU]);
	ip6erspan_tunnel_link_md(ign, t);
	ip6gre_tunnel_link(ign, t);
	return 0;
}

extern struct rtnl_link_ops ip6gre_link_ops __read_mostly;


#include <linux/livepatch.h>

extern typeof(__ip6gre_bucket) __ip6gre_bucket
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, __ip6gre_bucket);
extern typeof(ip6erspan_set_version) ip6erspan_set_version
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6erspan_set_version);
extern typeof(ip6erspan_tnl_link_config) ip6erspan_tnl_link_config
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6erspan_tnl_link_config);
extern typeof(ip6gre_link_ops) ip6gre_link_ops
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_link_ops);
extern typeof(ip6gre_net_id) ip6gre_net_id
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_net_id);
extern typeof(ip6gre_netlink_encap_parms) ip6gre_netlink_encap_parms
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_netlink_encap_parms);
extern typeof(ip6gre_netlink_parms) ip6gre_netlink_parms
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_netlink_parms);
extern typeof(ip6gre_tnl_copy_tnl_parm) ip6gre_tnl_copy_tnl_parm
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_tnl_copy_tnl_parm);
extern typeof(ip6gre_tnl_link_config) ip6gre_tnl_link_config
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_tnl_link_config);
extern typeof(ip6gre_tunnel_find) ip6gre_tunnel_find
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_tunnel_find);
extern typeof(ip6gre_tunnel_setup) ip6gre_tunnel_setup
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_tunnel_setup);
extern typeof(ip6gre_tunnel_unlink) ip6gre_tunnel_unlink
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_gre, ip6gre_tunnel_unlink);
extern typeof(ip6_tnl_encap_setup) ip6_tnl_encap_setup
	 KLP_RELOC_SYMBOL(ip6_gre, ip6_tunnel, ip6_tnl_encap_setup);
