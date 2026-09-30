/*
 * livepatch_bsc1273011
 *
 * Fix for CVE-2026-63921, bsc#1273011
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1273011.h"


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

extern unsigned int vti6_net_id __read_mostly;
struct vti6_net {
	/* the vti6 tunnel fallback device */
	struct net_device *fb_tnl_dev;
	/* lists for storing tunnels in use */
	struct ip6_tnl __rcu *tnls_r_l[IP6_VTI_HASH_SIZE];
	struct ip6_tnl __rcu *tnls_wc[1];
	struct ip6_tnl __rcu **tnls[2];
};

extern struct ip6_tnl __rcu **
vti6_tnl_bucket(struct vti6_net *ip6n, const struct __ip6_tnl_parm *p);

static void
vti6_tnl_link(struct vti6_net *ip6n, struct ip6_tnl *t)
{
	struct ip6_tnl __rcu **tp = vti6_tnl_bucket(ip6n, &t->parms);

	rcu_assign_pointer(t->next, rtnl_dereference(*tp));
	rcu_assign_pointer(*tp, t);
}

extern void
vti6_tnl_unlink(struct vti6_net *ip6n, struct ip6_tnl *t);

extern struct ip6_tnl *vti6_locate(struct net *net, struct __ip6_tnl_parm *p,
				   int create);

extern void vti6_link_config(struct ip6_tnl *t, bool keep_mtu);

static int
vti6_tnl_change(struct ip6_tnl *t, const struct __ip6_tnl_parm *p,
		bool keep_mtu)
{
	t->parms.laddr = p->laddr;
	t->parms.raddr = p->raddr;
	t->parms.link = p->link;
	t->parms.i_key = p->i_key;
	t->parms.o_key = p->o_key;
	t->parms.proto = p->proto;
	t->parms.fwmark = p->fwmark;
	dst_cache_reset(&t->dst_cache);
	vti6_link_config(t, keep_mtu);
	return 0;
}

int klpp_vti6_update(struct ip6_tnl *t, struct __ip6_tnl_parm *p, bool keep_mtu)
{
	struct net *net = t->net;
	struct vti6_net *ip6n;
	int err;

	ip6n = net_generic(net, vti6_net_id);
	vti6_tnl_unlink(ip6n, t);
	synchronize_net();
	err = vti6_tnl_change(t, p, keep_mtu);
	vti6_tnl_link(ip6n, t);
	netdev_state_change(t->dev);
	return err;
}

extern void
vti6_parm_from_user(struct __ip6_tnl_parm *p, const struct ip6_tnl_parm2 *u);

extern void
vti6_parm_to_user(struct ip6_tnl_parm2 *u, const struct __ip6_tnl_parm *p);

int klpp_vti6_siocdevprivate(struct net_device *dev, struct ifreq *ifr, void __user *data, int cmd)
{
	int err = 0;
	struct ip6_tnl_parm2 p;
	struct __ip6_tnl_parm p1;
	struct ip6_tnl *t = NULL;
	struct net *net = dev_net(dev);
	struct vti6_net *ip6n = net_generic(net, vti6_net_id);

	memset(&p1, 0, sizeof(p1));

	switch (cmd) {
	case SIOCGETTUNNEL:
		if (dev == ip6n->fb_tnl_dev) {
			if (copy_from_user(&p, data, sizeof(p))) {
				err = -EFAULT;
				break;
			}
			vti6_parm_from_user(&p1, &p);
			t = vti6_locate(net, &p1, 0);
		} else {
			memset(&p, 0, sizeof(p));
		}
		if (!t)
			t = netdev_priv(dev);
		vti6_parm_to_user(&p, &t->parms);
		if (copy_to_user(data, &p, sizeof(p)))
			err = -EFAULT;
		break;
	case SIOCADDTUNNEL:
	case SIOCCHGTUNNEL:
		err = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			break;
		err = -EFAULT;
		if (copy_from_user(&p, data, sizeof(p)))
			break;
		err = -EINVAL;
		if (p.proto != IPPROTO_IPV6  && p.proto != 0)
			break;
		vti6_parm_from_user(&p1, &p);
		if (dev != ip6n->fb_tnl_dev && cmd == SIOCCHGTUNNEL) {
			struct ip6_tnl *self = netdev_priv(dev);

			err = -EPERM;
			if (!ns_capable(self->net->user_ns, CAP_NET_ADMIN))
				break;
			t = vti6_locate(self->net, &p1, false);
			if (t) {
				if (t->dev != dev) {
					err = -EEXIST;
					break;
				}
			} else
				t = self;

			err = klpp_vti6_update(t, &p1, false);
                        } else {
			t = vti6_locate(net, &p1, cmd == SIOCADDTUNNEL);
		}
		if (t) {
			err = 0;
			vti6_parm_to_user(&p, &t->parms);
			if (copy_to_user(data, &p, sizeof(p)))
				err = -EFAULT;

		} else
			err = (cmd == SIOCADDTUNNEL ? -ENOBUFS : -ENOENT);
		break;
	case SIOCDELTUNNEL:
		err = -EPERM;
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN))
			break;

		if (dev == ip6n->fb_tnl_dev) {
			err = -EFAULT;
			if (copy_from_user(&p, data, sizeof(p)))
				break;
			err = -ENOENT;
			vti6_parm_from_user(&p1, &p);
			t = vti6_locate(net, &p1, 0);
			if (!t)
				break;
			err = -EPERM;
			if (t->dev == ip6n->fb_tnl_dev)
				break;
			dev = t->dev;
		}
		err = 0;
		unregister_netdevice(dev);
		break;
	default:
		err = -EINVAL;
	}
	return err;
}

extern void vti6_netlink_parms(struct nlattr *data[],
			       struct __ip6_tnl_parm *parms);

int klpp_vti6_changelink(struct net_device *dev, struct nlattr *tb[], struct nlattr *data[], struct netlink_ext_ack *extack)
{
	struct ip6_tnl *t = netdev_priv(dev);
	struct net *net = t->net;
	struct __ip6_tnl_parm p;
	struct vti6_net *ip6n;

	ip6n = net_generic(net, vti6_net_id);
	if (dev == ip6n->fb_tnl_dev)
		return -EINVAL;

	vti6_netlink_parms(data, &p);

	t = vti6_locate(net, &p, 0);

	if (t) {
		if (t->dev != dev)
			return -EEXIST;
	} else
		t = netdev_priv(dev);

        return klpp_vti6_update(t, &p, tb && tb[IFLA_MTU]);
}


#include <linux/livepatch.h>

extern typeof(vti6_link_config) vti6_link_config
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_link_config);
extern typeof(vti6_locate) vti6_locate
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_locate);
extern typeof(vti6_net_id) vti6_net_id
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_net_id);
extern typeof(vti6_netlink_parms) vti6_netlink_parms
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_netlink_parms);
extern typeof(vti6_parm_from_user) vti6_parm_from_user
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_parm_from_user);
extern typeof(vti6_parm_to_user) vti6_parm_to_user
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_parm_to_user);
extern typeof(vti6_tnl_bucket) vti6_tnl_bucket
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_tnl_bucket);
extern typeof(vti6_tnl_unlink) vti6_tnl_unlink
	 KLP_RELOC_SYMBOL(ip6_vti, ip6_vti, vti6_tnl_unlink);
