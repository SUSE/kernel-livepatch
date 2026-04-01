/*
 * livepatch_bsc1258784
 *
 * Fix for CVE-2026-23209, bsc#1258784
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


#include "livepatch_bsc1258784.h"


/* klp-ccp: from drivers/net/macvlan.c */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rculist.h>
#include <linux/notifier.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/net_tstamp.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/if_link.h>
#include <linux/if_macvlan.h>

/* klp-ccp: from include/linux/if_macvlan.h */
int klpp_macvlan_common_newlink(struct net *src_net, struct net_device *dev,
				  struct nlattr *tb[], struct nlattr *data[],
				  struct netlink_ext_ack *extack);

/* klp-ccp: from drivers/net/macvlan.c */
#include <linux/hash.h>
#include <linux/workqueue.h>
#include <net/rtnetlink.h>
#include <net/xfrm.h>
#include <linux/netpoll.h>
#include <linux/phy.h>

#define MACVLAN_HASH_BITS	8
#define MACVLAN_HASH_SIZE	(1<<MACVLAN_HASH_BITS)
#define MACVLAN_DEFAULT_BC_QUEUE_LEN	1000

#define MACVLAN_F_PASSTHRU	1

struct macvlan_port {
	struct net_device	*dev;
	struct hlist_head	vlan_hash[MACVLAN_HASH_SIZE];
	struct list_head	vlans;
	struct sk_buff_head	bc_queue;
	struct work_struct	bc_work;
	u32			bc_queue_len_used;
	int			bc_cutoff;
	u32			flags;
	int			count;
	struct hlist_head	vlan_source_hash[MACVLAN_HASH_SIZE];
	DECLARE_BITMAP(bc_filter, MACVLAN_MC_FILTER_SZ);
	DECLARE_BITMAP(mc_filter, MACVLAN_MC_FILTER_SZ);
	unsigned char           perm_addr[ETH_ALEN];
};

extern void macvlan_port_destroy(struct net_device *dev);
static void update_port_bc_queue_len(struct macvlan_port *port);

static inline bool macvlan_passthru(const struct macvlan_port *port)
{
	return port->flags & MACVLAN_F_PASSTHRU;
}

static inline void macvlan_set_passthru(struct macvlan_port *port)
{
	port->flags |= MACVLAN_F_PASSTHRU;
}

static struct macvlan_port *macvlan_port_get_rtnl(const struct net_device *dev)
{
	return rtnl_dereference(dev->rx_handler_data);
}

extern void macvlan_process_broadcast(struct work_struct *w);

extern void macvlan_flush_sources(struct macvlan_port *port,
				  struct macvlan_dev *vlan);

extern rx_handler_result_t macvlan_handle_frame(struct sk_buff **pskb);

extern void macvlan_compute_filter(unsigned long *mc_filter,
				   struct net_device *dev,
				   struct macvlan_dev *vlan, int cutoff);

static void macvlan_recompute_bc_filter(struct macvlan_dev *vlan)
{
	if (vlan->port->bc_cutoff < 0) {
		bitmap_zero(vlan->port->bc_filter, MACVLAN_MC_FILTER_SZ);
		return;
	}

	macvlan_compute_filter(vlan->port->bc_filter, vlan->lowerdev, NULL,
			       vlan->port->bc_cutoff);
}

static void update_port_bc_cutoff(struct macvlan_dev *vlan, int cutoff)
{
	if (vlan->port->bc_cutoff == cutoff)
		return;

	vlan->port->bc_cutoff = cutoff;
	macvlan_recompute_bc_filter(vlan);
}

#define MACVLAN_FEATURES \
	(NETIF_F_SG | NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_FRAGLIST | \
	 NETIF_F_GSO | NETIF_F_TSO | NETIF_F_LRO | \
	 NETIF_F_TSO_ECN | NETIF_F_TSO6 | NETIF_F_GRO | NETIF_F_RXCSUM | \
	 NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_HW_VLAN_STAG_FILTER)

static int macvlan_port_create(struct net_device *dev)
{
	struct macvlan_port *port;
	unsigned int i;
	int err;

	if (dev->type != ARPHRD_ETHER || dev->flags & IFF_LOOPBACK)
		return -EINVAL;

	if (netdev_is_rx_handler_busy(dev))
		return -EBUSY;

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (port == NULL)
		return -ENOMEM;

	port->dev = dev;
	ether_addr_copy(port->perm_addr, dev->dev_addr);
	INIT_LIST_HEAD(&port->vlans);
	for (i = 0; i < MACVLAN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&port->vlan_hash[i]);
	for (i = 0; i < MACVLAN_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&port->vlan_source_hash[i]);

	port->bc_queue_len_used = 0;
	port->bc_cutoff = 1;
	skb_queue_head_init(&port->bc_queue);
	INIT_WORK(&port->bc_work, macvlan_process_broadcast);

	err = netdev_rx_handler_register(dev, macvlan_handle_frame, port);
	if (err)
		kfree(port);
	else
		dev->priv_flags |= IFF_MACVLAN_PORT;
	return err;
}

void macvlan_port_destroy(struct net_device *dev);

extern int macvlan_changelink_sources(struct macvlan_dev *vlan, u32 mode,
				      struct nlattr *data[]);

int klpp_macvlan_common_newlink(struct net *src_net, struct net_device *dev,
			   struct nlattr *tb[], struct nlattr *data[],
			   struct netlink_ext_ack *extack)
{
	struct macvlan_dev *vlan = netdev_priv(dev);
	struct macvlan_port *port;
	struct net_device *lowerdev;
	int err;
	int macmode;
	bool create = false;

	if (!tb[IFLA_LINK])
		return -EINVAL;

	lowerdev = __dev_get_by_index(src_net, nla_get_u32(tb[IFLA_LINK]));
	if (lowerdev == NULL)
		return -ENODEV;

	/* When creating macvlans or macvtaps on top of other macvlans - use
	 * the real device as the lowerdev.
	 */
	if (netif_is_macvlan(lowerdev))
		lowerdev = macvlan_dev_real_dev(lowerdev);

	if (!tb[IFLA_MTU])
		dev->mtu = lowerdev->mtu;
	else if (dev->mtu > lowerdev->mtu)
		return -EINVAL;

	/* MTU range: 68 - lowerdev->max_mtu */
	dev->min_mtu = ETH_MIN_MTU;
	dev->max_mtu = lowerdev->max_mtu;

	if (!tb[IFLA_ADDRESS])
		eth_hw_addr_random(dev);

	if (!netif_is_macvlan_port(lowerdev)) {
		err = macvlan_port_create(lowerdev);
		if (err < 0)
			return err;
		create = true;
	}
	port = macvlan_port_get_rtnl(lowerdev);

	/* Only 1 macvlan device can be created in passthru mode */
	if (macvlan_passthru(port)) {
		/* The macvlan port must be not created this time,
		 * still goto destroy_macvlan_port for readability.
		 */
		err = -EINVAL;
		goto destroy_macvlan_port;
	}

	vlan->lowerdev = lowerdev;
	vlan->dev      = dev;
	vlan->port     = port;
	vlan->set_features = MACVLAN_FEATURES;

	vlan->mode     = MACVLAN_MODE_VEPA;
	if (data && data[IFLA_MACVLAN_MODE])
		vlan->mode = nla_get_u32(data[IFLA_MACVLAN_MODE]);

	if (data && data[IFLA_MACVLAN_FLAGS])
		vlan->flags = nla_get_u16(data[IFLA_MACVLAN_FLAGS]);

	if (vlan->mode == MACVLAN_MODE_PASSTHRU) {
		if (port->count) {
			err = -EINVAL;
			goto destroy_macvlan_port;
		}
		macvlan_set_passthru(port);
		eth_hw_addr_inherit(dev, lowerdev);
	}

	if (data && data[IFLA_MACVLAN_MACADDR_MODE]) {
		if (vlan->mode != MACVLAN_MODE_SOURCE) {
			err = -EINVAL;
			goto destroy_macvlan_port;
		}
		macmode = nla_get_u32(data[IFLA_MACVLAN_MACADDR_MODE]);
		err = macvlan_changelink_sources(vlan, macmode, data);
		if (err)
			goto destroy_macvlan_port;
	}

	vlan->bc_queue_len_req = MACVLAN_DEFAULT_BC_QUEUE_LEN;
	if (data && data[IFLA_MACVLAN_BC_QUEUE_LEN])
		vlan->bc_queue_len_req = nla_get_u32(data[IFLA_MACVLAN_BC_QUEUE_LEN]);

	if (data && data[IFLA_MACVLAN_BC_CUTOFF])
		update_port_bc_cutoff(
			vlan, nla_get_s32(data[IFLA_MACVLAN_BC_CUTOFF]));

	err = register_netdevice(dev);
	if (err < 0)
		goto destroy_macvlan_port;

	dev->priv_flags |= IFF_MACVLAN;
	err = netdev_upper_dev_link(lowerdev, dev, extack);
	if (err)
		goto unregister_netdev;

	list_add_tail_rcu(&vlan->list, &port->vlans);
	update_port_bc_queue_len(vlan->port);
	netif_stacked_transfer_operstate(lowerdev, dev);
	linkwatch_fire_event(dev);

	return 0;

unregister_netdev:
	/* macvlan_uninit would free the macvlan port */
	unregister_netdevice(dev);
	return err;
destroy_macvlan_port:
	/* the macvlan port may be freed by macvlan_uninit when fail to register.
	 * so we destroy the macvlan port only when it's valid.
	 */
	if (macvlan_port_get_rtnl(lowerdev)) {
		macvlan_flush_sources(port, vlan);
		if (create)
			macvlan_port_destroy(port->dev);
	}
	/* @dev might have been made visible before an error was detected.
	 * Make sure to observe an RCU grace period before our caller
	 * (rtnl_newlink()) frees it.
	 */
	synchronize_net();
	return err;
}

typeof(klpp_macvlan_common_newlink) klpp_macvlan_common_newlink;

static void update_port_bc_queue_len(struct macvlan_port *port)
{
	u32 max_bc_queue_len_req = 0;
	struct macvlan_dev *vlan;

	list_for_each_entry(vlan, &port->vlans, list) {
		if (vlan->bc_queue_len_req > max_bc_queue_len_req)
			max_bc_queue_len_req = vlan->bc_queue_len_req;
	}
	port->bc_queue_len_used = max_bc_queue_len_req;
}


#include <linux/livepatch.h>

extern typeof(macvlan_changelink_sources) macvlan_changelink_sources
	 KLP_RELOC_SYMBOL(macvlan, macvlan, macvlan_changelink_sources);
extern typeof(macvlan_compute_filter) macvlan_compute_filter
	 KLP_RELOC_SYMBOL(macvlan, macvlan, macvlan_compute_filter);
extern typeof(macvlan_flush_sources) macvlan_flush_sources
	 KLP_RELOC_SYMBOL(macvlan, macvlan, macvlan_flush_sources);
extern typeof(macvlan_handle_frame) macvlan_handle_frame
	 KLP_RELOC_SYMBOL(macvlan, macvlan, macvlan_handle_frame);
extern typeof(macvlan_port_destroy) macvlan_port_destroy
	 KLP_RELOC_SYMBOL(macvlan, macvlan, macvlan_port_destroy);
extern typeof(macvlan_process_broadcast) macvlan_process_broadcast
	 KLP_RELOC_SYMBOL(macvlan, macvlan, macvlan_process_broadcast);
