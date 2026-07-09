/*
 * livepatch_bsc1267206
 *
 * Fix for CVE-2026-45970, bsc#1267206
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


#include "livepatch_bsc1267206.h"


/* klp-ccp: from drivers/net/bonding/bond_main.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/filter.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/socket.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/bitops.h>
#include <linux/io.h>
#include <asm/dma.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <linux/rtnetlink.h>
#include <linux/smp.h>
#include <linux/if_ether.h>
#include <net/arp.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/if_bonding.h>
#include <linux/phy.h>
#include <linux/jiffies.h>
#include <linux/preempt.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/pkt_sched.h>
#include <linux/rculist.h>
#include <net/flow_dissector.h>
#include <net/xfrm.h>
#include <net/bonding.h>
#include <net/bond_3ad.h>
#include <net/bond_alb.h>
#if IS_ENABLED(CONFIG_TLS_DEVICE)
#include <net/tls.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <net/ip6_route.h>
#include <net/xdp.h>
/* klp-ccp: from drivers/net/bonding/bonding_priv.h */
#include <generated/utsrelease.h>

/* klp-ccp: from drivers/net/bonding/bond_main.c */
extern void bond_hw_addr_flush(struct net_device *bond_dev,
			       struct net_device *slave_dev);

static void bond_work_cancel_all(struct bonding *bond)
{
	cancel_delayed_work_sync(&bond->mii_work);
	cancel_delayed_work_sync(&bond->arp_work);
	cancel_delayed_work_sync(&bond->alb_work);
	cancel_delayed_work_sync(&bond->ad_work);
	cancel_delayed_work_sync(&bond->mcast_work);
	cancel_delayed_work_sync(&bond->slave_arr_work);
}

int klpp_bond_close(struct net_device *bond_dev)
{
	struct bonding *bond = netdev_priv(bond_dev);
	struct slave *slave;

	bond_work_cancel_all(bond);
	bond->send_peer_notif = 0;
	WRITE_ONCE(bond->recv_probe, NULL);

	/* Wait for any in-flight RX handlers */
	synchronize_net();

	if (bond_is_lb(bond))
		bond_alb_deinitialize(bond);

	if (bond_uses_primary(bond)) {
		rcu_read_lock();
		slave = rcu_dereference(bond->curr_active_slave);
		if (slave)
			bond_hw_addr_flush(bond_dev, slave->dev);
		rcu_read_unlock();
	} else {
		struct list_head *iter;

		bond_for_each_slave(bond, slave, iter)
			bond_hw_addr_flush(bond_dev, slave->dev);
	}

	return 0;
}


#include <linux/livepatch.h>

extern typeof(bond_alb_deinitialize) bond_alb_deinitialize
	 KLP_RELOC_SYMBOL(bonding, bonding, bond_alb_deinitialize);
extern typeof(bond_hw_addr_flush) bond_hw_addr_flush
	 KLP_RELOC_SYMBOL(bonding, bonding, bond_hw_addr_flush);
