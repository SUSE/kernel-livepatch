/*
 * livepatch_bsc1258051
 *
 * Fix for CVE-2026-23074, bsc#1258051
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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


/* klp-ccp: from net/sched/sch_teql.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/if_arp.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/moduleparam.h>
#include <net/dst.h>
#include <net/neighbour.h>
#include <net/pkt_sched.h>

struct teql_master {
	struct Qdisc_ops qops;
	struct net_device *dev;
	struct Qdisc *slaves;
	struct list_head master_list;
	unsigned long	tx_bytes;
	unsigned long	tx_packets;
	unsigned long	tx_errors;
	unsigned long	tx_dropped;
};

struct teql_sched_data {
	struct Qdisc *next;
	struct teql_master *m;
	struct sk_buff_head q;
};

#define NEXT_SLAVE(q) (((struct teql_sched_data *)qdisc_priv(q))->next)

#define FMASK (IFF_BROADCAST | IFF_POINTOPOINT)

int klpp_teql_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack)
{
	struct net_device *dev = qdisc_dev(sch);
	struct teql_master *m = (struct teql_master *)sch->ops;
	struct teql_sched_data *q = qdisc_priv(sch);

	if (dev->hard_header_len > m->dev->hard_header_len)
		return -EINVAL;

	if (m->dev == dev)
		return -ELOOP;

	if (sch->parent != TC_H_ROOT) {
		NL_SET_ERR_MSG_MOD(extack, "teql can only be used as root");
		return -EOPNOTSUPP;
	}

	q->m = m;

	skb_queue_head_init(&q->q);

	if (m->slaves) {
		if (m->dev->flags & IFF_UP) {
			if ((m->dev->flags & IFF_POINTOPOINT &&
			     !(dev->flags & IFF_POINTOPOINT)) ||
			    (m->dev->flags & IFF_BROADCAST &&
			     !(dev->flags & IFF_BROADCAST)) ||
			    (m->dev->flags & IFF_MULTICAST &&
			     !(dev->flags & IFF_MULTICAST)) ||
			    dev->mtu < m->dev->mtu)
				return -EINVAL;
		} else {
			if (!(dev->flags&IFF_POINTOPOINT))
				m->dev->flags &= ~IFF_POINTOPOINT;
			if (!(dev->flags&IFF_BROADCAST))
				m->dev->flags &= ~IFF_BROADCAST;
			if (!(dev->flags&IFF_MULTICAST))
				m->dev->flags &= ~IFF_MULTICAST;
			if (dev->mtu < m->dev->mtu)
				m->dev->mtu = dev->mtu;
		}
		q->next = NEXT_SLAVE(m->slaves);
		NEXT_SLAVE(m->slaves) = sch;
	} else {
		q->next = sch;
		m->slaves = sch;
		m->dev->mtu = dev->mtu;
		m->dev->flags = (m->dev->flags&~FMASK)|(dev->flags&FMASK);
	}
	return 0;
}


#include "livepatch_bsc1258051.h"

