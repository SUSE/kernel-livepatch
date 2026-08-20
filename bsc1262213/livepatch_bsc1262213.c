/*
 * livepatch_bsc1262213
 *
 * Fix for CVE-2026-23449, bsc#1262213
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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


#include "livepatch_bsc1262213.h"


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

/* klp-ccp: from include/net/sch_generic.h */
static inline void klpp_dev_reset_queue(struct net_device *dev,
				   struct netdev_queue *dev_queue,
				   void *_unused)
{
	struct Qdisc *qdisc;
	bool nolock;

	qdisc = rtnl_dereference(dev_queue->qdisc_sleeping);
	if (!qdisc)
		return;

	nolock = qdisc->flags & TCQ_F_NOLOCK;

	if (nolock)
		spin_lock_bh(&qdisc->seqlock);
	spin_lock_bh(qdisc_lock(qdisc));

	qdisc_reset(qdisc);

	spin_unlock_bh(qdisc_lock(qdisc));
	if (nolock) {
		clear_bit(__QDISC_STATE_MISSED, &qdisc->state);
		clear_bit(__QDISC_STATE_DRAINING, &qdisc->state);
		spin_unlock_bh(&qdisc->seqlock);
	}
}

/* klp-ccp: from net/sched/sch_teql.c */
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

void
klpp_teql_destroy(struct Qdisc *sch)
{
	struct Qdisc *q, *prev;
	struct teql_sched_data *dat = qdisc_priv(sch);
	struct teql_master *master = dat->m;

	if (!master)
		return;

	prev = master->slaves;
	if (prev) {
		do {
			q = NEXT_SLAVE(prev);
			if (q == sch) {
				NEXT_SLAVE(prev) = NEXT_SLAVE(q);
				if (q == master->slaves) {
					master->slaves = NEXT_SLAVE(q);
					if (q == master->slaves) {
						struct netdev_queue *txq;

						txq = netdev_get_tx_queue(master->dev, 0);
						master->slaves = NULL;

						klpp_dev_reset_queue(master->dev,
								txq, NULL);
					}
				}
				skb_queue_purge(&dat->q);
				break;
			}

		} while ((prev = q) != master->slaves);
	}
}


