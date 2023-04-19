/*
 * bsc1207822_net_sched_sch_generic
 *
 * Fix for CVE-2023-0590, bsc#1207822
 *
 *  Copyright (c) 2023 SUSE
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

/* klp-ccp: from net/sched/sch_generic.c */
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/netdevice.h>

/* klp-ccp: from include/linux/netdevice.h */
static void (*klpe___netdev_watchdog_up)(struct net_device *dev);

/* klp-ccp: from net/sched/sch_generic.c */
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/if_vlan.h>
#include <linux/if_macvlan.h>
#include <net/sch_generic.h>

/* klp-ccp: from include/net/sch_generic.h */
static struct Qdisc_ops (*klpe_mq_qdisc_ops);
static struct Qdisc_ops (*klpe_noqueue_qdisc_ops);

/* klp-ccp: from net/sched/sch_generic.c */
#include <net/pkt_sched.h>

extern const struct Qdisc_ops *default_qdisc_ops;

static void (*klpe_dev_watchdog)(unsigned long arg);

static void klpr_dev_watchdog_up(struct net_device *dev)
{
	(*klpe___netdev_watchdog_up)(dev);
}

extern struct Qdisc noop_qdisc;

struct Qdisc *qdisc_create_dflt(struct netdev_queue *dev_queue,
				const struct Qdisc_ops *ops,
				unsigned int parentid,
				struct netlink_ext_ack *extack);

void qdisc_put(struct Qdisc *qdisc);

static void klpr_attach_one_default_qdisc(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_unused)
{
	struct Qdisc *qdisc;
	const struct Qdisc_ops *ops = default_qdisc_ops;

	if (dev->priv_flags & IFF_NO_QUEUE)
		ops = &(*klpe_noqueue_qdisc_ops);

	qdisc = qdisc_create_dflt(dev_queue, ops, TC_H_ROOT, NULL);
	if (!qdisc) {
		netdev_info(dev, "activation failed\n");
		return;
	}
	if (!netif_is_multiqueue(dev))
		qdisc->flags |= TCQ_F_ONETXQUEUE | TCQ_F_NOPARENT;
	dev_queue->qdisc_sleeping = qdisc;
}

static void klpr_attach_default_qdiscs(struct net_device *dev)
{
	struct netdev_queue *txq;
	struct Qdisc *qdisc;

	txq = netdev_get_tx_queue(dev, 0);

	if (!netif_is_multiqueue(dev) ||
	    dev->priv_flags & IFF_NO_QUEUE) {
		netdev_for_each_tx_queue(dev, klpr_attach_one_default_qdisc, NULL);
		qdisc = txq->qdisc_sleeping;
		rcu_assign_pointer(dev->qdisc, qdisc);
		qdisc_refcount_inc(qdisc);
	} else {
		qdisc = qdisc_create_dflt(txq, &(*klpe_mq_qdisc_ops), TC_H_ROOT, NULL);
		if (qdisc) {
			rcu_assign_pointer(dev->qdisc, qdisc);
			qdisc->ops->attach(qdisc);
		}
	}
	qdisc = rtnl_dereference(dev->qdisc);
#ifdef CONFIG_NET_SCHED
	if (qdisc != &noop_qdisc)
		qdisc_hash_add(qdisc, false);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

static void transition_one_qdisc(struct net_device *dev,
				 struct netdev_queue *dev_queue,
				 void *_need_watchdog)
{
	struct Qdisc *new_qdisc = dev_queue->qdisc_sleeping;
	int *need_watchdog_p = _need_watchdog;

	if (!(new_qdisc->flags & TCQ_F_BUILTIN))
		clear_bit(__QDISC_STATE_DEACTIVATED, &new_qdisc->state);

	rcu_assign_pointer(dev_queue->qdisc, new_qdisc);
	if (need_watchdog_p) {
		dev_queue->trans_start = 0;
		*need_watchdog_p = 1;
	}
}

void klpp_dev_activate(struct net_device *dev)
{
	int need_watchdog;

	/* No queueing discipline is attached to device;
	 * create default one for devices, which need queueing
	 * and noqueue_qdisc for virtual interfaces
	 */

	if (rtnl_dereference(dev->qdisc) == &noop_qdisc)
		klpr_attach_default_qdiscs(dev);

	if (!netif_carrier_ok(dev))
		/* Delay activation until next carrier-on event */
		return;

	need_watchdog = 0;
	netdev_for_each_tx_queue(dev, transition_one_qdisc, &need_watchdog);
	if (dev_ingress_queue(dev))
		transition_one_qdisc(dev, dev_ingress_queue(dev), NULL);

	if (need_watchdog) {
		netif_trans_update(dev);
		klpr_dev_watchdog_up(dev);
	}
}

static void dev_init_scheduler_queue(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_qdisc)
{
	struct Qdisc *qdisc = _qdisc;

	rcu_assign_pointer(dev_queue->qdisc, qdisc);
	dev_queue->qdisc_sleeping = qdisc;
}

void klpp_dev_init_scheduler(struct net_device *dev)
{
	rcu_assign_pointer(dev->qdisc, &noop_qdisc);
	netdev_for_each_tx_queue(dev, dev_init_scheduler_queue, &noop_qdisc);
	if (dev_ingress_queue(dev))
		dev_init_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);

	setup_timer(&dev->watchdog_timer, (*klpe_dev_watchdog), (unsigned long)dev);
}

static void shutdown_scheduler_queue(struct net_device *dev,
				     struct netdev_queue *dev_queue,
				     void *_qdisc_default)
{
	struct Qdisc *qdisc = dev_queue->qdisc_sleeping;
	struct Qdisc *qdisc_default = _qdisc_default;

	if (qdisc) {
		rcu_assign_pointer(dev_queue->qdisc, qdisc_default);
		dev_queue->qdisc_sleeping = qdisc_default;

		qdisc_put(qdisc);
	}
}

void klpp_dev_shutdown(struct net_device *dev)
{
	netdev_for_each_tx_queue(dev, shutdown_scheduler_queue, &noop_qdisc);
	if (dev_ingress_queue(dev))
		shutdown_scheduler_queue(dev, dev_ingress_queue(dev), &noop_qdisc);
	qdisc_put(rtnl_dereference(dev->qdisc));
	rcu_assign_pointer(dev->qdisc, &noop_qdisc);

	WARN_ON(timer_pending(&dev->watchdog_timer));
}




#include <linux/kernel.h>
#include "livepatch_bsc1207822.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__netdev_watchdog_up", (void *)&klpe___netdev_watchdog_up },
	{ "dev_watchdog", (void *)&klpe_dev_watchdog },
	{ "mq_qdisc_ops", (void *)&klpe_mq_qdisc_ops },
	{ "noqueue_qdisc_ops", (void *)&klpe_noqueue_qdisc_ops },
};

int bsc1207822_net_sched_sch_generic_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

