/*
 * livepatch_bsc1245505
 *
 * Fix for CVE-2025-38087, bsc#1245505
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

/* klp-ccp: from net/sched/sch_taprio.c */
#include <linux/ethtool.h>
#include <linux/ethtool_netlink.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/time.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>

#include <net/sch_generic.h>

/* klp-ccp: from net/sched/sch_mqprio_lib.h */
#include <linux/types.h>

/* klp-ccp: from net/sched/sch_taprio.c */
extern struct list_head taprio_list;

struct sched_gate_list {
	/* Longest non-zero contiguous gate durations per traffic class,
	 * or 0 if a traffic class gate never opens during the schedule.
	 */
	u64 max_open_gate_duration[TC_MAX_QUEUE];
	u32 max_frm_len[TC_MAX_QUEUE]; /* for the fast path */
	u32 max_sdu[TC_MAX_QUEUE]; /* for dump */
	struct rcu_head rcu;
	struct list_head entries;
	size_t num_entries;
	ktime_t cycle_end_time;
	s64 cycle_time;
	s64 cycle_time_extension;
	s64 base_time;
};

struct taprio_sched {
	struct Qdisc **qdiscs;
	struct Qdisc *root;
	u32 flags;
	enum tk_offsets tk_offset;
	int clockid;
	bool offloaded;
	bool detected_mqprio;
	bool broken_mqprio;
	atomic64_t picos_per_byte; /* Using picoseconds because for 10Gbps+
				    * speeds it's sub-nanoseconds per byte
				    */

	/* Protects the update side of the RCU protected current_entry */
	spinlock_t current_entry_lock;
	struct sched_entry __rcu *current_entry;
	struct sched_gate_list __rcu *oper_sched;
	struct sched_gate_list __rcu *admin_sched;
	struct hrtimer advance_timer;
	struct list_head taprio_list;
	int cur_txq[TC_MAX_QUEUE];
	u32 max_sdu[TC_MAX_QUEUE]; /* save info from the user */
	u32 fp[TC_QOPT_MAX_QUEUE]; /* only for dump and offloading */
	u32 txtime_delay;
};

extern void taprio_update_queue_max_sdu(struct taprio_sched *q,
					struct sched_gate_list *sched,
					struct qdisc_size_table *stab);

extern void taprio_set_picos_per_byte(struct net_device *dev,
				      struct taprio_sched *q);

int klpp_taprio_dev_notifier(struct notifier_block *nb, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct sched_gate_list *oper, *admin;
	struct qdisc_size_table *stab;
	struct taprio_sched *q;

	ASSERT_RTNL();

	if (event != NETDEV_UP && event != NETDEV_CHANGE)
		return NOTIFY_DONE;

	list_for_each_entry(q, &taprio_list, taprio_list) {
		if (dev != qdisc_dev(q->root))
			continue;

		taprio_set_picos_per_byte(dev, q);

		stab = rtnl_dereference(q->root->stab);

		rcu_read_lock();
		oper = rcu_dereference(q->oper_sched);
		if (oper)
			taprio_update_queue_max_sdu(q, oper, stab);

		admin = rcu_dereference(q->admin_sched);
		if (admin)
			taprio_update_queue_max_sdu(q, admin, stab);
		rcu_read_unlock();

		break;
	}

	return NOTIFY_DONE;
}


#include "livepatch_bsc1245505.h"

#include <linux/livepatch.h>

extern typeof(taprio_list) taprio_list
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_list);
extern typeof(taprio_set_picos_per_byte) taprio_set_picos_per_byte
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_set_picos_per_byte);
extern typeof(taprio_update_queue_max_sdu) taprio_update_queue_max_sdu
	 KLP_RELOC_SYMBOL(sch_taprio, sch_taprio, taprio_update_queue_max_sdu);
