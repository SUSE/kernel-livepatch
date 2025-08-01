/*
 * livepatch_bsc1245797
 *
 * Fix for CVE-2025-21702, bsc#1245797
 *
 *  Upstream commit:
 *  647cef20e649 ("pfifo_tail_enqueue: Drop new packet when sch->limit == 0")
 *
 *  SLE12-SP5 commit:
 *  2cd061199a36d2fdb2e8c573b678aacf457e1524
 *
 *  SLE15-SP3 commit:
 *  f34470d3c0f70a6abd44703e35dccfa7f42a2d78
 *
 *  SLE15-SP4 and -SP5 commit:
 *  874558cc5e977e19150f984a696b338bf8050369
 *
 *  SLE15-SP6 commit:
 *  9693f3391e475ed04ef32858c6f3461e93ccdfa8
 *
 *  SLE MICRO-6-0 commit:
 *  9693f3391e475ed04ef32858c6f3461e93ccdfa8
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

/* klp-ccp: from net/sched/sch_fifo.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

int klpp_pfifo_tail_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			    struct sk_buff **to_free)
{
	unsigned int prev_backlog;

	if (unlikely(sch->limit == 0))
		return qdisc_drop(skb, sch, to_free);

	if (likely(sch->q.qlen < sch->limit))
		return qdisc_enqueue_tail(skb, sch);

	prev_backlog = sch->qstats.backlog;
	/* queue full, remove one skb to fulfill the limit */
	__qdisc_queue_drop_head(sch, &sch->q, to_free);
	qdisc_qstats_drop(sch);
	qdisc_enqueue_tail(skb, sch);

	qdisc_tree_reduce_backlog(sch, 0, prev_backlog - sch->qstats.backlog);
	return NET_XMIT_CN;
}


#include "livepatch_bsc1245797.h"

