/*
 * livepatch_bsc1245350
 *
 * Fix for CVE-2025-38083, bsc#1245350
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


/* klp-ccp: from net/sched/sch_prio.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

struct prio_sched_data {
	int bands;
	struct tcf_proto __rcu *filter_list;
	struct tcf_block *block;
	u8  prio2band[TC_PRIO_MAX+1];
	struct Qdisc *queues[TCQ_PRIO_BANDS];
};

extern int prio_offload(struct Qdisc *sch, struct tc_prio_qopt *qopt);

int klpp_prio_tune(struct Qdisc *sch, struct nlattr *opt,
		     struct netlink_ext_ack *extack)
{
	struct prio_sched_data *q = qdisc_priv(sch);
	struct Qdisc *queues[TCQ_PRIO_BANDS];
	int oldbands = q->bands, i;
	struct tc_prio_qopt *qopt;

	if (nla_len(opt) < sizeof(*qopt))
		return -EINVAL;
	qopt = nla_data(opt);

	if (qopt->bands > TCQ_PRIO_BANDS || qopt->bands < TCQ_MIN_PRIO_BANDS)
		return -EINVAL;

	for (i = 0; i <= TC_PRIO_MAX; i++) {
		if (qopt->priomap[i] >= qopt->bands)
			return -EINVAL;
	}

	/* Before commit, make sure we can allocate all new qdiscs */
	for (i = oldbands; i < qopt->bands; i++) {
		queues[i] = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
					      TC_H_MAKE(sch->handle, i + 1),
					      extack);
		if (!queues[i]) {
			while (i > oldbands)
				qdisc_put(queues[--i]);
			return -ENOMEM;
		}
	}

	prio_offload(sch, qopt);
	sch_tree_lock(sch);
	q->bands = qopt->bands;
	memcpy(q->prio2band, qopt->priomap, TC_PRIO_MAX+1);

	for (i = q->bands; i < oldbands; i++)
		qdisc_purge_queue(q->queues[i]);

	for (i = oldbands; i < q->bands; i++) {
		q->queues[i] = queues[i];
		if (q->queues[i] != &noop_qdisc)
			qdisc_hash_add(q->queues[i], true);
	}

	sch_tree_unlock(sch);

	for (i = q->bands; i < oldbands; i++)
		qdisc_put(q->queues[i]);
	return 0;
}


#include "livepatch_bsc1245350.h"

#include <linux/livepatch.h>

extern typeof(prio_offload) prio_offload
	 KLP_RELOC_SYMBOL(sch_prio, sch_prio, prio_offload);
