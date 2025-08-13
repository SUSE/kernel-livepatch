/*
 * livepatch_bsc1245776
 *
 *
 * Fix for CVE-2025-37752, bsc#1245776
 *
 *  Upstream commit:
 *  b3bf8f63e617 ("net_sched: sch_sfq: move the limit validation")
 *
 *  SLE12-SP5 commit:
 *  3268e2e5fad07903519a545589740bd51888ab1d
 *
 *  SLE15-SP3 commit:
 *  e09b6aad5d2ab48ce9abe092580d25ba09b8290f
 *
 *  SLE15-SP4 and -SP5 commit:
 *  875a484f9a1fed622112ff0055a22ba926cc6278
 *
 *  SLE15-SP6 commit:
 *  8b36a9aee1d0d1b9b688e95a468fa1851d6b154e
 *
 *  SLE MICRO-6-0 commit:
 *  8b36a9aee1d0d1b9b688e95a468fa1851d6b154e
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

/* klp-ccp: from net/sched/sch_sfq.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/in.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/siphash.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/red.h>

#define SFQ_MAX_DEPTH		127 /* max number of packets per flow */
#define SFQ_DEFAULT_FLOWS	128
#define SFQ_MAX_FLOWS		(0x10000 - SFQ_MAX_DEPTH - 1) /* max number of flows */
#define SFQ_EMPTY_SLOT		0xffff
#define SFQ_DEFAULT_HASH_DIVISOR 1024

typedef u16 sfq_index;

struct sfq_head {
	sfq_index	next;
	sfq_index	prev;
};

struct sfq_slot {
	struct sk_buff	*skblist_next;
	struct sk_buff	*skblist_prev;
	sfq_index	qlen; /* number of skbs in skblist */
	sfq_index	next; /* next slot in sfq RR chain */
	struct sfq_head dep; /* anchor in dep[] chains */
	unsigned short	hash; /* hash value (index in ht[]) */
	int		allot; /* credit for this slot */

	unsigned int    backlog;
	struct red_vars vars;
};

struct sfq_sched_data {
/* frequently used fields */
	int		limit;		/* limit of total number of packets in this qdisc */
	unsigned int	divisor;	/* number of slots in hash table */
	u8		headdrop;
	u8		maxdepth;	/* limit of packets per flow */

	siphash_key_t 	perturbation;
	u8		cur_depth;	/* depth of longest slot */
	u8		flags;
	struct tcf_proto __rcu *filter_list;
	struct tcf_block *block;
	sfq_index	*ht;		/* Hash table ('divisor' slots) */
	struct sfq_slot	*slots;		/* Flows table ('maxflows' entries) */

	struct red_parms *red_parms;
	struct tc_sfqred_stats stats;
	struct sfq_slot *tail;		/* current slot in round */

	struct sfq_head	dep[SFQ_MAX_DEPTH + 1];
					/* Linked lists of slots, indexed by depth
					 * dep[0] : list of unused flows
					 * dep[1] : list of flows with 1 packet
					 * dep[X] : list of flows with X packets
					 */

	unsigned int	maxflows;	/* number of flows in flows array */
	int		perturb_period;
	unsigned int	quantum;	/* Allotment per round: MUST BE >= MTU */
	struct timer_list perturb_timer;
	struct Qdisc	*sch;
};

static inline struct sfq_head *sfq_dep_head(struct sfq_sched_data *q, sfq_index val)
{
	if (val < SFQ_MAX_FLOWS)
		return &q->slots[val].dep;
	return &q->dep[val - SFQ_MAX_FLOWS];
}

static inline void sfq_link(struct sfq_sched_data *q, sfq_index x)
{
	sfq_index p, n;
	struct sfq_slot *slot = &q->slots[x];
	int qlen = slot->qlen;

	p = qlen + SFQ_MAX_FLOWS;
	n = q->dep[qlen].next;

	slot->dep.next = n;
	slot->dep.prev = p;

	q->dep[qlen].next = x;		/* sfq_dep_head(q, p)->next = x */
	sfq_dep_head(q, n)->prev = x;
}

static inline void slot_queue_init(struct sfq_slot *slot)
{
	memset(slot, 0, sizeof(*slot));
	slot->skblist_prev = slot->skblist_next = (struct sk_buff *)slot;
}

extern unsigned int sfq_drop(struct Qdisc *sch, struct sk_buff **to_free);

extern void sfq_perturbation(struct timer_list *t);

static int klpp_sfq_change(struct Qdisc *sch, struct nlattr *opt,
		      struct netlink_ext_ack *extack)
{
	struct sfq_sched_data *q = qdisc_priv(sch);
	struct tc_sfq_qopt *ctl = nla_data(opt);
	struct tc_sfq_qopt_v1 *ctl_v1 = NULL;
	unsigned int qlen, dropped = 0;
	struct red_parms *p = NULL;
	struct sk_buff *to_free = NULL;
	struct sk_buff *tail = NULL;
	unsigned int maxflows;
	unsigned int quantum;
	unsigned int divisor;
	int perturb_period;
	u8 headdrop;
	u8 maxdepth;
	int limit;
	u8 flags;

	if (opt->nla_len < nla_attr_size(sizeof(*ctl)))
		return -EINVAL;
	if (opt->nla_len >= nla_attr_size(sizeof(*ctl_v1)))
		ctl_v1 = nla_data(opt);
	if (ctl->divisor &&
	    (!is_power_of_2(ctl->divisor) || ctl->divisor > 65536))
		return -EINVAL;

	if ((int)ctl->quantum < 0) {
		NL_SET_ERR_MSG_MOD(extack, "invalid quantum");
		return -EINVAL;
	}
	if (ctl_v1 && !red_check_params(ctl_v1->qth_min, ctl_v1->qth_max,
					ctl_v1->Wlog, ctl_v1->Scell_log, NULL))
		return -EINVAL;
	if (ctl_v1 && ctl_v1->qth_min) {
		p = kmalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
	}

	sch_tree_lock(sch);

	limit = q->limit;
	divisor = q->divisor;
	headdrop = q->headdrop;
	maxdepth = q->maxdepth;
	maxflows = q->maxflows;
	perturb_period = q->perturb_period;
	quantum = q->quantum;
	flags = q->flags;

	/* update and validate configuration */
	if (ctl->quantum)
		quantum = ctl->quantum;
	perturb_period = ctl->perturb_period * HZ;
	if (ctl->flows)
		maxflows = min_t(u32, ctl->flows, SFQ_MAX_FLOWS);
	if (ctl->divisor) {
		divisor = ctl->divisor;
		maxflows = min_t(u32, maxflows, divisor);
	}
	if (ctl_v1) {
		if (ctl_v1->depth)
			maxdepth = min_t(u32, ctl_v1->depth, SFQ_MAX_DEPTH);
		if (p) {
			red_set_parms(p,
				      ctl_v1->qth_min, ctl_v1->qth_max,
				      ctl_v1->Wlog,
				      ctl_v1->Plog, ctl_v1->Scell_log,
				      NULL,
				      ctl_v1->max_P);
		}
		flags = ctl_v1->flags;
		headdrop = ctl_v1->headdrop;
	}
	if (ctl->limit) {
		limit = min_t(u32, ctl->limit, maxdepth * maxflows);
		maxflows = min_t(u32, maxflows, limit);
	}
	if (limit == 1) {
		sch_tree_unlock(sch);
		kfree(p);
		return -EINVAL;
	}

	/* commit configuration */
	q->limit = limit;
	q->divisor = divisor;
	q->headdrop = headdrop;
	q->maxdepth = maxdepth;
	q->maxflows = maxflows;
	WRITE_ONCE(q->perturb_period, perturb_period);
	q->quantum = quantum;
	q->flags = flags;
	if (p)
		swap(q->red_parms, p);

	qlen = sch->q.qlen;
	while (sch->q.qlen > q->limit) {
		dropped += sfq_drop(sch, &to_free);
		if (!tail)
			tail = to_free;
	}

	rtnl_kfree_skbs(to_free, tail);
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	del_timer(&q->perturb_timer);
	if (q->perturb_period) {
		mod_timer(&q->perturb_timer, jiffies + q->perturb_period);
		get_random_bytes(&q->perturbation, sizeof(q->perturbation));
	}
	sch_tree_unlock(sch);
	kfree(p);
	return 0;
}

static void *sfq_alloc(size_t sz)
{
	return  kvmalloc(sz, GFP_KERNEL);
}

int klpp_sfq_init(struct Qdisc *sch, struct nlattr *opt,
		  struct netlink_ext_ack *extack)
{
	struct sfq_sched_data *q = qdisc_priv(sch);
	int i;
	int err;

	q->sch = sch;
	timer_setup(&q->perturb_timer, sfq_perturbation, TIMER_DEFERRABLE);

	err = tcf_block_get(&q->block, &q->filter_list, sch, extack);
	if (err)
		return err;

	for (i = 0; i < SFQ_MAX_DEPTH + 1; i++) {
		q->dep[i].next = i + SFQ_MAX_FLOWS;
		q->dep[i].prev = i + SFQ_MAX_FLOWS;
	}

	q->limit = SFQ_MAX_DEPTH;
	q->maxdepth = SFQ_MAX_DEPTH;
	q->cur_depth = 0;
	q->tail = NULL;
	q->divisor = SFQ_DEFAULT_HASH_DIVISOR;
	q->maxflows = SFQ_DEFAULT_FLOWS;
	q->quantum = psched_mtu(qdisc_dev(sch));
	q->perturb_period = 0;
	get_random_bytes(&q->perturbation, sizeof(q->perturbation));

	if (opt) {
		int err = klpp_sfq_change(sch, opt, extack);
		if (err)
			return err;
	}

	q->ht = sfq_alloc(sizeof(q->ht[0]) * q->divisor);
	q->slots = sfq_alloc(sizeof(q->slots[0]) * q->maxflows);
	if (!q->ht || !q->slots) {
		/* Note: sfq_destroy() will be called by our caller */
		return -ENOMEM;
	}

	for (i = 0; i < q->divisor; i++)
		q->ht[i] = SFQ_EMPTY_SLOT;

	for (i = 0; i < q->maxflows; i++) {
		slot_queue_init(&q->slots[i]);
		sfq_link(q, i);
	}
	if (q->limit >= 1)
		sch->flags |= TCQ_F_CAN_BYPASS;
	else
		sch->flags &= ~TCQ_F_CAN_BYPASS;
	return 0;
}


#include "livepatch_bsc1245776.h"

#include <linux/livepatch.h>

extern typeof(sfq_drop) sfq_drop KLP_RELOC_SYMBOL(sch_sfq, sch_sfq, sfq_drop);
extern typeof(sfq_perturbation) sfq_perturbation
	 KLP_RELOC_SYMBOL(sch_sfq, sch_sfq, sfq_perturbation);
