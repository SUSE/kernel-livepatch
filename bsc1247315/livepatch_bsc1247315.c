/*
 * livepatch_bsc1247315
 *
 * Fix for CVE-2025-38477, bsc#1247315
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

/* klp-ccp: from net/sched/sch_qfq.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#define QFQ_MAX_SLOTS	32

#define QFQ_MAX_INDEX		24
#define QFQ_MAX_WSHIFT		10

#define	QFQ_MAX_WEIGHT		(1<<QFQ_MAX_WSHIFT) /* see qfq_slot_insert */
#define QFQ_MAX_WSUM		(64*QFQ_MAX_WEIGHT)

#define FRAC_BITS		30	/* fixed point arithmetic */
#define ONE_FP			(1UL << FRAC_BITS)

#define QFQ_MTU_SHIFT		16	/* to support TSO/GSO */
#define QFQ_MIN_LMAX		512	/* see qfq_slot_insert */
#define QFQ_MAX_LMAX		(1UL << QFQ_MTU_SHIFT)

enum qfq_state { ER, IR, EB, IB, QFQ_MAX_STATE };

struct qfq_class {
	struct Qdisc_class_common common;

	unsigned int filter_cnt;

	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	struct net_rate_estimator __rcu *rate_est;
	struct Qdisc *qdisc;
	struct list_head alist;		/* Link for active-classes list. */
	struct qfq_aggregate *agg;	/* Parent aggregate. */
	int deficit;			/* DRR deficit counter. */
};

struct qfq_aggregate {
	struct hlist_node next;	/* Link for the slot list. */
	u64 S, F;		/* flow timestamps (exact) */

	/* group we belong to. In principle we would need the index,
	 * which is log_2(lmax/weight), but we never reference it
	 * directly, only the group.
	 */
	struct qfq_group *grp;

	/* these are copied from the flowset. */
	u32	class_weight; /* Weight of each class in this aggregate. */
	/* Max pkt size for the classes in this aggregate, DRR quantum. */
	int	lmax;

	u32	inv_w;	    /* ONE_FP/(sum of weights of classes in aggr.). */
	u32	budgetmax;  /* Max budget for this aggregate. */
	u32	initial_budget, budget;     /* Initial and current budget. */

	int		  num_classes;	/* Number of classes in this aggr. */
	struct list_head  active;	/* DRR queue of active classes. */

	struct hlist_node nonfull_next;	/* See nonfull_aggs in qfq_sched. */
};

struct qfq_group {
	u64 S, F;			/* group timestamps (approx). */
	unsigned int slot_shift;	/* Slot shift. */
	unsigned int index;		/* Group index. */
	unsigned int front;		/* Index of the front slot. */
	unsigned long full_slots;	/* non-empty slots */

	/* Array of RR lists of active aggregates. */
	struct hlist_head slots[QFQ_MAX_SLOTS];
};

struct qfq_sched {
	struct tcf_proto __rcu *filter_list;
	struct tcf_block	*block;
	struct Qdisc_class_hash clhash;

	u64			oldV, V;	/* Precise virtual times. */
	struct qfq_aggregate	*in_serv_agg;   /* Aggregate being served. */
	u32			wsum;		/* weight sum */
	u32			iwsum;		/* inverse weight sum */

	unsigned long bitmaps[QFQ_MAX_STATE];	    /* Group bitmaps. */
	struct qfq_group groups[QFQ_MAX_INDEX + 1]; /* The groups. */
	u32 min_slot_shift;	/* Index of the group-0 bit in the bitmaps. */

	u32 max_agg_classes;		/* Max number of classes per aggr. */
	struct hlist_head nonfull_aggs; /* Aggs with room for more classes. */
};

extern const struct nla_policy qfq_policy[TCA_QFQ_MAX + 1];

static void qfq_init_agg(struct qfq_sched *q, struct qfq_aggregate *agg,
			 u32 lmax, u32 weight)
{
	INIT_LIST_HEAD(&agg->active);
	hlist_add_head(&agg->nonfull_next, &q->nonfull_aggs);

	agg->lmax = lmax;
	agg->class_weight = weight;
}

static struct qfq_aggregate *qfq_find_agg(struct qfq_sched *q,
					  u32 lmax, u32 weight)
{
	struct qfq_aggregate *agg;

	hlist_for_each_entry(agg, &q->nonfull_aggs, nonfull_next)
		if (agg->lmax == lmax && agg->class_weight == weight)
			return agg;

	return NULL;
}

extern void qfq_update_agg(struct qfq_sched *q, struct qfq_aggregate *agg,
			   int new_num_classes);

extern void qfq_add_to_agg(struct qfq_sched *q,
			   struct qfq_aggregate *agg,
			   struct qfq_class *cl);

extern struct qfq_aggregate *qfq_choose_next_agg(struct qfq_sched *);

static void qfq_destroy_agg(struct qfq_sched *q, struct qfq_aggregate *agg)
{
	hlist_del_init(&agg->nonfull_next);
	q->wsum -= agg->class_weight;
	if (q->wsum != 0)
		q->iwsum = ONE_FP / q->wsum;

	if (q->in_serv_agg == agg)
		q->in_serv_agg = qfq_choose_next_agg(q);
	kfree(agg);
}

static void qfq_rm_from_agg(struct qfq_sched *q, struct qfq_class *cl)
{
	struct qfq_aggregate *agg = cl->agg;

	cl->agg = NULL;
	if (agg->num_classes == 1) { /* agg being emptied, destroy it */
		qfq_destroy_agg(q, agg);
		return;
	}
	qfq_update_agg(q, agg, agg->num_classes-1);
}

extern void qfq_deact_rm_from_agg(struct qfq_sched *q, struct qfq_class *cl);

int klpp_qfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
			    struct nlattr **tca, unsigned long *arg,
			    struct netlink_ext_ack *extack)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_class *cl = (struct qfq_class *)*arg;
	bool existing = false;
	struct nlattr *tb[TCA_QFQ_MAX + 1];
	struct qfq_aggregate *new_agg = NULL;
	u32 weight, lmax, inv_w, old_weight, old_lmax;
	int err;
	int delta_w;

	if (NL_REQ_ATTR_CHECK(extack, NULL, tca, TCA_OPTIONS)) {
		NL_SET_ERR_MSG_MOD(extack, "missing options");
		return -EINVAL;
	}

	err = nla_parse_nested_deprecated(tb, TCA_QFQ_MAX, tca[TCA_OPTIONS],
					  qfq_policy, extack);
	if (err < 0)
		return err;

	if (tb[TCA_QFQ_WEIGHT])
		weight = nla_get_u32(tb[TCA_QFQ_WEIGHT]);
	else
		weight = 1;

	if (tb[TCA_QFQ_LMAX]) {
		lmax = nla_get_u32(tb[TCA_QFQ_LMAX]);
	} else {
		/* MTU size is user controlled */
		lmax = psched_mtu(qdisc_dev(sch));
		if (lmax < QFQ_MIN_LMAX || lmax > QFQ_MAX_LMAX) {
			NL_SET_ERR_MSG_MOD(extack,
					   "MTU size out of bounds for qfq");
			return -EINVAL;
		}
	}

	inv_w = ONE_FP / weight;
	weight = ONE_FP / inv_w;

	if (cl != NULL) {
		sch_tree_lock(sch);
		old_weight = cl->agg->class_weight;
		old_lmax   = cl->agg->lmax;
		sch_tree_unlock(sch);
		if (lmax == old_lmax && weight == old_weight)
			return 0; /* nothing to change */
	}

	delta_w = weight - (cl ? old_weight : 0);

	if (q->wsum + delta_w > QFQ_MAX_WSUM) {
		NL_SET_ERR_MSG_FMT_MOD(extack,
				       "total weight out of range (%d + %u)\n",
				       delta_w, q->wsum);
		return -EINVAL;
	}

	if (cl != NULL) { /* modify existing class */
		if (tca[TCA_RATE]) {
			err = gen_replace_estimator(&cl->bstats, NULL,
						    &cl->rate_est,
						    NULL,
						    true,
						    tca[TCA_RATE]);
			if (err)
				return err;
		}
		existing = true;
		goto set_change_agg;
	}

	/* create and init new class */
	cl = kzalloc(sizeof(struct qfq_class), GFP_KERNEL);
	if (cl == NULL)
		return -ENOBUFS;

	gnet_stats_basic_sync_init(&cl->bstats);
	cl->common.classid = classid;
	cl->deficit = lmax;

	cl->qdisc = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
				      classid, NULL);
	if (cl->qdisc == NULL)
		cl->qdisc = &noop_qdisc;

	if (tca[TCA_RATE]) {
		err = gen_new_estimator(&cl->bstats, NULL,
					&cl->rate_est,
					NULL,
					true,
					tca[TCA_RATE]);
		if (err)
			goto destroy_class;
	}

	if (cl->qdisc != &noop_qdisc)
		qdisc_hash_add(cl->qdisc, true);

set_change_agg:
	sch_tree_lock(sch);
	new_agg = qfq_find_agg(q, lmax, weight);
	if (new_agg == NULL) { /* create new aggregate */
		sch_tree_unlock(sch);
		new_agg = kzalloc(sizeof(*new_agg), GFP_KERNEL);
		if (new_agg == NULL) {
			err = -ENOBUFS;
			gen_kill_estimator(&cl->rate_est);
			goto destroy_class;
		}
		sch_tree_lock(sch);
		qfq_init_agg(q, new_agg, lmax, weight);
	}
	if (existing)
		qfq_deact_rm_from_agg(q, cl);
	else
		qdisc_class_hash_insert(&q->clhash, &cl->common);
	qfq_add_to_agg(q, new_agg, cl);
	sch_tree_unlock(sch);
	qdisc_class_hash_grow(sch, &q->clhash);

	*arg = (unsigned long)cl;
	return 0;

destroy_class:
	qdisc_put(cl->qdisc);
	kfree(cl);
	return err;
}

void klpp_qfq_destroy_class(struct Qdisc *sch, struct qfq_class *cl)
{
	gen_kill_estimator(&cl->rate_est);
	qdisc_put(cl->qdisc);
	kfree(cl);
}

int klpp_qfq_delete_class(struct Qdisc *sch, unsigned long arg,
			    struct netlink_ext_ack *extack)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_class *cl = (struct qfq_class *)arg;

	if (cl->filter_cnt > 0)
		return -EBUSY;

	sch_tree_lock(sch);

	qdisc_purge_queue(cl->qdisc);
	qdisc_class_hash_remove(&q->clhash, &cl->common);
	qfq_rm_from_agg(q, cl);

	sch_tree_unlock(sch);

	klpp_qfq_destroy_class(sch, cl);
	return 0;
}

int klpp_qfq_dump_class(struct Qdisc *sch, unsigned long arg,
			  struct sk_buff *skb, struct tcmsg *tcm)
{
	struct qfq_class *cl = (struct qfq_class *)arg;
	struct nlattr *nest;
	u32 class_weight, lmax;

	tcm->tcm_parent	= TC_H_ROOT;
	tcm->tcm_handle	= cl->common.classid;
	tcm->tcm_info	= cl->qdisc->handle;

	nest = nla_nest_start_noflag(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	sch_tree_lock(sch);
	class_weight	= cl->agg->class_weight;
	lmax		= cl->agg->lmax;
	sch_tree_unlock(sch);
	if (nla_put_u32(skb, TCA_QFQ_WEIGHT, class_weight) ||
	    nla_put_u32(skb, TCA_QFQ_LMAX, lmax))
		goto nla_put_failure;
	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

int klpp_qfq_dump_class_stats(struct Qdisc *sch, unsigned long arg,
				struct gnet_dump *d)
{
	struct qfq_class *cl = (struct qfq_class *)arg;
	struct tc_qfq_stats xstats;

	memset(&xstats, 0, sizeof(xstats));

	sch_tree_lock(sch);
	xstats.weight = cl->agg->class_weight;
	xstats.lmax = cl->agg->lmax;
	sch_tree_unlock(sch);

	if (gnet_stats_copy_basic(d, NULL, &cl->bstats, true) < 0 ||
	    gnet_stats_copy_rate_est(d, &cl->rate_est) < 0 ||
	    qdisc_qstats_copy(d, cl->qdisc) < 0)
		return -1;

	return gnet_stats_copy_app(d, &xstats, sizeof(xstats));
}

struct qfq_aggregate *qfq_choose_next_agg(struct qfq_sched *q);

void klpp_qfq_destroy_qdisc(struct Qdisc *sch)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_class *cl;
	struct hlist_node *next;
	unsigned int i;

	tcf_block_put(q->block);

	for (i = 0; i < q->clhash.hashsize; i++) {
		hlist_for_each_entry_safe(cl, next, &q->clhash.hash[i],
					  common.hnode) {
			qfq_rm_from_agg(q, cl);
			klpp_qfq_destroy_class(sch, cl);
		}
	}
	qdisc_class_hash_destroy(&q->clhash);
}


#include "livepatch_bsc1247315.h"

#include <linux/livepatch.h>

extern typeof(qfq_add_to_agg) qfq_add_to_agg
	 KLP_RELOC_SYMBOL(sch_qfq, sch_qfq, qfq_add_to_agg);
extern typeof(qfq_choose_next_agg) qfq_choose_next_agg
	 KLP_RELOC_SYMBOL(sch_qfq, sch_qfq, qfq_choose_next_agg);
extern typeof(qfq_deact_rm_from_agg) qfq_deact_rm_from_agg
	 KLP_RELOC_SYMBOL(sch_qfq, sch_qfq, qfq_deact_rm_from_agg);
extern typeof(qfq_policy) qfq_policy
	 KLP_RELOC_SYMBOL(sch_qfq, sch_qfq, qfq_policy);
extern typeof(qfq_update_agg) qfq_update_agg
	 KLP_RELOC_SYMBOL(sch_qfq, sch_qfq, qfq_update_agg);
