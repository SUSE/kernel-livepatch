/*
 * livepatch_bsc1215300
 *
 * Fix for CVE-2023-4921, bsc#1215300
 *
 *  Upstream commit:
 *  8fc134fee27f ("net: sched: sch_qfq: Fix UAF in qfq_dequeue()")
 *  6d25d1dc76bf ("net: sched: sch_qfq: Use non-work-conserving warning handler")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  f1f032edc402d428e50dfe42aa487c0a5ca885b9
 *  aabd8932fa70852e56c39ad42532d218850101f3
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b3e4331a0c1ab8136776b1b9c50912adb2be6876
 *  aabd8932fa70852e56c39ad42532d218850101f3
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b50ba0e31ca0088fb85d852496aca093c347e628
 *  9408063deb6eb4aaef97f316dc8e00e65a5989e0
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

#if !IS_MODULE(CONFIG_NET_SCH_QFQ)
#error "Live patch supports only CONFIG=m"
#endif

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

enum qfq_state { ER, IR, EB, IB, QFQ_MAX_STATE };

struct qfq_class {
	struct Qdisc_class_common common;

	unsigned int filter_cnt;

	struct gnet_stats_basic_packed bstats;
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

enum update_reason {enqueue, requeue};

static struct qfq_class *qfq_find_class(struct Qdisc *sch, u32 classid)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, classid);
	if (clc == NULL)
		return NULL;
	return container_of(clc, struct qfq_class, common);
}

static void klpr_qfq_activate_agg(struct qfq_sched *, struct qfq_aggregate *,
			     enum update_reason);

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

static void (*klpe_qfq_add_to_agg)(struct qfq_sched *q,
			   struct qfq_aggregate *agg,
			   struct qfq_class *cl);

static struct qfq_aggregate *(*klpe_qfq_choose_next_agg)(struct qfq_sched *);

static void (*klpe_qfq_deact_rm_from_agg)(struct qfq_sched *q, struct qfq_class *cl);

static int klpr_qfq_change_agg(struct Qdisc *sch, struct qfq_class *cl, u32 weight,
			   u32 lmax)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_aggregate *new_agg = qfq_find_agg(q, lmax, weight);

	if (new_agg == NULL) { /* create new aggregate */
		new_agg = kzalloc(sizeof(*new_agg), GFP_ATOMIC);
		if (new_agg == NULL)
			return -ENOBUFS;
		qfq_init_agg(q, new_agg, lmax, weight);
	}
	(*klpe_qfq_deact_rm_from_agg)(q, cl);
	(*klpe_qfq_add_to_agg)(q, new_agg, cl);

	return 0;
}

static struct qfq_class *qfq_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_class *cl;
	struct tcf_result res;
	struct tcf_proto *fl;
	int result;

	if (TC_H_MAJ(skb->priority ^ sch->handle) == 0) {
		pr_debug("qfq_classify: found %d\n", skb->priority);
		cl = qfq_find_class(sch, skb->priority);
		if (cl != NULL)
			return cl;
	}

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	fl = rcu_dereference_bh(q->filter_list);
	result = tcf_classify(skb, fl, &res, false);
	if (result >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/* fall through */
		case TC_ACT_SHOT:
			return NULL;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		cl = (struct qfq_class *)res.class;
		if (cl == NULL)
			cl = qfq_find_class(sch, res.classid);
		return cl;
	}

	return NULL;
}

static inline int qfq_gt(u64 a, u64 b)
{
	return (s64)(a - b) > 0;
}

static inline u64 qfq_round_down(u64 ts, unsigned int shift)
{
	return ts & ~((1ULL << shift) - 1);
}

static inline struct qfq_group *qfq_ffs(struct qfq_sched *q,
					unsigned long bitmap)
{
	int index = __ffs(bitmap);
	return &q->groups[index];
}

static inline unsigned long mask_from(unsigned long bitmap, int from)
{
	return bitmap & ~((1UL << from) - 1);
}

static struct Qdisc_ops (*klpe_plug_qdisc_ops);

static struct sk_buff *klpp_agg_dequeue(struct qfq_aggregate *agg,
			struct qfq_class *cl, unsigned int len)
{
	struct sk_buff *skb = qdisc_dequeue_peeked(cl->qdisc);

	if (!skb)
		return NULL;

	cl->deficit -= (int) len;

	if (cl->qdisc->q.qlen == 0) /* no more packets, remove from list */
		list_del(&cl->alist);
	else {
		struct sk_buff *sk;
		if (cl->qdisc->ops == klpe_plug_qdisc_ops)
			sk = qdisc_peek_dequeued(cl->qdisc);
		else
			sk = cl->qdisc->ops->peek(cl->qdisc);

		if (cl->deficit < qdisc_pkt_len(sk)) {
			cl->deficit += agg->lmax;
			list_move_tail(&cl->alist, &agg->active);
		}
	}

	return skb;
}

static inline struct sk_buff *klpp_qfq_peek_skb(struct qfq_aggregate *agg,
					   struct qfq_class **cl,
					   unsigned int *len)
{
	struct sk_buff *skb;

	*cl = list_first_entry(&agg->active, struct qfq_class, alist);

	if ((*cl)->qdisc->ops == klpe_plug_qdisc_ops)
		skb = qdisc_peek_dequeued((*cl)->qdisc);
	else
		skb = (*cl)->qdisc->ops->peek((*cl)->qdisc);

	if (skb == NULL)
		qdisc_warn_nonwc("qfq_dequeue", (*cl)->qdisc);
	else
		*len = qdisc_pkt_len(skb);

	return skb;
}

static inline void charge_actual_service(struct qfq_aggregate *agg)
{
	/* Compute the service received by the aggregate, taking into
	 * account that, after decreasing the number of classes in
	 * agg, it may happen that
	 * agg->initial_budget - agg->budget > agg->bugdetmax
	 */
	u32 service_received = min(agg->budgetmax,
				   agg->initial_budget - agg->budget);

	agg->F = agg->S + (u64)service_received * agg->inv_w;
}

static void qfq_update_start(struct qfq_sched *q, struct qfq_aggregate *agg)
{
	unsigned long mask;
	u64 limit, roundedF;
	int slot_shift = agg->grp->slot_shift;

	roundedF = qfq_round_down(agg->F, slot_shift);
	limit = qfq_round_down(q->V, slot_shift) + (1ULL << slot_shift);

	if (!qfq_gt(agg->F, q->V) || qfq_gt(roundedF, limit)) {
		/* timestamp was stale */
		mask = mask_from(q->bitmaps[ER], agg->grp->index);
		if (mask) {
			struct qfq_group *next = qfq_ffs(q, mask);
			if (qfq_gt(roundedF, next->F)) {
				if (qfq_gt(limit, next->F))
					agg->S = next->F;
				else /* preserve timestamp correctness */
					agg->S = limit;
				return;
			}
		}
		agg->S = q->V;
	} else  /* timestamp is not stale */
		agg->S = agg->F;
}

static inline void
qfq_update_agg_ts(struct qfq_sched *q,
		    struct qfq_aggregate *agg, enum update_reason reason)
{
	if (reason != requeue)
		qfq_update_start(q, agg);
	else /* just charge agg for the service received */
		agg->S = agg->F;

	agg->F = agg->S + (u64)agg->budgetmax * agg->inv_w;
}

static void (*klpe_qfq_schedule_agg)(struct qfq_sched *q, struct qfq_aggregate *agg);

struct sk_buff *klpp_qfq_dequeue(struct Qdisc *sch)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_aggregate *in_serv_agg = q->in_serv_agg;
	struct qfq_class *cl;
	struct sk_buff *skb = NULL;
	/* next-packet len, 0 means no more active classes in in-service agg */
	unsigned int len = 0;

	if (in_serv_agg == NULL)
		return NULL;

	if (!list_empty(&in_serv_agg->active))
		skb = klpp_qfq_peek_skb(in_serv_agg, &cl, &len);

	/*
	 * If there are no active classes in the in-service aggregate,
	 * or if the aggregate has not enough budget to serve its next
	 * class, then choose the next aggregate to serve.
	 */
	if (len == 0 || in_serv_agg->budget < len) {
		charge_actual_service(in_serv_agg);

		/* recharge the budget of the aggregate */
		in_serv_agg->initial_budget = in_serv_agg->budget =
			in_serv_agg->budgetmax;

		if (!list_empty(&in_serv_agg->active)) {
			/*
			 * Still active: reschedule for
			 * service. Possible optimization: if no other
			 * aggregate is active, then there is no point
			 * in rescheduling this aggregate, and we can
			 * just keep it as the in-service one. This
			 * should be however a corner case, and to
			 * handle it, we would need to maintain an
			 * extra num_active_aggs field.
			*/
			qfq_update_agg_ts(q, in_serv_agg, requeue);
			(*klpe_qfq_schedule_agg)(q, in_serv_agg);
		} else if (sch->q.qlen == 0) { /* no aggregate to serve */
			q->in_serv_agg = NULL;
			return NULL;
		}

		/*
		 * If we get here, there are other aggregates queued:
		 * choose the new aggregate to serve.
		 */
		in_serv_agg = q->in_serv_agg = (*klpe_qfq_choose_next_agg)(q);
		skb = klpp_qfq_peek_skb(in_serv_agg, &cl, &len);
	}
	if (!skb)
		return NULL;

	sch->q.qlen--;

	skb = klpp_agg_dequeue(in_serv_agg, cl, len);

	if (!skb) {
		sch->q.qlen++;
		return NULL;
	}

	qdisc_qstats_backlog_dec(sch, skb);
	qdisc_bstats_update(sch, skb);

	/* If lmax is lowered, through qfq_change_class, for a class
	 * owning pending packets with larger size than the new value
	 * of lmax, then the following condition may hold.
	 */
	if (unlikely(in_serv_agg->budget < len))
		in_serv_agg->budget = 0;
	else
		in_serv_agg->budget -= len;

	q->V += (u64)len * q->iwsum;
	pr_debug("qfq dequeue: len %u F %lld now %lld\n",
		 len, (unsigned long long) in_serv_agg->F,
		 (unsigned long long) q->V);

	return skb;
}

int klpp_qfq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free)
{
	unsigned int len = qdisc_pkt_len(skb), gso_segs;
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_class *cl;
	struct qfq_aggregate *agg;
	int err = 0;

	cl = qfq_classify(skb, sch, &err);
	if (cl == NULL) {
		if (err & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return err;
	}
	pr_debug("qfq_enqueue: cl = %x\n", cl->common.classid);

	if (unlikely(cl->agg->lmax < len)) {
		pr_debug("qfq: increasing maxpkt from %u to %u for class %u",
			 cl->agg->lmax, len, cl->common.classid);
		err = klpr_qfq_change_agg(sch, cl, cl->agg->class_weight, len);
		if (err) {
			cl->qstats.drops++;
			return qdisc_drop(skb, sch, to_free);
		}
	}

	gso_segs = skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 1;
	err = qdisc_enqueue(skb, cl->qdisc, to_free);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		pr_debug("qfq_enqueue: enqueue failed %d\n", err);
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}

	cl->bstats.bytes += len;
	cl->bstats.packets += gso_segs;
	sch->qstats.backlog += len;
	++sch->q.qlen;

	agg = cl->agg;
	/* if the queue was not empty, then done here */
	if (cl->qdisc->q.qlen != 1) {
		struct sk_buff *sk;
		if (cl->qdisc->ops == klpe_plug_qdisc_ops)
			sk = qdisc_peek_dequeued(cl->qdisc);
		else
			sk = cl->qdisc->ops->peek(cl->qdisc);

		if (unlikely(skb == sk) &&
		    list_first_entry(&agg->active, struct qfq_class, alist)
		    == cl && cl->deficit < len)
			list_move_tail(&cl->alist, &agg->active);

		return err;
	}

	/* schedule class for service within the aggregate */
	cl->deficit = agg->lmax;
	list_add_tail(&cl->alist, &agg->active);

	if (list_first_entry(&agg->active, struct qfq_class, alist) != cl ||
	    q->in_serv_agg == agg)
		return err; /* non-empty or in service, nothing else to do */

	klpr_qfq_activate_agg(q, agg, enqueue);

	return err;
}

static void klpr_qfq_activate_agg(struct qfq_sched *q, struct qfq_aggregate *agg,
			     enum update_reason reason)
{
	agg->initial_budget = agg->budget = agg->budgetmax; /* recharge budg. */

	qfq_update_agg_ts(q, agg, reason);
	if (q->in_serv_agg == NULL) { /* no aggr. in service or scheduled */
		q->in_serv_agg = agg; /* start serving this aggregate */
		 /* update V: to be in service, agg must be eligible */
		q->oldV = q->V = agg->S;
	} else if (agg != q->in_serv_agg)
		(*klpe_qfq_schedule_agg)(q, agg);
}



#include "livepatch_bsc1215300.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sch_qfq"
#define LP_MODULE_PLUG "sch_plug"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "qfq_add_to_agg", (void *)&klpe_qfq_add_to_agg, "sch_qfq" },
	{ "qfq_choose_next_agg", (void *)&klpe_qfq_choose_next_agg,
	  "sch_qfq" },
	{ "qfq_deact_rm_from_agg", (void *)&klpe_qfq_deact_rm_from_agg,
	  "sch_qfq" },
	{ "qfq_schedule_agg", (void *)&klpe_qfq_schedule_agg, "sch_qfq" },
};

static struct klp_kallsyms_reloc klp_funcs_plug[] = {
	{ "plug_qdisc_ops", (void *)&klpe_plug_qdisc_ops, "sch_plug" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret = 0;

	if (action != MODULE_STATE_COMING || (strcmp(mod->name, LP_MODULE) &&
	    strcmp(mod->name, LP_MODULE_PLUG)))
		return 0;

	mutex_lock(&module_mutex);
	if (!strcmp(mod->name, LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	} else if (!strcmp(mod->name, LP_MODULE_PLUG)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs_plug,
							    ARRAY_SIZE(klp_funcs_plug));
		if (ret == -ENOENT)
			ret = 0;
	}

out:
	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
			__func__);

	mutex_unlock(&module_mutex);
	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1215300_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	/*
	 * Is not guaranteed that sch_plug is loaded, so don't error found if
	 * the symbol is not found.
	 */
	if (find_module(LP_MODULE_PLUG)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs_plug,
						    ARRAY_SIZE(klp_funcs_plug));
		if (ret == -ENOENT)
			ret = 0;

		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1215300_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
