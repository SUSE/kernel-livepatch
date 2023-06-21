/*
 * livepatch_bsc1210989
 *
 * Fix for CVE-2023-31436, bsc#1210989
 *
 *  Upstream commit:
 *  3037933448f6 ("net: sched: sch_qfq: prevent slab-out-of-bounds in qfq_activate_agg")
 *
 *  SLE12-SP4, SLE12-SP5 and SLE15-SP1 commit:
 *  a507e9439d3951018937b86b0ae9b0fcbe006fe8
 *
 *  SLE15-SP2 and -SP3 commit:
 *  eeb865daf04077277aeb55a06dee2ec82567de41
 *
 *  SLE15-SP4 commit:
 *  8a9beae58e11e9090de3658f148e0a8f0f77511d
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

#define QFQ_MAX_SLOTS	32

#define QFQ_MAX_INDEX		24
#define QFQ_MAX_WSHIFT		10

#define	QFQ_MAX_WEIGHT		(1<<QFQ_MAX_WSHIFT) /* see qfq_slot_insert */
#define QFQ_MAX_WSUM		(64*QFQ_MAX_WEIGHT)

#define FRAC_BITS		30	/* fixed point arithmetic */
#define ONE_FP			(1UL << FRAC_BITS)

#define QFQ_MTU_SHIFT		16	/* to support TSO/GSO */
#define QFQ_MIN_LMAX		512	/* see qfq_slot_insert */

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

static const struct nla_policy (*klpe_qfq_policy)[TCA_QFQ_MAX + 1];

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

static void (*klpe_qfq_deact_rm_from_agg)(struct qfq_sched *q, struct qfq_class *cl);

int klpp_qfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
			    struct nlattr **tca, unsigned long *arg,
			    struct netlink_ext_ack *extack)
{
	struct qfq_sched *q = qdisc_priv(sch);
	struct qfq_class *cl = (struct qfq_class *)*arg;
	bool existing = false;
	struct nlattr *tb[TCA_QFQ_MAX + 1];
	struct qfq_aggregate *new_agg = NULL;
	u32 weight, lmax, inv_w;
	int err;
	int delta_w;

	if (tca[TCA_OPTIONS] == NULL) {
		pr_notice("qfq: no options\n");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_QFQ_MAX, tca[TCA_OPTIONS], (*klpe_qfq_policy),
			       NULL);
	if (err < 0)
		return err;

	if (tb[TCA_QFQ_WEIGHT]) {
		weight = nla_get_u32(tb[TCA_QFQ_WEIGHT]);
		if (!weight || weight > (1UL << QFQ_MAX_WSHIFT)) {
			pr_notice("qfq: invalid weight %u\n", weight);
			return -EINVAL;
		}
	} else
		weight = 1;

	if (tb[TCA_QFQ_LMAX])
		lmax = nla_get_u32(tb[TCA_QFQ_LMAX]);
	else
		lmax = psched_mtu(qdisc_dev(sch));

	if (lmax < QFQ_MIN_LMAX || lmax > (1UL << QFQ_MTU_SHIFT)) {
		pr_notice("qfq: invalid max length %u\n", lmax);
		return -EINVAL;
	}

	inv_w = ONE_FP / weight;
	weight = ONE_FP / inv_w;

	if (cl != NULL &&
	    lmax == cl->agg->lmax &&
	    weight == cl->agg->class_weight)
		return 0; /* nothing to change */

	delta_w = weight - (cl ? cl->agg->class_weight : 0);

	if (q->wsum + delta_w > QFQ_MAX_WSUM) {
		pr_notice("qfq: total weight out of range (%d + %u)\n",
			  delta_w, q->wsum);
		return -EINVAL;
	}

	if (cl != NULL) { /* modify existing class */
		if (tca[TCA_RATE]) {
			err = gen_replace_estimator(&cl->bstats, NULL,
						    &cl->rate_est,
						    NULL,
						    qdisc_root_sleeping_running(sch),
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
					qdisc_root_sleeping_running(sch),
					tca[TCA_RATE]);
		if (err)
			goto destroy_class;
	}

	if (cl->qdisc != &noop_qdisc)
		qdisc_hash_add(cl->qdisc, true);
	sch_tree_lock(sch);
	qdisc_class_hash_insert(&q->clhash, &cl->common);
	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &q->clhash);

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
		(*klpe_qfq_deact_rm_from_agg)(q, cl);
	(*klpe_qfq_add_to_agg)(q, new_agg, cl);
	sch_tree_unlock(sch);

	*arg = (unsigned long)cl;
	return 0;

destroy_class:
	qdisc_put(cl->qdisc);
	kfree(cl);
	return err;
}



#define LP_MODULE "sch_qfq"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1210989.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "qfq_add_to_agg", (void *)&klpe_qfq_add_to_agg, "sch_qfq" },
	{ "qfq_deact_rm_from_agg", (void *)&klpe_qfq_deact_rm_from_agg,
	  "sch_qfq" },
	{ "qfq_policy", (void *)&klpe_qfq_policy, "sch_qfq" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1210989_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1210989_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
