/*
 * livepatch_bsc1246356
 *
 * Fix for CVE-2025-38177, bsc#1246356
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

/* klp-ccp: from net/sched/sch_hfsc.c */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/compiler.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/init.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

#include <asm/div64.h>

struct internal_sc {
	u64	sm1;	/* scaled slope of the 1st segment */
	u64	ism1;	/* scaled inverse-slope of the 1st segment */
	u64	dx;	/* the x-projection of the 1st segment */
	u64	dy;	/* the y-projection of the 1st segment */
	u64	sm2;	/* scaled slope of the 2nd segment */
	u64	ism2;	/* scaled inverse-slope of the 2nd segment */
};

struct runtime_sc {
	u64	x;	/* current starting position on x-axis */
	u64	y;	/* current starting position on y-axis */
	u64	sm1;	/* scaled slope of the 1st segment */
	u64	ism1;	/* scaled inverse-slope of the 1st segment */
	u64	dx;	/* the x-projection of the 1st segment */
	u64	dy;	/* the y-projection of the 1st segment */
	u64	sm2;	/* scaled slope of the 2nd segment */
	u64	ism2;	/* scaled inverse-slope of the 2nd segment */
};

enum hfsc_class_flags {
	HFSC_RSC = 0x1,
	HFSC_FSC = 0x2,
	HFSC_USC = 0x4
};

struct hfsc_class {
	struct Qdisc_class_common cl_common;

	struct gnet_stats_basic_packed bstats;
	struct gnet_stats_queue qstats;
	struct net_rate_estimator __rcu *rate_est;
	struct tcf_proto __rcu *filter_list; /* filter list */
	struct tcf_block *block;
	unsigned int	filter_cnt;	/* filter count */
	unsigned int	level;		/* class level in hierarchy */

	struct hfsc_sched *sched;	/* scheduler data */
	struct hfsc_class *cl_parent;	/* parent class */
	struct list_head siblings;	/* sibling classes */
	struct list_head children;	/* child classes */
	struct Qdisc	*qdisc;		/* leaf qdisc */

	struct rb_node el_node;		/* qdisc's eligible tree member */
	struct rb_root vt_tree;		/* active children sorted by cl_vt */
	struct rb_node vt_node;		/* parent's vt_tree member */
	struct rb_root cf_tree;		/* active children sorted by cl_f */
	struct rb_node cf_node;		/* parent's cf_heap member */

	u64	cl_total;		/* total work in bytes */
	u64	cl_cumul;		/* cumulative work in bytes done by
					   real-time criteria */

	u64	cl_d;			/* deadline*/
	u64	cl_e;			/* eligible time */
	u64	cl_vt;			/* virtual time */
	u64	cl_f;			/* time when this class will fit for
					   link-sharing, max(myf, cfmin) */
	u64	cl_myf;			/* my fit-time (calculated from this
					   class's own upperlimit curve) */
	u64	cl_cfmin;		/* earliest children's fit-time (used
					   with cl_myf to obtain cl_f) */
	u64	cl_cvtmin;		/* minimal virtual time among the
					   children fit for link-sharing
					   (monotonic within a period) */
	u64	cl_vtadj;		/* intra-period cumulative vt
					   adjustment */
	u64	cl_cvtoff;		/* largest virtual time seen among
					   the children */

	struct internal_sc cl_rsc;	/* internal real-time service curve */
	struct internal_sc cl_fsc;	/* internal fair service curve */
	struct internal_sc cl_usc;	/* internal upperlimit service curve */
	struct runtime_sc cl_deadline;	/* deadline curve */
	struct runtime_sc cl_eligible;	/* eligible curve */
	struct runtime_sc cl_virtual;	/* virtual curve */
	struct runtime_sc cl_ulimit;	/* upperlimit curve */

	u8		cl_flags;	/* which curves are valid */
	u32		cl_vtperiod;	/* vt period sequence number */
	u32		cl_parentperiod;/* parent's vt period sequence number*/
	u32		cl_nactive;	/* number of active children */
};

struct hfsc_sched {
	u16	defcls;				/* default class id */
	struct hfsc_class root;			/* root class */
	struct Qdisc_class_hash clhash;		/* class hash */
	struct rb_root eligible;		/* eligible tree */
	struct qdisc_watchdog watchdog;		/* watchdog timer */
};

static void
(*klpe_eltree_insert)(struct hfsc_class *cl);

static inline void
klpp_eltree_remove(struct hfsc_class *cl)
{
	if (!RB_EMPTY_NODE(&cl->el_node)) {
		rb_erase(&cl->el_node, &cl->sched->eligible);
		RB_CLEAR_NODE(&cl->el_node);
	}
}

static inline void
klpp_eltree_update(struct hfsc_class *cl)
{
	klpp_eltree_remove(cl);
	(*klpe_eltree_insert)(cl);
}

static inline struct hfsc_class *
eltree_get_mindl(struct hfsc_sched *q, u64 cur_time)
{
	struct hfsc_class *p, *cl = NULL;
	struct rb_node *n;

	for (n = rb_first(&q->eligible); n != NULL; n = rb_next(n)) {
		p = rb_entry(n, struct hfsc_class, el_node);
		if (p->cl_e > cur_time)
			break;
		if (cl == NULL || p->cl_d < cl->cl_d)
			cl = p;
	}
	return cl;
}

static inline struct hfsc_class *
eltree_get_minel(struct hfsc_sched *q)
{
	struct rb_node *n;

	n = rb_first(&q->eligible);
	if (n == NULL)
		return NULL;
	return rb_entry(n, struct hfsc_class, el_node);
}

static void
(*klpe_vttree_insert)(struct hfsc_class *cl);

static inline void
vttree_remove(struct hfsc_class *cl)
{
	rb_erase(&cl->vt_node, &cl->cl_parent->vt_tree);
}

static inline void
klpr_vttree_update(struct hfsc_class *cl)
{
	vttree_remove(cl);
	(*klpe_vttree_insert)(cl);
}

static inline struct hfsc_class *
vttree_firstfit(struct hfsc_class *cl, u64 cur_time)
{
	struct hfsc_class *p;
	struct rb_node *n;

	for (n = rb_first(&cl->vt_tree); n != NULL; n = rb_next(n)) {
		p = rb_entry(n, struct hfsc_class, vt_node);
		if (p->cl_f <= cur_time)
			return p;
	}
	return NULL;
}

static struct hfsc_class *
vttree_get_minvt(struct hfsc_class *cl, u64 cur_time)
{
	/* if root-class's cfmin is bigger than cur_time nothing to do */
	if (cl->cl_cfmin > cur_time)
		return NULL;

	while (cl->level > 0) {
		cl = vttree_firstfit(cl, cur_time);
		if (cl == NULL)
			return NULL;
		/*
		 * update parent's cl_cvtmin.
		 */
		if (cl->cl_parent->cl_cvtmin < cl->cl_vt)
			cl->cl_parent->cl_cvtmin = cl->cl_vt;
	}
	return cl;
}

static void
(*klpe_cftree_insert)(struct hfsc_class *cl);

static inline void
cftree_remove(struct hfsc_class *cl)
{
	rb_erase(&cl->cf_node, &cl->cl_parent->cf_tree);
}

static inline void
klpr_cftree_update(struct hfsc_class *cl)
{
	cftree_remove(cl);
	(*klpe_cftree_insert)(cl);
}

static u64
(*klpe_rtsc_y2x)(struct runtime_sc *rtsc, u64 y);

void
klpp_update_ed(struct hfsc_class *cl, unsigned int next_len)
{
	cl->cl_e = (*klpe_rtsc_y2x)(&cl->cl_eligible, cl->cl_cumul);
	cl->cl_d = (*klpe_rtsc_y2x)(&cl->cl_deadline, cl->cl_cumul + next_len);

	klpp_eltree_update(cl);
}

static inline void
klpr_update_d(struct hfsc_class *cl, unsigned int next_len)
{
	cl->cl_d = (*klpe_rtsc_y2x)(&cl->cl_deadline, cl->cl_cumul + next_len);
}

static inline void
update_cfmin(struct hfsc_class *cl)
{
	struct rb_node *n = rb_first(&cl->cf_tree);
	struct hfsc_class *p;

	if (n == NULL) {
		cl->cl_cfmin = 0;
		return;
	}
	p = rb_entry(n, struct hfsc_class, cf_node);
	cl->cl_cfmin = p->cl_f;
}

static void
klpr_update_vf(struct hfsc_class *cl, unsigned int len, u64 cur_time)
{
	u64 f; /* , myf_bound, delta; */
	int go_passive = 0;

	if (cl->qdisc->q.qlen == 0 && cl->cl_flags & HFSC_FSC)
		go_passive = 1;

	for (; cl->cl_parent != NULL; cl = cl->cl_parent) {
		cl->cl_total += len;

		if (!(cl->cl_flags & HFSC_FSC) || cl->cl_nactive == 0)
			continue;

		if (go_passive && --cl->cl_nactive == 0)
			go_passive = 1;
		else
			go_passive = 0;

		/* update vt */
		cl->cl_vt = (*klpe_rtsc_y2x)(&cl->cl_virtual, cl->cl_total) + cl->cl_vtadj;

		/*
		 * if vt of the class is smaller than cvtmin,
		 * the class was skipped in the past due to non-fit.
		 * if so, we need to adjust vtadj.
		 */
		if (cl->cl_vt < cl->cl_parent->cl_cvtmin) {
			cl->cl_vtadj += cl->cl_parent->cl_cvtmin - cl->cl_vt;
			cl->cl_vt = cl->cl_parent->cl_cvtmin;
		}

		if (go_passive) {
			/* no more active child, going passive */

			/* update cvtoff of the parent class */
			if (cl->cl_vt > cl->cl_parent->cl_cvtoff)
				cl->cl_parent->cl_cvtoff = cl->cl_vt;

			/* remove this class from the vt tree */
			vttree_remove(cl);

			cftree_remove(cl);
			update_cfmin(cl->cl_parent);

			continue;
		}

		/* update the vt tree */
		klpr_vttree_update(cl);

		/* update f */
		if (cl->cl_flags & HFSC_USC) {
			cl->cl_myf = (*klpe_rtsc_y2x)(&cl->cl_ulimit, cl->cl_total);
#if 0
#error "klp-ccp: non-taken branch"
#endif
		}

		f = max(cl->cl_myf, cl->cl_cfmin);
		if (f != cl->cl_f) {
			cl->cl_f = f;
			klpr_cftree_update(cl);
			update_cfmin(cl->cl_parent);
		}
	}
}

static unsigned int
(*klpe_qdisc_peek_len)(struct Qdisc *sch);

void
klpp_hfsc_qlen_notify(struct Qdisc *sch, unsigned long arg)
{
	struct hfsc_class *cl = (struct hfsc_class *)arg;

	/* vttree is now handled in update_vf() so that update_vf(cl, 0, 0)
	 * needs to be called explicitly to remove a class from vttree.
	 */
	if (cl->cl_nactive)
		klpr_update_vf(cl, 0, 0);
	if (cl->cl_flags & HFSC_RSC)
		klpp_eltree_remove(cl);
}

static void
hfsc_schedule_watchdog(struct Qdisc *sch)
{
	struct hfsc_sched *q = qdisc_priv(sch);
	struct hfsc_class *cl;
	u64 next_time = 0;

	cl = eltree_get_minel(q);
	if (cl)
		next_time = cl->cl_e;
	if (q->root.cl_cfmin != 0) {
		if (next_time == 0 || next_time > q->root.cl_cfmin)
			next_time = q->root.cl_cfmin;
	}
	if (next_time)
		qdisc_watchdog_schedule(&q->watchdog, next_time);
}

struct sk_buff *
klpp_hfsc_dequeue(struct Qdisc *sch)
{
	struct hfsc_sched *q = qdisc_priv(sch);
	struct hfsc_class *cl;
	struct sk_buff *skb;
	u64 cur_time;
	unsigned int next_len;
	int realtime = 0;

	if (sch->q.qlen == 0)
		return NULL;

	cur_time = psched_get_time();

	/*
	 * if there are eligible classes, use real-time criteria.
	 * find the class with the minimum deadline among
	 * the eligible classes.
	 */
	cl = eltree_get_mindl(q, cur_time);
	if (cl) {
		realtime = 1;
	} else {
		/*
		 * use link-sharing criteria
		 * get the class with the minimum vt in the hierarchy
		 */
		cl = vttree_get_minvt(&q->root, cur_time);
		if (cl == NULL) {
			qdisc_qstats_overlimit(sch);
			hfsc_schedule_watchdog(sch);
			return NULL;
		}
	}

	skb = qdisc_dequeue_peeked(cl->qdisc);
	if (skb == NULL) {
		qdisc_warn_nonwc("HFSC", cl->qdisc);
		return NULL;
	}

	bstats_update(&cl->bstats, skb);
	klpr_update_vf(cl, qdisc_pkt_len(skb), cur_time);
	if (realtime)
		cl->cl_cumul += qdisc_pkt_len(skb);

	if (cl->cl_flags & HFSC_RSC) {
		if (cl->qdisc->q.qlen != 0) {
			/* update ed */
			next_len = (*klpe_qdisc_peek_len)(cl->qdisc);
			if (realtime)
				klpp_update_ed(cl, next_len);
			else
				klpr_update_d(cl, next_len);
		} else {
			/* the class becomes passive */
			klpp_eltree_remove(cl);
		}
	}

	qdisc_bstats_update(sch, skb);
	qdisc_qstats_backlog_dec(sch, skb);
	sch->q.qlen--;

	return skb;
}


#include "livepatch_bsc1246356.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sch_hfsc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cftree_insert", (void *)&klpe_cftree_insert, "sch_hfsc" },
	{ "eltree_insert", (void *)&klpe_eltree_insert, "sch_hfsc" },
	{ "qdisc_peek_len", (void *)&klpe_qdisc_peek_len, "sch_hfsc" },
	{ "rtsc_y2x", (void *)&klpe_rtsc_y2x, "sch_hfsc" },
	{ "vttree_insert", (void *)&klpe_vttree_insert, "sch_hfsc" },
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

int livepatch_bsc1246356_init(void)
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

void livepatch_bsc1246356_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
