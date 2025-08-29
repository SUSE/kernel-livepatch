/*
 * livepatch_bsc1245791
 *
 * Fix for CVE-2025-37890, bsc#1245791
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
#include <net/pkt_cls.h>
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

	struct gnet_stats_basic_sync bstats;
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

extern void
vttree_insert(struct hfsc_class *cl);

extern void
cftree_insert(struct hfsc_class *cl);

static inline void
cftree_remove(struct hfsc_class *cl)
{
	rb_erase(&cl->cf_node, &cl->cl_parent->cf_tree);
}

static inline void
cftree_update(struct hfsc_class *cl)
{
	cftree_remove(cl);
	cftree_insert(cl);
}

extern u64
rtsc_y2x(struct runtime_sc *rtsc, u64 y);

extern void
rtsc_min(struct runtime_sc *rtsc, struct internal_sc *isc, u64 x, u64 y);

extern void
init_ed(struct hfsc_class *cl, unsigned int next_len);

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
init_vf(struct hfsc_class *cl, unsigned int len)
{
	struct hfsc_class *max_cl;
	struct rb_node *n;
	u64 vt, f, cur_time;
	int go_active;

	cur_time = 0;
	go_active = 1;
	for (; cl->cl_parent != NULL; cl = cl->cl_parent) {
		if (go_active && cl->cl_nactive++ == 0)
			go_active = 1;
		else
			go_active = 0;

		if (go_active) {
			n = rb_last(&cl->cl_parent->vt_tree);
			if (n != NULL) {
				max_cl = rb_entry(n, struct hfsc_class, vt_node);
				/*
				 * set vt to the average of the min and max
				 * classes.  if the parent's period didn't
				 * change, don't decrease vt of the class.
				 */
				vt = max_cl->cl_vt;
				if (cl->cl_parent->cl_cvtmin != 0)
					vt = (cl->cl_parent->cl_cvtmin + vt)/2;

				if (cl->cl_parent->cl_vtperiod !=
				    cl->cl_parentperiod || vt > cl->cl_vt)
					cl->cl_vt = vt;
			} else {
				/*
				 * first child for a new parent backlog period.
				 * initialize cl_vt to the highest value seen
				 * among the siblings. this is analogous to
				 * what cur_time would provide in realtime case.
				 */
				cl->cl_vt = cl->cl_parent->cl_cvtoff;
				cl->cl_parent->cl_cvtmin = 0;
			}

			/* update the virtual curve */
			rtsc_min(&cl->cl_virtual, &cl->cl_fsc, cl->cl_vt, cl->cl_total);
			cl->cl_vtadj = 0;

			cl->cl_vtperiod++;  /* increment vt period */
			cl->cl_parentperiod = cl->cl_parent->cl_vtperiod;
			if (cl->cl_parent->cl_nactive == 0)
				cl->cl_parentperiod++;
			cl->cl_f = 0;

			vttree_insert(cl);
			cftree_insert(cl);

			if (cl->cl_flags & HFSC_USC) {
				/* class has upper limit curve */
				if (cur_time == 0)
					cur_time = psched_get_time();

				/* update the ulimit curve */
				rtsc_min(&cl->cl_ulimit, &cl->cl_usc, cur_time,
					 cl->cl_total);
				/* compute myf */
				cl->cl_myf = rtsc_y2x(&cl->cl_ulimit,
						      cl->cl_total);
			}
		}

		f = max(cl->cl_myf, cl->cl_cfmin);
		if (f != cl->cl_f) {
			cl->cl_f = f;
			cftree_update(cl);
		}
		update_cfmin(cl->cl_parent);
	}
}

static inline struct hfsc_class *
hfsc_find_class(u32 classid, struct Qdisc *sch)
{
	struct hfsc_sched *q = qdisc_priv(sch);
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, classid);
	if (clc == NULL)
		return NULL;
	return container_of(clc, struct hfsc_class, cl_common);
}

static struct hfsc_class *
hfsc_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct hfsc_sched *q = qdisc_priv(sch);
	struct hfsc_class *head, *cl;
	struct tcf_result res;
	struct tcf_proto *tcf;
	int result;

	if (TC_H_MAJ(skb->priority ^ sch->handle) == 0 &&
	    (cl = hfsc_find_class(skb->priority, sch)) != NULL)
		if (cl->level == 0)
			return cl;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	head = &q->root;
	tcf = rcu_dereference_bh(q->root.filter_list);
	while (tcf && (result = tcf_classify(skb, NULL, tcf, &res, false)) >= 0) {
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			fallthrough;
		case TC_ACT_SHOT:
			return NULL;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		cl = (struct hfsc_class *)res.class;
		if (!cl) {
			cl = hfsc_find_class(res.classid, sch);
			if (!cl)
				break; /* filter selected invalid classid */
			if (cl->level >= head->level)
				break; /* filter may only point downwards */
		}

		if (cl->level == 0)
			return cl; /* hit leaf class */

		/* apply inner filter chain */
		tcf = rcu_dereference_bh(cl->filter_list);
		head = cl;
	}

	/* classification failed, try default class */
	cl = hfsc_find_class(TC_H_MAKE(TC_H_MAJ(sch->handle), q->defcls), sch);
	if (cl == NULL || cl->level > 0)
		return NULL;

	return cl;
}

static bool cl_in_el_or_vttree(struct hfsc_class *cl)
{
   return ((cl->cl_flags & HFSC_FSC) && cl->cl_nactive) ||
       ((cl->cl_flags & HFSC_RSC) && !RB_EMPTY_NODE(&cl->el_node));
}

int
klpp_hfsc_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free)
{
	unsigned int len = qdisc_pkt_len(skb);
	struct hfsc_class *cl;
	int err;
	bool first;

	cl = hfsc_classify(skb, sch, &err);
	if (cl == NULL) {
		if (err & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return err;
	}

	first = !cl->qdisc->q.qlen;
	err = qdisc_enqueue(skb, cl->qdisc, to_free);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}

	if (first && !cl_in_el_or_vttree(cl)) {
		if (cl->cl_flags & HFSC_RSC)
			init_ed(cl, len);
		if (cl->cl_flags & HFSC_FSC)
			init_vf(cl, len);
		/*
		 * If this is the first packet, isolate the head so an eventual
		 * head drop before the first dequeue operation has no chance
		 * to invalidate the deadline.
		 */
		if (cl->cl_flags & HFSC_RSC)
			cl->qdisc->ops->peek(cl->qdisc);

	}

	sch->qstats.backlog += len;
	sch->q.qlen++;

	return NET_XMIT_SUCCESS;
}


#include "livepatch_bsc1245791.h"

#include <linux/livepatch.h>

extern typeof(cftree_insert) cftree_insert
	 KLP_RELOC_SYMBOL(sch_hfsc, sch_hfsc, cftree_insert);
extern typeof(init_ed) init_ed KLP_RELOC_SYMBOL(sch_hfsc, sch_hfsc, init_ed);
extern typeof(rtsc_min) rtsc_min KLP_RELOC_SYMBOL(sch_hfsc, sch_hfsc, rtsc_min);
extern typeof(rtsc_y2x) rtsc_y2x KLP_RELOC_SYMBOL(sch_hfsc, sch_hfsc, rtsc_y2x);
extern typeof(vttree_insert) vttree_insert
	 KLP_RELOC_SYMBOL(sch_hfsc, sch_hfsc, vttree_insert);
