/*
 * livepatch_bsc1207188
 *
 * Fix for CVE-2023-23454, bsc#1207188
 *
 *  Upstream commit:
 *  caa4b35b4317 ("net: sched: cbq: dont intepret cls results when asked to
 *                 drop")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  fcfa3870b4ceed301268a92e43e10fac7514c574
 *
 *  SLE15-SP2 and -SP3 commit:
 *  0726009d20ee6b54d15b8053994a8bfc27160a54
 *
 *  SLE15-SP4 commit:
 *  6b9dae79c766df51df013bd89a2ae087f17e0a90
 *
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_NET_SCH_CBQ)
#error "Live patch supports only CONFIG_NET_SCH_CBQ=m"
#endif

/* klp-ccp: from net/sched/sch_cbq.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct cbq_class {
	struct Qdisc_class_common common;
	struct cbq_class	*next_alive;	/* next class with backlog in this priority band */

/* Parameters */
	unsigned char		priority;	/* class priority */
	unsigned char		priority2;	/* priority to be used after overlimit */
	unsigned char		ewma_log;	/* time constant for idle time calculation */

	u32			defmap;

	/* Link-sharing scheduler parameters */
	long			maxidle;	/* Class parameters: see below. */
	long			offtime;
	long			minidle;
	u32			avpkt;
	struct qdisc_rate_table	*R_tab;

	/* General scheduler (WRR) parameters */
	long			allot;
	long			quantum;	/* Allotment per WRR round */
	long			weight;		/* Relative allotment: see below */

	struct Qdisc		*qdisc;		/* Ptr to CBQ discipline */
	struct cbq_class	*split;		/* Ptr to split node */
	struct cbq_class	*share;		/* Ptr to LS parent in the class tree */
	struct cbq_class	*tparent;	/* Ptr to tree parent in the class tree */
	struct cbq_class	*borrow;	/* NULL if class is bandwidth limited;
						   parent otherwise */
	struct cbq_class	*sibling;	/* Sibling chain */
	struct cbq_class	*children;	/* Pointer to children chain */

	struct Qdisc		*q;		/* Elementary queueing discipline */


/* Variables */
	unsigned char		cpriority;	/* Effective priority */
	unsigned char		delayed;
	unsigned char		level;		/* level of the class in hierarchy:
						   0 for leaf classes, and maximal
						   level of children + 1 for nodes.
						 */

	psched_time_t		last;		/* Last end of service */
	psched_time_t		undertime;
	long			avgidle;
	long			deficit;	/* Saved deficit for WRR */
	psched_time_t		penalized;
	struct gnet_stats_basic_packed bstats;
	struct gnet_stats_queue qstats;
	struct net_rate_estimator __rcu *rate_est;
	struct tc_cbq_xstats	xstats;

	struct tcf_proto __rcu	*filter_list;
	struct tcf_block	*block;

	int			filters;

	struct cbq_class	*defaults[TC_PRIO_MAX + 1];
};

struct cbq_sched_data {
	struct Qdisc_class_hash	clhash;			/* Hash table of all classes */
	int			nclasses[TC_CBQ_MAXPRIO + 1];
	unsigned int		quanta[TC_CBQ_MAXPRIO + 1];

	struct cbq_class	link;

	unsigned int		activemask;
	struct cbq_class	*active[TC_CBQ_MAXPRIO + 1];	/* List of all classes
								   with backlog */

#ifdef CONFIG_NET_CLS_ACT
	struct cbq_class	*rx_class;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct cbq_class	*tx_class;
	struct cbq_class	*tx_borrowed;
	int			tx_len;
	psched_time_t		now;		/* Cached timestamp */
	unsigned int		pmask;

	struct hrtimer		delay_timer;
	struct qdisc_watchdog	watchdog;	/* Watchdog timer,
						   started when CBQ has
						   backlog, but cannot
						   transmit just now */
	psched_tdiff_t		wd_expires;
	int			toplevel;
	u32			hgenerator;
};

static inline struct cbq_class *
cbq_class_lookup(struct cbq_sched_data *q, u32 classid)
{
	struct Qdisc_class_common *clc;

	clc = qdisc_class_find(&q->clhash, classid);
	if (clc == NULL)
		return NULL;
	return container_of(clc, struct cbq_class, common);
}

#ifdef CONFIG_NET_CLS_ACT

static struct cbq_class *
cbq_reclassify(struct sk_buff *skb, struct cbq_class *this)
{
	struct cbq_class *cl;

	for (cl = this->tparent; cl; cl = cl->tparent) {
		struct cbq_class *new = cl->defaults[TC_PRIO_BESTEFFORT];

		if (new != NULL && new != this)
			return new;
	}
	return NULL;
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static struct cbq_class *
klpp_cbq_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct cbq_sched_data *q = qdisc_priv(sch);
	struct cbq_class *head = &q->link;
	struct cbq_class **defmap;
	struct cbq_class *cl = NULL;
	u32 prio = skb->priority;
	struct tcf_proto *fl;
	struct tcf_result res;

	/*
	 *  Step 1. If skb->priority points to one of our classes, use it.
	 */
	if (TC_H_MAJ(prio ^ sch->handle) == 0 &&
	    (cl = cbq_class_lookup(q, prio)) != NULL)
		return cl;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	for (;;) {
		int result = 0;
		defmap = head->defaults;

		fl = rcu_dereference_bh(head->filter_list);
		/*
		 * Step 2+n. Apply classifier.
		 */
		result = tcf_classify(skb, fl, &res, true);
		if (!fl || result < 0)
			goto fallback;

		/*
		 * Fix CVE-2023-23454
		 *  +2 lines
		 */
		if (result == TC_ACT_SHOT)
			return NULL;

		cl = (void *)res.class;
		if (!cl) {
			if (TC_H_MAJ(res.classid))
				cl = cbq_class_lookup(q, res.classid);
			else if ((cl = defmap[res.classid & TC_PRIO_MAX]) == NULL)
				cl = defmap[TC_PRIO_BESTEFFORT];

			if (cl == NULL)
				goto fallback;
		}
		if (cl->level >= head->level)
			goto fallback;
#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			/*
			 * Fix CVE-2023-23454
			 *  -2 lines
			 */
			return NULL;
		case TC_ACT_RECLASSIFY:
			return cbq_reclassify(skb, cl);
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (cl->level == 0)
			return cl;

		/*
		 * Step 3+n. If classifier selected a link sharing class,
		 *	   apply agency specific classifier.
		 *	   Repeat this procdure until we hit a leaf node.
		 */
		head = cl;
	}

fallback:
	cl = head;

	/*
	 * Step 4. No success...
	 */
	if (TC_H_MAJ(prio) == 0 &&
	    !(cl = head->defaults[prio & TC_PRIO_MAX]) &&
	    !(cl = head->defaults[TC_PRIO_BESTEFFORT]))
		return head;

	return cl;
}

static inline void cbq_activate_class(struct cbq_class *cl)
{
	struct cbq_sched_data *q = qdisc_priv(cl->qdisc);
	int prio = cl->cpriority;
	struct cbq_class *cl_tail;

	cl_tail = q->active[prio];
	q->active[prio] = cl;

	if (cl_tail != NULL) {
		cl->next_alive = cl_tail->next_alive;
		cl_tail->next_alive = cl;
	} else {
		cl->next_alive = cl;
		q->activemask |= (1<<prio);
	}
}

static void
cbq_mark_toplevel(struct cbq_sched_data *q, struct cbq_class *cl)
{
	int toplevel = q->toplevel;

	if (toplevel > cl->level) {
		psched_time_t now = psched_get_time();

		do {
			if (cl->undertime < now) {
				q->toplevel = cl->level;
				return;
			}
		} while ((cl = cl->borrow) != NULL && toplevel > cl->level);
	}
}

int
klpp_cbq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
	    struct sk_buff **to_free)
{
	struct cbq_sched_data *q = qdisc_priv(sch);
	int uninitialized_var(ret);
	struct cbq_class *cl = klpp_cbq_classify(skb, sch, &ret);

#ifdef CONFIG_NET_CLS_ACT
	q->rx_class = cl;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (cl == NULL) {
		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return ret;
	}

	ret = qdisc_enqueue(skb, cl->q, to_free);
	if (ret == NET_XMIT_SUCCESS) {
		sch->q.qlen++;
		cbq_mark_toplevel(q, cl);
		if (!cl->next_alive)
			cbq_activate_class(cl);
		return ret;
	}

	if (net_xmit_drop_count(ret)) {
		qdisc_qstats_drop(sch);
		cbq_mark_toplevel(q, cl);
		cl->qstats.drops++;
	}
	return ret;
}



#include <linux/types.h>
#include "livepatch_bsc1207188.h"
