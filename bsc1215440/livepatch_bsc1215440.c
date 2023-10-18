/*
 * livepatch_bsc1215440
 *
 * Fix for CVE-2023-4623, bsc#1215440
 *
 *  Upstream commit:
 *  b3d26c5702c7 ("net/sched: sch_hfsc: Ensure inner classes have fsc curve")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  522fe97f80d9362ff1f89f3428cb1cb7a0925274
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  72e753f41985551ddde9f8a3d856b7f044676ef6
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_NET_SCH_HFSC)

#if !IS_MODULE(CONFIG_NET_SCH_HFSC)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/sched/sch_hfsc.c */
#include <linux/kernel.h>

/* klp-ccp: from net/sched/sch_hfsc.c */
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

static void
(*klpe_sc2isc)(struct tc_service_curve *sc, struct internal_sc *isc);

static void
rtsc_init(struct runtime_sc *rtsc, struct internal_sc *isc, u64 x, u64 y)
{
	rtsc->x	   = x;
	rtsc->y    = y;
	rtsc->sm1  = isc->sm1;
	rtsc->ism1 = isc->ism1;
	rtsc->dx   = isc->dx;
	rtsc->dy   = isc->dy;
	rtsc->sm2  = isc->sm2;
	rtsc->ism2 = isc->ism2;
}

static u64
(*klpe_rtsc_y2x)(struct runtime_sc *rtsc, u64 y);

static void
(*klpe_rtsc_min)(struct runtime_sc *rtsc, struct internal_sc *isc, u64 x, u64 y);

static void
(*klpe_init_ed)(struct hfsc_class *cl, unsigned int next_len);

static void
(*klpe_update_ed)(struct hfsc_class *cl, unsigned int next_len);

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
klpr_init_vf(struct hfsc_class *cl, unsigned int len)
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
			(*klpe_rtsc_min)(&cl->cl_virtual, &cl->cl_fsc, cl->cl_vt, cl->cl_total);
			cl->cl_vtadj = 0;

			cl->cl_vtperiod++;  /* increment vt period */
			cl->cl_parentperiod = cl->cl_parent->cl_vtperiod;
			if (cl->cl_parent->cl_nactive == 0)
				cl->cl_parentperiod++;
			cl->cl_f = 0;

			(*klpe_vttree_insert)(cl);
			(*klpe_cftree_insert)(cl);

			if (cl->cl_flags & HFSC_USC) {
				/* class has upper limit curve */
				if (cur_time == 0)
					cur_time = psched_get_time();

				/* update the ulimit curve */
				(*klpe_rtsc_min)(&cl->cl_ulimit, &cl->cl_usc, cur_time,
					 cl->cl_total);
				/* compute myf */
				cl->cl_myf = (*klpe_rtsc_y2x)(&cl->cl_ulimit,
						      cl->cl_total);
			}
		}

		f = max(cl->cl_myf, cl->cl_cfmin);
		if (f != cl->cl_f) {
			cl->cl_f = f;
			klpr_cftree_update(cl);
		}
		update_cfmin(cl->cl_parent);
	}
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

static void
hfsc_adjust_levels(struct hfsc_class *cl)
{
	struct hfsc_class *p;
	unsigned int level;

	do {
		level = 0;
		list_for_each_entry(p, &cl->children, siblings) {
			if (p->level >= level)
				level = p->level + 1;
		}
		cl->level = level;
	} while ((cl = cl->cl_parent) != NULL);
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

static void
klpr_hfsc_change_rsc(struct hfsc_class *cl, struct tc_service_curve *rsc,
		u64 cur_time)
{
	(*klpe_sc2isc)(rsc, &cl->cl_rsc);
	rtsc_init(&cl->cl_deadline, &cl->cl_rsc, cur_time, cl->cl_cumul);
	cl->cl_eligible = cl->cl_deadline;
	if (cl->cl_rsc.sm1 <= cl->cl_rsc.sm2) {
		cl->cl_eligible.dx = 0;
		cl->cl_eligible.dy = 0;
	}
	cl->cl_flags |= HFSC_RSC;
}

static void
klpr_hfsc_change_fsc(struct hfsc_class *cl, struct tc_service_curve *fsc)
{
	(*klpe_sc2isc)(fsc, &cl->cl_fsc);
	rtsc_init(&cl->cl_virtual, &cl->cl_fsc, cl->cl_vt, cl->cl_total);
	cl->cl_flags |= HFSC_FSC;
}

static void
klpr_hfsc_change_usc(struct hfsc_class *cl, struct tc_service_curve *usc,
		u64 cur_time)
{
	(*klpe_sc2isc)(usc, &cl->cl_usc);
	rtsc_init(&cl->cl_ulimit, &cl->cl_usc, cur_time, cl->cl_total);
	cl->cl_flags |= HFSC_USC;
}

static const struct nla_policy (*klpe_hfsc_policy)[TCA_HFSC_MAX + 1];

int
klpp_hfsc_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
		  struct nlattr **tca, unsigned long *arg,
		  struct netlink_ext_ack *extack)
{
	struct hfsc_sched *q = qdisc_priv(sch);
	struct hfsc_class *cl = (struct hfsc_class *)*arg;
	struct hfsc_class *parent = NULL;
	struct nlattr *opt = tca[TCA_OPTIONS];
	struct nlattr *tb[TCA_HFSC_MAX + 1];
	struct tc_service_curve *rsc = NULL, *fsc = NULL, *usc = NULL;
	u64 cur_time;
	int err;

	if (opt == NULL)
		return -EINVAL;

	err = nla_parse_nested_deprecated(tb, TCA_HFSC_MAX, opt, (*klpe_hfsc_policy),
					  NULL);
	if (err < 0)
		return err;

	if (tb[TCA_HFSC_RSC]) {
		rsc = nla_data(tb[TCA_HFSC_RSC]);
		if (rsc->m1 == 0 && rsc->m2 == 0)
			rsc = NULL;
	}

	if (tb[TCA_HFSC_FSC]) {
		fsc = nla_data(tb[TCA_HFSC_FSC]);
		if (fsc->m1 == 0 && fsc->m2 == 0)
			fsc = NULL;
	}

	if (tb[TCA_HFSC_USC]) {
		usc = nla_data(tb[TCA_HFSC_USC]);
		if (usc->m1 == 0 && usc->m2 == 0)
			usc = NULL;
	}

	if (cl != NULL) {
		int old_flags;

		if (parentid) {
			if (cl->cl_parent &&
			    cl->cl_parent->cl_common.classid != parentid)
				return -EINVAL;
			if (cl->cl_parent == NULL && parentid != TC_H_ROOT)
				return -EINVAL;
		}
		cur_time = psched_get_time();

		if (tca[TCA_RATE]) {
			err = gen_replace_estimator(&cl->bstats, NULL,
						    &cl->rate_est,
						    NULL,
						    true,
						    tca[TCA_RATE]);
			if (err)
				return err;
		}

		sch_tree_lock(sch);
		old_flags = cl->cl_flags;

		if (rsc != NULL)
			klpr_hfsc_change_rsc(cl, rsc, cur_time);
		if (fsc != NULL)
			klpr_hfsc_change_fsc(cl, fsc);
		if (usc != NULL)
			klpr_hfsc_change_usc(cl, usc, cur_time);

		if (cl->qdisc->q.qlen != 0) {
			int len = (*klpe_qdisc_peek_len)(cl->qdisc);

			if (cl->cl_flags & HFSC_RSC) {
				if (old_flags & HFSC_RSC)
					(*klpe_update_ed)(cl, len);
				else
					(*klpe_init_ed)(cl, len);
			}

			if (cl->cl_flags & HFSC_FSC) {
				if (old_flags & HFSC_FSC)
					klpr_update_vf(cl, 0, cur_time);
				else
					klpr_init_vf(cl, len);
			}
		}
		sch_tree_unlock(sch);

		return 0;
	}

	if (parentid == TC_H_ROOT)
		return -EEXIST;

	parent = &q->root;
	if (parentid) {
		parent = hfsc_find_class(parentid, sch);
		if (parent == NULL)
			return -ENOENT;
	}

	if (!(parent->cl_flags & HFSC_FSC) && parent != &q->root) {
		NL_SET_ERR_MSG(extack, "Invalid parent - parent class must have FSC");
		return -EINVAL;
	}

	if (classid == 0 || TC_H_MAJ(classid ^ sch->handle) != 0)
		return -EINVAL;
	if (hfsc_find_class(classid, sch))
		return -EEXIST;

	if (rsc == NULL && fsc == NULL)
		return -EINVAL;

	cl = kzalloc(sizeof(struct hfsc_class), GFP_KERNEL);
	if (cl == NULL)
		return -ENOBUFS;

	err = tcf_block_get(&cl->block, &cl->filter_list, sch, extack);
	if (err) {
		kfree(cl);
		return err;
	}

	if (tca[TCA_RATE]) {
		err = gen_new_estimator(&cl->bstats, NULL, &cl->rate_est,
					NULL, true, tca[TCA_RATE]);
		if (err) {
			tcf_block_put(cl->block);
			kfree(cl);
			return err;
		}
	}

	if (rsc != NULL)
		klpr_hfsc_change_rsc(cl, rsc, 0);
	if (fsc != NULL)
		klpr_hfsc_change_fsc(cl, fsc);
	if (usc != NULL)
		klpr_hfsc_change_usc(cl, usc, 0);

	cl->cl_common.classid = classid;
	cl->sched     = q;
	cl->cl_parent = parent;
	cl->qdisc = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
				      classid, NULL);
	if (cl->qdisc == NULL)
		cl->qdisc = &noop_qdisc;
	else
		qdisc_hash_add(cl->qdisc, true);
	INIT_LIST_HEAD(&cl->children);
	cl->vt_tree = RB_ROOT;
	cl->cf_tree = RB_ROOT;

	sch_tree_lock(sch);
	qdisc_class_hash_insert(&q->clhash, &cl->cl_common);
	list_add_tail(&cl->siblings, &parent->children);
	if (parent->level == 0)
		qdisc_purge_queue(parent->qdisc);
	hfsc_adjust_levels(parent);
	sch_tree_unlock(sch);

	qdisc_class_hash_grow(sch, &q->clhash);

	*arg = (unsigned long)cl;
	return 0;
}


#include "livepatch_bsc1215440.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sch_hfsc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "cftree_insert", (void *)&klpe_cftree_insert, "sch_hfsc" },
	{ "hfsc_policy", (void *)&klpe_hfsc_policy, "sch_hfsc" },
	{ "init_ed", (void *)&klpe_init_ed, "sch_hfsc" },
	{ "qdisc_peek_len", (void *)&klpe_qdisc_peek_len, "sch_hfsc" },
	{ "rtsc_min", (void *)&klpe_rtsc_min, "sch_hfsc" },
	{ "rtsc_y2x", (void *)&klpe_rtsc_y2x, "sch_hfsc" },
	{ "sc2isc", (void *)&klpe_sc2isc, "sch_hfsc" },
	{ "update_ed", (void *)&klpe_update_ed, "sch_hfsc" },
	{ "vttree_insert", (void *)&klpe_vttree_insert, "sch_hfsc" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1215440_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1215440_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_NET_SCH_HFSC) */
