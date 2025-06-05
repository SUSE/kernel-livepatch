/*
 * livepatch_bsc1239077
 *
 * Fix for CVE-2024-57996, bsc#1239077
 *
 *  Upstream commit:
 *  10685681bafc ("net_sched: sch_sfq: don't allow 1 packet limit")
 *
 *  SLE12-SP5 commit:
 *  30f09ffc7d152eb32a403a14f6f3215fafe1cca2
 *
 *  SLE15-SP3 commit:
 *  bc548b8f45c999a45fe9d6d69460abc081af1f66
 *
 *  SLE15-SP4 and -SP5 commit:
 *  1575e3738b6bab9db18c300ddaade48e47fcad6c
 *
 *  SLE15-SP6 commit:
 *  8f719fe557de88ace9315fec529485d043b29cca
 *
 *  SLE MICRO-6-0 commit:
 *  8f719fe557de88ace9315fec529485d043b29cca
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
#include <linux/jhash.h>
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

#define SFQ_ALLOT_SHIFT		3
#define SFQ_ALLOT_SIZE(X)	DIV_ROUND_UP(X, 1 << SFQ_ALLOT_SHIFT)

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
	short		allot; /* credit for this slot */

	unsigned int    backlog;
	struct red_vars vars;
};

struct sfq_sched_data {
/* frequently used fields */
	int		limit;		/* limit of total number of packets in this qdisc */
	unsigned int	divisor;	/* number of slots in hash table */
	u8		headdrop;
	u8		maxdepth;	/* limit of packets per flow */

	u32		perturbation;
	u8		cur_depth;	/* depth of longest slot */
	u8		flags;
	unsigned short  scaled_quantum; /* SFQ_ALLOT_SIZE(quantum) */
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

static unsigned int (*klpe_sfq_drop)(struct Qdisc *sch, struct sk_buff **to_free);

static void (*klpe_sfq_perturbation)(unsigned long arg);

static int klpp_sfq_change(struct Qdisc *sch, struct nlattr *opt)
{
	struct sfq_sched_data *q = qdisc_priv(sch);
	struct tc_sfq_qopt *ctl = nla_data(opt);
	struct tc_sfq_qopt_v1 *ctl_v1 = NULL;
	unsigned int qlen, dropped = 0;
	struct red_parms *p = NULL;
	struct sk_buff *to_free = NULL;
	struct sk_buff *tail = NULL;

	if (opt->nla_len < nla_attr_size(sizeof(*ctl)))
		return -EINVAL;
	if (opt->nla_len >= nla_attr_size(sizeof(*ctl_v1)))
		ctl_v1 = nla_data(opt);
	if (ctl->divisor &&
	    (!is_power_of_2(ctl->divisor) || ctl->divisor > 65536))
		return -EINVAL;

	/* slot->allot is a short, make sure quantum is not too big. */
	if (ctl->quantum) {
		unsigned int scaled = SFQ_ALLOT_SIZE(ctl->quantum);

		if (scaled <= 0 || scaled > SHRT_MAX)
			return -EINVAL;
	}

	if (ctl_v1 && !red_check_params(ctl_v1->qth_min, ctl_v1->qth_max,
					ctl_v1->Wlog))
		return -EINVAL;
	if (ctl_v1 && ctl_v1->qth_min) {
		p = kmalloc(sizeof(*p), GFP_KERNEL);
		if (!p)
			return -ENOMEM;
	}
	if (ctl->limit == 1)
		return -EINVAL;
	sch_tree_lock(sch);
	if (ctl->quantum) {
		q->quantum = ctl->quantum;
		q->scaled_quantum = SFQ_ALLOT_SIZE(q->quantum);
	}
	q->perturb_period = ctl->perturb_period * HZ;
	if (ctl->flows)
		q->maxflows = min_t(u32, ctl->flows, SFQ_MAX_FLOWS);
	if (ctl->divisor) {
		q->divisor = ctl->divisor;
		q->maxflows = min_t(u32, q->maxflows, q->divisor);
	}
	if (ctl_v1) {
		if (ctl_v1->depth)
			q->maxdepth = min_t(u32, ctl_v1->depth, SFQ_MAX_DEPTH);
		if (p) {
			swap(q->red_parms, p);
			red_set_parms(q->red_parms,
				      ctl_v1->qth_min, ctl_v1->qth_max,
				      ctl_v1->Wlog,
				      ctl_v1->Plog, ctl_v1->Scell_log,
				      NULL,
				      ctl_v1->max_P);
		}
		q->flags = ctl_v1->flags;
		q->headdrop = ctl_v1->headdrop;
	}
	if (ctl->limit) {
		q->limit = min_t(u32, ctl->limit, q->maxdepth * q->maxflows);
		q->maxflows = min_t(u32, q->maxflows, q->limit);
	}

	qlen = sch->q.qlen;
	while (sch->q.qlen > q->limit) {
		dropped += (*klpe_sfq_drop)(sch, &to_free);
		if (!tail)
			tail = to_free;
	}

	rtnl_kfree_skbs(to_free, tail);
	qdisc_tree_reduce_backlog(sch, qlen - sch->q.qlen, dropped);

	del_timer(&q->perturb_timer);
	if (q->perturb_period) {
		mod_timer(&q->perturb_timer, jiffies + q->perturb_period);
		q->perturbation = prandom_u32();
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

	setup_deferrable_timer(&q->perturb_timer, (*klpe_sfq_perturbation),
			       (unsigned long)sch);

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
	q->scaled_quantum = SFQ_ALLOT_SIZE(q->quantum);
	q->perturb_period = 0;
	q->perturbation = prandom_u32();

	if (opt) {
		int err = klpp_sfq_change(sch, opt);
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


#include "livepatch_bsc1239077.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sch_sfq"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sfq_drop", (void *)&klpe_sfq_drop, "sch_sfq" },
	{ "sfq_perturbation", (void *)&klpe_sfq_perturbation, "sch_sfq" },
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

int livepatch_bsc1239077_init(void)
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

void livepatch_bsc1239077_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
