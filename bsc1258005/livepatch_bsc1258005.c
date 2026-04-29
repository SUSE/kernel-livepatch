/*
 * livepatch_bsc1258005
 *
 * Fix for CVE-2025-71066, bsc#1258005
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1258005.h"


/* klp-ccp: from net/sched/sch_ets.c */
#include <linux/module.h>
#include <net/gen_stats.h>
#include <net/netlink.h>
#include <net/pkt_cls.h>
#include <net/pkt_sched.h>
#include <net/sch_generic.h>

struct ets_class {
	struct list_head alist; /* In struct ets_sched.active. */
	struct Qdisc *qdisc;
	u32 quantum;
	u32 deficit;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
};

struct ets_sched {
	struct list_head active;
	struct tcf_proto __rcu *filter_list;
	struct tcf_block *block;
	unsigned int nbands;
	unsigned int nstrict;
	u8 prio2band[TC_PRIO_MAX + 1];
	struct ets_class classes[TCQ_ETS_MAX_BANDS];
};

extern const struct nla_policy ets_policy[TCA_ETS_MAX + 1];

extern const struct nla_policy ets_priomap_policy[TCA_ETS_MAX + 1];

extern const struct nla_policy ets_quanta_policy[TCA_ETS_MAX + 1];

static bool klpp_cl_is_active(struct ets_class *cl)
{
	return !list_empty(&cl->alist);
}

static int ets_quantum_parse(struct Qdisc *sch, const struct nlattr *attr,
			     unsigned int *quantum,
			     struct netlink_ext_ack *extack)
{
	*quantum = nla_get_u32(attr);
	if (!*quantum) {
		NL_SET_ERR_MSG(extack, "ETS quantum cannot be zero");
		return -EINVAL;
	}
	return 0;
}

static struct ets_class *
ets_class_from_arg(struct Qdisc *sch, unsigned long arg)
{
	struct ets_sched *q = qdisc_priv(sch);

	if (arg == 0 || arg > q->nbands)
		return NULL;
	return &q->classes[arg - 1];
}

static u32 ets_class_id(struct Qdisc *sch, const struct ets_class *cl)
{
	struct ets_sched *q = qdisc_priv(sch);
	int band = cl - q->classes;

	return TC_H_MAKE(sch->handle, band + 1);
}

extern void ets_offload_change(struct Qdisc *sch);

static bool ets_class_is_strict(struct ets_sched *q, const struct ets_class *cl)
{
	unsigned int band = cl - q->classes;

	return band < q->nstrict;
}

void klpp_ets_class_qlen_notify(struct Qdisc *sch, unsigned long arg)
{
	struct ets_class *cl = ets_class_from_arg(sch, arg);
	struct ets_sched *q = qdisc_priv(sch);

	/* We get notified about zero-length child Qdiscs as well if they are
	 * offloaded. Those aren't on the active list though, so don't attempt
	 * to remove them.
	 */
	if (!ets_class_is_strict(q, cl) && sch->q.qlen)
		list_del_init(&cl->alist);
}

static struct ets_class *ets_classify(struct sk_buff *skb, struct Qdisc *sch,
				      int *qerr)
{
	struct ets_sched *q = qdisc_priv(sch);
	u32 band = skb->priority;
	struct tcf_result res;
	struct tcf_proto *fl;
	int err;

	*qerr = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
	if (TC_H_MAJ(skb->priority) != sch->handle) {
		fl = rcu_dereference_bh(q->filter_list);
		err = tcf_classify(skb, NULL, fl, &res, false);
#ifdef CONFIG_NET_CLS_ACT
		switch (err) {
		case TC_ACT_STOLEN:
		case TC_ACT_QUEUED:
		case TC_ACT_TRAP:
			*qerr = NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
			fallthrough;
		case TC_ACT_SHOT:
			return NULL;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (!fl || err < 0) {
			if (TC_H_MAJ(band))
				band = 0;
			return &q->classes[q->prio2band[band & TC_PRIO_MAX]];
		}
		band = res.classid;
	}
	band = TC_H_MIN(band) - 1;
	if (band >= q->nbands)
		return &q->classes[q->prio2band[0]];
	return &q->classes[band];
}

int klpp_ets_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			     struct sk_buff **to_free)
{
	unsigned int len = qdisc_pkt_len(skb);
	struct ets_sched *q = qdisc_priv(sch);
	struct ets_class *cl;
	int err = 0;

	cl = ets_classify(skb, sch, &err);
	if (!cl) {
		if (err & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		return err;
	}

	err = qdisc_enqueue(skb, cl->qdisc, to_free);
	if (unlikely(err != NET_XMIT_SUCCESS)) {
		if (net_xmit_drop_count(err)) {
			cl->qstats.drops++;
			qdisc_qstats_drop(sch);
		}
		return err;
	}

	if (!klpp_cl_is_active(cl) && !ets_class_is_strict(q, cl)) {
		list_add_tail(&cl->alist, &q->active);
		cl->deficit = cl->quantum;
	}

	sch->qstats.backlog += len;
	sch->q.qlen++;
	return err;
}

static struct sk_buff *
ets_qdisc_dequeue_skb(struct Qdisc *sch, struct sk_buff *skb)
{
	qdisc_bstats_update(sch, skb);
	qdisc_qstats_backlog_dec(sch, skb);
	sch->q.qlen--;
	return skb;
}

struct sk_buff *klpp_ets_qdisc_dequeue(struct Qdisc *sch)
{
	struct ets_sched *q = qdisc_priv(sch);
	struct ets_class *cl;
	struct sk_buff *skb;
	unsigned int band;
	unsigned int len;

	while (1) {
		for (band = 0; band < q->nstrict; band++) {
			cl = &q->classes[band];
			skb = qdisc_dequeue_peeked(cl->qdisc);
			if (skb)
				return ets_qdisc_dequeue_skb(sch, skb);
		}

		if (list_empty(&q->active))
			goto out;

		cl = list_first_entry(&q->active, struct ets_class, alist);
		skb = cl->qdisc->ops->peek(cl->qdisc);
		if (!skb) {
			qdisc_warn_nonwc(__func__, cl->qdisc);
			goto out;
		}

		len = qdisc_pkt_len(skb);
		if (len <= cl->deficit) {
			cl->deficit -= len;
			skb = qdisc_dequeue_peeked(cl->qdisc);
			if (unlikely(!skb))
				goto out;
			if (cl->qdisc->q.qlen == 0)
				list_del_init(&cl->alist);
			return ets_qdisc_dequeue_skb(sch, skb);
		}

		cl->deficit += cl->quantum;
		list_move_tail(&cl->alist, &q->active);
	}
out:
	return NULL;
}

static int ets_qdisc_priomap_parse(struct nlattr *priomap_attr,
				   unsigned int nbands, u8 *priomap,
				   struct netlink_ext_ack *extack)
{
	const struct nlattr *attr;
	int prio = 0;
	u8 band;
	int rem;
	int err;

	err = __nla_validate_nested(priomap_attr, TCA_ETS_MAX,
				    ets_priomap_policy, NL_VALIDATE_STRICT,
				    extack);
	if (err)
		return err;

	nla_for_each_nested(attr, priomap_attr, rem) {
		switch (nla_type(attr)) {
		case TCA_ETS_PRIOMAP_BAND:
			if (prio > TC_PRIO_MAX) {
				NL_SET_ERR_MSG_MOD(extack, "Too many priorities in ETS priomap");
				return -EINVAL;
			}
			band = nla_get_u8(attr);
			if (band >= nbands) {
				NL_SET_ERR_MSG_MOD(extack, "Invalid band number in ETS priomap");
				return -EINVAL;
			}
			priomap[prio++] = band;
			break;
		default:
			WARN_ON_ONCE(1); /* Validate should have caught this. */
			return -EINVAL;
		}
	}

	return 0;
}

static int ets_qdisc_quanta_parse(struct Qdisc *sch, struct nlattr *quanta_attr,
				  unsigned int nbands, unsigned int nstrict,
				  unsigned int *quanta,
				  struct netlink_ext_ack *extack)
{
	const struct nlattr *attr;
	int band = nstrict;
	int rem;
	int err;

	err = __nla_validate_nested(quanta_attr, TCA_ETS_MAX,
				    ets_quanta_policy, NL_VALIDATE_STRICT,
				    extack);
	if (err < 0)
		return err;

	nla_for_each_nested(attr, quanta_attr, rem) {
		switch (nla_type(attr)) {
		case TCA_ETS_QUANTA_BAND:
			if (band >= nbands) {
				NL_SET_ERR_MSG_MOD(extack, "ETS quanta has more values than bands");
				return -EINVAL;
			}
			err = ets_quantum_parse(sch, attr, &quanta[band++],
						extack);
			if (err)
				return err;
			break;
		default:
			WARN_ON_ONCE(1); /* Validate should have caught this. */
			return -EINVAL;
		}
	}

	return 0;
}

int klpp_ets_qdisc_change(struct Qdisc *sch, struct nlattr *opt,
			    struct netlink_ext_ack *extack)
{
	unsigned int quanta[TCQ_ETS_MAX_BANDS] = {0};
	struct Qdisc *queues[TCQ_ETS_MAX_BANDS];
	struct ets_sched *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_ETS_MAX + 1];
	unsigned int oldbands = q->nbands;
	u8 priomap[TC_PRIO_MAX + 1];
	unsigned int nstrict = 0;
	unsigned int nbands;
	unsigned int i;
	int err;

	err = nla_parse_nested(tb, TCA_ETS_MAX, opt, ets_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_ETS_NBANDS]) {
		NL_SET_ERR_MSG_MOD(extack, "Number of bands is a required argument");
		return -EINVAL;
	}
	nbands = nla_get_u8(tb[TCA_ETS_NBANDS]);
	if (nbands < 1 || nbands > TCQ_ETS_MAX_BANDS) {
		NL_SET_ERR_MSG_MOD(extack, "Invalid number of bands");
		return -EINVAL;
	}
	/* Unless overridden, traffic goes to the last band. */
	memset(priomap, nbands - 1, sizeof(priomap));

	if (tb[TCA_ETS_NSTRICT]) {
		nstrict = nla_get_u8(tb[TCA_ETS_NSTRICT]);
		if (nstrict > nbands) {
			NL_SET_ERR_MSG_MOD(extack, "Invalid number of strict bands");
			return -EINVAL;
		}
	}

	if (tb[TCA_ETS_PRIOMAP]) {
		err = ets_qdisc_priomap_parse(tb[TCA_ETS_PRIOMAP],
					      nbands, priomap, extack);
		if (err)
			return err;
	}

	if (tb[TCA_ETS_QUANTA]) {
		err = ets_qdisc_quanta_parse(sch, tb[TCA_ETS_QUANTA],
					     nbands, nstrict, quanta, extack);
		if (err)
			return err;
	}
	/* If there are more bands than strict + quanta provided, the remaining
	 * ones are ETS with quantum of MTU. Initialize the missing values here.
	 */
	for (i = nstrict; i < nbands; i++) {
		if (!quanta[i])
			quanta[i] = psched_mtu(qdisc_dev(sch));
	}

	/* Before commit, make sure we can allocate all new qdiscs */
	for (i = oldbands; i < nbands; i++) {
		queues[i] = qdisc_create_dflt(sch->dev_queue, &pfifo_qdisc_ops,
					      ets_class_id(sch, &q->classes[i]),
					      extack);
		if (!queues[i]) {
			while (i > oldbands)
				qdisc_put(queues[--i]);
			return -ENOMEM;
		}
	}

	sch_tree_lock(sch);

	for (i = nbands; i < oldbands; i++) {
		if (klpp_cl_is_active(&q->classes[i]))
			list_del_init(&q->classes[i].alist);
		qdisc_purge_queue(q->classes[i].qdisc);
	}

	q->nbands = nbands;
	for (i = nstrict; i < q->nstrict; i++) {
		if (q->classes[i].qdisc->q.qlen) {
			list_add_tail(&q->classes[i].alist, &q->active);
			q->classes[i].deficit = quanta[i];
		}
	}
	q->nstrict = nstrict;
	memcpy(q->prio2band, priomap, sizeof(priomap));

	for (i = 0; i < q->nbands; i++)
		q->classes[i].quantum = quanta[i];

	for (i = oldbands; i < q->nbands; i++) {
		q->classes[i].qdisc = queues[i];
		if (q->classes[i].qdisc != &noop_qdisc)
			qdisc_hash_add(q->classes[i].qdisc, true);
	}

	sch_tree_unlock(sch);

	ets_offload_change(sch);
	for (i = q->nbands; i < oldbands; i++) {
		qdisc_put(q->classes[i].qdisc);
		q->classes[i].qdisc = NULL;
		q->classes[i].quantum = 0;
		q->classes[i].deficit = 0;
		gnet_stats_basic_sync_init(&q->classes[i].bstats);
		memset(&q->classes[i].qstats, 0, sizeof(q->classes[i].qstats));
	}
	return 0;
}

void klpp_ets_qdisc_reset(struct Qdisc *sch)
{
	struct ets_sched *q = qdisc_priv(sch);
	int band;

	for (band = q->nstrict; band < q->nbands; band++) {
		if (q->classes[band].qdisc->q.qlen)
			list_del_init(&q->classes[band].alist);
	}
	for (band = 0; band < q->nbands; band++)
		qdisc_reset(q->classes[band].qdisc);
}


#include <linux/livepatch.h>

extern typeof(ets_offload_change) ets_offload_change
	 KLP_RELOC_SYMBOL(sch_ets, sch_ets, ets_offload_change);
extern typeof(ets_policy) ets_policy
	 KLP_RELOC_SYMBOL(sch_ets, sch_ets, ets_policy);
extern typeof(ets_priomap_policy) ets_priomap_policy
	 KLP_RELOC_SYMBOL(sch_ets, sch_ets, ets_priomap_policy);
extern typeof(ets_quanta_policy) ets_quanta_policy
	 KLP_RELOC_SYMBOL(sch_ets, sch_ets, ets_quanta_policy);
