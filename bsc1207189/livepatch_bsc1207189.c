/*
 * livepatch_bsc1207189
 *
 * Fix for CVE-2023-23455, bsc#1207189
 *
 *  Upstream commit:
 *  a2965c7be052 ("net: sched: atm: dont intepret cls results when asked to
 *                 drop")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  9f135a38ee10d6f664440267c36b1c0117464244
 *
 *  SLE15-SP2 and -SP3 commit:
 *  49dc51cede44e09c2ff96d439639941f85af91db
 *
 *  SLE15-SP4 commit:
 *  7c3cc04c75f692dbee0a52bb90acc3d45044fe8c
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

#if IS_ENABLED(CONFIG_NET_SCH_ATM)

#if !IS_MODULE(CONFIG_NET_SCH_ATM)
#error "Live patch supports only CONFIG_NET_SCH_ATM=m"
#endif

/* klp-ccp: from net/sched/sch_atm.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/atmdev.h>
#include <linux/atmclip.h>
#include <linux/rtnetlink.h>
#include <linux/file.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

struct atm_flow_data {
	struct Qdisc_class_common common;
	struct Qdisc		*q;	/* FIFO, TBF, etc. */
	struct tcf_proto __rcu	*filter_list;
	struct tcf_block	*block;
	struct atm_vcc		*vcc;	/* VCC; NULL if VCC is closed */
	void			(*old_pop)(struct atm_vcc *vcc,
					   struct sk_buff *skb); /* chaining */
	struct atm_qdisc_data	*parent;	/* parent qdisc */
	struct socket		*sock;		/* for closing */
	int			ref;		/* reference count */
	struct gnet_stats_basic_packed	bstats;
	struct gnet_stats_queue	qstats;
	struct list_head	list;
	struct atm_flow_data	*excess;	/* flow for excess traffic;
						   NULL to set CLP instead */
	int			hdr_len;
	unsigned char		hdr[0];		/* header data; MUST BE LAST */
};

struct atm_qdisc_data {
	struct atm_flow_data	link;		/* unclassified skbs go here */
	struct list_head	flows;		/* NB: "link" is also on this
						   list */
	struct tasklet_struct	task;		/* dequeue tasklet */
};

static inline struct atm_flow_data *lookup_flow(struct Qdisc *sch, u32 classid)
{
	struct atm_qdisc_data *p = qdisc_priv(sch);
	struct atm_flow_data *flow;

	list_for_each_entry(flow, &p->flows, list) {
		if (flow->common.classid == classid)
			return flow;
	}
	return NULL;
}

static unsigned long (*klpe_atm_tc_find)(struct Qdisc *sch, u32 classid);

int klpp_atm_tc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free)
{
	struct atm_qdisc_data *p = qdisc_priv(sch);
	struct atm_flow_data *flow;
	struct tcf_result res;
	int result;
	int ret = NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;

	pr_debug("atm_tc_enqueue(skb %p,sch %p,[qdisc %p])\n", skb, sch, p);
	result = TC_ACT_OK;	/* be nice to gcc */
	flow = NULL;
	if (TC_H_MAJ(skb->priority) != sch->handle ||
	    !(flow = (struct atm_flow_data *)(*klpe_atm_tc_find)(sch, skb->priority))) {
		struct tcf_proto *fl;

		list_for_each_entry(flow, &p->flows, list) {
			fl = rcu_dereference_bh(flow->filter_list);
			if (fl) {
				result = tcf_classify(skb, fl, &res, true);
				if (result < 0)
					continue;
				/*
				 * Fix CVE-2023-23455
				 *  +5 lines
				 */
				if (result == TC_ACT_SHOT) {
					__qdisc_drop(skb, to_free);
					goto drop;
				}

				flow = (struct atm_flow_data *)res.class;
				if (!flow)
					flow = lookup_flow(sch, res.classid);
				goto done;
			}
		}
		flow = NULL;
done:
		;
	}
	if (!flow) {
		flow = &p->link;
	} else {
		if (flow->vcc)
			ATM_SKB(skb)->atm_options = flow->vcc->atm_options;

#ifdef CONFIG_NET_CLS_ACT
		switch (result) {
		case TC_ACT_QUEUED:
		case TC_ACT_STOLEN:
		case TC_ACT_TRAP:
			__qdisc_drop(skb, to_free);
			return NET_XMIT_SUCCESS | __NET_XMIT_STOLEN;
		case TC_ACT_SHOT:
			__qdisc_drop(skb, to_free);
			goto drop;
		case TC_ACT_RECLASSIFY:
			if (flow->excess)
				flow = flow->excess;
			else
				ATM_SKB(skb)->atm_options |= ATM_ATMOPT_CLP;
			break;
		}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	}

	ret = qdisc_enqueue(skb, flow->q, to_free);
	if (ret != NET_XMIT_SUCCESS) {
drop: __maybe_unused
		if (net_xmit_drop_count(ret)) {
			qdisc_qstats_drop(sch);
			if (flow)
				flow->qstats.drops++;
		}
		return ret;
	}
	/*
	 * Okay, this may seem weird. We pretend we've dropped the packet if
	 * it goes via ATM. The reason for this is that the outer qdisc
	 * expects to be able to q->dequeue the packet later on if we return
	 * success at this place. Also, sch->q.qdisc needs to reflect whether
	 * there is a packet egligible for dequeuing or not. Note that the
	 * statistics of the outer qdisc are necessarily wrong because of all
	 * this. There's currently no correct solution for this.
	 */
	if (flow == &p->link) {
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;
	}
	tasklet_schedule(&p->task);
	return NET_XMIT_SUCCESS | __NET_XMIT_BYPASS;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1207189.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "sch_atm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "atm_tc_find", (void *)&klpe_atm_tc_find, "sch_atm" },
};

static int livepatch_bsc1207189_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1207189_module_nb = {
	.notifier_call = livepatch_bsc1207189_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1207189_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1207189_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1207189_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1207189_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NET_SCH_ATM) */
