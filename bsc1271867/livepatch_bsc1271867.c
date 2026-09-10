/*
 * livepatch_bsc1271867
 *
 * Fix for CVE-2026-64530, bsc#1271867
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


#include "livepatch_bsc1271867.h"


/* klp-ccp: from net/sched/cls_api.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <linux/rhashtable.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

/* klp-ccp: from include/net/pkt_cls.h */
#ifdef CONFIG_NET_CLS_ACT

struct sk_buff *klpp_tcf_qevent_handle(struct tcf_qevent *qe, struct Qdisc *sch, struct sk_buff *skb,
				  struct sk_buff **to_free, int *ret);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/sched/cls_api.c */
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_csum.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_police.h>
#include <net/tc_act/tc_sample.h>
#include <net/tc_act/tc_skbedit.h>
#include <net/tc_act/tc_ct.h>
#include <net/tc_act/tc_mpls.h>
#include <net/tc_act/tc_gate.h>
#include <net/flow_offload.h>
#include <net/tc_wrapper.h>

int tcf_classify(struct sk_buff *skb,
		 const struct tcf_block *block,
		 const struct tcf_proto *tp,
		 struct tcf_result *res, bool compat_mode);

extern typeof(tcf_classify) tcf_classify;

#ifdef CONFIG_NET_CLS_ACT

struct sk_buff *klpp_tcf_qevent_handle(struct tcf_qevent *qe, struct Qdisc *sch, struct sk_buff *skb,
				  struct sk_buff **to_free, int *ret)
{
	struct tcf_result cl_res;
	struct tcf_proto *fl;

	if (!qe->info.block_index)
		return skb;

	fl = rcu_dereference_bh(qe->filter_chain);

	switch (tcf_classify(skb, NULL, fl, &cl_res, false)) {
	case TC_ACT_SHOT:
		qdisc_qstats_drop(sch);
		__qdisc_drop(skb, to_free);
		*ret = __NET_XMIT_BYPASS;
		return NULL;
	case TC_ACT_STOLEN:
	case TC_ACT_QUEUED:
	case TC_ACT_TRAP:
		__qdisc_drop(skb, to_free);
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	case TC_ACT_REDIRECT:
		skb_do_redirect(skb);
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	case TC_ACT_CONSUMED:
		*ret = __NET_XMIT_STOLEN;
		return NULL;
	}

	return skb;
}

typeof(klpp_tcf_qevent_handle) klpp_tcf_qevent_handle;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif


#include <linux/livepatch.h>

extern typeof(skb_do_redirect) skb_do_redirect
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_do_redirect);
