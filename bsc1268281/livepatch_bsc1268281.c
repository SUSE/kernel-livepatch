/*
 * livepatch_bsc1268281
 *
 * Fix for CVE-2026-46319, bsc#1268281
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1268281.h"


/* klp-ccp: from net/sched/act_ct.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>
#include <net/act_api.h>
#include <net/ip.h>
#include <net/ipv6_frag.h>
#include <uapi/linux/tc_act/tc_ct.h>
#include <net/tc_act/tc_ct.h>
#include <net/tc_wrapper.h>

#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#include <net/netfilter/nf_conntrack_act_ct.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <uapi/linux/netfilter/nf_nat.h>

extern struct rhashtable zones_ht;
extern struct mutex zones_mutex;

struct tcf_ct_flow_table {
	struct rhash_head node; /* In zones tables */

	struct rcu_work rwork;
	struct nf_flowtable nf_ft;
	refcount_t ref;
	u16 zone;

	bool dying;
};

extern const struct rhashtable_params zones_params;

extern struct nf_flowtable_type flowtable_ct;

static int tcf_ct_flow_table_get(struct net *net, struct tcf_ct_params *params)
{
	struct tcf_ct_flow_table *ct_ft;
	int err = -ENOMEM;

	mutex_lock(&zones_mutex);
	rcu_read_lock();
	ct_ft = rhashtable_lookup(&zones_ht, &params->zone, zones_params);
	if (ct_ft && refcount_inc_not_zero(&ct_ft->ref)) {
		rcu_read_unlock();
		goto out_unlock;
	}
	rcu_read_unlock();

	ct_ft = kzalloc(sizeof(*ct_ft), GFP_KERNEL);
	if (!ct_ft)
		goto err_alloc;
	refcount_set(&ct_ft->ref, 1);

	ct_ft->zone = params->zone;
	err = rhashtable_insert_fast(&zones_ht, &ct_ft->node, zones_params);
	if (err)
		goto err_insert;

	ct_ft->nf_ft.type = &flowtable_ct;
	ct_ft->nf_ft.flags |= NF_FLOWTABLE_HW_OFFLOAD |
			      NF_FLOWTABLE_COUNTER;
	err = nf_flow_table_init(&ct_ft->nf_ft);
	if (err)
		goto err_init;
	write_pnet(&ct_ft->nf_ft.net, net);

	__module_get(THIS_MODULE);
out_unlock:
	params->ct_ft = ct_ft;
	params->nf_ft = &ct_ft->nf_ft;
	mutex_unlock(&zones_mutex);

	return 0;

err_init:
	rhashtable_remove_fast(&zones_ht, &ct_ft->node, zones_params);
err_insert:
	kfree(ct_ft);
err_alloc:
	mutex_unlock(&zones_mutex);
	return err;
}

extern struct tc_action_ops act_ct_ops;

struct tc_ct_action_net {
	struct tc_action_net tn; /* Must be first */
	bool labels;
};

extern void tcf_ct_params_free(struct tcf_ct_params *params);

extern void tcf_ct_params_free_rcu(struct rcu_head *head);

extern const struct nla_policy ct_policy[TCA_CT_MAX + 1];

static int tcf_ct_fill_params_nat(struct tcf_ct_params *p,
				  struct tc_ct *parm,
				  struct nlattr **tb,
				  struct netlink_ext_ack *extack)
{
	struct nf_nat_range2 *range;

	if (!(p->ct_action & TCA_CT_ACT_NAT))
		return 0;

	if (!IS_ENABLED(CONFIG_NF_NAT)) {
		NL_SET_ERR_MSG_MOD(extack, "Netfilter nat isn't enabled in kernel");
		return -EOPNOTSUPP;
	}

	if (!(p->ct_action & (TCA_CT_ACT_NAT_SRC | TCA_CT_ACT_NAT_DST)))
		return 0;

	if ((p->ct_action & TCA_CT_ACT_NAT_SRC) &&
	    (p->ct_action & TCA_CT_ACT_NAT_DST)) {
		NL_SET_ERR_MSG_MOD(extack, "dnat and snat can't be enabled at the same time");
		return -EOPNOTSUPP;
	}

	range = &p->range;
	if (tb[TCA_CT_NAT_IPV4_MIN]) {
		struct nlattr *max_attr = tb[TCA_CT_NAT_IPV4_MAX];

		p->ipv4_range = true;
		range->flags |= NF_NAT_RANGE_MAP_IPS;
		range->min_addr.ip =
			nla_get_in_addr(tb[TCA_CT_NAT_IPV4_MIN]);

		range->max_addr.ip = max_attr ?
				     nla_get_in_addr(max_attr) :
				     range->min_addr.ip;
	} else if (tb[TCA_CT_NAT_IPV6_MIN]) {
		struct nlattr *max_attr = tb[TCA_CT_NAT_IPV6_MAX];

		p->ipv4_range = false;
		range->flags |= NF_NAT_RANGE_MAP_IPS;
		range->min_addr.in6 =
			nla_get_in6_addr(tb[TCA_CT_NAT_IPV6_MIN]);

		range->max_addr.in6 = max_attr ?
				      nla_get_in6_addr(max_attr) :
				      range->min_addr.in6;
	}

	if (tb[TCA_CT_NAT_PORT_MIN]) {
		range->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
		range->min_proto.all = nla_get_be16(tb[TCA_CT_NAT_PORT_MIN]);

		range->max_proto.all = tb[TCA_CT_NAT_PORT_MAX] ?
				       nla_get_be16(tb[TCA_CT_NAT_PORT_MAX]) :
				       range->min_proto.all;
	}

	return 0;
}

extern void tcf_ct_set_key_val(struct nlattr **tb,
			       void *val, int val_type,
			       void *mask, int mask_type,
			       int len);

static int tcf_ct_fill_params(struct net *net,
			      struct tcf_ct_params *p,
			      struct tc_ct *parm,
			      struct nlattr **tb,
			      struct netlink_ext_ack *extack)
{
	struct tc_ct_action_net *tn = net_generic(net, act_ct_ops.net_id);
	struct nf_conntrack_zone zone;
	int err, family, proto, len;
	struct nf_conn *tmpl;
	char *name;

	p->zone = NF_CT_DEFAULT_ZONE_ID;

	tcf_ct_set_key_val(tb,
			   &p->ct_action, TCA_CT_ACTION,
			   NULL, TCA_CT_UNSPEC,
			   sizeof(p->ct_action));

	if (p->ct_action & TCA_CT_ACT_CLEAR)
		return 0;

	err = tcf_ct_fill_params_nat(p, parm, tb, extack);
	if (err)
		return err;

	if (tb[TCA_CT_MARK]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_MARK)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack mark isn't enabled.");
			return -EOPNOTSUPP;
		}
		tcf_ct_set_key_val(tb,
				   &p->mark, TCA_CT_MARK,
				   &p->mark_mask, TCA_CT_MARK_MASK,
				   sizeof(p->mark));
	}

	if (tb[TCA_CT_LABELS]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_LABELS)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack labels isn't enabled.");
			return -EOPNOTSUPP;
		}

		if (!tn->labels) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to set connlabel length");
			return -EOPNOTSUPP;
		}
		tcf_ct_set_key_val(tb,
				   p->labels, TCA_CT_LABELS,
				   p->labels_mask, TCA_CT_LABELS_MASK,
				   sizeof(p->labels));
	}

	if (tb[TCA_CT_ZONE]) {
		if (!IS_ENABLED(CONFIG_NF_CONNTRACK_ZONES)) {
			NL_SET_ERR_MSG_MOD(extack, "Conntrack zones isn't enabled.");
			return -EOPNOTSUPP;
		}

		tcf_ct_set_key_val(tb,
				   &p->zone, TCA_CT_ZONE,
				   NULL, TCA_CT_UNSPEC,
				   sizeof(p->zone));
	}

	nf_ct_zone_init(&zone, p->zone, NF_CT_DEFAULT_ZONE_DIR, 0);
	tmpl = nf_ct_tmpl_alloc(net, &zone, GFP_KERNEL);
	if (!tmpl) {
		NL_SET_ERR_MSG_MOD(extack, "Failed to allocate conntrack template");
		return -ENOMEM;
	}
	p->tmpl = tmpl;
	if (tb[TCA_CT_HELPER_NAME]) {
		name = nla_data(tb[TCA_CT_HELPER_NAME]);
		len = nla_len(tb[TCA_CT_HELPER_NAME]);
		if (len > 16 || name[len - 1] != '\0') {
			NL_SET_ERR_MSG_MOD(extack, "Failed to parse helper name.");
			err = -EINVAL;
			goto err;
		}
		family = tb[TCA_CT_HELPER_FAMILY] ? nla_get_u8(tb[TCA_CT_HELPER_FAMILY]) : AF_INET;
		proto = tb[TCA_CT_HELPER_PROTO] ? nla_get_u8(tb[TCA_CT_HELPER_PROTO]) : IPPROTO_TCP;
		err = nf_ct_add_helper(tmpl, name, family, proto,
				       p->ct_action & TCA_CT_ACT_NAT, &p->helper);
		if (err) {
			NL_SET_ERR_MSG_MOD(extack, "Failed to add helper");
			goto err;
		}
	}

	__set_bit(IPS_CONFIRMED_BIT, &tmpl->status);
	return 0;
err:
	nf_ct_put(p->tmpl);
	p->tmpl = NULL;
	return err;
}

int klpp_tcf_ct_init(struct net *net, struct nlattr *nla,
		       struct nlattr *est, struct tc_action **a,
		       struct tcf_proto *tp, u32 flags,
		       struct netlink_ext_ack *extack)
{
	struct tc_action_net *tn = net_generic(net, act_ct_ops.net_id);
	bool bind = flags & TCA_ACT_FLAGS_BIND;
	struct tcf_ct_params *params = NULL;
	struct nlattr *tb[TCA_CT_MAX + 1];
	struct tcf_chain *goto_ch = NULL;
	struct tc_ct *parm;
	struct tcf_ct *c;
	int err, res = 0;
	u32 index;

	if (!nla) {
		NL_SET_ERR_MSG_MOD(extack, "Ct requires attributes to be passed");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, TCA_CT_MAX, nla, ct_policy, extack);
	if (err < 0)
		return err;

	if (!tb[TCA_CT_PARMS]) {
		NL_SET_ERR_MSG_MOD(extack, "Missing required ct parameters");
		return -EINVAL;
	}
	parm = nla_data(tb[TCA_CT_PARMS]);
	index = parm->index;
	err = tcf_idr_check_alloc(tn, &index, a, bind);
	if (err < 0)
		return err;

	if (!err) {
		err = tcf_idr_create_from_flags(tn, index, est, a,
						&act_ct_ops, bind, flags);
		if (err) {
			tcf_idr_cleanup(tn, index);
			return err;
		}
		res = ACT_P_CREATED;
	} else {
		if (bind)
			return 0;

		if (!(flags & TCA_ACT_FLAGS_REPLACE)) {
			tcf_idr_release(*a, bind);
			return -EEXIST;
		}
	}
	err = tcf_action_check_ctrlact(parm->action, tp, &goto_ch, extack);
	if (err < 0)
		goto cleanup;

	c = to_ct(*a);

	params = kzalloc(sizeof(*params), GFP_KERNEL);
	if (unlikely(!params)) {
		err = -ENOMEM;
		goto cleanup;
	}

	err = tcf_ct_fill_params(net, params, parm, tb, extack);
	if (err)
		goto cleanup;

	err = tcf_ct_flow_table_get(net, params);
	if (err)
		goto cleanup;

	spin_lock_bh(&c->tcf_lock);
	goto_ch = tcf_action_set_ctrlact(*a, parm->action, goto_ch);
	params = rcu_replace_pointer(c->params, params,
				     lockdep_is_held(&c->tcf_lock));
	spin_unlock_bh(&c->tcf_lock);

	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	if (params)
		call_rcu(&params->rcu, tcf_ct_params_free_rcu);

	return res;

cleanup:
	if (goto_ch)
		tcf_chain_put_by_act(goto_ch);
	if (params)
		tcf_ct_params_free(params);
	tcf_idr_release(*a, bind);
	return err;
}

extern struct tc_action_ops act_ct_ops;


#include <linux/livepatch.h>

extern typeof(__this_module) __this_module
	 KLP_RELOC_SYMBOL(act_ct, act_ct, __this_module);
extern typeof(act_ct_ops) act_ct_ops
	 KLP_RELOC_SYMBOL(act_ct, act_ct, act_ct_ops);
extern typeof(ct_policy) ct_policy KLP_RELOC_SYMBOL(act_ct, act_ct, ct_policy);
extern typeof(flowtable_ct) flowtable_ct
	 KLP_RELOC_SYMBOL(act_ct, act_ct, flowtable_ct);
extern typeof(tcf_ct_params_free) tcf_ct_params_free
	 KLP_RELOC_SYMBOL(act_ct, act_ct, tcf_ct_params_free);
extern typeof(tcf_ct_params_free_rcu) tcf_ct_params_free_rcu
	 KLP_RELOC_SYMBOL(act_ct, act_ct, tcf_ct_params_free_rcu);
extern typeof(tcf_ct_set_key_val) tcf_ct_set_key_val
	 KLP_RELOC_SYMBOL(act_ct, act_ct, tcf_ct_set_key_val);
extern typeof(zones_ht) zones_ht KLP_RELOC_SYMBOL(act_ct, act_ct, zones_ht);
extern typeof(zones_mutex) zones_mutex
	 KLP_RELOC_SYMBOL(act_ct, act_ct, zones_mutex);
extern typeof(zones_params) zones_params
	 KLP_RELOC_SYMBOL(act_ct, act_ct, zones_params);
extern typeof(nf_ct_add_helper) nf_ct_add_helper
	 KLP_RELOC_SYMBOL(act_ct, nf_conntrack, nf_ct_add_helper);
extern typeof(nf_ct_destroy) nf_ct_destroy
	 KLP_RELOC_SYMBOL(act_ct, nf_conntrack, nf_ct_destroy);
extern typeof(nf_ct_tmpl_alloc) nf_ct_tmpl_alloc
	 KLP_RELOC_SYMBOL(act_ct, nf_conntrack, nf_ct_tmpl_alloc);
extern typeof(nf_flow_table_init) nf_flow_table_init
	 KLP_RELOC_SYMBOL(act_ct, nf_flow_table, nf_flow_table_init);
