/*
 * livepatch_bsc1264253
 *
 * Fix for CVE-2026-43025, bsc#1264253
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


#include "livepatch_bsc1264253.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/netfilter/nf_conntrack_netlink.c */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rculist.h>
#include <linux/rculist_nulls.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/security.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/netlink.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <net/netlink.h>
#include <net/sock.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>

/* klp-ccp: from include/net/netfilter/nf_conntrack_expect.h */
static struct nf_conntrack_expect *(*klpe_nf_ct_expect_alloc)(struct nf_conn *me);

static void (*klpe_nf_ct_expect_put)(struct nf_conntrack_expect *exp);
static int (*klpe_nf_ct_expect_related_report)(struct nf_conntrack_expect *expect, 
				u32 portid, int report);

/* klp-ccp: from include/net/netfilter/nf_conntrack_core.h */
static struct nf_conntrack_tuple_hash *
(*klpe_nf_conntrack_find_get)(struct net *net,
		      const struct nf_conntrack_zone *zone,
		      const struct nf_conntrack_tuple *tuple);

/* klp-ccp: from net/netfilter/nf_conntrack_netlink.c */
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_helper.h>

/* klp-ccp: from include/net/netfilter/nf_conntrack_helper.h */
static struct nf_ct_helper_expectfn *
(*klpe_nf_ct_helper_expectfn_find_by_name)(const char *name);

/* klp-ccp: from net/netfilter/nf_conntrack_netlink.c */
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_l3proto.h>
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_tuple.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_timestamp.h>
#include <net/netfilter/nf_conntrack_labels.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_synproxy.h>
#ifdef CONFIG_NF_NAT_NEEDED
#include <net/netfilter/nf_nat_core.h>
#include <net/netfilter/nf_nat_l4proto.h>
#include <net/netfilter/nf_nat_helper.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

static int
(*klpe_ctnetlink_parse_tuple)(const struct nlattr * const cda[],
		      struct nf_conntrack_tuple *tuple, u32 type,
		      u_int8_t l3num, struct nf_conntrack_zone *zone);

static const struct nla_policy (*klpe_exp_nla_policy)[CTA_EXPECT_MAX+1];

static struct nf_conntrack_expect *
klpr_ctnetlink_alloc_expect(const struct nlattr *const cda[], struct nf_conn *ct,
		       struct nf_conntrack_tuple *tuple,
		       struct nf_conntrack_tuple *mask);

#ifdef CONFIG_NETFILTER_NETLINK_GLUE_CT

static int klpr_ctnetlink_glue_exp_parse(const struct nlattr * const *cda,
				    const struct nf_conn *ct,
				    struct nf_conntrack_tuple *tuple,
				    struct nf_conntrack_tuple *mask)
{
	int err;

	err = (*klpe_ctnetlink_parse_tuple)(cda, tuple, CTA_EXPECT_TUPLE,
				    nf_ct_l3num(ct), NULL);
	if (err < 0)
		return err;

	return (*klpe_ctnetlink_parse_tuple)(cda, mask, CTA_EXPECT_MASK,
				     nf_ct_l3num(ct), NULL);
}

int
klpp_ctnetlink_glue_attach_expect(const struct nlattr *attr, struct nf_conn *ct,
			     u32 portid, u32 report)
{
	struct nlattr *cda[CTA_EXPECT_MAX+1];
	struct nf_conntrack_tuple tuple, mask;
	struct nf_conntrack_expect *exp;
	int err;

	err = nla_parse_nested(cda, CTA_EXPECT_MAX, attr, (*klpe_exp_nla_policy),
			       NULL);
	if (err < 0)
		return err;

	err = klpr_ctnetlink_glue_exp_parse((const struct nlattr * const *)cda,
				       ct, &tuple, &mask);
	if (err < 0)
		return err;

	exp = klpr_ctnetlink_alloc_expect((const struct nlattr * const *)cda, ct,
				     &tuple, &mask);
	if (IS_ERR(exp))
		return PTR_ERR(exp);

	err = (*klpe_nf_ct_expect_related_report)(exp, portid, report);
	(*klpe_nf_ct_expect_put)(exp);
	return err;
}

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NETFILTER_NETLINK_GLUE_CT */

static const struct nla_policy (*klpe_exp_nat_nla_policy)[CTA_EXPECT_NAT_MAX+1];

static int
klpr_ctnetlink_parse_expect_nat(const struct nlattr *attr,
			   struct nf_conntrack_expect *exp,
			   u_int8_t u3)
{
#ifdef CONFIG_NF_NAT_NEEDED
	struct nlattr *tb[CTA_EXPECT_NAT_MAX+1];
	struct nf_conntrack_tuple nat_tuple = {};
	int err;

	err = nla_parse_nested(tb, CTA_EXPECT_NAT_MAX, attr,
			       (*klpe_exp_nat_nla_policy), NULL);
	if (err < 0)
		return err;

	if (!tb[CTA_EXPECT_NAT_DIR] || !tb[CTA_EXPECT_NAT_TUPLE])
		return -EINVAL;

	err = (*klpe_ctnetlink_parse_tuple)((const struct nlattr * const *)tb,
				    &nat_tuple, CTA_EXPECT_NAT_TUPLE,
				    u3, NULL);
	if (err < 0)
		return err;

	exp->saved_addr = nat_tuple.src.u3;
	exp->saved_proto = nat_tuple.src.u;
	exp->dir = ntohl(nla_get_be32(tb[CTA_EXPECT_NAT_DIR]));

	return 0;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static struct nf_conntrack_expect *
klpr_ctnetlink_alloc_expect(const struct nlattr * const cda[], struct nf_conn *ct,
		       struct nf_conntrack_tuple *tuple,
		       struct nf_conntrack_tuple *mask)
{
	u_int32_t class = 0;
	struct nf_conntrack_helper *helper;
	struct nf_conntrack_expect *exp;
	struct nf_conn_help *help;
	int err;

	help = nfct_help(ct);
	if (!help)
		return ERR_PTR(-EOPNOTSUPP);

	helper = rcu_dereference(help->helper);
	if (!helper)
		return ERR_PTR(-EOPNOTSUPP);

	if (cda[CTA_EXPECT_CLASS]) {
		class = ntohl(nla_get_be32(cda[CTA_EXPECT_CLASS]));
		if (class > helper->expect_class_max)
			return ERR_PTR(-EINVAL);
	}
	exp = (*klpe_nf_ct_expect_alloc)(ct);
	if (!exp)
		return ERR_PTR(-ENOMEM);

	if (cda[CTA_EXPECT_FLAGS]) {
		exp->flags = ntohl(nla_get_be32(cda[CTA_EXPECT_FLAGS]));
		exp->flags &= ~NF_CT_EXPECT_USERSPACE;
	} else {
		exp->flags = 0;
	}
	if (cda[CTA_EXPECT_FN]) {
		const char *name = nla_data(cda[CTA_EXPECT_FN]);
		struct nf_ct_helper_expectfn *expfn;

		expfn = (*klpe_nf_ct_helper_expectfn_find_by_name)(name);
		if (expfn == NULL) {
			err = -EINVAL;
			goto err_out;
		}
		exp->expectfn = expfn->expectfn;
	} else
		exp->expectfn = NULL;

	exp->class = class;
	exp->master = ct;
	exp->helper = helper;
	exp->tuple = *tuple;
	exp->mask.src.u3 = mask->src.u3;
	exp->mask.src.u.all = mask->src.u.all;

	if (cda[CTA_EXPECT_NAT]) {
		err = klpr_ctnetlink_parse_expect_nat(cda[CTA_EXPECT_NAT],
						 exp, nf_ct_l3num(ct));
		if (err < 0)
			goto err_out;
	}
	return exp;
err_out:
	(*klpe_nf_ct_expect_put)(exp);
	return ERR_PTR(err);
}

int
klpp_ctnetlink_create_expect(struct net *net,
			const struct nf_conntrack_zone *zone,
			const struct nlattr * const cda[],
			u_int8_t u3, u32 portid, int report)
{
	struct nf_conntrack_tuple tuple, mask, master_tuple;
	struct nf_conntrack_tuple_hash *h = NULL;
	struct nf_conntrack_expect *exp;
	struct nf_conn *ct;
	int err;

	/* caller guarantees that those three CTA_EXPECT_* exist */
	err = (*klpe_ctnetlink_parse_tuple)(cda, &tuple, CTA_EXPECT_TUPLE,
				    u3, NULL);
	if (err < 0)
		return err;
	err = (*klpe_ctnetlink_parse_tuple)(cda, &mask, CTA_EXPECT_MASK,
				    u3, NULL);
	if (err < 0)
		return err;
	err = (*klpe_ctnetlink_parse_tuple)(cda, &master_tuple, CTA_EXPECT_MASTER,
				    u3, NULL);
	if (err < 0)
		return err;

	/* Look for master conntrack of this expectation */
	h = (*klpe_nf_conntrack_find_get)(net, zone, &master_tuple);
	if (!h)
		return -ENOENT;
	ct = nf_ct_tuplehash_to_ctrack(h);

	rcu_read_lock();
	exp = klpr_ctnetlink_alloc_expect(cda, ct, &tuple, &mask);
	if (IS_ERR(exp)) {
		err = PTR_ERR(exp);
		goto err_rcu;
	}

	err = (*klpe_nf_ct_expect_related_report)(exp, portid, report);
	(*klpe_nf_ct_expect_put)(exp);
err_rcu:
	rcu_read_unlock();
	nf_ct_put(ct);

	return err;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_conntrack_netlink"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ctnetlink_parse_tuple", (void *)&klpe_ctnetlink_parse_tuple,
	  "nf_conntrack_netlink" },
	{ "exp_nat_nla_policy", (void *)&klpe_exp_nat_nla_policy,
	  "nf_conntrack_netlink" },
	{ "exp_nla_policy", (void *)&klpe_exp_nla_policy,
	  "nf_conntrack_netlink" },
	{ "nf_conntrack_find_get", (void *)&klpe_nf_conntrack_find_get,
	  "nf_conntrack" },
	{ "nf_ct_expect_alloc", (void *)&klpe_nf_ct_expect_alloc,
	  "nf_conntrack" },
	{ "nf_ct_expect_put", (void *)&klpe_nf_ct_expect_put, "nf_conntrack" },
	{ "nf_ct_expect_related_report",
	  (void *)&klpe_nf_ct_expect_related_report, "nf_conntrack" },
	{ "nf_ct_helper_expectfn_find_by_name",
	  (void *)&klpe_nf_ct_helper_expectfn_find_by_name, "nf_conntrack" },
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

int livepatch_bsc1264253_init(void)
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

void livepatch_bsc1264253_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
