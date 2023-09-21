/*
 * livepatch_bsc1213064
 *
 * Fix for CVE-2023-31248, bsc#1213064
 *
 *  Upstream commit:
 *  515ad530795c ("netfilter: nf_tables: do not ignore genmask when looking up chain by id")
 *
 *  SLE12-SP5, SLE15-SP1 and SP2 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  414921d41310a07aa4648948b40c8d53f658b91a
 *
 *  SLE15-SP4 and -SP5 commit:
 *  2b5600c20d9ff2fd78fabcdf9411e1537fcd0e94
 *
 *  Copyright (c) 2023 SUSE
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

#if !IS_MODULE(CONFIG_NF_TABLES)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <linux/init.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/vmalloc.h>
#include <linux/rhashtable.h>
#include <linux/audit.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_tables_core.h>

static void (*klpe_nf_tables_rule_release)(const struct nft_ctx *ctx, struct nft_rule *rule);

static unsigned int (*klpe_nf_tables_net_id);

static inline struct nftables_pernet *klpr_nft_pernet(const struct net *net)
{
	return net_generic(net, (*klpe_nf_tables_net_id));
}

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <net/netfilter/nf_tables.h>

/* klp-ccp: from include/net/netfilter/nf_tables_offload.h */
static struct nft_flow_rule *(*klpe_nft_flow_rule_create)(struct net *net, const struct nft_rule *rule);

static void (*klpe_nft_flow_rule_destroy)(struct nft_flow_rule *flow);

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <net/net_namespace.h>

enum {
	NFT_VALIDATE_SKIP	= 0,
	NFT_VALIDATE_NEED,
	NFT_VALIDATE_DO,
};

static const struct rhashtable_params (*klpe_nft_chain_ht_params);

static void klpr_nft_validate_state_update(struct net *net, u8 new_validate_state)
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(net);

	switch (nft_net->validate_state) {
	case NFT_VALIDATE_SKIP:
		WARN_ON_ONCE(new_validate_state == NFT_VALIDATE_DO);
		break;
	case NFT_VALIDATE_NEED:
		break;
	case NFT_VALIDATE_DO:
		if (new_validate_state == NFT_VALIDATE_NEED)
			return;
	}

	nft_net->validate_state = new_validate_state;
}

static void nft_ctx_init(struct nft_ctx *ctx,
			 struct net *net,
			 const struct sk_buff *skb,
			 const struct nlmsghdr *nlh,
			 u8 family,
			 struct nft_table *table,
			 struct nft_chain *chain,
			 const struct nlattr * const *nla)
{
	ctx->net	= net;
	ctx->family	= family;
	ctx->level	= 0;
	ctx->table	= table;
	ctx->chain	= chain;
	ctx->nla   	= nla;
	ctx->portid	= NETLINK_CB(skb).portid;
	ctx->report	= nlmsg_report(nlh);
	ctx->flags	= nlh->nlmsg_flags;
	ctx->seq	= nlh->nlmsg_seq;
}

static struct nft_trans *(*klpe_nft_trans_rule_add)(struct nft_ctx *ctx, int msg_type,
					    struct nft_rule *rule);

static int (*klpe_nft_delrule)(struct nft_ctx *ctx, struct nft_rule *rule);

static struct nft_table *klpr_nft_table_lookup(const struct net *net,
					  const struct nlattr *nla,
					  u8 family, u8 genmask, u32 nlpid)
{
	struct nftables_pernet *nft_net;
	struct nft_table *table;

	if (nla == NULL)
		return ERR_PTR(-EINVAL);

	nft_net = klpr_nft_pernet(net);
	list_for_each_entry_rcu(table, &nft_net->tables, list,
				lockdep_is_held(&nft_net->commit_mutex)) {
		if (!nla_strcmp(nla, table->name) &&
		    table->family == family &&
		    nft_active_genmask(table, genmask)) {
			if (nft_table_has_owner(table) &&
			    nlpid && table->nlpid != nlpid)
				return ERR_PTR(-EPERM);

			return table;
		}
	}

	return ERR_PTR(-ENOENT);
}

static inline u64 nf_tables_alloc_handle(struct nft_table *table)
{
	return ++table->hgenerator;
}

static bool lockdep_commit_lock_is_held(const struct net *net)
{
#ifdef CONFIG_PROVE_LOCKING
#error "klp-ccp: non-taken branch"
#else
	return true;
#endif
}

static struct nft_chain *klpr_nft_chain_lookup(struct net *net,
					  struct nft_table *table,
					  const struct nlattr *nla, u8 genmask)
{
	char search[NFT_CHAIN_MAXNAMELEN + 1];
	struct rhlist_head *tmp, *list;
	struct nft_chain *chain;

	if (nla == NULL)
		return ERR_PTR(-EINVAL);

	nla_strscpy(search, nla, sizeof(search));

	WARN_ON(!rcu_read_lock_held() &&
		!lockdep_commit_lock_is_held(net));

	chain = ERR_PTR(-ENOENT);
	rcu_read_lock();
	list = rhltable_lookup(&table->chains_ht, search, (*klpe_nft_chain_ht_params));
	if (!list)
		goto out_unlock;

	rhl_for_each_entry_rcu(chain, tmp, list, rhlhead) {
		if (nft_active_genmask(chain, genmask))
			goto out_unlock;
	}
	chain = ERR_PTR(-ENOENT);
out_unlock:
	rcu_read_unlock();
	return chain;
}

static struct nft_chain *klpp_nft_chain_lookup_byid(const struct net *net,
					       const struct nft_table *table,
					       const struct nlattr *nla, u8 genmask)
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(net);
	u32 id = ntohl(nla_get_be32(nla));
	struct nft_trans *trans;

	list_for_each_entry(trans, &nft_net->commit_list, list) {
		struct nft_chain *chain = trans->ctx.chain;

		if (trans->msg_type == NFT_MSG_NEWCHAIN &&
		    chain->table == table &&
		    id == nft_trans_chain_id(trans) &&
		    nft_active_genmask(chain, genmask))
			return chain;
	}
	return ERR_PTR(-ENOENT);
}

struct nft_expr_info {
	const struct nft_expr_ops	*ops;
	const struct nlattr		*attr;
	struct nlattr			*tb[NFT_EXPR_MAXATTR + 1];
};

static int (*klpe_nf_tables_expr_parse)(const struct nft_ctx *ctx,
				const struct nlattr *nla,
				struct nft_expr_info *info);

static int nf_tables_newexpr(const struct nft_ctx *ctx,
			     const struct nft_expr_info *expr_info,
			     struct nft_expr *expr)
{
	const struct nft_expr_ops *ops = expr_info->ops;
	int err;

	expr->ops = ops;
	if (ops->init) {
		err = ops->init(ctx, expr, (const struct nlattr **)expr_info->tb);
		if (err < 0)
			goto err1;
	}

	return 0;
err1:
	expr->ops = NULL;
	return err;
}

static struct nft_rule *__nft_rule_lookup(const struct nft_chain *chain,
					  u64 handle)
{
	struct nft_rule *rule;

	// FIXME: this sucks
	list_for_each_entry_rcu(rule, &chain->rules, list) {
		if (handle == rule->handle)
			return rule;
	}

	return ERR_PTR(-ENOENT);
}

static int (*klpe_nft_table_validate)(struct net *net, const struct nft_table *table);

static struct nft_rule *(*klpe_nft_rule_lookup_byid)(const struct net *net,
					     const struct nft_chain *chain,
					     const struct nlattr *nla);

#define NFT_RULE_MAXEXPRS	128

int klpp_nf_tables_newrule(struct sk_buff *skb, const struct nfnl_info *info,
			     const struct nlattr * const nla[])
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(info->net);
	struct netlink_ext_ack *extack = info->extack;
	unsigned int size, i, n, ulen = 0, usize = 0;
	u8 genmask = nft_genmask_next(info->net);
	struct nft_rule *rule, *old_rule = NULL;
	struct nft_expr_info *expr_info = NULL;
	u8 family = info->nfmsg->nfgen_family;
	struct nft_flow_rule *flow = NULL;
	struct net *net = info->net;
	struct nft_userdata *udata;
	struct nft_table *table;
	struct nft_chain *chain;
	struct nft_trans *trans;
	u64 handle, pos_handle;
	struct nft_expr *expr;
	struct nft_ctx ctx;
	struct nlattr *tmp;
	int err, rem;

	lockdep_assert_held(&nft_net->commit_mutex);

	table = klpr_nft_table_lookup(net, nla[NFTA_RULE_TABLE], family, genmask,
				 NETLINK_CB(skb).portid);
	if (IS_ERR(table)) {
		NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_TABLE]);
		return PTR_ERR(table);
	}

	if (nla[NFTA_RULE_CHAIN]) {
		chain = klpr_nft_chain_lookup(net, table, nla[NFTA_RULE_CHAIN],
					 genmask);
		if (IS_ERR(chain)) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_CHAIN]);
			return PTR_ERR(chain);
		}
		if (nft_chain_is_bound(chain))
			return -EOPNOTSUPP;

	} else if (nla[NFTA_RULE_CHAIN_ID]) {
		chain = klpp_nft_chain_lookup_byid(net, table, nla[NFTA_RULE_CHAIN_ID],
						   genmask);
		if (IS_ERR(chain)) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_CHAIN_ID]);
			return PTR_ERR(chain);
		}
	} else {
		return -EINVAL;
	}

	if (nla[NFTA_RULE_HANDLE]) {
		handle = be64_to_cpu(nla_get_be64(nla[NFTA_RULE_HANDLE]));
		rule = __nft_rule_lookup(chain, handle);
		if (IS_ERR(rule)) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_HANDLE]);
			return PTR_ERR(rule);
		}

		if (info->nlh->nlmsg_flags & NLM_F_EXCL) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_HANDLE]);
			return -EEXIST;
		}
		if (info->nlh->nlmsg_flags & NLM_F_REPLACE)
			old_rule = rule;
		else
			return -EOPNOTSUPP;
	} else {
		if (!(info->nlh->nlmsg_flags & NLM_F_CREATE) ||
		    info->nlh->nlmsg_flags & NLM_F_REPLACE)
			return -EINVAL;
		handle = nf_tables_alloc_handle(table);

		if (chain->use == UINT_MAX)
			return -EOVERFLOW;

		if (nla[NFTA_RULE_POSITION]) {
			pos_handle = be64_to_cpu(nla_get_be64(nla[NFTA_RULE_POSITION]));
			old_rule = __nft_rule_lookup(chain, pos_handle);
			if (IS_ERR(old_rule)) {
				NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_POSITION]);
				return PTR_ERR(old_rule);
			}
		} else if (nla[NFTA_RULE_POSITION_ID]) {
			old_rule = (*klpe_nft_rule_lookup_byid)(net, chain, nla[NFTA_RULE_POSITION_ID]);
			if (IS_ERR(old_rule)) {
				NL_SET_BAD_ATTR(extack, nla[NFTA_RULE_POSITION_ID]);
				return PTR_ERR(old_rule);
			}
		}
	}

	nft_ctx_init(&ctx, net, skb, info->nlh, family, table, chain, nla);

	n = 0;
	size = 0;
	if (nla[NFTA_RULE_EXPRESSIONS]) {
		expr_info = kvmalloc_array(NFT_RULE_MAXEXPRS,
					   sizeof(struct nft_expr_info),
					   GFP_KERNEL);
		if (!expr_info)
			return -ENOMEM;

		nla_for_each_nested(tmp, nla[NFTA_RULE_EXPRESSIONS], rem) {
			err = -EINVAL;
			if (nla_type(tmp) != NFTA_LIST_ELEM)
				goto err_release_expr;
			if (n == NFT_RULE_MAXEXPRS)
				goto err_release_expr;
			err = (*klpe_nf_tables_expr_parse)(&ctx, tmp, &expr_info[n]);
			if (err < 0) {
				NL_SET_BAD_ATTR(extack, tmp);
				goto err_release_expr;
			}
			size += expr_info[n].ops->size;
			n++;
		}
	}
	/* Check for overflow of dlen field */
	err = -EFBIG;
	if (size >= 1 << 12)
		goto err_release_expr;

	if (nla[NFTA_RULE_USERDATA]) {
		ulen = nla_len(nla[NFTA_RULE_USERDATA]);
		if (ulen > 0)
			usize = sizeof(struct nft_userdata) + ulen;
	}

	err = -ENOMEM;
	rule = kzalloc(sizeof(*rule) + size + usize, GFP_KERNEL);
	if (rule == NULL)
		goto err_release_expr;

	nft_activate_next(net, rule);

	rule->handle = handle;
	rule->dlen   = size;
	rule->udata  = ulen ? 1 : 0;

	if (ulen) {
		udata = nft_userdata(rule);
		udata->len = ulen - 1;
		nla_memcpy(udata->data, nla[NFTA_RULE_USERDATA], ulen);
	}

	expr = nft_expr_first(rule);
	for (i = 0; i < n; i++) {
		err = nf_tables_newexpr(&ctx, &expr_info[i], expr);
		if (err < 0) {
			NL_SET_BAD_ATTR(extack, expr_info[i].attr);
			goto err_release_rule;
		}

		if (expr_info[i].ops->validate)
			klpr_nft_validate_state_update(net, NFT_VALIDATE_NEED);

		expr_info[i].ops = NULL;
		expr = nft_expr_next(expr);
	}

	if (chain->flags & NFT_CHAIN_HW_OFFLOAD) {
		flow = (*klpe_nft_flow_rule_create)(net, rule);
		if (IS_ERR(flow)) {
			err = PTR_ERR(flow);
			goto err_release_rule;
		}
	}

	if (info->nlh->nlmsg_flags & NLM_F_REPLACE) {
		err = (*klpe_nft_delrule)(&ctx, old_rule);
		if (err < 0)
			goto err_destroy_flow_rule;

		trans = (*klpe_nft_trans_rule_add)(&ctx, NFT_MSG_NEWRULE, rule);
		if (trans == NULL) {
			err = -ENOMEM;
			goto err_destroy_flow_rule;
		}
		list_add_tail_rcu(&rule->list, &old_rule->list);
	} else {
		trans = (*klpe_nft_trans_rule_add)(&ctx, NFT_MSG_NEWRULE, rule);
		if (!trans) {
			err = -ENOMEM;
			goto err_destroy_flow_rule;
		}

		if (info->nlh->nlmsg_flags & NLM_F_APPEND) {
			if (old_rule)
				list_add_rcu(&rule->list, &old_rule->list);
			else
				list_add_tail_rcu(&rule->list, &chain->rules);
		 } else {
			if (old_rule)
				list_add_tail_rcu(&rule->list, &old_rule->list);
			else
				list_add_rcu(&rule->list, &chain->rules);
		}
	}
	kvfree(expr_info);
	chain->use++;

	if (flow)
		nft_trans_flow_rule(trans) = flow;

	if (nft_net->validate_state == NFT_VALIDATE_DO)
		return (*klpe_nft_table_validate)(net, table);

	return 0;

err_destroy_flow_rule:
	if (flow)
		(*klpe_nft_flow_rule_destroy)(flow);
err_release_rule:
	(*klpe_nf_tables_rule_release)(&ctx, rule);
err_release_expr:
	for (i = 0; i < n; i++) {
		if (expr_info[i].ops) {
			module_put(expr_info[i].ops->type->owner);
			if (expr_info[i].ops->type->release_ops)
				expr_info[i].ops->type->release_ops(expr_info[i].ops);
		}
	}
	kvfree(expr_info);

	return err;
}

static const struct nla_policy (*klpe_nft_verdict_policy)[NFTA_VERDICT_MAX + 1];

static int klpp_nft_verdict_init(const struct nft_ctx *ctx, struct nft_data *data,
			    struct nft_data_desc *desc, const struct nlattr *nla)
{
	u8 genmask = nft_genmask_next(ctx->net);
	struct nlattr *tb[NFTA_VERDICT_MAX + 1];
	struct nft_chain *chain;
	int err;

	err = nla_parse_nested_deprecated(tb, NFTA_VERDICT_MAX, nla,
					  (*klpe_nft_verdict_policy), NULL);
	if (err < 0)
		return err;

	if (!tb[NFTA_VERDICT_CODE])
		return -EINVAL;
	data->verdict.code = ntohl(nla_get_be32(tb[NFTA_VERDICT_CODE]));

	switch (data->verdict.code) {
	default:
		switch (data->verdict.code & NF_VERDICT_MASK) {
		case NF_ACCEPT:
		case NF_DROP:
		case NF_QUEUE:
			break;
		default:
			return -EINVAL;
		}
		fallthrough;
	case NFT_CONTINUE:
	case NFT_BREAK:
	case NFT_RETURN:
		break;
	case NFT_JUMP:
	case NFT_GOTO:
		if (tb[NFTA_VERDICT_CHAIN]) {
			chain = klpr_nft_chain_lookup(ctx->net, ctx->table,
						 tb[NFTA_VERDICT_CHAIN],
						 genmask);
		} else if (tb[NFTA_VERDICT_CHAIN_ID]) {
			chain = klpp_nft_chain_lookup_byid(ctx->net, ctx->table,
						      tb[NFTA_VERDICT_CHAIN_ID],
						      genmask);
			if (IS_ERR(chain))
				return PTR_ERR(chain);
		} else {
			return -EINVAL;
		}

		if (IS_ERR(chain))
			return PTR_ERR(chain);
		if (nft_is_base_chain(chain))
			return -EOPNOTSUPP;
		if (nft_chain_is_bound(chain))
			return -EINVAL;

		chain->use++;
		data->verdict.chain = chain;
		break;
	}

	desc->len = sizeof(data->verdict);
	desc->type = NFT_DATA_VERDICT;
	return 0;
}

static int nft_value_init(const struct nft_ctx *ctx,
			  struct nft_data *data, unsigned int size,
			  struct nft_data_desc *desc, const struct nlattr *nla)
{
	unsigned int len;

	len = nla_len(nla);
	if (len == 0)
		return -EINVAL;
	if (len > size)
		return -EOVERFLOW;

	nla_memcpy(data->data, nla, len);
	desc->type = NFT_DATA_VALUE;
	desc->len  = len;
	return 0;
}

static const struct nla_policy (*klpe_nft_data_policy)[NFTA_DATA_MAX + 1];

int klpp_nft_data_init(const struct nft_ctx *ctx,
		  struct nft_data *data, unsigned int size,
		  struct nft_data_desc *desc, const struct nlattr *nla)
{
	struct nlattr *tb[NFTA_DATA_MAX + 1];
	int err;

	err = nla_parse_nested_deprecated(tb, NFTA_DATA_MAX, nla,
					  (*klpe_nft_data_policy), NULL);
	if (err < 0)
		return err;

	if (tb[NFTA_DATA_VALUE])
		return nft_value_init(ctx, data, size, desc,
				      tb[NFTA_DATA_VALUE]);
	if (tb[NFTA_DATA_VERDICT] && ctx != NULL)
		return klpp_nft_verdict_init(ctx, data, desc, tb[NFTA_DATA_VERDICT]);
	return -EINVAL;
}



#include "livepatch_bsc1213064.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nf_tables_expr_parse", (void *)&klpe_nf_tables_expr_parse,
	  "nf_tables" },
	{ "nf_tables_net_id", (void *)&klpe_nf_tables_net_id, "nf_tables" },
	{ "nf_tables_rule_release", (void *)&klpe_nf_tables_rule_release,
	  "nf_tables" },
	{ "nft_chain_ht_params", (void *)&klpe_nft_chain_ht_params,
	  "nf_tables" },
	{ "nft_data_policy", (void *)&klpe_nft_data_policy, "nf_tables" },
	{ "nft_delrule", (void *)&klpe_nft_delrule, "nf_tables" },
	{ "nft_flow_rule_create", (void *)&klpe_nft_flow_rule_create,
	  "nf_tables" },
	{ "nft_flow_rule_destroy", (void *)&klpe_nft_flow_rule_destroy,
	  "nf_tables" },
	{ "nft_rule_lookup_byid", (void *)&klpe_nft_rule_lookup_byid,
	  "nf_tables" },
	{ "nft_table_validate", (void *)&klpe_nft_table_validate,
	  "nf_tables" },
	{ "nft_trans_rule_add", (void *)&klpe_nft_trans_rule_add,
	  "nf_tables" },
	{ "nft_verdict_policy", (void *)&klpe_nft_verdict_policy,
	  "nf_tables" },
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

int livepatch_bsc1213064_init(void)
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

void livepatch_bsc1213064_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
