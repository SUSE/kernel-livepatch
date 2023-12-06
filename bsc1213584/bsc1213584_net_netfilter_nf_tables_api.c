/*
 * bsc1213584_net_netfilter_nf_tables_api
 *
 * Fix for CVE-2023-3610, bsc#1213584
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

/* klp-ccp: from include/net/netfilter/nf_tables.h */
static void (*klpe_nft_data_hold)(const struct nft_data *data, enum nft_data_types type);

static void (*klpe_nft_set_elem_destroy)(const struct nft_set *set, void *elem,
			  bool destroy_expr);

static void (*klpe_nft_chain_del)(struct nft_chain *chain);
static void (*klpe_nf_tables_chain_destroy)(struct nft_ctx *ctx);

static unsigned int (*klpe_nf_tables_net_id);

static inline struct nftables_pernet *klpr_nft_pernet(const struct net *net)
{
	return net_generic(net, (*klpe_nf_tables_net_id));
}

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <net/netfilter/nf_tables.h>

/* klp-ccp: from include/net/netfilter/nf_tables_offload.h */
static void (*klpe_nft_flow_rule_destroy)(struct nft_flow_rule *flow);

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <net/net_namespace.h>

static void nft_trans_destroy(struct nft_trans *trans)
{
	list_del(&trans->list);
	kfree(trans);
}

static void (*klpe_nf_tables_unregister_hook)(struct net *net,
				      const struct nft_table *table,
				      struct nft_chain *chain);

static void nft_rule_expr_activate(const struct nft_ctx *ctx,
				   struct nft_rule *rule)
{
	struct nft_expr *expr;

	expr = nft_expr_first(rule);
	while (nft_expr_more(rule, expr)) {
		if (expr->ops->activate)
			expr->ops->activate(ctx, expr);

		expr = nft_expr_next(expr);
	}
}

static void (*klpe_nft_rule_expr_deactivate)(const struct nft_ctx *ctx,
				     struct nft_rule *rule,
				     enum nft_trans_phase phase);

struct nft_module_request {
	struct list_head	list;
	char			module[MODULE_NAME_LEN];
	bool			done;
};

static void (*klpe_nft_table_disable)(struct net *net, struct nft_table *table, u32 cnt);

static void klpr_nf_tables_table_disable(struct net *net, struct nft_table *table)
{
	table->flags &= ~NFT_TABLE_F_DORMANT;
	(*klpe_nft_table_disable)(net, table, 0);
	table->flags |= NFT_TABLE_F_DORMANT;
}

#define __NFT_TABLE_F_INTERNAL		(NFT_TABLE_F_MASK + 1)
#define __NFT_TABLE_F_WAS_DORMANT	(__NFT_TABLE_F_INTERNAL << 0)
#define __NFT_TABLE_F_WAS_AWAKEN	(__NFT_TABLE_F_INTERNAL << 1)
#define __NFT_TABLE_F_UPDATE		(__NFT_TABLE_F_WAS_DORMANT | 					 __NFT_TABLE_F_WAS_AWAKEN)

static void nf_tables_table_destroy(struct nft_ctx *ctx)
{
	if (WARN_ON(ctx->table->use > 0))
		return;

	rhltable_destroy(&ctx->table->chains_ht);
	kfree(ctx->table->name);
	kfree(ctx->table->udata);
	kfree(ctx->table);
}

static void (*klpe_nf_tables_rule_destroy)(const struct nft_ctx *ctx,
				   struct nft_rule *rule);

static void (*klpe_nft_set_destroy)(const struct nft_ctx *ctx, struct nft_set *set);

static bool nft_setelem_is_catchall(const struct nft_set *set,
				    const struct nft_set_elem *elem)
{
	struct nft_set_ext *ext = nft_set_elem_ext(set, elem->priv);

	if (nft_set_ext_exists(ext, NFT_SET_EXT_FLAGS) &&
	    *nft_set_ext_flags(ext) & NFT_SET_ELEM_CATCHALL)
		return true;

	return false;
}

static void (*klpe_nft_setelem_activate)(struct net *net, struct nft_set *set,
				 struct nft_set_elem *elem);

static void (*klpe_nft_setelem_remove)(const struct net *net,
			       const struct nft_set *set,
			       const struct nft_set_elem *elem);

static void klpr_nft_setelem_data_activate(const struct net *net,
				      const struct nft_set *set,
				      struct nft_set_elem *elem)
{
	const struct nft_set_ext *ext = nft_set_elem_ext(set, elem->priv);

	if (nft_set_ext_exists(ext, NFT_SET_EXT_DATA))
		(*klpe_nft_data_hold)(nft_set_ext_data(ext), set->dtype);
	if (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF))
		(*nft_set_ext_obj(ext))->use++;
}

static void (*klpe_nft_obj_destroy)(const struct nft_ctx *ctx, struct nft_object *obj);

static void nft_unregister_flowtable_net_hooks(struct net *net,
					       struct list_head *hook_list)
{
	struct nft_hook *hook;

	list_for_each_entry(hook, hook_list, list)
		nf_unregister_net_hook(net, &hook->ops);
}

static void (*klpe_nft_flowtable_hooks_destroy)(struct list_head *hook_list);

static void (*klpe_nf_tables_flowtable_destroy)(struct nft_flowtable *flowtable);

static int (*klpe_nf_tables_validate)(struct net *net);

static void (*klpe_nft_obj_del)(struct nft_object *obj);

static void (*klpe_nf_tables_module_autoload_cleanup)(struct net *net);

static void klpr_nf_tables_module_autoload(struct net *net)
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(net);
	struct nft_module_request *req, *next;
	LIST_HEAD(module_list);

	list_splice_init(&nft_net->module_list, &module_list);
	mutex_unlock(&nft_net->commit_mutex);
	list_for_each_entry_safe(req, next, &module_list, list) {
		request_module("%s", req->module);
		req->done = true;
	}
	mutex_lock(&nft_net->commit_mutex);
	list_splice(&module_list, &nft_net->module_list);
}

static void klpr_nf_tables_abort_release(struct nft_trans *trans)
{
	switch (trans->msg_type) {
	case NFT_MSG_NEWTABLE:
		nf_tables_table_destroy(&trans->ctx);
		break;
	case NFT_MSG_NEWCHAIN:
		(*klpe_nf_tables_chain_destroy)(&trans->ctx);
		break;
	case NFT_MSG_NEWRULE:
		(*klpe_nf_tables_rule_destroy)(&trans->ctx, nft_trans_rule(trans));
		break;
	case NFT_MSG_NEWSET:
		(*klpe_nft_set_destroy)(&trans->ctx, nft_trans_set(trans));
		break;
	case NFT_MSG_NEWSETELEM:
		(*klpe_nft_set_elem_destroy)(nft_trans_elem_set(trans),
				     nft_trans_elem(trans).priv, true);
		break;
	case NFT_MSG_NEWOBJ:
		(*klpe_nft_obj_destroy)(&trans->ctx, nft_trans_obj(trans));
		break;
	case NFT_MSG_NEWFLOWTABLE:
		if (nft_trans_flowtable_update(trans))
			(*klpe_nft_flowtable_hooks_destroy)(&nft_trans_flowtable_hooks(trans));
		else
			(*klpe_nf_tables_flowtable_destroy)(nft_trans_flowtable(trans));
		break;
	}
	kfree(trans);
}

static inline bool nft_chain_binding(const struct nft_chain *chain)
{
    return chain->flags & NFT_CHAIN_BINDING;
}

void klpp_nft_chain_trans_bind(const struct nft_ctx *ctx, struct nft_chain *chain)
{
	struct nftables_pernet *nft_net;
	struct net *net = ctx->net;
	struct nft_trans *trans;

	if (!nft_chain_binding(chain))
		return;

	nft_net = klpr_nft_pernet(net);
	list_for_each_entry_reverse(trans, &nft_net->commit_list, list) {
		switch (trans->msg_type) {
		case NFT_MSG_NEWCHAIN:
			/*
			 * I think that the new ->chain member in
			 * struct nft_trans_chain is redundant to
			 * ->ctx.chain, c.f. nf_tables_addchain(). It
			 * probably got introduced for consistency
			 * with the struct nft_trans_set case.
			 */
			if (trans->ctx.chain == chain) {
				/*
				 * Use an unallocated bit in
				 * ->ctx.flags (NLM_F_* values) for
				 * representing the new ->bound.
				 */
				trans->ctx.flags |= 0x8000;
			}
			break;
		case NFT_MSG_NEWRULE:
			if (trans->ctx.chain == chain) {
				/*
				 * Use an unallocated bit in
				 * ->ctx.flags (NLM_F_* values) for
				 * representing the new ->bound.
				 */
				trans->ctx.flags |= 0x8000;
			}
			break;
		}
	}
}

int klpp_nf_tables_bind_chain(const struct nft_ctx *ctx, struct nft_chain *chain)
{
	if (!nft_chain_binding(chain))
		return 0;

	if (nft_chain_binding(ctx->chain))
		return -EOPNOTSUPP;

	if (chain->bound)
		return -EBUSY;

	chain->bound = true;
	/*
	 * Skip the increment from the upstream fix. It pairs with the
	 * new decrement in nft_immediate_destroy(), which we're
	 * also skipping.
	 */
	/* chain->use++; */
	klpp_nft_chain_trans_bind(ctx, chain);

	return 0;
}

int klpp___nf_tables_abort(struct net *net, enum nfnl_abort_action action)
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(net);
	struct nft_trans *trans, *next;
	struct nft_trans_elem *te;
	struct nft_hook *hook;

	if (action == NFNL_ABORT_VALIDATE &&
	    (*klpe_nf_tables_validate)(net) < 0)
		return -EAGAIN;

	list_for_each_entry_safe_reverse(trans, next, &nft_net->commit_list,
					 list) {
		switch (trans->msg_type) {
		case NFT_MSG_NEWTABLE:
			if (nft_trans_table_update(trans)) {
				if (!(trans->ctx.table->flags & __NFT_TABLE_F_UPDATE)) {
					nft_trans_destroy(trans);
					break;
				}
				if (trans->ctx.table->flags & __NFT_TABLE_F_WAS_DORMANT) {
					klpr_nf_tables_table_disable(net, trans->ctx.table);
					trans->ctx.table->flags |= NFT_TABLE_F_DORMANT;
				} else if (trans->ctx.table->flags & __NFT_TABLE_F_WAS_AWAKEN) {
					trans->ctx.table->flags &= ~NFT_TABLE_F_DORMANT;
				}
				trans->ctx.table->flags &= ~__NFT_TABLE_F_UPDATE;
				nft_trans_destroy(trans);
			} else {
				list_del_rcu(&trans->ctx.table->list);
			}
			break;
		case NFT_MSG_DELTABLE:
			nft_clear(trans->ctx.net, trans->ctx.table);
			nft_trans_destroy(trans);
			break;
		case NFT_MSG_NEWCHAIN:
			if (nft_trans_chain_update(trans)) {
				free_percpu(nft_trans_chain_stats(trans));
				kfree(nft_trans_chain_name(trans));
				nft_trans_destroy(trans);
			} else {
				/*
				 * Be conservative: if all assumptions
				 * of the livepatch are correct, then
				 * ->ctx.flags would have been updated
				 * for bound chains, and the second
				 * expression in the || would never
				 * get executed. If OTOH something
				 * is wrong, resort to the original
				 * behaviour.
				 */
				if ((trans->ctx.flags & 0xf000) == 0x8000 ||
				    nft_chain_is_bound(trans->ctx.chain)) {
					nft_trans_destroy(trans);
					break;
				}
				trans->ctx.table->use--;
				(*klpe_nft_chain_del)(trans->ctx.chain);
				(*klpe_nf_tables_unregister_hook)(trans->ctx.net,
							  trans->ctx.table,
							  trans->ctx.chain);
			}
			break;
		case NFT_MSG_DELCHAIN:
			trans->ctx.table->use++;
			nft_clear(trans->ctx.net, trans->ctx.chain);
			nft_trans_destroy(trans);
			break;
		case NFT_MSG_NEWRULE:
			if ((trans->ctx.flags & 0xf000) == 0x8000) {
				nft_trans_destroy(trans);
				break;
			}
			trans->ctx.chain->use--;
			list_del_rcu(&nft_trans_rule(trans)->list);
			(*klpe_nft_rule_expr_deactivate)(&trans->ctx,
						 nft_trans_rule(trans),
						 NFT_TRANS_ABORT);
			if (trans->ctx.chain->flags & NFT_CHAIN_HW_OFFLOAD)
				(*klpe_nft_flow_rule_destroy)(nft_trans_flow_rule(trans));
			break;
		case NFT_MSG_DELRULE:
			trans->ctx.chain->use++;
			nft_clear(trans->ctx.net, nft_trans_rule(trans));
			nft_rule_expr_activate(&trans->ctx, nft_trans_rule(trans));
			if (trans->ctx.chain->flags & NFT_CHAIN_HW_OFFLOAD)
				(*klpe_nft_flow_rule_destroy)(nft_trans_flow_rule(trans));

			nft_trans_destroy(trans);
			break;
		case NFT_MSG_NEWSET:
			trans->ctx.table->use--;
			if (nft_trans_set_bound(trans)) {
				nft_trans_destroy(trans);
				break;
			}
			list_del_rcu(&nft_trans_set(trans)->list);
			break;
		case NFT_MSG_DELSET:
			trans->ctx.table->use++;
			nft_clear(trans->ctx.net, nft_trans_set(trans));
			nft_trans_destroy(trans);
			break;
		case NFT_MSG_NEWSETELEM:
			if (nft_trans_elem_set_bound(trans)) {
				nft_trans_destroy(trans);
				break;
			}
			te = (struct nft_trans_elem *)trans->data;
			(*klpe_nft_setelem_remove)(net, te->set, &te->elem);
			if (!nft_setelem_is_catchall(te->set, &te->elem))
				atomic_dec(&te->set->nelems);
			break;
		case NFT_MSG_DELSETELEM:
			te = (struct nft_trans_elem *)trans->data;

			klpr_nft_setelem_data_activate(net, te->set, &te->elem);
			(*klpe_nft_setelem_activate)(net, te->set, &te->elem);
			if (!nft_setelem_is_catchall(te->set, &te->elem))
				te->set->ndeact--;

			nft_trans_destroy(trans);
			break;
		case NFT_MSG_NEWOBJ:
			if (nft_trans_obj_update(trans)) {
				kfree(nft_trans_obj_newobj(trans));
				nft_trans_destroy(trans);
			} else {
				trans->ctx.table->use--;
				(*klpe_nft_obj_del)(nft_trans_obj(trans));
			}
			break;
		case NFT_MSG_DELOBJ:
			trans->ctx.table->use++;
			nft_clear(trans->ctx.net, nft_trans_obj(trans));
			nft_trans_destroy(trans);
			break;
		case NFT_MSG_NEWFLOWTABLE:
			if (nft_trans_flowtable_update(trans)) {
				nft_unregister_flowtable_net_hooks(net,
						&nft_trans_flowtable_hooks(trans));
			} else {
				trans->ctx.table->use--;
				list_del_rcu(&nft_trans_flowtable(trans)->list);
				nft_unregister_flowtable_net_hooks(net,
						&nft_trans_flowtable(trans)->hook_list);
			}
			break;
		case NFT_MSG_DELFLOWTABLE:
			if (nft_trans_flowtable_update(trans)) {
				list_for_each_entry(hook, &nft_trans_flowtable(trans)->hook_list, list)
					hook->inactive = false;
			} else {
				trans->ctx.table->use++;
				nft_clear(trans->ctx.net, nft_trans_flowtable(trans));
			}
			nft_trans_destroy(trans);
			break;
		}
	}

	synchronize_rcu();

	list_for_each_entry_safe_reverse(trans, next,
					 &nft_net->commit_list, list) {
		list_del(&trans->list);
		klpr_nf_tables_abort_release(trans);
	}

	if (action == NFNL_ABORT_AUTOLOAD)
		klpr_nf_tables_module_autoload(net);
	else
		(*klpe_nf_tables_module_autoload_cleanup)(net);

	return 0;
}


#include "livepatch_bsc1213584.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nf_tables_chain_destroy", (void *)&klpe_nf_tables_chain_destroy,
	  "nf_tables" },
	{ "nf_tables_flowtable_destroy",
	  (void *)&klpe_nf_tables_flowtable_destroy, "nf_tables" },
	{ "nf_tables_module_autoload_cleanup",
	  (void *)&klpe_nf_tables_module_autoload_cleanup, "nf_tables" },
	{ "nf_tables_net_id", (void *)&klpe_nf_tables_net_id, "nf_tables" },
	{ "nf_tables_rule_destroy", (void *)&klpe_nf_tables_rule_destroy,
	  "nf_tables" },
	{ "nf_tables_unregister_hook", (void *)&klpe_nf_tables_unregister_hook,
	  "nf_tables" },
	{ "nf_tables_validate", (void *)&klpe_nf_tables_validate,
	  "nf_tables" },
	{ "nft_chain_del", (void *)&klpe_nft_chain_del, "nf_tables" },
	{ "nft_data_hold", (void *)&klpe_nft_data_hold, "nf_tables" },
	{ "nft_flow_rule_destroy", (void *)&klpe_nft_flow_rule_destroy,
	  "nf_tables" },
	{ "nft_flowtable_hooks_destroy",
	  (void *)&klpe_nft_flowtable_hooks_destroy, "nf_tables" },
	{ "nft_obj_del", (void *)&klpe_nft_obj_del, "nf_tables" },
	{ "nft_obj_destroy", (void *)&klpe_nft_obj_destroy, "nf_tables" },
	{ "nft_rule_expr_deactivate", (void *)&klpe_nft_rule_expr_deactivate,
	  "nf_tables" },
	{ "nft_set_destroy", (void *)&klpe_nft_set_destroy, "nf_tables" },
	{ "nft_set_elem_destroy", (void *)&klpe_nft_set_elem_destroy,
	  "nf_tables" },
	{ "nft_setelem_activate", (void *)&klpe_nft_setelem_activate,
	  "nf_tables" },
	{ "nft_setelem_remove", (void *)&klpe_nft_setelem_remove,
	  "nf_tables" },
	{ "nft_table_disable", (void *)&klpe_nft_table_disable, "nf_tables" },
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

int bsc1213584_net_netfilter_nf_tables_api_init(void)
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

void bsc1213584_net_netfilter_nf_tables_api_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
