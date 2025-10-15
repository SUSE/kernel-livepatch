/*
 * livepatch_bsc1249534
 *
 * Fix for CVE-2025-38678, bsc#1249534
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

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <linux/module.h>
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
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_offload.h>
#include <net/net_namespace.h>
#include <net/sock.h>

extern unsigned int nf_tables_net_id __read_mostly;

extern struct list_head nf_tables_flowtables;

extern const struct rhashtable_params nft_chain_ht_params;

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

extern struct nft_trans *nft_trans_alloc_gfp(const struct nft_ctx *ctx,
					     int msg_type, u32 size, gfp_t gfp);

static struct nft_trans *nft_trans_alloc(const struct nft_ctx *ctx,
					 int msg_type, u32 size)
{
	return nft_trans_alloc_gfp(ctx, msg_type, size, GFP_KERNEL);
}

extern void nft_trans_destroy(struct nft_trans *trans);

extern int nft_netdev_register_hooks(struct net *net,
				     struct list_head *hook_list);

extern void nft_netdev_unregister_hooks(struct net *net,
					struct list_head *hook_list,
					bool release_netdev);

static int nf_tables_register_hook(struct net *net,
				   const struct nft_table *table,
				   struct nft_chain *chain)
{
	struct nft_base_chain *basechain;
	const struct nf_hook_ops *ops;

	if (table->flags & NFT_TABLE_F_DORMANT ||
	    !nft_is_base_chain(chain))
		return 0;

	basechain = nft_base_chain(chain);
	ops = &basechain->ops;

	if (basechain->type->ops_register)
		return basechain->type->ops_register(net, ops);

	if (nft_base_chain_netdev(table->family, basechain->ops.hooknum))
		return nft_netdev_register_hooks(net, &basechain->hook_list);

	return nf_register_net_hook(net, &basechain->ops);
}

static void __nf_tables_unregister_hook(struct net *net,
					const struct nft_table *table,
					struct nft_chain *chain,
					bool release_netdev)
{
	struct nft_base_chain *basechain;
	const struct nf_hook_ops *ops;

	if (table->flags & NFT_TABLE_F_DORMANT ||
	    !nft_is_base_chain(chain))
		return;
	basechain = nft_base_chain(chain);
	ops = &basechain->ops;

	if (basechain->type->ops_unregister)
		return basechain->type->ops_unregister(net, ops);

	if (nft_base_chain_netdev(table->family, basechain->ops.hooknum))
		nft_netdev_unregister_hooks(net, &basechain->hook_list,
					    release_netdev);
	else
		nf_unregister_net_hook(net, &basechain->ops);
}

static void nf_tables_unregister_hook(struct net *net,
				      const struct nft_table *table,
				      struct nft_chain *chain)
{
	return __nf_tables_unregister_hook(net, table, chain, false);
}

static void nft_trans_commit_list_add_tail(struct net *net, struct nft_trans *trans)
{
	struct nftables_pernet *nft_net = nft_pernet(net);

	switch (trans->msg_type) {
	case NFT_MSG_NEWSET:
		if (!nft_trans_set_update(trans) &&
		    nft_set_is_anonymous(nft_trans_set(trans)))
			list_add_tail(&trans->binding_list, &nft_net->binding_list);
		break;
	case NFT_MSG_NEWCHAIN:
		if (!nft_trans_chain_update(trans) &&
		    nft_chain_binding(nft_trans_chain(trans)))
			list_add_tail(&trans->binding_list, &nft_net->binding_list);
		break;
	}

	list_add_tail(&trans->list, &nft_net->commit_list);
}

static struct nft_trans *nft_trans_chain_add(struct nft_ctx *ctx, int msg_type)
{
	struct nft_trans *trans;

	trans = nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_chain));
	if (trans == NULL)
		return ERR_PTR(-ENOMEM);

	if (msg_type == NFT_MSG_NEWCHAIN) {
		nft_activate_next(ctx->net, ctx->chain);

		if (ctx->nla[NFTA_CHAIN_ID]) {
			nft_trans_chain_id(trans) =
				ntohl(nla_get_be32(ctx->nla[NFTA_CHAIN_ID]));
		}
	}
	nft_trans_chain(trans) = ctx->chain;
	nft_trans_commit_list_add_tail(ctx->net, trans);

	return trans;
}

static int nft_trans_flowtable_add(struct nft_ctx *ctx, int msg_type,
				   struct nft_flowtable *flowtable)
{
	struct nft_trans *trans;

	trans = nft_trans_alloc(ctx, msg_type,
				sizeof(struct nft_trans_flowtable));
	if (trans == NULL)
		return -ENOMEM;

	if (msg_type == NFT_MSG_NEWFLOWTABLE)
		nft_activate_next(ctx->net, flowtable);

	INIT_LIST_HEAD(&nft_trans_flowtable_hooks(trans));
	nft_trans_flowtable(trans) = flowtable;
	nft_trans_commit_list_add_tail(ctx->net, trans);

	return 0;
}

static struct nft_table *nft_table_lookup(const struct net *net,
					  const struct nlattr *nla,
					  u8 family, u8 genmask, u32 nlpid)
{
	struct nftables_pernet *nft_net;
	struct nft_table *table;

	if (nla == NULL)
		return ERR_PTR(-EINVAL);

	nft_net = nft_pernet(net);
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

#ifdef CONFIG_MODULES
__printf(2, 3) int nft_request_module(struct net *net, const char *fmt,
				      ...);

extern typeof(nft_request_module) nft_request_module;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static void lockdep_nfnl_nft_mutex_not_held(void)
{
#ifdef CONFIG_PROVE_LOCKING
#error "klp-ccp: non-taken branch"
#endif
}

#define __NFT_TABLE_F_INTERNAL		(NFT_TABLE_F_MASK + 1)
#define __NFT_TABLE_F_WAS_DORMANT	(__NFT_TABLE_F_INTERNAL << 0)
#define __NFT_TABLE_F_WAS_AWAKEN	(__NFT_TABLE_F_INTERNAL << 1)
#define __NFT_TABLE_F_UPDATE		(__NFT_TABLE_F_WAS_DORMANT | \
					 __NFT_TABLE_F_WAS_AWAKEN)

static struct nft_chain *
nft_chain_lookup_byhandle(const struct nft_table *table, u64 handle, u8 genmask)
{
	struct nft_chain *chain;

	list_for_each_entry(chain, &table->chains, list) {
		if (chain->handle == handle &&
		    nft_active_genmask(chain, genmask))
			return chain;
	}

	return ERR_PTR(-ENOENT);
}

static bool lockdep_commit_lock_is_held(const struct net *net)
{
#ifdef CONFIG_PROVE_LOCKING
#error "klp-ccp: non-taken branch"
#else
	return true;
#endif
}

static struct nft_chain *nft_chain_lookup(struct net *net,
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
	list = rhltable_lookup(&table->chains_ht, search, nft_chain_ht_params);
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

extern struct nft_stats __percpu *nft_stats_alloc(const struct nlattr *attr);

void nf_tables_chain_destroy(struct nft_ctx *ctx);

static struct nft_hook *nft_hook_list_find(struct list_head *hook_list,
					   const struct nft_hook *this)
{
	struct nft_hook *hook;

	list_for_each_entry(hook, hook_list, list) {
		if (this->ops.dev == hook->ops.dev)
			return hook;
	}

	return NULL;
}

extern int nf_tables_parse_netdev_hooks(struct net *net,
					const struct nlattr *attr,
					struct list_head *hook_list,
					struct netlink_ext_ack *extack);

struct nft_chain_hook {
	u32				num;
	s32				priority;
	const struct nft_chain_type	*type;
	struct list_head		list;
};

extern int nft_chain_parse_hook(struct net *net,
				struct nft_base_chain *basechain,
				const struct nlattr * const nla[],
				struct nft_chain_hook *hook, u8 family,
				u32 flags, struct netlink_ext_ack *extack);

extern void nft_chain_release_hook(struct nft_chain_hook *hook);

static void nft_last_rule(const struct nft_chain *chain, const void *ptr)
{
	struct nft_rule_dp_last *lrule;

	BUILD_BUG_ON(offsetof(struct nft_rule_dp_last, end) != 0);

	lrule = (struct nft_rule_dp_last *)ptr;
	lrule->end.is_last = 1;
	lrule->chain = chain;
	/* blob size does not include the trailer rule */
}

static struct nft_rule_blob *nf_tables_chain_alloc_rules(const struct nft_chain *chain,
							 unsigned int size)
{
	struct nft_rule_blob *blob;

	if (size > INT_MAX)
		return NULL;

	size += sizeof(struct nft_rule_blob) + sizeof(struct nft_rule_dp_last);

	blob = kvmalloc(size, GFP_KERNEL_ACCOUNT);
	if (!blob)
		return NULL;

	blob->size = 0;
	nft_last_rule(chain, blob->data);

	return blob;
}

static void nft_basechain_hook_init(struct nf_hook_ops *ops, u8 family,
				    const struct nft_chain_hook *hook,
				    struct nft_chain *chain)
{
	ops->pf			= family;
	ops->hooknum		= hook->num;
	ops->priority		= hook->priority;
	ops->priv		= chain;
	ops->hook		= hook->type->hooks[ops->hooknum];
	ops->hook_ops_type	= NF_HOOK_OP_NF_TABLES;
}

static int nft_basechain_init(struct nft_base_chain *basechain, u8 family,
			      struct nft_chain_hook *hook, u32 flags)
{
	struct nft_chain *chain;
	struct nft_hook *h;

	basechain->type = hook->type;
	INIT_LIST_HEAD(&basechain->hook_list);
	chain = &basechain->chain;

	if (nft_base_chain_netdev(family, hook->num)) {
		list_splice_init(&hook->list, &basechain->hook_list);
		list_for_each_entry(h, &basechain->hook_list, list)
			nft_basechain_hook_init(&h->ops, family, hook, chain);
	}
	nft_basechain_hook_init(&basechain->ops, family, hook, chain);

	chain->flags |= NFT_CHAIN_BASE | flags;
	basechain->policy = NF_ACCEPT;
	if (chain->flags & NFT_CHAIN_HW_OFFLOAD &&
	    !nft_chain_offload_support(basechain)) {
		list_splice_init(&basechain->hook_list, &hook->list);
		return -EOPNOTSUPP;
	}

	flow_block_init(&basechain->flow_block);

	return 0;
}

int nft_chain_add(struct nft_table *table, struct nft_chain *chain);

extern u64 chain_id;

static int nf_tables_addchain(struct nft_ctx *ctx, u8 family, u8 genmask,
			      u8 policy, u32 flags,
			      struct netlink_ext_ack *extack)
{
	const struct nlattr * const *nla = ctx->nla;
	struct nft_table *table = ctx->table;
	struct nft_base_chain *basechain;
	struct net *net = ctx->net;
	char name[NFT_NAME_MAXLEN];
	struct nft_rule_blob *blob;
	struct nft_trans *trans;
	struct nft_chain *chain;
	int err;

	if (nla[NFTA_CHAIN_HOOK]) {
		struct nft_stats __percpu *stats = NULL;
		struct nft_chain_hook hook = {};

		if (table->flags & __NFT_TABLE_F_UPDATE)
			return -EINVAL;

		if (flags & NFT_CHAIN_BINDING)
			return -EOPNOTSUPP;

		err = nft_chain_parse_hook(net, NULL, nla, &hook, family, flags,
					   extack);
		if (err < 0)
			return err;

		basechain = kzalloc(sizeof(*basechain), GFP_KERNEL_ACCOUNT);
		if (basechain == NULL) {
			nft_chain_release_hook(&hook);
			return -ENOMEM;
		}
		chain = &basechain->chain;

		if (nla[NFTA_CHAIN_COUNTERS]) {
			stats = nft_stats_alloc(nla[NFTA_CHAIN_COUNTERS]);
			if (IS_ERR(stats)) {
				nft_chain_release_hook(&hook);
				kfree(basechain);
				return PTR_ERR(stats);
			}
			rcu_assign_pointer(basechain->stats, stats);
		}

		err = nft_basechain_init(basechain, family, &hook, flags);
		if (err < 0) {
			nft_chain_release_hook(&hook);
			kfree(basechain);
			free_percpu(stats);
			return err;
		}
		if (stats)
			static_branch_inc(&nft_counters_enabled);
	} else {
		if (flags & NFT_CHAIN_BASE)
			return -EINVAL;
		if (flags & NFT_CHAIN_HW_OFFLOAD)
			return -EOPNOTSUPP;

		chain = kzalloc(sizeof(*chain), GFP_KERNEL_ACCOUNT);
		if (chain == NULL)
			return -ENOMEM;

		chain->flags = flags;
	}
	ctx->chain = chain;

	INIT_LIST_HEAD(&chain->rules);
	chain->handle = nf_tables_alloc_handle(table);
	chain->table = table;

	if (nla[NFTA_CHAIN_NAME]) {
		chain->name = nla_strdup(nla[NFTA_CHAIN_NAME], GFP_KERNEL_ACCOUNT);
	} else {
		if (!(flags & NFT_CHAIN_BINDING)) {
			err = -EINVAL;
			goto err_destroy_chain;
		}

		snprintf(name, sizeof(name), "__chain%llu", ++chain_id);
		chain->name = kstrdup(name, GFP_KERNEL_ACCOUNT);
	}

	if (!chain->name) {
		err = -ENOMEM;
		goto err_destroy_chain;
	}

	if (nla[NFTA_CHAIN_USERDATA]) {
		chain->udata = nla_memdup(nla[NFTA_CHAIN_USERDATA], GFP_KERNEL_ACCOUNT);
		if (chain->udata == NULL) {
			err = -ENOMEM;
			goto err_destroy_chain;
		}
		chain->udlen = nla_len(nla[NFTA_CHAIN_USERDATA]);
	}

	blob = nf_tables_chain_alloc_rules(chain, 0);
	if (!blob) {
		err = -ENOMEM;
		goto err_destroy_chain;
	}

	RCU_INIT_POINTER(chain->blob_gen_0, blob);
	RCU_INIT_POINTER(chain->blob_gen_1, blob);

	err = nf_tables_register_hook(net, table, chain);
	if (err < 0)
		goto err_destroy_chain;

	if (!nft_use_inc(&table->use)) {
		err = -EMFILE;
		goto err_use;
	}

	trans = nft_trans_chain_add(ctx, NFT_MSG_NEWCHAIN);
	if (IS_ERR(trans)) {
		err = PTR_ERR(trans);
		goto err_unregister_hook;
	}

	nft_trans_chain_policy(trans) = NFT_CHAIN_POLICY_UNSET;
	if (nft_is_base_chain(chain))
		nft_trans_chain_policy(trans) = policy;

	err = nft_chain_add(table, chain);
	if (err < 0) {
		nft_trans_destroy(trans);
		goto err_unregister_hook;
	}

	return 0;

err_unregister_hook:
	nft_use_dec_restore(&table->use);
err_use:
	nf_tables_unregister_hook(net, table, chain);
err_destroy_chain:
	nf_tables_chain_destroy(ctx);

	return err;
}

static int klpp_nf_tables_updchain(struct nft_ctx *ctx, u8 genmask, u8 policy,
			      u32 flags, const struct nlattr *attr,
			      struct netlink_ext_ack *extack)
{
	const struct nlattr * const *nla = ctx->nla;
	struct nft_base_chain *basechain = NULL;
	struct nft_table *table = ctx->table;
	struct nft_chain *chain = ctx->chain;
	struct nft_chain_hook hook = {};
	struct nft_stats *stats = NULL;
	struct nftables_pernet *nft_net;
	struct nft_hook *h, *next;
	struct nf_hook_ops *ops;
	struct nft_trans *trans;
	bool unregister = false;
	int err;

	if (chain->flags ^ flags)
		return -EOPNOTSUPP;

	INIT_LIST_HEAD(&hook.list);

	if (nla[NFTA_CHAIN_HOOK]) {
		if (!nft_is_base_chain(chain)) {
			NL_SET_BAD_ATTR(extack, attr);
			return -EEXIST;
		}

		basechain = nft_base_chain(chain);
		err = nft_chain_parse_hook(ctx->net, basechain, nla, &hook,
					   ctx->family, flags, extack);
		if (err < 0)
			return err;

		if (basechain->type != hook.type) {
			nft_chain_release_hook(&hook);
			NL_SET_BAD_ATTR(extack, attr);
			return -EEXIST;
		}

		if (nft_base_chain_netdev(ctx->family, basechain->ops.hooknum)) {
			list_for_each_entry_safe(h, next, &hook.list, list) {
				h->ops.pf	= basechain->ops.pf;
				h->ops.hooknum	= basechain->ops.hooknum;
				h->ops.priority	= basechain->ops.priority;
				h->ops.priv	= basechain->ops.priv;
				h->ops.hook	= basechain->ops.hook;

				if (nft_hook_list_find(&basechain->hook_list, h)) {
					list_del(&h->list);
					kfree(h);
					continue;
				}

				nft_net = nft_pernet(ctx->net);
				list_for_each_entry(trans, &nft_net->commit_list, list) {
					if (trans->msg_type != NFT_MSG_NEWCHAIN ||
					    trans->ctx.table != ctx->table ||
					    !nft_trans_chain_update(trans))
						continue;

					if (nft_hook_list_find(&nft_trans_chain_hooks(trans), h)) {
						nft_chain_release_hook(&hook);
						return -EEXIST;
					}
				}
			}
		} else {
			ops = &basechain->ops;
			if (ops->hooknum != hook.num ||
			    ops->priority != hook.priority) {
				nft_chain_release_hook(&hook);
				NL_SET_BAD_ATTR(extack, attr);
				return -EEXIST;
			}
		}
	}

	if (nla[NFTA_CHAIN_HANDLE] &&
	    nla[NFTA_CHAIN_NAME]) {
		struct nft_chain *chain2;

		chain2 = nft_chain_lookup(ctx->net, table,
					  nla[NFTA_CHAIN_NAME], genmask);
		if (!IS_ERR(chain2)) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_CHAIN_NAME]);
			err = -EEXIST;
			goto err_hooks;
		}
	}

	if (table->flags & __NFT_TABLE_F_UPDATE &&
	    !list_empty(&hook.list)) {
		NL_SET_BAD_ATTR(extack, attr);
		err = -EOPNOTSUPP;
		goto err_hooks;
	}

	if (!(table->flags & NFT_TABLE_F_DORMANT) &&
	    nft_is_base_chain(chain) &&
	    !list_empty(&hook.list)) {
		basechain = nft_base_chain(chain);
		ops = &basechain->ops;

		if (nft_base_chain_netdev(table->family, basechain->ops.hooknum)) {
			err = nft_netdev_register_hooks(ctx->net, &hook.list);
			if (err < 0)
				goto err_hooks;

			unregister = true;
		}
	}

	if (nla[NFTA_CHAIN_COUNTERS]) {
		if (!nft_is_base_chain(chain)) {
			err = -EOPNOTSUPP;
			goto err_hooks;
		}

		stats = nft_stats_alloc(nla[NFTA_CHAIN_COUNTERS]);
		if (IS_ERR(stats)) {
			err = PTR_ERR(stats);
			goto err_hooks;
		}
	}

	err = -ENOMEM;
	trans = nft_trans_alloc(ctx, NFT_MSG_NEWCHAIN,
				sizeof(struct nft_trans_chain));
	if (trans == NULL)
		goto err_trans;

	nft_trans_chain_stats(trans) = stats;
	nft_trans_chain_update(trans) = true;

	if (nla[NFTA_CHAIN_POLICY])
		nft_trans_chain_policy(trans) = policy;
	else
		nft_trans_chain_policy(trans) = -1;

	if (nla[NFTA_CHAIN_HANDLE] &&
	    nla[NFTA_CHAIN_NAME]) {
		struct nftables_pernet *nft_net = nft_pernet(ctx->net);
		struct nft_trans *tmp;
		char *name;

		err = -ENOMEM;
		name = nla_strdup(nla[NFTA_CHAIN_NAME], GFP_KERNEL_ACCOUNT);
		if (!name)
			goto err_trans;

		err = -EEXIST;
		list_for_each_entry(tmp, &nft_net->commit_list, list) {
			if (tmp->msg_type == NFT_MSG_NEWCHAIN &&
			    tmp->ctx.table == table &&
			    nft_trans_chain_update(tmp) &&
			    nft_trans_chain_name(tmp) &&
			    strcmp(name, nft_trans_chain_name(tmp)) == 0) {
				NL_SET_BAD_ATTR(extack, nla[NFTA_CHAIN_NAME]);
				kfree(name);
				goto err_trans;
			}
		}

		nft_trans_chain_name(trans) = name;
	}

	nft_trans_basechain(trans) = basechain;
	INIT_LIST_HEAD(&nft_trans_chain_hooks(trans));
	list_splice(&hook.list, &nft_trans_chain_hooks(trans));
	if (nla[NFTA_CHAIN_HOOK])
		module_put(hook.type->owner);

	nft_trans_commit_list_add_tail(ctx->net, trans);

	return 0;

err_trans:
	free_percpu(stats);
	kfree(trans);
err_hooks:
	if (nla[NFTA_CHAIN_HOOK]) {
		list_for_each_entry_safe(h, next, &hook.list, list) {
			if (unregister)
				nf_unregister_net_hook(ctx->net, &h->ops);
			list_del(&h->list);
			kfree_rcu(h, rcu);
		}
		module_put(hook.type->owner);
	}

	return err;
}

int klpp_nf_tables_newchain(struct sk_buff *skb, const struct nfnl_info *info,
			      const struct nlattr * const nla[])
{
	struct nftables_pernet *nft_net = nft_pernet(info->net);
	struct netlink_ext_ack *extack = info->extack;
	u8 genmask = nft_genmask_next(info->net);
	u8 family = info->nfmsg->nfgen_family;
	struct nft_chain *chain = NULL;
	struct net *net = info->net;
	const struct nlattr *attr;
	struct nft_table *table;
	u8 policy = NF_ACCEPT;
	struct nft_ctx ctx;
	u64 handle = 0;
	u32 flags = 0;

	lockdep_assert_held(&nft_net->commit_mutex);

	table = nft_table_lookup(net, nla[NFTA_CHAIN_TABLE], family, genmask,
				 NETLINK_CB(skb).portid);
	if (IS_ERR(table)) {
		NL_SET_BAD_ATTR(extack, nla[NFTA_CHAIN_TABLE]);
		return PTR_ERR(table);
	}

	chain = NULL;
	attr = nla[NFTA_CHAIN_NAME];

	if (nla[NFTA_CHAIN_HANDLE]) {
		handle = be64_to_cpu(nla_get_be64(nla[NFTA_CHAIN_HANDLE]));
		chain = nft_chain_lookup_byhandle(table, handle, genmask);
		if (IS_ERR(chain)) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_CHAIN_HANDLE]);
			return PTR_ERR(chain);
		}
		attr = nla[NFTA_CHAIN_HANDLE];
	} else if (nla[NFTA_CHAIN_NAME]) {
		chain = nft_chain_lookup(net, table, attr, genmask);
		if (IS_ERR(chain)) {
			if (PTR_ERR(chain) != -ENOENT) {
				NL_SET_BAD_ATTR(extack, attr);
				return PTR_ERR(chain);
			}
			chain = NULL;
		}
	} else if (!nla[NFTA_CHAIN_ID]) {
		return -EINVAL;
	}

	if (nla[NFTA_CHAIN_POLICY]) {
		if (chain != NULL &&
		    !nft_is_base_chain(chain)) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_CHAIN_POLICY]);
			return -EOPNOTSUPP;
		}

		if (chain == NULL &&
		    nla[NFTA_CHAIN_HOOK] == NULL) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_CHAIN_POLICY]);
			return -EOPNOTSUPP;
		}

		policy = ntohl(nla_get_be32(nla[NFTA_CHAIN_POLICY]));
		switch (policy) {
		case NF_DROP:
		case NF_ACCEPT:
			break;
		default:
			return -EINVAL;
		}
	}

	if (nla[NFTA_CHAIN_FLAGS])
		flags = ntohl(nla_get_be32(nla[NFTA_CHAIN_FLAGS]));
	else if (chain)
		flags = chain->flags;

	if (flags & ~NFT_CHAIN_FLAGS)
		return -EOPNOTSUPP;

	nft_ctx_init(&ctx, net, skb, info->nlh, family, table, chain, nla);

	if (chain != NULL) {
		if (chain->flags & NFT_CHAIN_BINDING)
			return -EINVAL;

		if (info->nlh->nlmsg_flags & NLM_F_EXCL) {
			NL_SET_BAD_ATTR(extack, attr);
			return -EEXIST;
		}
		if (info->nlh->nlmsg_flags & NLM_F_REPLACE)
			return -EOPNOTSUPP;

		flags |= chain->flags & NFT_CHAIN_BASE;
		return klpp_nf_tables_updchain(&ctx, genmask, policy, flags, attr,
					  extack);
	}

	return nf_tables_addchain(&ctx, family, genmask, policy, flags, extack);
}

struct nft_flowtable *nft_flowtable_lookup(const struct nft_table *table,
					   const struct nlattr *nla, u8 genmask);

extern typeof(nft_flowtable_lookup) nft_flowtable_lookup;

struct nft_flowtable_hook {
	u32			num;
	int			priority;
	struct list_head	list;
};

extern const struct nla_policy nft_flowtable_hook_policy[NFTA_FLOWTABLE_HOOK_MAX + 1];

static int nft_flowtable_parse_hook(const struct nft_ctx *ctx,
				    const struct nlattr * const nla[],
				    struct nft_flowtable_hook *flowtable_hook,
				    struct nft_flowtable *flowtable,
				    struct netlink_ext_ack *extack, bool add)
{
	struct nlattr *tb[NFTA_FLOWTABLE_HOOK_MAX + 1];
	struct nft_hook *hook;
	int hooknum, priority;
	int err;

	INIT_LIST_HEAD(&flowtable_hook->list);

	err = nla_parse_nested_deprecated(tb, NFTA_FLOWTABLE_HOOK_MAX,
					  nla[NFTA_FLOWTABLE_HOOK],
					  nft_flowtable_hook_policy, NULL);
	if (err < 0)
		return err;

	if (add) {
		if (!tb[NFTA_FLOWTABLE_HOOK_NUM] ||
		    !tb[NFTA_FLOWTABLE_HOOK_PRIORITY]) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_FLOWTABLE_NAME]);
			return -ENOENT;
		}

		hooknum = ntohl(nla_get_be32(tb[NFTA_FLOWTABLE_HOOK_NUM]));
		if (hooknum != NF_NETDEV_INGRESS)
			return -EOPNOTSUPP;

		priority = ntohl(nla_get_be32(tb[NFTA_FLOWTABLE_HOOK_PRIORITY]));

		flowtable_hook->priority	= priority;
		flowtable_hook->num		= hooknum;
	} else {
		if (tb[NFTA_FLOWTABLE_HOOK_NUM]) {
			hooknum = ntohl(nla_get_be32(tb[NFTA_FLOWTABLE_HOOK_NUM]));
			if (hooknum != flowtable->hooknum)
				return -EOPNOTSUPP;
		}

		if (tb[NFTA_FLOWTABLE_HOOK_PRIORITY]) {
			priority = ntohl(nla_get_be32(tb[NFTA_FLOWTABLE_HOOK_PRIORITY]));
			if (priority != flowtable->data.priority)
				return -EOPNOTSUPP;
		}

		flowtable_hook->priority	= flowtable->data.priority;
		flowtable_hook->num		= flowtable->hooknum;
	}

	if (tb[NFTA_FLOWTABLE_HOOK_DEVS]) {
		err = nf_tables_parse_netdev_hooks(ctx->net,
						   tb[NFTA_FLOWTABLE_HOOK_DEVS],
						   &flowtable_hook->list,
						   extack);
		if (err < 0)
			return err;
	}

	list_for_each_entry(hook, &flowtable_hook->list, list) {
		hook->ops.pf		= NFPROTO_NETDEV;
		hook->ops.hooknum	= flowtable_hook->num;
		hook->ops.priority	= flowtable_hook->priority;
		hook->ops.priv		= &flowtable->data;
		hook->ops.hook		= flowtable->data.type->hook;
	}

	return err;
}

static const struct nf_flowtable_type *__nft_flowtable_type_get(u8 family)
{
	const struct nf_flowtable_type *type;

	list_for_each_entry_rcu(type, &nf_tables_flowtables, list) {
		if (family == type->family)
			return type;
	}
	return NULL;
}

static const struct nf_flowtable_type *
nft_flowtable_type_get(struct net *net, u8 family)
{
	const struct nf_flowtable_type *type;

	rcu_read_lock();
	type = __nft_flowtable_type_get(family);
	if (type != NULL && try_module_get(type->owner)) {
		rcu_read_unlock();
		return type;
	}
	rcu_read_unlock();

	lockdep_nfnl_nft_mutex_not_held();
#ifdef CONFIG_MODULES
	if (type == NULL) {
		if (nft_request_module(net, "nf-flowtable-%u", family) == -EAGAIN)
			return ERR_PTR(-EAGAIN);
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return ERR_PTR(-ENOENT);
}

static void nft_unregister_flowtable_hook(struct net *net,
					  struct nft_flowtable *flowtable,
					  struct nft_hook *hook)
{
	nf_unregister_net_hook(net, &hook->ops);
	flowtable->data.type->setup(&flowtable->data, hook->ops.dev,
				    FLOW_BLOCK_UNBIND);
}

extern int nft_register_flowtable_net_hooks(struct net *net,
					    struct nft_table *table,
					    struct list_head *hook_list,
					    struct nft_flowtable *flowtable);

extern void nft_hooks_destroy(struct list_head *hook_list);

static int klpp_nft_flowtable_update(struct nft_ctx *ctx, const struct nlmsghdr *nlh,
				struct nft_flowtable *flowtable,
				struct netlink_ext_ack *extack)
{
	const struct nlattr * const *nla = ctx->nla;
	struct nft_flowtable_hook flowtable_hook;
	struct nftables_pernet *nft_net;
	struct nft_hook *hook, *next;
	struct nft_trans *trans;
	bool unregister = false;
	u32 flags;
	int err;

	err = nft_flowtable_parse_hook(ctx, nla, &flowtable_hook, flowtable,
				       extack, false);
	if (err < 0)
		return err;

	list_for_each_entry_safe(hook, next, &flowtable_hook.list, list) {
		if (nft_hook_list_find(&flowtable->hook_list, hook)) {
			list_del(&hook->list);
			kfree(hook);
			continue;
		}

		nft_net = nft_pernet(ctx->net);
		list_for_each_entry(trans, &nft_net->commit_list, list) {
			if (trans->msg_type != NFT_MSG_NEWFLOWTABLE ||
			    trans->ctx.table != ctx->table ||
			    !nft_trans_flowtable_update(trans))
				continue;

			if (nft_hook_list_find(&nft_trans_flowtable_hooks(trans), hook)) {
				err = -EEXIST;
				goto err_flowtable_update_hook;
			}
		}
	}

	if (nla[NFTA_FLOWTABLE_FLAGS]) {
		flags = ntohl(nla_get_be32(nla[NFTA_FLOWTABLE_FLAGS]));
		if (flags & ~NFT_FLOWTABLE_MASK) {
			err = -EOPNOTSUPP;
			goto err_flowtable_update_hook;
		}
		if ((flowtable->data.flags & NFT_FLOWTABLE_HW_OFFLOAD) ^
		    (flags & NFT_FLOWTABLE_HW_OFFLOAD)) {
			err = -EOPNOTSUPP;
			goto err_flowtable_update_hook;
		}
	} else {
		flags = flowtable->data.flags;
	}

	err = nft_register_flowtable_net_hooks(ctx->net, ctx->table,
					       &flowtable_hook.list, flowtable);
	if (err < 0)
		goto err_flowtable_update_hook;

	trans = nft_trans_alloc(ctx, NFT_MSG_NEWFLOWTABLE,
				sizeof(struct nft_trans_flowtable));
	if (!trans) {
		unregister = true;
		err = -ENOMEM;
		goto err_flowtable_update_hook;
	}

	nft_trans_flowtable_flags(trans) = flags;
	nft_trans_flowtable(trans) = flowtable;
	nft_trans_flowtable_update(trans) = true;
	INIT_LIST_HEAD(&nft_trans_flowtable_hooks(trans));
	list_splice(&flowtable_hook.list, &nft_trans_flowtable_hooks(trans));

	nft_trans_commit_list_add_tail(ctx->net, trans);

	return 0;

err_flowtable_update_hook:
	list_for_each_entry_safe(hook, next, &flowtable_hook.list, list) {
		if (unregister)
			nft_unregister_flowtable_hook(ctx->net, flowtable, hook);
		list_del_rcu(&hook->list);
		kfree_rcu(hook, rcu);
	}

	return err;

}

int klpp_nf_tables_newflowtable(struct sk_buff *skb,
				  const struct nfnl_info *info,
				  const struct nlattr * const nla[])
{
	struct netlink_ext_ack *extack = info->extack;
	struct nft_flowtable_hook flowtable_hook;
	u8 genmask = nft_genmask_next(info->net);
	u8 family = info->nfmsg->nfgen_family;
	const struct nf_flowtable_type *type;
	struct nft_flowtable *flowtable;
	struct nft_hook *hook, *next;
	struct net *net = info->net;
	struct nft_table *table;
	struct nft_ctx ctx;
	int err;

	if (!nla[NFTA_FLOWTABLE_TABLE] ||
	    !nla[NFTA_FLOWTABLE_NAME] ||
	    !nla[NFTA_FLOWTABLE_HOOK])
		return -EINVAL;

	table = nft_table_lookup(net, nla[NFTA_FLOWTABLE_TABLE], family,
				 genmask, NETLINK_CB(skb).portid);
	if (IS_ERR(table)) {
		NL_SET_BAD_ATTR(extack, nla[NFTA_FLOWTABLE_TABLE]);
		return PTR_ERR(table);
	}

	flowtable = nft_flowtable_lookup(table, nla[NFTA_FLOWTABLE_NAME],
					 genmask);
	if (IS_ERR(flowtable)) {
		err = PTR_ERR(flowtable);
		if (err != -ENOENT) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_FLOWTABLE_NAME]);
			return err;
		}
	} else {
		if (info->nlh->nlmsg_flags & NLM_F_EXCL) {
			NL_SET_BAD_ATTR(extack, nla[NFTA_FLOWTABLE_NAME]);
			return -EEXIST;
		}

		nft_ctx_init(&ctx, net, skb, info->nlh, family, table, NULL, nla);

		return klpp_nft_flowtable_update(&ctx, info->nlh, flowtable, extack);
	}

	nft_ctx_init(&ctx, net, skb, info->nlh, family, table, NULL, nla);

	if (!nft_use_inc(&table->use))
		return -EMFILE;

	flowtable = kzalloc(sizeof(*flowtable), GFP_KERNEL_ACCOUNT);
	if (!flowtable) {
		err = -ENOMEM;
		goto flowtable_alloc;
	}

	flowtable->table = table;
	flowtable->handle = nf_tables_alloc_handle(table);
	INIT_LIST_HEAD(&flowtable->hook_list);

	flowtable->name = nla_strdup(nla[NFTA_FLOWTABLE_NAME], GFP_KERNEL_ACCOUNT);
	if (!flowtable->name) {
		err = -ENOMEM;
		goto err1;
	}

	type = nft_flowtable_type_get(net, family);
	if (IS_ERR(type)) {
		err = PTR_ERR(type);
		goto err2;
	}

	if (nla[NFTA_FLOWTABLE_FLAGS]) {
		flowtable->data.flags =
			ntohl(nla_get_be32(nla[NFTA_FLOWTABLE_FLAGS]));
		if (flowtable->data.flags & ~NFT_FLOWTABLE_MASK) {
			err = -EOPNOTSUPP;
			goto err3;
		}
	}

	write_pnet(&flowtable->data.net, net);
	flowtable->data.type = type;
	err = type->init(&flowtable->data);
	if (err < 0)
		goto err3;

	err = nft_flowtable_parse_hook(&ctx, nla, &flowtable_hook, flowtable,
				       extack, true);
	if (err < 0)
		goto err4;

	list_splice(&flowtable_hook.list, &flowtable->hook_list);
	flowtable->data.priority = flowtable_hook.priority;
	flowtable->hooknum = flowtable_hook.num;

	err = nft_register_flowtable_net_hooks(ctx.net, table,
					       &flowtable->hook_list,
					       flowtable);
	if (err < 0) {
		nft_hooks_destroy(&flowtable->hook_list);
		goto err4;
	}

	err = nft_trans_flowtable_add(&ctx, NFT_MSG_NEWFLOWTABLE, flowtable);
	if (err < 0)
		goto err5;

	list_add_tail_rcu(&flowtable->list, &table->flowtables);

	return 0;
err5:
	list_for_each_entry_safe(hook, next, &flowtable->hook_list, list) {
		nft_unregister_flowtable_hook(net, flowtable, hook);
		list_del_rcu(&hook->list);
		kfree_rcu(hook, rcu);
	}
err4:
	flowtable->data.type->free(&flowtable->data);
err3:
	module_put(type->owner);
err2:
	kfree(flowtable->name);
err1:
	kfree(flowtable);
flowtable_alloc:
	nft_use_dec_restore(&table->use);

	return err;
}


#include "livepatch_bsc1249534.h"

#include <linux/livepatch.h>

extern typeof(chain_id) chain_id
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, chain_id);
extern typeof(nf_tables_chain_destroy) nf_tables_chain_destroy
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nf_tables_chain_destroy);
extern typeof(nf_tables_flowtables) nf_tables_flowtables
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nf_tables_flowtables);
extern typeof(nf_tables_net_id) nf_tables_net_id
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nf_tables_net_id);
extern typeof(nf_tables_parse_netdev_hooks) nf_tables_parse_netdev_hooks
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nf_tables_parse_netdev_hooks);
extern typeof(nft_chain_add) nft_chain_add
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_chain_add);
extern typeof(nft_chain_ht_params) nft_chain_ht_params
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_chain_ht_params);
extern typeof(nft_chain_offload_support) nft_chain_offload_support
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_chain_offload_support);
extern typeof(nft_chain_parse_hook) nft_chain_parse_hook
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_chain_parse_hook);
extern typeof(nft_chain_release_hook) nft_chain_release_hook
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_chain_release_hook);
extern typeof(nft_counters_enabled) nft_counters_enabled
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_counters_enabled);
extern typeof(nft_flowtable_hook_policy) nft_flowtable_hook_policy
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_flowtable_hook_policy);
extern typeof(nft_flowtable_lookup) nft_flowtable_lookup
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_flowtable_lookup);
extern typeof(nft_hooks_destroy) nft_hooks_destroy
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_hooks_destroy);
extern typeof(nft_netdev_register_hooks) nft_netdev_register_hooks
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_netdev_register_hooks);
extern typeof(nft_netdev_unregister_hooks) nft_netdev_unregister_hooks
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_netdev_unregister_hooks);
extern typeof(nft_register_flowtable_net_hooks) nft_register_flowtable_net_hooks
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_register_flowtable_net_hooks);
extern typeof(nft_request_module) nft_request_module
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_request_module);
extern typeof(nft_stats_alloc) nft_stats_alloc
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_stats_alloc);
extern typeof(nft_trans_alloc_gfp) nft_trans_alloc_gfp
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_trans_alloc_gfp);
extern typeof(nft_trans_destroy) nft_trans_destroy
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_trans_destroy);
