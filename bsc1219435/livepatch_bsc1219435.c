/*
 * livepatch_bsc1219435
 *
 * Fix for CVE-2024-1086, bsc#1219435
 *
 *  Upstream commit:
 *  f342de4e2f33 ("netfilter: nf_tables: reject QUEUE/DROP verdict parameters")
 *
 *  SLE12-SP5 commit:
 *  1f429032c0f635a82a6498fa6af4ee221478157d
 *
 *  SLE15-SP2 and -SP3 commit:
 *  33a2cdd70c1e180b31f92aa5fd2a3785693608a7
 *
 *  SLE15-SP4 and SLE15-SP5 commit:
 *  5f917ff63572e2a68dd0fb81f77be37e9dcb1078
 *
 *
 *  Copyright (c) 2024 SUSE
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

#if !IS_MODULE(CONFIG_NF_TABLES)
#error "Live patch supports only CONFIG_NF_TABLES=m"
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
#include <net/netfilter/nf_tables.h>
#include <net/net_namespace.h>

static const struct rhashtable_params (*klpe_nft_chain_ht_params);

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

static struct nft_chain *(*klpe_nft_chain_lookup_byid)(const struct net *net,
					       const struct nft_table *table,
					       const struct nlattr *nla, u8 genmask);

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
	case NF_ACCEPT:
	case NF_DROP:
	case NF_QUEUE:
		break;
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
			chain = (*klpe_nft_chain_lookup_byid)(ctx->net, ctx->table,
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
	default:
		return -EINVAL;
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



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1219435.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nft_chain_ht_params", (void *)&klpe_nft_chain_ht_params,
	  "nf_tables" },
	{ "nft_chain_lookup_byid", (void *)&klpe_nft_chain_lookup_byid,
	  "nf_tables" },
	{ "nft_data_policy", (void *)&klpe_nft_data_policy, "nf_tables" },
	{ "nft_verdict_policy", (void *)&klpe_nft_verdict_policy, "nf_tables" },
};

static int livepatch_bsc1219435_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1219435_module_nb = {
	.notifier_call = livepatch_bsc1219435_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1219435_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&livepatch_bsc1219435_module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LIVEPATCHED_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						  ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&livepatch_bsc1219435_module_nb);

	module_put(mod);
	return ret;
}

void livepatch_bsc1219435_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1219435_module_nb);
}
