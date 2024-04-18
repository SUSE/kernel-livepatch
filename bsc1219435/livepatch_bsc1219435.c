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
#include <linux/module.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
#include <net/net_namespace.h>

static struct nft_chain *(*klpe_nf_tables_chain_lookup)(const struct nft_table *table,
						const struct nlattr *nla,
						u8 genmask);

static const struct nla_policy (*klpe_nft_verdict_policy)[NFTA_VERDICT_MAX + 1];

static int klpp_nft_verdict_init(const struct nft_ctx *ctx, struct nft_data *data,
			    struct nft_data_desc *desc, const struct nlattr *nla)
{
	u8 genmask = nft_genmask_next(ctx->net);
	struct nlattr *tb[NFTA_VERDICT_MAX + 1];
	struct nft_chain *chain;
	int err;

	err = nla_parse_nested(tb, NFTA_VERDICT_MAX, nla, (*klpe_nft_verdict_policy),
			       NULL);
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
		if (!tb[NFTA_VERDICT_CHAIN])
			return -EINVAL;
		chain = (*klpe_nf_tables_chain_lookup)(ctx->table,
					       tb[NFTA_VERDICT_CHAIN], genmask);
		if (IS_ERR(chain))
			return PTR_ERR(chain);
		if (nft_is_base_chain(chain))
			return -EOPNOTSUPP;

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

	err = nla_parse_nested(tb, NFTA_DATA_MAX, nla, (*klpe_nft_data_policy), NULL);
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
	{ "nf_tables_chain_lookup", (void *)&klpe_nf_tables_chain_lookup,
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

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
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

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1219435_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1219435_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1219435_module_nb);
}
