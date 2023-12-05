/*
 * bsc1213584_net_netfilter_nft_immediate
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

/* klp-ccp: from net/netfilter/nft_immediate.c */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>

/* klp-ccp: from include/net/netfilter/nf_tables.h */
static int (*klpe_nft_data_init)(const struct nft_ctx *ctx,
		  struct nft_data *data, unsigned int size,
		  struct nft_data_desc *desc, const struct nlattr *nla);

static void (*klpe_nft_data_release)(const struct nft_data *data, enum nft_data_types type);

static int (*klpe_nft_parse_register_store)(const struct nft_ctx *ctx,
			     const struct nlattr *attr, u8 *dreg,
			     const struct nft_data *data,
			     enum nft_data_types type, unsigned int len);

/* klp-ccp: from net/netfilter/nft_immediate.c */
#include <net/netfilter/nf_tables.h>

#include "livepatch_bsc1213584.h"

int klpp_nft_immediate_init(const struct nft_ctx *ctx,
			      const struct nft_expr *expr,
			      const struct nlattr * const tb[])
{
	struct nft_immediate_expr *priv = nft_expr_priv(expr);
	struct nft_data_desc desc;
	int err;

	if (tb[NFTA_IMMEDIATE_DREG] == NULL ||
	    tb[NFTA_IMMEDIATE_DATA] == NULL)
		return -EINVAL;

	err = (*klpe_nft_data_init)(ctx, &priv->data, sizeof(priv->data), &desc,
			    tb[NFTA_IMMEDIATE_DATA]);
	if (err < 0)
		return err;

	priv->dlen = desc.len;

	err = (*klpe_nft_parse_register_store)(ctx, tb[NFTA_IMMEDIATE_DREG],
				       &priv->dreg, &priv->data, desc.type,
				       desc.len);
	if (err < 0)
		goto err1;

	if (priv->dreg == NFT_REG_VERDICT) {
		struct nft_chain *chain = priv->data.verdict.chain;

		switch (priv->data.verdict.code) {
		case NFT_JUMP:
		case NFT_GOTO:
			err = klpp_nf_tables_bind_chain(ctx, chain);
			if (err < 0)
				goto err1;
			break;
		default:
			break;
		}
	}

	return 0;

err1:
	(*klpe_nft_data_release)(&priv->data, desc.type);
	return err;
}

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nft_data_init", (void *)&klpe_nft_data_init, "nf_tables" },
	{ "nft_data_release", (void *)&klpe_nft_data_release, "nf_tables" },
	{ "nft_parse_register_store", (void *)&klpe_nft_parse_register_store,
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

int bsc1213584_net_netfilter_nft_immediate_init(void)
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

void bsc1213584_net_netfilter_nft_immediate_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
