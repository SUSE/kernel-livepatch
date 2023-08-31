/*
 * bsc1211187_net_netfilter_nf_tables_api
 *
 * Fix for CVE-2023-32233, bsc#1211187
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

/* klp-ccp: from include/linux/netfilter/nfnetlink.h */
static int (*klpe_nfnetlink_has_listeners)(struct net *net, unsigned int group);

static int (*klpe_nfnetlink_set_err)(struct net *net, u32 portid, u32 group, int error);

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_tables_core.h>

static unsigned int (*klpe_nf_tables_net_id);

static inline struct nftables_pernet *klpr_nft_pernet(const struct net *net)
{
	return net_generic(net, (*klpe_nf_tables_net_id));
}

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <net/netfilter/nf_tables.h>
#include <net/net_namespace.h>

struct nftnl_skb_parms {
	bool report;
};
#define NFT_CB(skb)	(*(struct nftnl_skb_parms*)&((skb)->cb))

static void nft_notify_enqueue(struct sk_buff *skb, bool report,
			       struct list_head *notify_list)
{
	NFT_CB(skb).report = report;
	list_add_tail(&skb->list, notify_list);
}

static int (*klpe_nf_tables_fill_set)(struct sk_buff *skb, const struct nft_ctx *ctx,
			      const struct nft_set *set, u16 event, u16 flags);

static void klpr_nf_tables_set_notify(const struct nft_ctx *ctx,
				 const struct nft_set *set, int event,
			         gfp_t gfp_flags)
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(ctx->net);
	u32 portid = ctx->portid;
	struct sk_buff *skb;
	u16 flags = 0;
	int err;

	if (!ctx->report &&
	    !(*klpe_nfnetlink_has_listeners)(ctx->net, NFNLGRP_NFTABLES))
		return;

	skb = nlmsg_new(NLMSG_GOODSIZE, gfp_flags);
	if (skb == NULL)
		goto err;

	if (ctx->flags & (NLM_F_CREATE | NLM_F_EXCL))
		flags |= ctx->flags & (NLM_F_CREATE | NLM_F_EXCL);

	err = (*klpe_nf_tables_fill_set)(skb, ctx, set, event, flags);
	if (err < 0) {
		kfree_skb(skb);
		goto err;
	}

	nft_notify_enqueue(skb, ctx->report, &nft_net->notify_list);
	return;
err:
	(*klpe_nfnetlink_set_err)(ctx->net, portid, NFNLGRP_NFTABLES, -ENOBUFS);
}

static void klpr_nf_tables_unbind_set(const struct nft_ctx *ctx, struct nft_set *set,
				 struct nft_set_binding *binding, bool event)
{
	list_del_rcu(&binding->list);

	if (list_empty(&set->bindings) && nft_set_is_anonymous(set)) {
		list_del_rcu(&set->list);
		if (event)
			klpr_nf_tables_set_notify(ctx, set, NFT_MSG_DELSET,
					     GFP_KERNEL);
	}
}

void nf_tables_activate_set(const struct nft_ctx *ctx, struct nft_set *set)
{
	if (nft_set_is_anonymous(set))
		nft_clear(ctx->net, set);

	set->use++;
}

void klpp_nf_tables_deactivate_set(const struct nft_ctx *ctx, struct nft_set *set,
			      struct nft_set_binding *binding,
			      enum nft_trans_phase phase)
{
	switch (phase) {
	case NFT_TRANS_PREPARE:
		if (nft_set_is_anonymous(set))
			nft_deactivate_next(ctx->net, set);

		set->use--;
		return;
	case NFT_TRANS_ABORT:
	case NFT_TRANS_RELEASE:
		set->use--;
		fallthrough;
	default:
		klpr_nf_tables_unbind_set(ctx, set, binding,
				     phase == NFT_TRANS_COMMIT);
	}
}



#include "livepatch_bsc1211187.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nf_tables_fill_set", (void *)&klpe_nf_tables_fill_set,
	  "nf_tables" },
	{ "nf_tables_net_id", (void *)&klpe_nf_tables_net_id, "nf_tables" },
	{ "nfnetlink_has_listeners", (void *)&klpe_nfnetlink_has_listeners,
	  "nfnetlink" },
	{ "nfnetlink_set_err", (void *)&klpe_nfnetlink_set_err, "nfnetlink" },
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

int bsc1211187_net_netfilter_nf_tables_api_init(void)
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

void bsc1211187_net_netfilter_nf_tables_api_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
