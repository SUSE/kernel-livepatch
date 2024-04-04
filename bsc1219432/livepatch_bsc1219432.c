/*
 * livepatch_bsc1219432
 *
 * Fix for CVE-2024-1085, bsc#1219432
 *
 *  Upstream commit:
 *  b1db244ffd04 ("netfilter: nf_tables: check if catch-all set element is
 *                 active in next generation")
 *
 *  SLE12-SP5 commit:
 *  not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  not affected
 *
 *  SLE15-SP4 and SLE15-SP5 commit:
 *  7b3f4c4f5afc04ef65072eeecf941c84261d1b25
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

/* klp-ccp: from include/net/netfilter/nf_tables.h */
static void (*klpe_nft_data_release)(const struct nft_data *data, enum nft_data_types type);

static const struct nft_set_ext_type (*klpe_nft_set_ext_types)[];

static inline void klpr_nft_set_ext_add_length(struct nft_set_ext_tmpl *tmpl, u8 id,
					  unsigned int len)
{
	tmpl->len	 = ALIGN(tmpl->len, (*klpe_nft_set_ext_types)[id].align);
	BUG_ON(tmpl->len > U8_MAX);
	tmpl->offset[id] = tmpl->len;
	tmpl->len	+= (*klpe_nft_set_ext_types)[id].len + len;
}

static inline void klpr_nft_set_ext_add(struct nft_set_ext_tmpl *tmpl, u8 id)
{
	klpr_nft_set_ext_add_length(tmpl, id, 0);
}

static void *(*klpe_nft_set_elem_init)(const struct nft_set *set,
			const struct nft_set_ext_tmpl *tmpl,
			const u32 *key, const u32 *key_end, const u32 *data,
			u64 timeout, u64 expiration, gfp_t gfp);

static unsigned int (*klpe_nf_tables_net_id);

static inline struct nftables_pernet *klpr_nft_pernet(const struct net *net)
{
	return net_generic(net, (*klpe_nf_tables_net_id));
}

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <net/netfilter/nf_tables.h>
#include <net/net_namespace.h>
static struct nft_trans *(*klpe_nft_trans_alloc_gfp)(const struct nft_ctx *ctx,
					     int msg_type, u32 size, gfp_t gfp);

static struct nft_trans *klpr_nft_trans_alloc(const struct nft_ctx *ctx,
					 int msg_type, u32 size)
{
	return (*klpe_nft_trans_alloc_gfp)(ctx, msg_type, size, GFP_KERNEL);
}

static void klpr_nft_trans_commit_list_add_tail(struct net *net, struct nft_trans *trans)
{
	struct nftables_pernet *nft_net = klpr_nft_pernet(net);

	list_add_tail(&trans->list, &nft_net->commit_list);
}

struct nft_set_elem_catchall {
	struct list_head	list;
	struct rcu_head		rcu;
	void			*elem;
};

static const struct nla_policy (*klpe_nft_set_elem_policy)[NFTA_SET_ELEM_MAX + 1];

static int nft_setelem_parse_flags(const struct nft_set *set,
				   const struct nlattr *attr, u32 *flags)
{
	if (attr == NULL)
		return 0;

	*flags = ntohl(nla_get_be32(attr));
	if (*flags & ~(NFT_SET_ELEM_INTERVAL_END | NFT_SET_ELEM_CATCHALL))
		return -EOPNOTSUPP;
	if (!(set->flags & NFT_SET_INTERVAL) &&
	    *flags & NFT_SET_ELEM_INTERVAL_END)
		return -EINVAL;

	return 0;
}

static int (*klpe_nft_setelem_parse_key)(struct nft_ctx *ctx, struct nft_set *set,
				 struct nft_data *key, struct nlattr *attr);

static struct nft_trans *klpr_nft_trans_elem_alloc(struct nft_ctx *ctx,
					      int msg_type,
					      struct nft_set *set)
{
	struct nft_trans *trans;

	trans = klpr_nft_trans_alloc(ctx, msg_type, sizeof(struct nft_trans_elem));
	if (trans == NULL)
		return NULL;

	nft_trans_elem_set(trans) = set;
	return trans;
}

static int klpp_nft_setelem_catchall_deactivate(const struct net *net,
					   struct nft_set *set,
					   struct nft_set_elem *elem)
{
	struct nft_set_elem_catchall *catchall;
	struct nft_set_ext *ext;

	list_for_each_entry(catchall, &set->catchall_list, list) {
		ext = nft_set_elem_ext(set, catchall->elem);
		if (!nft_is_active_next(net, ext) ||
		    nft_set_elem_mark_busy(ext))
			continue;

		kfree(elem->priv);
		elem->priv = catchall->elem;
		nft_set_elem_change_active(net, set, ext);
		return 0;
	}

	return -ENOENT;
}

static int __nft_setelem_deactivate(const struct net *net,
				    struct nft_set *set,
				    struct nft_set_elem *elem)
{
	void *priv;

	priv = set->ops->deactivate(net, set, elem);
	if (!priv)
		return -ENOENT;

	kfree(elem->priv);
	elem->priv = priv;
	set->ndeact++;

	return 0;
}

static int klpp_nft_setelem_deactivate(const struct net *net,
				  struct nft_set *set,
				  struct nft_set_elem *elem, u32 flags)
{
	int ret;

	if (flags & NFT_SET_ELEM_CATCHALL)
		ret = klpp_nft_setelem_catchall_deactivate(net, set, elem);
	else
		ret = __nft_setelem_deactivate(net, set, elem);

	return ret;
}

static void klpr_nft_setelem_data_deactivate(const struct net *net,
					const struct nft_set *set,
					struct nft_set_elem *elem)
{
	const struct nft_set_ext *ext = nft_set_elem_ext(set, elem->priv);

	if (nft_set_ext_exists(ext, NFT_SET_EXT_DATA))
		(*klpe_nft_data_release)(nft_set_ext_data(ext), set->dtype);
	if (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF))
		(*nft_set_ext_obj(ext))->use--;
}

int klpp_nft_del_setelem(struct nft_ctx *ctx, struct nft_set *set,
			   const struct nlattr *attr)
{
	struct nlattr *nla[NFTA_SET_ELEM_MAX + 1];
	struct nft_set_ext_tmpl tmpl;
	struct nft_set_elem elem;
	struct nft_set_ext *ext;
	struct nft_trans *trans;
	u32 flags = 0;
	int err;

	err = nla_parse_nested_deprecated(nla, NFTA_SET_ELEM_MAX, attr,
					  (*klpe_nft_set_elem_policy), NULL);
	if (err < 0)
		return err;

	err = nft_setelem_parse_flags(set, nla[NFTA_SET_ELEM_FLAGS], &flags);
	if (err < 0)
		return err;

	if (!nla[NFTA_SET_ELEM_KEY] && !(flags & NFT_SET_ELEM_CATCHALL))
		return -EINVAL;

	nft_set_ext_prepare(&tmpl);

	if (flags != 0)
		klpr_nft_set_ext_add(&tmpl, NFT_SET_EXT_FLAGS);

	if (nla[NFTA_SET_ELEM_KEY]) {
		err = (*klpe_nft_setelem_parse_key)(ctx, set, &elem.key.val,
					    nla[NFTA_SET_ELEM_KEY]);
		if (err < 0)
			return err;

		klpr_nft_set_ext_add_length(&tmpl, NFT_SET_EXT_KEY, set->klen);
	}

	if (nla[NFTA_SET_ELEM_KEY_END]) {
		err = (*klpe_nft_setelem_parse_key)(ctx, set, &elem.key_end.val,
					    nla[NFTA_SET_ELEM_KEY_END]);
		if (err < 0)
			return err;

		klpr_nft_set_ext_add_length(&tmpl, NFT_SET_EXT_KEY_END, set->klen);
	}

	err = -ENOMEM;
	elem.priv = (*klpe_nft_set_elem_init)(set, &tmpl, elem.key.val.data,
				      elem.key_end.val.data, NULL, 0, 0,
				      GFP_KERNEL);
	if (elem.priv == NULL)
		goto fail_elem;

	ext = nft_set_elem_ext(set, elem.priv);
	if (flags)
		*nft_set_ext_flags(ext) = flags;

	trans = klpr_nft_trans_elem_alloc(ctx, NFT_MSG_DELSETELEM, set);
	if (trans == NULL)
		goto fail_trans;

	err = klpp_nft_setelem_deactivate(ctx->net, set, &elem, flags);
	if (err < 0)
		goto fail_ops;

	klpr_nft_setelem_data_deactivate(ctx->net, set, &elem);

	nft_trans_elem(trans) = elem;
	klpr_nft_trans_commit_list_add_tail(ctx->net, trans);
	return 0;

fail_ops:
	kfree(trans);
fail_trans:
	kfree(elem.priv);
fail_elem:
	(*klpe_nft_data_release)(&elem.key.val, NFT_DATA_VALUE);
	return err;
}

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1219432.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nf_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nf_tables_net_id", (void *)&klpe_nf_tables_net_id, "nf_tables" },
	{ "nft_data_release", (void *)&klpe_nft_data_release, "nf_tables" },
	{ "nft_set_elem_init", (void *)&klpe_nft_set_elem_init, "nf_tables" },
	{ "nft_set_elem_policy", (void *)&klpe_nft_set_elem_policy,
	  "nf_tables" },
	{ "nft_set_ext_types", (void *)&klpe_nft_set_ext_types, "nf_tables" },
	{ "nft_setelem_parse_key", (void *)&klpe_nft_setelem_parse_key,
	  "nf_tables" },
	{ "nft_trans_alloc_gfp", (void *)&klpe_nft_trans_alloc_gfp,
	  "nf_tables" },
};

static int livepatch_bsc1219432_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1219432_module_nb = {
	.notifier_call = livepatch_bsc1219432_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1219432_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&livepatch_bsc1219432_module_nb);
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
		unregister_module_notifier(&livepatch_bsc1219432_module_nb);

	module_put(mod);
	return ret;
}

void livepatch_bsc1219432_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1219432_module_nb);
}
