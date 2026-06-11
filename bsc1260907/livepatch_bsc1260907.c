/*
 * livepatch_bsc1260907
 *
 * Fix for CVE-2026-23278, bsc#1260907
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1260907.h"


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

extern int nft_mapelem_deactivate(const struct nft_ctx *ctx,
				  struct nft_set *set,
				  const struct nft_set_iter *iter,
				  struct nft_set_elem *elem);

struct nft_set_elem_catchall {
	struct list_head	list;
	struct rcu_head		rcu;
	void			*elem;
};

static void nft_map_catchall_deactivate(const struct nft_ctx *ctx,
					struct nft_set *set)
{
	u8 genmask = nft_genmask_next(ctx->net);
	struct nft_set_elem_catchall *catchall;
	struct nft_set_elem elem;
	struct nft_set_ext *ext;

	list_for_each_entry(catchall, &set->catchall_list, list) {
		ext = nft_set_elem_ext(set, catchall->elem);
		if (!nft_set_elem_active(ext, genmask))
			continue;

		nft_set_elem_change_active(ctx->net, set, ext);
		elem.priv = catchall->elem;
		nft_setelem_data_deactivate(ctx->net, set, &elem);
	}
}

void klpp_nft_map_deactivate(const struct nft_ctx *ctx, struct nft_set *set)
{
	struct nft_set_iter iter = {
		.genmask	= nft_genmask_next(ctx->net),
		.type		= NFT_ITER_UPDATE,
		.fn		= nft_mapelem_deactivate,
	};

	set->ops->walk(ctx, set, &iter);
	WARN_ON_ONCE(iter.err);

	nft_map_catchall_deactivate(ctx, set);
}

static void nft_setelem_data_activate(const struct net *net,
				      const struct nft_set *set,
				      struct nft_set_elem *elem);

extern int nft_mapelem_activate(const struct nft_ctx *ctx,
				struct nft_set *set,
				const struct nft_set_iter *iter,
				struct nft_set_elem *elem);

static void nft_map_catchall_activate(const struct nft_ctx *ctx,
				      struct nft_set *set)
{
	u8 genmask = nft_genmask_next(ctx->net);
	struct nft_set_elem_catchall *catchall;
	struct nft_set_elem elem;
	struct nft_set_ext *ext;

	list_for_each_entry(catchall, &set->catchall_list, list) {
		ext = nft_set_elem_ext(set, catchall->elem);
		if (nft_set_elem_active(ext, genmask))
			continue;

		nft_clear(ctx->net, ext);
		elem.priv = catchall->elem;
		nft_setelem_data_activate(ctx->net, set, &elem);
	}
}

void klpp_nft_map_activate(const struct nft_ctx *ctx, struct nft_set *set)
{
	struct nft_set_iter iter = {
		.genmask	= nft_genmask_next(ctx->net),
		.type		= NFT_ITER_UPDATE,
		.fn		= nft_mapelem_activate,
	};

	set->ops->walk(ctx, set, &iter);
	WARN_ON_ONCE(iter.err);

	nft_map_catchall_activate(ctx, set);
}

void nft_data_hold(const struct nft_data *data, enum nft_data_types type);

static void nft_setelem_data_activate(const struct net *net,
				      const struct nft_set *set,
				      struct nft_set_elem *elem)
{
	const struct nft_set_ext *ext = nft_set_elem_ext(set, elem->priv);

	if (nft_set_ext_exists(ext, NFT_SET_EXT_DATA))
		nft_data_hold(nft_set_ext_data(ext), set->dtype);
	if (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF))
		nft_use_inc_restore(&(*nft_set_ext_obj(ext))->use);
}

void nft_setelem_data_deactivate(const struct net *net,
				 const struct nft_set *set,
				 struct nft_set_elem *elem);


#include <linux/livepatch.h>

extern typeof(nft_data_hold) nft_data_hold
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_data_hold);
extern typeof(nft_mapelem_activate) nft_mapelem_activate
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_mapelem_activate);
extern typeof(nft_mapelem_deactivate) nft_mapelem_deactivate
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_mapelem_deactivate);
extern typeof(nft_setelem_data_deactivate) nft_setelem_data_deactivate
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_setelem_data_deactivate);
