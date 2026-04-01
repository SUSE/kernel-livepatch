/*
 * livepatch_bsc1258183
 *
 * Fix for CVE-2026-23111, bsc#1258183
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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

/* klp-ccp: from include/linux/rhashtable.h */
#define _LINUX_RHASHTABLE_H

/* klp-ccp: from include/linux/unaligned/packed_struct.h */
#define _LINUX_UNALIGNED_PACKED_STRUCT_H

/* klp-ccp: from net/netfilter/nf_tables_api.c */
#include <linux/audit.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_tables.h>

#include <net/net_namespace.h>
#include <net/sock.h>

struct nft_set_elem_catchall {
	struct list_head	list;
	struct rcu_head		rcu;
	void			*elem;
};

static void nft_setelem_data_activate(const struct net *net,
				      const struct nft_set *set,
				      struct nft_set_elem *elem);

extern int nft_mapelem_activate(const struct nft_ctx *ctx,
				struct nft_set *set,
				const struct nft_set_iter *iter,
				struct nft_set_elem *elem);

static void klpp_nft_map_catchall_activate(const struct nft_ctx *ctx,
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
		break;
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

	klpp_nft_map_catchall_activate(ctx, set);
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


#include "livepatch_bsc1258183.h"

#include <linux/livepatch.h>

extern typeof(nft_data_hold) nft_data_hold
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_data_hold);
extern typeof(nft_mapelem_activate) nft_mapelem_activate
	 KLP_RELOC_SYMBOL(nf_tables, nf_tables, nft_mapelem_activate);
