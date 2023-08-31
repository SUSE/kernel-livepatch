/*
 * bsc1211187_net_netfilter_nft_lookup
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

/* klp-ccp: from net/netfilter/nft_lookup.c */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>

struct nft_lookup {
	struct nft_set			*set;
	u8				sreg;
	u8				dreg;
	bool				invert;
	struct nft_set_binding		binding;
};

#include "livepatch_bsc1211187.h"

void klpp_nft_lookup_activate(const struct nft_ctx *ctx,
				const struct nft_expr *expr)
{
	struct nft_lookup *priv = nft_expr_priv(expr);

	nf_tables_activate_set(ctx, priv->set);
}
