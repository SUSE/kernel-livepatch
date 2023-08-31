/*
 * livepatch_bsc1213063
 *
 * Fix for CVE-2023-35001, bsc#1213063
 *
 *  Upstream commit:
 *  caf3ef7468f7 ("netfilter: nf_tables: prevent OOB access in nft_byteorder_eval")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  846f41704c459c32e7b53f1e60b90fc186bf30f8
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b0acbe2fa34bafe1ebb36e8075649c4de720a151
 *
 *  SLE15-SP4 and -SP5 commit:
 *  2165cfd370539caa4e7d4ca396e7c629a28b3fec
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

#if IS_ENABLED(CONFIG_NF_TABLES)

#if !IS_MODULE(CONFIG_NF_TABLES)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1213063.h"

/* klp-ccp: from net/netfilter/nft_byteorder.c */
#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_core.h>

/* klp-ccp: from include/net/netfilter/nf_tables_core.h */
void klpp_nft_byteorder_eval(const struct nft_expr *expr,
			struct nft_regs *regs, const struct nft_pktinfo *pkt);

/* klp-ccp: from net/netfilter/nft_byteorder.c */
#include <net/netfilter/nf_tables.h>

struct nft_byteorder {
	u8			sreg;
	u8			dreg;
	enum nft_byteorder_ops	op:8;
	u8			len;
	u8			size;
};

void klpp_nft_byteorder_eval(const struct nft_expr *expr,
			struct nft_regs *regs,
			const struct nft_pktinfo *pkt)
{
	const struct nft_byteorder *priv = nft_expr_priv(expr);
	u32 *src = &regs->data[priv->sreg];
	u32 *dst = &regs->data[priv->dreg];
	u16 *s16, *d16;
	unsigned int i;

	s16 = (void *)src;
	d16 = (void *)dst;

	switch (priv->size) {
	case 8: {
		u64 src64;

		switch (priv->op) {
		case NFT_BYTEORDER_NTOH:
			for (i = 0; i < priv->len / 8; i++) {
				src64 = nft_reg_load64(&src[i]);
				nft_reg_store64(&dst[i], be64_to_cpu(src64));
			}
			break;
		case NFT_BYTEORDER_HTON:
			for (i = 0; i < priv->len / 8; i++) {
				src64 = (__force __u64)
					cpu_to_be64(nft_reg_load64(&src[i]));
				nft_reg_store64(&dst[i], src64);
			}
			break;
		}
		break;
	}
	case 4:
		switch (priv->op) {
		case NFT_BYTEORDER_NTOH:
			for (i = 0; i < priv->len / 4; i++)
				dst[i] = ntohl((__force __be32)src[i]);
			break;
		case NFT_BYTEORDER_HTON:
			for (i = 0; i < priv->len / 4; i++)
				dst[i] = (__force __u32)htonl(src[i]);
			break;
		}
		break;
	case 2:
		switch (priv->op) {
		case NFT_BYTEORDER_NTOH:
			for (i = 0; i < priv->len / 2; i++)
				d16[i] = ntohs((__force __be16)s16[i]);
			break;
		case NFT_BYTEORDER_HTON:
			for (i = 0; i < priv->len / 2; i++)
				d16[i] = (__force __u16)htons(s16[i]);
			break;
		}
		break;
	}
}

#endif /* IS_ENABLED(CONFIG_NF_TABLES) */
