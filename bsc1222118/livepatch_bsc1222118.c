/*
 * livepatch_bsc1222118
 *
 * Fix for CVE-2023-52628, bsc#1222118
 *
 *  Upstream commit:
 *  fd94d9dadee5 ("netfilter: nftables: exthdr: fix 4-byte stack OOB write")
 *
 *  SLE12-SP5 commit:
 *  b9ba6b954c8ea94c4152c76e8a252d1ddebb815b
 *
 *  SLE15-SP2 and -SP3 commit:
 *  780699b6f33772e8ae57fa59583f97ea19ad9cc9
 *
 *  SLE15-SP4 and -SP5 commit:
 *  0de26c1e9eeb9986f80e29c2fa6a68f30f1d674f
 *
 *  Copyright (c) 2024 SUSE
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


/* klp-ccp: from net/netfilter/nft_exthdr.c */
#include <asm/unaligned.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/sctp.h>
#include <net/netfilter/nf_tables_core.h>
#include <net/netfilter/nf_tables.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/tcp.h */
#define MAX_TCP_OPTION_SPACE 40

#define TCPOPT_NOP		1	/* Padding */

/* klp-ccp: from net/netfilter/nft_exthdr.c */
struct nft_exthdr {
	u8			type;
	u8			offset;
	u8			len;
	u8			op;
	u8			dreg;
	u8			sreg;
	u8			flags;
};

static unsigned int optlen(const u8 *opt, unsigned int offset)
{
	/* Beware zero-length options: make finite progress */
	if (opt[offset] <= TCPOPT_NOP || opt[offset + 1] == 0)
		return 1;
	else
		return opt[offset + 1];
}

static int klpp_nft_skb_copy_to_reg(const struct sk_buff *skb, int offset, u32 *dest, unsigned int len)
{
	if (len % NFT_REG32_SIZE)
		dest[len / NFT_REG32_SIZE] = 0;

	return skb_copy_bits(skb, offset, dest, len);
}

void klpp_nft_exthdr_ipv6_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_exthdr *priv = nft_expr_priv(expr);
	u32 *dest = &regs->data[priv->dreg];
	unsigned int offset = 0;
	int err;

	if (pkt->skb->protocol != htons(ETH_P_IPV6))
		goto err;

	err = ipv6_find_hdr(pkt->skb, &offset, priv->type, NULL, NULL);
	if (priv->flags & NFT_EXTHDR_F_PRESENT) {
		nft_reg_store8(dest, err >= 0);
		return;
	} else if (err < 0) {
		goto err;
	}
	offset += priv->offset;

	if (klpp_nft_skb_copy_to_reg(pkt->skb, offset, dest, priv->len) < 0)
		goto err;
	return;
err:
	regs->verdict.code = NFT_BREAK;
}

static int ipv4_find_option(struct net *net, struct sk_buff *skb,
			    unsigned int *offset, int target)
{
	unsigned char optbuf[sizeof(struct ip_options) + 40];
	struct ip_options *opt = (struct ip_options *)optbuf;
	struct iphdr *iph, _iph;
	unsigned int start;
	bool found = false;
	__be32 info;
	int optlen;

	iph = skb_header_pointer(skb, 0, sizeof(_iph), &_iph);
	if (!iph)
		return -EBADMSG;
	start = sizeof(struct iphdr);

	optlen = iph->ihl * 4 - (int)sizeof(struct iphdr);
	if (optlen <= 0)
		return -ENOENT;

	memset(opt, 0, sizeof(struct ip_options));
	/* Copy the options since __ip_options_compile() modifies
	 * the options.
	 */
	if (skb_copy_bits(skb, start, opt->__data, optlen))
		return -EBADMSG;
	opt->optlen = optlen;

	if (__ip_options_compile(net, opt, NULL, &info))
		return -EBADMSG;

	switch (target) {
	case IPOPT_SSRR:
	case IPOPT_LSRR:
		if (!opt->srr)
			break;
		found = target == IPOPT_SSRR ? opt->is_strictroute :
					       !opt->is_strictroute;
		if (found)
			*offset = opt->srr + start;
		break;
	case IPOPT_RR:
		if (!opt->rr)
			break;
		*offset = opt->rr + start;
		found = true;
		break;
	case IPOPT_RA:
		if (!opt->router_alert)
			break;
		*offset = opt->router_alert + start;
		found = true;
		break;
	default:
		return -EOPNOTSUPP;
	}
	return found ? target : -ENOENT;
}

void klpp_nft_exthdr_ipv4_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	struct nft_exthdr *priv = nft_expr_priv(expr);
	u32 *dest = &regs->data[priv->dreg];
	struct sk_buff *skb = pkt->skb;
	unsigned int offset;
	int err;

	if (skb->protocol != htons(ETH_P_IP))
		goto err;

	err = ipv4_find_option(nft_net(pkt), skb, &offset, priv->type);
	if (priv->flags & NFT_EXTHDR_F_PRESENT) {
		nft_reg_store8(dest, err >= 0);
		return;
	} else if (err < 0) {
		goto err;
	}
	offset += priv->offset;

	if (klpp_nft_skb_copy_to_reg(pkt->skb, offset, dest, priv->len) < 0)
		goto err;
	return;
err:
	regs->verdict.code = NFT_BREAK;
}

static void *
nft_tcp_header_pointer(const struct nft_pktinfo *pkt,
		       unsigned int len, void *buffer, unsigned int *tcphdr_len)
{
	struct tcphdr *tcph;

	if (pkt->tprot != IPPROTO_TCP)
		return NULL;

	tcph = skb_header_pointer(pkt->skb, nft_thoff(pkt), sizeof(*tcph), buffer);
	if (!tcph)
		return NULL;

	*tcphdr_len = __tcp_hdrlen(tcph);
	if (*tcphdr_len < sizeof(*tcph) || *tcphdr_len > len)
		return NULL;

	return skb_header_pointer(pkt->skb, nft_thoff(pkt), *tcphdr_len, buffer);
}

void klpp_nft_exthdr_tcp_eval(const struct nft_expr *expr,
				struct nft_regs *regs,
				const struct nft_pktinfo *pkt)
{
	u8 buff[sizeof(struct tcphdr) + MAX_TCP_OPTION_SPACE];
	struct nft_exthdr *priv = nft_expr_priv(expr);
	unsigned int i, optl, tcphdr_len, offset;
	u32 *dest = &regs->data[priv->dreg];
	struct tcphdr *tcph;
	u8 *opt;

	tcph = nft_tcp_header_pointer(pkt, sizeof(buff), buff, &tcphdr_len);
	if (!tcph)
		goto err;

	opt = (u8 *)tcph;
	for (i = sizeof(*tcph); i < tcphdr_len - 1; i += optl) {
		optl = optlen(opt, i);

		if (priv->type != opt[i])
			continue;

		if (i + optl > tcphdr_len || priv->len + priv->offset > optl)
			goto err;

		offset = i + priv->offset;
		if (priv->flags & NFT_EXTHDR_F_PRESENT) {
			*dest = 1;
		} else {
			if (priv->len % NFT_REG32_SIZE)
				dest[priv->len / NFT_REG32_SIZE] = 0;
			memcpy(dest, opt + offset, priv->len);
		}

		return;
	}

err:
	if (priv->flags & NFT_EXTHDR_F_PRESENT)
		*dest = 0;
	else
		regs->verdict.code = NFT_BREAK;
}

void klpp_nft_exthdr_sctp_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt)
{
	unsigned int offset = nft_thoff(pkt) + sizeof(struct sctphdr);
	struct nft_exthdr *priv = nft_expr_priv(expr);
	u32 *dest = &regs->data[priv->dreg];
	const struct sctp_chunkhdr *sch;
	struct sctp_chunkhdr _sch;

	if (pkt->tprot != IPPROTO_SCTP)
		goto err;

	do {
		sch = skb_header_pointer(pkt->skb, offset, sizeof(_sch), &_sch);
		if (!sch || !sch->length)
			break;

		if (sch->type == priv->type) {
			if (priv->flags & NFT_EXTHDR_F_PRESENT) {
				nft_reg_store8(dest, true);
				return;
			}
			if (priv->offset + priv->len > ntohs(sch->length) ||
			    offset + ntohs(sch->length) > pkt->skb->len)
				break;

			if (klpp_nft_skb_copy_to_reg(pkt->skb, offset + priv->offset,
					  dest, priv->len) < 0)
				break;
			return;
		}
		offset += SCTP_PAD4(ntohs(sch->length));
	} while (offset < pkt->skb->len);
err:
	if (priv->flags & NFT_EXTHDR_F_PRESENT)
		nft_reg_store8(dest, false);
	else
		regs->verdict.code = NFT_BREAK;
}


#include "livepatch_bsc1222118.h"

