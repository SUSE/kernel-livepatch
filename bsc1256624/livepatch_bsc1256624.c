/*
 * livepatch_bsc1256624
 *
 * Fix for CVE-2025-71085, bsc#1256624
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


#include "livepatch_bsc1256624.h"


/* klp-ccp: from net/ipv6/calipso.c */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/jhash.h>
#include <linux/audit.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/tcp.h>
#include <net/netlabel.h>
#include <net/calipso.h>
#include <linux/atomic.h>
#include <linux/bug.h>
#include <asm/unaligned.h>
#include <linux/crc-ccitt.h>

#define CALIPSO_OPT_LEN_MAX (2 + 252)

#define CALIPSO_HDR_LEN (2 + 8)

#define CALIPSO_MAX_BUFFER (6 + CALIPSO_OPT_LEN_MAX)

static int calipso_map_cat_hton(const struct calipso_doi *doi_def,
				const struct netlbl_lsm_secattr *secattr,
				unsigned char *net_cat,
				u32 net_cat_len)
{
	int spot = -1;
	u32 net_spot_max = 0;
	u32 net_clen_bits = net_cat_len * 8;

	for (;;) {
		spot = netlbl_catmap_walk(secattr->attr.mls.cat,
					  spot + 1);
		if (spot < 0)
			break;
		if (spot >= net_clen_bits)
			return -ENOSPC;
		netlbl_bitmap_setbit(net_cat, spot, 1);

		if (spot > net_spot_max)
			net_spot_max = spot;
	}

	return (net_spot_max / 32 + 1) * 4;
}

extern int calipso_pad_write(unsigned char *buf, unsigned int offset,
			     unsigned int count);

static int calipso_genopt(unsigned char *buf, u32 start, u32 buf_len,
			  const struct calipso_doi *doi_def,
			  const struct netlbl_lsm_secattr *secattr)
{
	int ret_val;
	u32 len, pad;
	u16 crc;
	static const unsigned char padding[4] = {2, 1, 0, 3};
	unsigned char *calipso;

	/* CALIPSO has 4n + 2 alignment */
	pad = padding[start & 3];
	if (buf_len <= start + pad + CALIPSO_HDR_LEN)
		return -ENOSPC;

	if ((secattr->flags & NETLBL_SECATTR_MLS_LVL) == 0)
		return -EPERM;

	len = CALIPSO_HDR_LEN;

	if (secattr->flags & NETLBL_SECATTR_MLS_CAT) {
		ret_val = calipso_map_cat_hton(doi_def,
					       secattr,
					       buf + start + pad + len,
					       buf_len - start - pad - len);
		if (ret_val < 0)
			return ret_val;
		len += ret_val;
	}

	calipso_pad_write(buf, start, pad);
	calipso = buf + start + pad;

	calipso[0] = IPV6_TLV_CALIPSO;
	calipso[1] = len - 2;
	*(__be32 *)(calipso + 2) = htonl(doi_def->doi);
	calipso[6] = (len - CALIPSO_HDR_LEN) / 4;
	calipso[7] = secattr->attr.mls.lvl;
	crc = ~crc_ccitt(0xffff, calipso, len);
	calipso[8] = crc & 0xff;
	calipso[9] = (crc >> 8) & 0xff;
	return pad + len;
}

extern int calipso_opt_find(struct ipv6_opt_hdr *hop, unsigned int *start,
			    unsigned int *end);

int klpp_calipso_skbuff_setattr(struct sk_buff *skb,
				  const struct calipso_doi *doi_def,
				  const struct netlbl_lsm_secattr *secattr)
{
	int ret_val;
	struct ipv6hdr *ip6_hdr;
	struct ipv6_opt_hdr *hop;
	unsigned char buf[CALIPSO_MAX_BUFFER];
	int len_delta, new_end, pad, payload;
	unsigned int start, end;

	ip6_hdr = ipv6_hdr(skb);
	if (ip6_hdr->nexthdr == NEXTHDR_HOP) {
		hop = (struct ipv6_opt_hdr *)(ip6_hdr + 1);
		ret_val = calipso_opt_find(hop, &start, &end);
		if (ret_val && ret_val != -ENOENT)
			return ret_val;
	} else {
		start = 0;
		end = 0;
	}

	memset(buf, 0, sizeof(buf));
	ret_val = calipso_genopt(buf, start & 3, sizeof(buf), doi_def, secattr);
	if (ret_val < 0)
		return ret_val;

	new_end = start + ret_val;
	/* At this point new_end aligns to 4n, so (new_end & 4) pads to 8n */
	pad = ((new_end & 4) + (end & 7)) & 7;
	len_delta = new_end - (int)end + pad;
	ret_val = skb_cow(skb,
			  skb_headroom(skb) + (len_delta > 0 ? len_delta : 0));
	if (ret_val < 0)
		return ret_val;

	ip6_hdr = ipv6_hdr(skb); /* Reset as skb_cow() may have moved it */

	if (len_delta) {
		if (len_delta > 0)
			skb_push(skb, len_delta);
		else
			skb_pull(skb, -len_delta);
		memmove((char *)ip6_hdr - len_delta, ip6_hdr,
			sizeof(*ip6_hdr) + start);
		skb_reset_network_header(skb);
		ip6_hdr = ipv6_hdr(skb);
		payload = ntohs(ip6_hdr->payload_len);
		ip6_hdr->payload_len = htons(payload + len_delta);
	}

	hop = (struct ipv6_opt_hdr *)(ip6_hdr + 1);
	if (start == 0) {
		struct ipv6_opt_hdr *new_hop = (struct ipv6_opt_hdr *)buf;

		new_hop->nexthdr = ip6_hdr->nexthdr;
		new_hop->hdrlen = len_delta / 8 - 1;
		ip6_hdr->nexthdr = NEXTHDR_HOP;
	} else {
		hop->hdrlen += len_delta / 8;
	}
	memcpy((char *)hop + start, buf + (start & 3), new_end - start);
	calipso_pad_write((unsigned char *)hop, new_end, pad);

	return 0;
}


#include <linux/livepatch.h>

extern typeof(calipso_opt_find) calipso_opt_find
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, calipso_opt_find);
extern typeof(calipso_pad_write) calipso_pad_write
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, calipso_pad_write);
