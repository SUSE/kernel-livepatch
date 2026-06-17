/*
 * bsc1266229_net_ipv4_udp_offload
 *
 * Fix for CVE-2026-43503, bsc#1266229
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


#include "livepatch_bsc1265224.h"


/* klp-ccp: from net/ipv4/udp_offload.c */
#include <linux/skbuff.h>
#include <net/gro.h>

/* klp-ccp: from include/net/gro.h */
struct sk_buff *klpp_udp_gro_receive(struct list_head *head, struct sk_buff *skb,
				struct udphdr *uh, struct sock *sk);

/* klp-ccp: from net/ipv4/udp_offload.c */
#include <net/gso.h>
#include <net/udp.h>
#include <net/protocol.h>
#include <net/inet_common.h>

static int klpp_skb_gro_receive_list(struct sk_buff *p, struct sk_buff *skb)
{
	if (unlikely(p->len + skb->len >= 65536))
		return -E2BIG;

	if (NAPI_GRO_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NAPI_GRO_CB(p)->last->next = skb;

	skb_pull(skb, skb_gro_offset(skb));

	NAPI_GRO_CB(p)->last = skb;
	NAPI_GRO_CB(p)->count++;
	p->data_len += skb->len;

	/* sk ownership - if any - completely transferred to the aggregated packet */
	skb->destructor = NULL;
	skb->sk = NULL;
	p->truesize += skb->truesize;
	p->len += skb->len;

	skb_shinfo(p)->flags |= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;

	NAPI_GRO_CB(skb)->same_flow = 1;

	return 0;
}

#define UDP_GRO_CNT_MAX 64
static struct sk_buff *klpp_udp_gro_receive_segment(struct list_head *head,
					       struct sk_buff *skb)
{
	struct udphdr *uh = udp_gro_udphdr(skb);
	struct sk_buff *pp = NULL;
	struct udphdr *uh2;
	struct sk_buff *p;
	unsigned int ulen;
	int ret = 0;

	/* requires non zero csum, for symmetry with GSO */
	if (!uh->check) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	/* Do not deal with padded or malicious packets, sorry ! */
	ulen = ntohs(uh->len);
	if (ulen <= sizeof(*uh) || ulen != skb_gro_len(skb)) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}
	/* pull encapsulating udp header */
	skb_gro_pull(skb, sizeof(struct udphdr));

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = udp_hdr(p);

		/* Match ports only, as csum is always non zero */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		if (NAPI_GRO_CB(skb)->is_flist != NAPI_GRO_CB(p)->is_flist) {
			NAPI_GRO_CB(skb)->flush = 1;
			return p;
		}

		/* Terminate the flow on len mismatch or if it grow "too much".
		 * Under small packet flood GRO count could elsewhere grow a lot
		 * leading to excessive truesize values.
		 * On len mismatch merge the first packet shorter than gso_size,
		 * otherwise complete the GRO packet.
		 */
		if (ulen > ntohs(uh2->len)) {
			pp = p;
		} else {
			if (NAPI_GRO_CB(skb)->is_flist) {
				if (!pskb_may_pull(skb, skb_gro_offset(skb))) {
					NAPI_GRO_CB(skb)->flush = 1;
					return NULL;
				}
				if ((skb->ip_summed != p->ip_summed) ||
				    (skb->csum_level != p->csum_level)) {
					NAPI_GRO_CB(skb)->flush = 1;
					return NULL;
				}
				ret = klpp_skb_gro_receive_list(p, skb);
			} else {
				skb_gro_postpull_rcsum(skb, uh,
						       sizeof(struct udphdr));

				ret = skb_gro_receive(p, skb);
			}
		}

		if (ret || ulen != ntohs(uh2->len) ||
		    NAPI_GRO_CB(p)->count >= UDP_GRO_CNT_MAX)
			pp = p;

		return pp;
	}

	/* mismatch, but we never need to flush */
	return NULL;
}

struct sk_buff *klpp_udp_gro_receive(struct list_head *head, struct sk_buff *skb,
				struct udphdr *uh, struct sock *sk)
{
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct udphdr *uh2;
	unsigned int off = skb_gro_offset(skb);
	int flush = 1;

	/* We can do L4 aggregation only if the packet can't land in a tunnel
	 * otherwise we could corrupt the inner stream. Detecting such packets
	 * cannot be foolproof and the aggregation might still happen in some
	 * cases. Such packets should be caught in udp_unexpected_gso later.
	 */
	NAPI_GRO_CB(skb)->is_flist = 0;
	if (!sk || !udp_sk(sk)->gro_receive) {
		if (skb->dev->features & NETIF_F_GRO_FRAGLIST)
			NAPI_GRO_CB(skb)->is_flist = sk ? !udp_test_bit(GRO_ENABLED, sk) : 1;

		if ((!sk && (skb->dev->features & NETIF_F_GRO_UDP_FWD)) ||
		    (sk && udp_test_bit(GRO_ENABLED, sk)) || NAPI_GRO_CB(skb)->is_flist)
			return call_gro_receive(klpp_udp_gro_receive_segment, head, skb);

		/* no GRO, be sure flush the current packet */
		goto out;
	}

	if (NAPI_GRO_CB(skb)->encap_mark ||
	    (uh->check && skb->ip_summed != CHECKSUM_PARTIAL &&
	     NAPI_GRO_CB(skb)->csum_cnt == 0 &&
	     !NAPI_GRO_CB(skb)->csum_valid))
		goto out;

	/* mark that this skb passed once through the tunnel gro layer */
	NAPI_GRO_CB(skb)->encap_mark = 1;

	flush = 0;

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		uh2 = (struct udphdr   *)(p->data + off);

		/* Match ports and either checksums are either both zero
		 * or nonzero.
		 */
		if ((*(u32 *)&uh->source != *(u32 *)&uh2->source) ||
		    (!uh->check ^ !uh2->check)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	skb_gro_pull(skb, sizeof(struct udphdr)); /* pull encapsulating udp header */
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct udphdr));
	pp = call_gro_receive_sk(udp_sk(sk)->gro_receive, sk, head, skb);

out:
	skb_gro_flush_final(skb, pp, flush);
	return pp;
}

typeof(klpp_udp_gro_receive) klpp_udp_gro_receive;


#include <linux/livepatch.h>

extern typeof(skb_gro_receive) skb_gro_receive
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_gro_receive);
