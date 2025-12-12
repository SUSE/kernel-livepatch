/*
 * livepatch_bsc1251203
 *
 * Fix for CVE-2025-38476, bsc#1251203
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

/* klp-ccp: from net/ipv6/rpl_iptunnel.c */
#include <net/dst_cache.h>
#include <net/ip6_route.h>
#include <net/lwtunnel.h>
#include <net/ipv6.h>
#include <net/rpl.h>

struct rpl_iptunnel_encap {
	DECLARE_FLEX_ARRAY(struct ipv6_rpl_sr_hdr, srh);
};

struct rpl_lwt {
	struct dst_cache cache;
	struct rpl_iptunnel_encap tuninfo;
};

static inline struct rpl_lwt *rpl_lwt_lwtunnel(struct lwtunnel_state *lwt)
{
	return (struct rpl_lwt *)lwt->data;
}

static inline struct rpl_iptunnel_encap *
rpl_encap_lwtunnel(struct lwtunnel_state *lwt)
{
	return &rpl_lwt_lwtunnel(lwt)->tuninfo;
}

static int rpl_do_srh_inline(struct sk_buff *skb, const struct rpl_lwt *rlwt,
			     const struct ipv6_rpl_sr_hdr *srh,
			     struct dst_entry *cache_dst)
{
	struct ipv6_rpl_sr_hdr *isrh, *csrh;
	struct ipv6hdr oldhdr;
	struct ipv6hdr *hdr;
	unsigned char *buf;
	size_t hdrlen;
	int err;

	memcpy(&oldhdr, ipv6_hdr(skb), sizeof(oldhdr));

	buf = kcalloc(struct_size(srh, segments.addr, srh->segments_left), 2, GFP_ATOMIC);
	if (!buf)
		return -ENOMEM;

	isrh = (struct ipv6_rpl_sr_hdr *)buf;
	csrh = (struct ipv6_rpl_sr_hdr *)(buf + ((srh->hdrlen + 1) << 3));

	memcpy(isrh, srh, sizeof(*isrh));
	memcpy(isrh->rpl_segaddr, &srh->rpl_segaddr[1],
	       (srh->segments_left - 1) * 16);
	isrh->rpl_segaddr[srh->segments_left - 1] = oldhdr.daddr;

	ipv6_rpl_srh_compress(csrh, isrh, &srh->rpl_segaddr[0],
			      isrh->segments_left - 1);

	hdrlen = ((csrh->hdrlen + 1) << 3);

	err = skb_cow_head(skb, hdrlen + dst_dev_overhead(cache_dst, skb));
	if (unlikely(err)) {
		kfree(buf);
		return err;
	}

	skb_pull(skb, sizeof(struct ipv6hdr));
	skb_postpull_rcsum(skb, skb_network_header(skb),
			   sizeof(struct ipv6hdr));

	skb_push(skb, sizeof(struct ipv6hdr) + hdrlen);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);

	hdr = ipv6_hdr(skb);
	memmove(hdr, &oldhdr, sizeof(*hdr));
	isrh = (void *)hdr + sizeof(*hdr);
	memcpy(isrh, csrh, hdrlen);

	isrh->nexthdr = hdr->nexthdr;
	hdr->nexthdr = NEXTHDR_ROUTING;
	hdr->daddr = srh->rpl_segaddr[0];

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	skb_postpush_rcsum(skb, hdr, sizeof(struct ipv6hdr) + hdrlen);

	kfree(buf);

	return 0;
}

static int rpl_do_srh(struct sk_buff *skb, const struct rpl_lwt *rlwt,
		      struct dst_entry *cache_dst)
{
	struct dst_entry *dst = skb_dst(skb);
	struct rpl_iptunnel_encap *tinfo;

	if (skb->protocol != htons(ETH_P_IPV6))
		return -EINVAL;

	tinfo = rpl_encap_lwtunnel(dst->lwtstate);

	return rpl_do_srh_inline(skb, rlwt, tinfo->srh, cache_dst);
}

int klpp_rpl_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct dst_entry *dst = NULL;
	struct rpl_lwt *rlwt;
	int err;

	rlwt = rpl_lwt_lwtunnel(orig_dst->lwtstate);

	local_bh_disable();
	dst = dst_cache_get(&rlwt->cache);
	local_bh_enable();

	err = rpl_do_srh(skb, rlwt, dst);
	if (unlikely(err))
		goto drop;

	if (unlikely(!dst)) {
		struct ipv6hdr *hdr = ipv6_hdr(skb);
		struct flowi6 fl6;

		memset(&fl6, 0, sizeof(fl6));
		fl6.daddr = hdr->daddr;
		fl6.saddr = hdr->saddr;
		fl6.flowlabel = ip6_flowinfo(hdr);
		fl6.flowi6_mark = skb->mark;
		fl6.flowi6_proto = hdr->nexthdr;

		dst = ip6_route_output(net, NULL, &fl6);
		if (dst->error) {
			err = dst->error;
			goto drop;
		}

		local_bh_disable();
		dst_cache_set_ip6(&rlwt->cache, dst, &fl6.saddr);
		local_bh_enable();

		err = skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev));
		if (unlikely(err))
			goto drop;
	}

	skb_dst_drop(skb);
	skb_dst_set(skb, dst);

	return dst_output(net, sk, skb);

drop:
	dst_release(dst);
	kfree_skb(skb);
	return err;
}

int klpp_rpl_input(struct sk_buff *skb)
{
	struct dst_entry *orig_dst = skb_dst(skb);
	struct dst_entry *dst = NULL;
	struct lwtunnel_state *lwtst;
	struct rpl_lwt *rlwt;
	int err;

	/* We cannot dereference "orig_dst" once ip6_route_input() or
	 * skb_dst_drop() is called. However, in order to detect a dst loop, we
	 * need the address of its lwtstate. So, save the address of lwtstate
	 * now and use it later as a comparison.
	 */
	lwtst = orig_dst->lwtstate;

	rlwt = rpl_lwt_lwtunnel(lwtst);

	local_bh_disable();
	dst = dst_cache_get(&rlwt->cache);
	local_bh_enable();

	err = rpl_do_srh(skb, rlwt, dst);
	if (unlikely(err)) {
		dst_release(dst);
		goto drop;
	}

	if (!dst) {
		ip6_route_input(skb);
		dst = skb_dst(skb);

		/* cache only if we don't create a dst reference loop */
		if (!dst->error && lwtst != dst->lwtstate) {
			local_bh_disable();
			dst_cache_set_ip6(&rlwt->cache, dst,
					  &ipv6_hdr(skb)->saddr);
			local_bh_enable();
		}

		err = skb_cow_head(skb, LL_RESERVED_SPACE(dst->dev));
		if (unlikely(err))
			goto drop;
	} else {
		skb_dst_drop(skb);
		skb_dst_set(skb, dst);
	}

	return dst_input(skb);

drop:
	kfree_skb(skb);
	return err;
}

#include "livepatch_bsc1251203.h"

#include <linux/livepatch.h>

extern typeof(ip6_route_input) ip6_route_input
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip6_route_input);
extern typeof(ipv6_rpl_srh_compress) ipv6_rpl_srh_compress
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipv6_rpl_srh_compress);
