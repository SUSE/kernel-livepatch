/*
 * bsc1265224_net_core_skbuff
 *
 * Fix for CVE-2026-46300 and CVE-2026-43503, bsc#1265224 and bsc#1266229
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

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/inet.h>

/* klp-ccp: from net/core/skbuff.c */
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <linux/netdevice.h>
#ifdef CONFIG_NET_CLS_ACT
#include <net/pkt_sched.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/skbuff_ref.h>
#include <linux/splice.h>
#include <linux/cache.h>
#include <linux/rtnetlink.h>
#include <linux/init.h>
#include <linux/scatterlist.h>
#include <linux/errqueue.h>
#include <linux/prefetch.h>
#include <linux/bitfield.h>
#include <linux/if_vlan.h>
#include <linux/mpls.h>
#include <linux/kcov.h>
#include <net/protocol.h>
#include <net/dst.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <net/gso.h>
#include <net/ip6_checksum.h>
#include <net/xfrm.h>
#include <net/mpls.h>
#include <net/mptcp.h>
#include <net/mctp.h>
#include <net/page_pool/helpers.h>
#include <net/dropreason.h>
#include <linux/uaccess.h>
#include <trace/events/skb.h>
#include <linux/highmem.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <linux/indirect_call_wrapper.h>
#include <linux/textsearch.h>
/* klp-ccp: from net/core/dev.h */
#include <linux/types.h>
/* klp-ccp: from net/core/sock_destructor.h */
#include <net/tcp.h>

/* klp-ccp: from net/core/skbuff.c */
struct sk_buff *__alloc_skb(unsigned int size, gfp_t gfp_mask,
			    int flags, int node);

extern typeof(__alloc_skb) __alloc_skb;

extern void skb_clone_fraglist(struct sk_buff *skb);

static bool is_pp_page(struct page *page)
{
	return (page->pp_magic & ~0x3UL) == PP_SIGNATURE;
}

#if IS_ENABLED(CONFIG_PAGE_POOL)
bool napi_pp_put_page(netmem_ref netmem);

extern typeof(napi_pp_put_page) napi_pp_put_page;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static int skb_pp_frag_ref(struct sk_buff *skb)
{
	struct skb_shared_info *shinfo;
	struct page *head_page;
	int i;

	if (!skb->pp_recycle)
		return -EINVAL;

	shinfo = skb_shinfo(skb);

	for (i = 0; i < shinfo->nr_frags; i++) {
		head_page = compound_head(skb_frag_page(&shinfo->frags[i]));
		if (likely(is_pp_page(head_page)))
			page_pool_ref_page(head_page);
		else
			page_ref_inc(head_page);
	}
	return 0;
}

void skb_release_head_state(struct sk_buff *skb);

void __fix_address
kfree_skb_reason(struct sk_buff *skb, enum skb_drop_reason reason);

extern typeof(kfree_skb_reason) kfree_skb_reason;

void __fix_address
kfree_skb_list_reason(struct sk_buff *segs, enum skb_drop_reason reason);

extern typeof(kfree_skb_list_reason) kfree_skb_list_reason;

extern void __copy_skb_header(struct sk_buff *new, const struct sk_buff *old);

extern int skb_zerocopy_clone(struct sk_buff *nskb, struct sk_buff *orig,
			      gfp_t gfp_mask);

int skb_copy_ubufs(struct sk_buff *skb, gfp_t gfp_mask);

extern typeof(skb_copy_ubufs) skb_copy_ubufs;

struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask);

extern typeof(skb_clone) skb_clone;

void skb_headers_offset_update(struct sk_buff *skb, int off);

extern typeof(skb_headers_offset_update) skb_headers_offset_update;

void skb_copy_header(struct sk_buff *new, const struct sk_buff *old);

extern typeof(skb_copy_header) skb_copy_header;

static inline int skb_alloc_rx_flag(const struct sk_buff *skb)
{
	if (skb_pfmemalloc(skb))
		return SKB_ALLOC_RX;
	return 0;
}

struct sk_buff *klpp___pskb_copy_fclone(struct sk_buff *skb, int headroom,
				   gfp_t gfp_mask, bool fclone)
{
	unsigned int size = skb_headlen(skb) + headroom;
	int flags = skb_alloc_rx_flag(skb) | (fclone ? SKB_ALLOC_FCLONE : 0);
	struct sk_buff *n = __alloc_skb(size, gfp_mask, flags, NUMA_NO_NODE);

	if (!n)
		goto out;

	/* Set the data pointer */
	skb_reserve(n, headroom);
	/* Set the tail pointer and length */
	skb_put(n, skb_headlen(skb));
	/* Copy the bytes */
	skb_copy_from_linear_data(skb, n->data, n->len);

	n->truesize += skb->data_len;
	n->data_len  = skb->data_len;
	n->len	     = skb->len;

	if (skb_shinfo(skb)->nr_frags) {
		int i;

		if (skb_orphan_frags(skb, gfp_mask) ||
		    skb_zerocopy_clone(n, skb, gfp_mask)) {
			kfree_skb(n);
			n = NULL;
			goto out;
		}
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			skb_shinfo(n)->frags[i] = skb_shinfo(skb)->frags[i];
			skb_frag_ref(skb, i);
		}
		skb_shinfo(n)->nr_frags = i;
		skb_shinfo(n)->flags |= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;
	}

	if (skb_has_frag_list(skb)) {
		skb_shinfo(n)->frag_list = skb_shinfo(skb)->frag_list;
		skb_clone_fraglist(n);
	}

	skb_copy_header(n, skb);
out:
	return n;
}

typeof(klpp___pskb_copy_fclone) klpp___pskb_copy_fclone;

int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail,
		     gfp_t gfp_mask);

extern typeof(pskb_expand_head) pskb_expand_head;

int __skb_unclone_keeptruesize(struct sk_buff *skb, gfp_t pri);

void *skb_put(struct sk_buff *skb, unsigned int len);

extern typeof(skb_put) skb_put;

int ___pskb_trim(struct sk_buff *skb, unsigned int len);

extern typeof(___pskb_trim) ___pskb_trim;

void *__pskb_pull_tail(struct sk_buff *skb, int delta);

extern typeof(__pskb_pull_tail) __pskb_pull_tail;

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);

extern typeof(skb_copy_bits) skb_copy_bits;

__wsum skb_checksum(const struct sk_buff *skb, int offset,
		    int len, __wsum csum);

extern typeof(skb_checksum) skb_checksum;

__wsum skb_copy_and_csum_bits(const struct sk_buff *skb, int offset,
				    u8 *to, int len);

extern typeof(skb_copy_and_csum_bits) skb_copy_and_csum_bits;

static int skb_prepare_for_shift(struct sk_buff *skb)
{
	return skb_unclone_keeptruesize(skb, GFP_ATOMIC);
}

int klpp_skb_shift(struct sk_buff *tgt, struct sk_buff *skb, int shiftlen)
{
	int from, to, merge, todo;
	skb_frag_t *fragfrom, *fragto;

	BUG_ON(shiftlen > skb->len);

	if (skb_headlen(skb))
		return 0;
	if (skb_zcopy(tgt) || skb_zcopy(skb))
		return 0;

	todo = shiftlen;
	from = 0;
	to = skb_shinfo(tgt)->nr_frags;
	fragfrom = &skb_shinfo(skb)->frags[from];

	/* Actual merge is delayed until the point when we know we can
	 * commit all, so that we don't have to undo partial changes
	 */
	if (!to ||
	    !skb_can_coalesce(tgt, to, skb_frag_page(fragfrom),
			      skb_frag_off(fragfrom))) {
		merge = -1;
	} else {
		merge = to - 1;

		todo -= skb_frag_size(fragfrom);
		if (todo < 0) {
			if (skb_prepare_for_shift(skb) ||
			    skb_prepare_for_shift(tgt))
				return 0;

			/* All previous frag pointers might be stale! */
			fragfrom = &skb_shinfo(skb)->frags[from];
			fragto = &skb_shinfo(tgt)->frags[merge];

			skb_frag_size_add(fragto, shiftlen);
			skb_frag_size_sub(fragfrom, shiftlen);
			skb_frag_off_add(fragfrom, shiftlen);

			goto onlymerged;
		}

		from++;
	}

	/* Skip full, not-fitting skb to avoid expensive operations */
	if ((shiftlen == skb->len) &&
	    (skb_shinfo(skb)->nr_frags - from) > (MAX_SKB_FRAGS - to))
		return 0;

	if (skb_prepare_for_shift(skb) || skb_prepare_for_shift(tgt))
		return 0;

	while ((todo > 0) && (from < skb_shinfo(skb)->nr_frags)) {
		if (to == MAX_SKB_FRAGS)
			return 0;

		fragfrom = &skb_shinfo(skb)->frags[from];
		fragto = &skb_shinfo(tgt)->frags[to];

		if (todo >= skb_frag_size(fragfrom)) {
			*fragto = *fragfrom;
			todo -= skb_frag_size(fragfrom);
			from++;
			to++;

		} else {
			__skb_frag_ref(fragfrom);
			skb_frag_page_copy(fragto, fragfrom);
			skb_frag_off_copy(fragto, fragfrom);
			skb_frag_size_set(fragto, todo);

			skb_frag_off_add(fragfrom, todo);
			skb_frag_size_sub(fragfrom, todo);
			todo = 0;

			to++;
			break;
		}
	}

	/* Ready to "commit" this state change to tgt */
	skb_shinfo(tgt)->nr_frags = to;

	if (merge >= 0) {
		fragfrom = &skb_shinfo(skb)->frags[0];
		fragto = &skb_shinfo(tgt)->frags[merge];

		skb_frag_size_add(fragto, skb_frag_size(fragfrom));
		__skb_frag_unref(fragfrom, skb->pp_recycle);
	}

	/* Reposition in the original skb */
	to = 0;
	while (from < skb_shinfo(skb)->nr_frags)
		skb_shinfo(skb)->frags[to++] = skb_shinfo(skb)->frags[from++];
	skb_shinfo(skb)->nr_frags = to;

	BUG_ON(todo > 0 && !skb_shinfo(skb)->nr_frags);

onlymerged:
	/* Most likely the tgt won't ever need its checksum anymore, skb on
	 * the other hand might need it if it needs to be resent
	 */
	tgt->ip_summed = CHECKSUM_PARTIAL;
	skb->ip_summed = CHECKSUM_PARTIAL;

	skb_shinfo(tgt)->flags |= skb_shinfo(skb)->flags & SKBFL_SHARED_FRAG;

	skb_len_add(skb, -shiftlen);
	skb_len_add(tgt, shiftlen);

	return shiftlen;
}

static inline skb_frag_t skb_head_frag_to_page_desc(struct sk_buff *frag_skb)
{
	skb_frag_t head_frag;
	struct page *page;

	page = virt_to_head_page(frag_skb->head);
	skb_frag_fill_page_desc(&head_frag, page, frag_skb->data -
				(unsigned char *)page_address(page),
				skb_headlen(frag_skb));
	return head_frag;
}

struct sk_buff *klpp_skb_segment(struct sk_buff *head_skb,
			    netdev_features_t features)
{
	struct sk_buff *segs = NULL;
	struct sk_buff *tail = NULL;
	struct sk_buff *list_skb = skb_shinfo(head_skb)->frag_list;
	unsigned int mss = skb_shinfo(head_skb)->gso_size;
	unsigned int doffset = head_skb->data - skb_mac_header(head_skb);
	unsigned int offset = doffset;
	unsigned int tnl_hlen = skb_tnl_header_len(head_skb);
	unsigned int partial_segs = 0;
	unsigned int headroom;
	unsigned int len = head_skb->len;
	struct sk_buff *frag_skb;
	skb_frag_t *frag;
	__be16 proto;
	bool csum, sg;
	int err = -ENOMEM;
	int i = 0;
	int nfrags, pos;

	if ((skb_shinfo(head_skb)->gso_type & SKB_GSO_DODGY) &&
	    mss != GSO_BY_FRAGS && mss != skb_headlen(head_skb)) {
		struct sk_buff *check_skb;

		for (check_skb = list_skb; check_skb; check_skb = check_skb->next) {
			if (skb_headlen(check_skb) && !check_skb->head_frag) {
				/* gso_size is untrusted, and we have a frag_list with
				 * a linear non head_frag item.
				 *
				 * If head_skb's headlen does not fit requested gso_size,
				 * it means that the frag_list members do NOT terminate
				 * on exact gso_size boundaries. Hence we cannot perform
				 * skb_frag_t page sharing. Therefore we must fallback to
				 * copying the frag_list skbs; we do so by disabling SG.
				 */
				features &= ~NETIF_F_SG;
				break;
			}
		}
	}

	__skb_push(head_skb, doffset);
	proto = skb_network_protocol(head_skb, NULL);
	if (unlikely(!proto))
		return ERR_PTR(-EINVAL);

	sg = !!(features & NETIF_F_SG);
	csum = !!can_checksum_protocol(features, proto);

	if (sg && csum && (mss != GSO_BY_FRAGS))  {
		if (!(features & NETIF_F_GSO_PARTIAL)) {
			struct sk_buff *iter;
			unsigned int frag_len;

			if (!list_skb ||
			    !net_gso_ok(features, skb_shinfo(head_skb)->gso_type))
				goto normal;

			/* If we get here then all the required
			 * GSO features except frag_list are supported.
			 * Try to split the SKB to multiple GSO SKBs
			 * with no frag_list.
			 * Currently we can do that only when the buffers don't
			 * have a linear part and all the buffers except
			 * the last are of the same length.
			 */
			frag_len = list_skb->len;
			skb_walk_frags(head_skb, iter) {
				if (frag_len != iter->len && iter->next)
					goto normal;
				if (skb_headlen(iter) && !iter->head_frag)
					goto normal;

				len -= iter->len;
			}

			if (len != frag_len)
				goto normal;
		}

		/* GSO partial only requires that we trim off any excess that
		 * doesn't fit into an MSS sized block, so take care of that
		 * now.
		 * Cap len to not accidentally hit GSO_BY_FRAGS.
		 */
		partial_segs = min(len, GSO_BY_FRAGS - 1) / mss;
		if (partial_segs > 1)
			mss *= partial_segs;
		else
			partial_segs = 0;
	}

normal:
	headroom = skb_headroom(head_skb);
	pos = skb_headlen(head_skb);

	if (skb_orphan_frags(head_skb, GFP_ATOMIC))
		return ERR_PTR(-ENOMEM);

	nfrags = skb_shinfo(head_skb)->nr_frags;
	frag = skb_shinfo(head_skb)->frags;
	frag_skb = head_skb;

	do {
		struct sk_buff *nskb;
		skb_frag_t *nskb_frag;
		int hsize;
		int size;

		if (unlikely(mss == GSO_BY_FRAGS)) {
			len = list_skb->len;
		} else {
			len = head_skb->len - offset;
			if (len > mss)
				len = mss;
		}

		hsize = skb_headlen(head_skb) - offset;

		if (hsize <= 0 && i >= nfrags && skb_headlen(list_skb) &&
		    (skb_headlen(list_skb) == len || sg)) {
			BUG_ON(skb_headlen(list_skb) > len);

			nskb = skb_clone(list_skb, GFP_ATOMIC);
			if (unlikely(!nskb))
				goto err;

			i = 0;
			nfrags = skb_shinfo(list_skb)->nr_frags;
			frag = skb_shinfo(list_skb)->frags;
			frag_skb = list_skb;
			pos += skb_headlen(list_skb);

			while (pos < offset + len) {
				BUG_ON(i >= nfrags);

				size = skb_frag_size(frag);
				if (pos + size > offset + len)
					break;

				i++;
				pos += size;
				frag++;
			}

			list_skb = list_skb->next;

			if (unlikely(pskb_trim(nskb, len))) {
				kfree_skb(nskb);
				goto err;
			}

			hsize = skb_end_offset(nskb);
			if (skb_cow_head(nskb, doffset + headroom)) {
				kfree_skb(nskb);
				goto err;
			}

			nskb->truesize += skb_end_offset(nskb) - hsize;
			skb_release_head_state(nskb);
			__skb_push(nskb, doffset);
		} else {
			if (hsize < 0)
				hsize = 0;
			if (hsize > len || !sg)
				hsize = len;

			nskb = __alloc_skb(hsize + doffset + headroom,
					   GFP_ATOMIC, skb_alloc_rx_flag(head_skb),
					   NUMA_NO_NODE);

			if (unlikely(!nskb))
				goto err;

			skb_reserve(nskb, headroom);
			__skb_put(nskb, doffset);
		}

		if (segs)
			tail->next = nskb;
		else
			segs = nskb;
		tail = nskb;

		__copy_skb_header(nskb, head_skb);

		skb_headers_offset_update(nskb, skb_headroom(nskb) - headroom);
		skb_reset_mac_len(nskb);

		skb_copy_from_linear_data_offset(head_skb, -tnl_hlen,
						 nskb->data - tnl_hlen,
						 doffset + tnl_hlen);

		if (nskb->len == len + doffset)
			goto perform_csum_check;

		if (!sg) {
			if (!csum) {
				if (!nskb->remcsum_offload)
					nskb->ip_summed = CHECKSUM_NONE;
				SKB_GSO_CB(nskb)->csum =
					skb_copy_and_csum_bits(head_skb, offset,
							       skb_put(nskb,
								       len),
							       len);
				SKB_GSO_CB(nskb)->csum_start =
					skb_headroom(nskb) + doffset;
			} else {
				if (skb_copy_bits(head_skb, offset, skb_put(nskb, len), len))
					goto err;
			}
			continue;
		}

		nskb_frag = skb_shinfo(nskb)->frags;

		skb_copy_from_linear_data_offset(head_skb, offset,
						 skb_put(nskb, hsize), hsize);

		skb_shinfo(nskb)->flags |= (skb_shinfo(head_skb)->flags |
					    skb_shinfo(frag_skb)->flags) &
					   SKBFL_SHARED_FRAG;

		if (skb_zerocopy_clone(nskb, frag_skb, GFP_ATOMIC))
			goto err;

		while (pos < offset + len) {
			if (i >= nfrags) {
				if (skb_orphan_frags(list_skb, GFP_ATOMIC) ||
				    skb_zerocopy_clone(nskb, list_skb,
						       GFP_ATOMIC))
					goto err;

				i = 0;
				nfrags = skb_shinfo(list_skb)->nr_frags;
				frag = skb_shinfo(list_skb)->frags;
				frag_skb = list_skb;

				skb_shinfo(nskb)->flags |= skb_shinfo(frag_skb)->flags & SKBFL_SHARED_FRAG;

				if (!skb_headlen(list_skb)) {
					BUG_ON(!nfrags);
				} else {
					BUG_ON(!list_skb->head_frag);

					/* to make room for head_frag. */
					i--;
					frag--;
				}

				list_skb = list_skb->next;
			}

			if (unlikely(skb_shinfo(nskb)->nr_frags >=
				     MAX_SKB_FRAGS)) {
				net_warn_ratelimited(
					"skb_segment: too many frags: %u %u\n",
					pos, mss);
				err = -EINVAL;
				goto err;
			}

			*nskb_frag = (i < 0) ? skb_head_frag_to_page_desc(frag_skb) : *frag;
			__skb_frag_ref(nskb_frag);
			size = skb_frag_size(nskb_frag);

			if (pos < offset) {
				skb_frag_off_add(nskb_frag, offset - pos);
				skb_frag_size_sub(nskb_frag, offset - pos);
			}

			skb_shinfo(nskb)->nr_frags++;

			if (pos + size <= offset + len) {
				i++;
				frag++;
				pos += size;
			} else {
				skb_frag_size_sub(nskb_frag, pos + size - (offset + len));
				goto skip_fraglist;
			}

			nskb_frag++;
		}

skip_fraglist:
		nskb->data_len = len - hsize;
		nskb->len += nskb->data_len;
		nskb->truesize += nskb->data_len;

perform_csum_check:
		if (!csum) {
			if (skb_has_shared_frag(nskb) &&
			    __skb_linearize(nskb))
				goto err;

			if (!nskb->remcsum_offload)
				nskb->ip_summed = CHECKSUM_NONE;
			SKB_GSO_CB(nskb)->csum =
				skb_checksum(nskb, doffset,
					     nskb->len - doffset, 0);
			SKB_GSO_CB(nskb)->csum_start =
				skb_headroom(nskb) + doffset;
		}
	} while ((offset += len) < head_skb->len);

	/* Some callers want to get the end of the list.
	 * Put it in segs->prev to avoid walking the list.
	 * (see validate_xmit_skb_list() for example)
	 */
	segs->prev = tail;

	if (partial_segs) {
		struct sk_buff *iter;
		int type = skb_shinfo(head_skb)->gso_type;
		unsigned short gso_size = skb_shinfo(head_skb)->gso_size;

		/* Update type to add partial and then remove dodgy if set */
		type |= (features & NETIF_F_GSO_PARTIAL) / NETIF_F_GSO_PARTIAL * SKB_GSO_PARTIAL;
		type &= ~SKB_GSO_DODGY;

		/* Update GSO info and prepare to start updating headers on
		 * our way back down the stack of protocols.
		 */
		for (iter = segs; iter; iter = iter->next) {
			skb_shinfo(iter)->gso_size = gso_size;
			skb_shinfo(iter)->gso_segs = partial_segs;
			skb_shinfo(iter)->gso_type = type;
			SKB_GSO_CB(iter)->data_offset = skb_headroom(iter) + doffset;
		}

		if (tail->len - doffset <= gso_size)
			skb_shinfo(tail)->gso_size = 0;
		else if (tail != segs)
			skb_shinfo(tail)->gso_segs = DIV_ROUND_UP(tail->len - doffset, gso_size);
	}

	/* Following permits correct backpressure, for protocols
	 * using skb_set_owner_w().
	 * Idea is to tranfert ownership from head_skb to last segment.
	 */
	if (head_skb->destructor == sock_wfree) {
		swap(tail->truesize, head_skb->truesize);
		swap(tail->destructor, head_skb->destructor);
		swap(tail->sk, head_skb->sk);
	}
	return segs;

err:
	kfree_skb_list(segs);
	return ERR_PTR(err);
}

typeof(klpp_skb_segment) klpp_skb_segment;

bool klpp_skb_try_coalesce(struct sk_buff *to, struct sk_buff *from,
		      bool *fragstolen, int *delta_truesize)
{
	struct skb_shared_info *to_shinfo, *from_shinfo;
	int i, delta, len = from->len;

	*fragstolen = false;

	if (skb_cloned(to))
		return false;

	/* In general, avoid mixing page_pool and non-page_pool allocated
	 * pages within the same SKB. In theory we could take full
	 * references if @from is cloned and !@to->pp_recycle but its
	 * tricky (due to potential race with the clone disappearing) and
	 * rare, so not worth dealing with.
	 */
	if (to->pp_recycle != from->pp_recycle)
		return false;

	if (len <= skb_tailroom(to)) {
		if (len)
			BUG_ON(skb_copy_bits(from, 0, skb_put(to, len), len));
		*delta_truesize = 0;
		return true;
	}

	to_shinfo = skb_shinfo(to);
	from_shinfo = skb_shinfo(from);
	if (to_shinfo->frag_list || from_shinfo->frag_list)
		return false;
	if (skb_zcopy(to) || skb_zcopy(from))
		return false;

	if (skb_headlen(from) != 0) {
		struct page *page;
		unsigned int offset;

		if (to_shinfo->nr_frags +
		    from_shinfo->nr_frags >= MAX_SKB_FRAGS)
			return false;

		if (skb_head_is_locked(from))
			return false;

		delta = from->truesize - SKB_DATA_ALIGN(sizeof(struct sk_buff));

		page = virt_to_head_page(from->head);
		offset = from->data - (unsigned char *)page_address(page);

		skb_fill_page_desc(to, to_shinfo->nr_frags,
				   page, offset, skb_headlen(from));
		*fragstolen = true;
	} else {
		if (to_shinfo->nr_frags +
		    from_shinfo->nr_frags > MAX_SKB_FRAGS)
			return false;

		delta = from->truesize - SKB_TRUESIZE(skb_end_offset(from));
	}

	WARN_ON_ONCE(delta < len);

	memcpy(to_shinfo->frags + to_shinfo->nr_frags,
	       from_shinfo->frags,
	       from_shinfo->nr_frags * sizeof(skb_frag_t));
	to_shinfo->nr_frags += from_shinfo->nr_frags;
	if (from_shinfo->nr_frags)
		to_shinfo->flags |= from_shinfo->flags & SKBFL_SHARED_FRAG;

	if (!skb_cloned(from))
		from_shinfo->nr_frags = 0;

	/* if the skb is not cloned this does nothing
	 * since we set nr_frags to 0.
	 */
	if (skb_pp_frag_ref(from)) {
		for (i = 0; i < from_shinfo->nr_frags; i++)
			__skb_frag_ref(&from_shinfo->frags[i]);
	}

	to->truesize += delta;
	to->len += len;
	to->data_len += len;

	*delta_truesize = delta;
	return true;
}

typeof(klpp_skb_try_coalesce) klpp_skb_try_coalesce;


#include <linux/livepatch.h>

extern typeof(__copy_skb_header) __copy_skb_header
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __copy_skb_header);
extern typeof(__skb_unclone_keeptruesize) __skb_unclone_keeptruesize
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __skb_unclone_keeptruesize);
extern typeof(skb_clone_fraglist) skb_clone_fraglist
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_clone_fraglist);
extern typeof(skb_network_protocol) skb_network_protocol
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_network_protocol);
extern typeof(skb_release_head_state) skb_release_head_state
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_release_head_state);
extern typeof(skb_zerocopy_clone) skb_zerocopy_clone
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_zerocopy_clone);
