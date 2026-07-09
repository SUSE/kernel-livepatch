/*
 * livepatch_bsc1269023
 *
 * Fix for CVE-2026-52943, bsc#1269023
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


#include "livepatch_bsc1269023.h"


/* klp-ccp: from net/core/skbuff.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/in.h>
#include <linux/inet.h>
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
#ifndef __GENKSYMS__
#include <net/gro.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
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
# define HAVE_SKB_SMALL_HEAD_CACHE 1

#ifdef HAVE_SKB_SMALL_HEAD_CACHE
extern struct kmem_cache *skb_small_head_cache __ro_after_init;

#define GRO_MAX_HEAD_PAD (GRO_MAX_HEAD + NET_SKB_PAD + NET_IP_ALIGN)
#define SKB_SMALL_HEAD_SIZE SKB_HEAD_ALIGN(max(MAX_TCP_HEADER, \
					       GRO_MAX_HEAD_PAD))

#define SKB_SMALL_HEAD_CACHE_SIZE					\
	(is_power_of_2(SKB_SMALL_HEAD_SIZE) ?			\
		(SKB_SMALL_HEAD_SIZE + L1_CACHE_BYTES) :	\
		SKB_SMALL_HEAD_SIZE)

#define SKB_SMALL_HEAD_HEADROOM						\
	SKB_WITH_OVERHEAD(SKB_SMALL_HEAD_CACHE_SIZE)
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* HAVE_SKB_SMALL_HEAD_CACHE */

extern void *kmalloc_reserve(unsigned int *size, gfp_t flags, int node,
			     bool *pfmemalloc);

extern void skb_clone_fraglist(struct sk_buff *skb);

static void skb_kfree_head(void *head, unsigned int end_offset)
{
#ifdef HAVE_SKB_SMALL_HEAD_CACHE
	if (end_offset == SKB_SMALL_HEAD_HEADROOM)
		kmem_cache_free(skb_small_head_cache, head);
	else
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		kfree(head);
}

extern void skb_free_head(struct sk_buff *skb);

extern void skb_release_data(struct sk_buff *skb, enum skb_drop_reason reason);

void __fix_address
kfree_skb_reason(struct sk_buff *skb, enum skb_drop_reason reason);

extern typeof(kfree_skb_reason) kfree_skb_reason;

void __fix_address
kfree_skb_list_reason(struct sk_buff *segs, enum skb_drop_reason reason);

extern typeof(kfree_skb_list_reason) kfree_skb_list_reason;

#ifdef CONFIG_TRACEPOINTS

void consume_skb(struct sk_buff *skb);

extern typeof(consume_skb) consume_skb;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

int skb_copy_ubufs(struct sk_buff *skb, gfp_t gfp_mask);

extern typeof(skb_copy_ubufs) skb_copy_ubufs;

struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp_mask);

extern typeof(skb_clone) skb_clone;

void skb_headers_offset_update(struct sk_buff *skb, int off);

extern typeof(skb_headers_offset_update) skb_headers_offset_update;

static int klpp_pskb_carve_inside_header(struct sk_buff *skb, const u32 off,
				    const int headlen, gfp_t gfp_mask)
{
	int i;
	unsigned int size = skb_end_offset(skb);
	int new_hlen = headlen - off;
	u8 *data;

	if (skb_pfmemalloc(skb))
		gfp_mask |= __GFP_MEMALLOC;

	data = kmalloc_reserve(&size, gfp_mask, NUMA_NO_NODE, NULL);
	if (!data)
		return -ENOMEM;
	size = SKB_WITH_OVERHEAD(size);

	/* Copy real data, and all frags */
	skb_copy_from_linear_data_offset(skb, off, data, new_hlen);
	skb->len -= off;

	memcpy((struct skb_shared_info *)(data + size),
	       skb_shinfo(skb),
	       offsetof(struct skb_shared_info,
			frags[skb_shinfo(skb)->nr_frags]));
	if (skb_cloned(skb)) {
		/* drop the old head gracefully */
		if (skb_orphan_frags(skb, gfp_mask)) {
			skb_kfree_head(data, size);
			return -ENOMEM;
		}
		if (skb_zcopy(skb))
			net_zcopy_get(skb_zcopy(skb));
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++)
			skb_frag_ref(skb, i);
		if (skb_has_frag_list(skb))
			skb_clone_fraglist(skb);
		skb_release_data(skb, SKB_CONSUMED);
	} else {
		/* we can reuse existing recount- all we did was
		 * relocate values
		 */
		skb_free_head(skb);
	}

	skb->head = data;
	skb->data = data;
	skb->head_frag = 0;
	skb_set_end_offset(skb, size);
	skb_set_tail_pointer(skb, skb_headlen(skb));
	skb_headers_offset_update(skb, 0);
	skb->cloned = 0;
	skb->hdr_len = 0;
	skb->nohdr = 0;
	atomic_set(&skb_shinfo(skb)->dataref, 1);

	return 0;
}

int klpp_pskb_carve(struct sk_buff *skb, const u32 off, gfp_t gfp);

static int klpr_pskb_carve_frag_list(struct sk_buff *skb,
				struct skb_shared_info *shinfo, int eat,
				gfp_t gfp_mask)
{
	struct sk_buff *list = shinfo->frag_list;
	struct sk_buff *clone = NULL;
	struct sk_buff *insp = NULL;

	do {
		if (!list) {
			pr_err("Not enough bytes to eat. Want %d\n", eat);
			return -EFAULT;
		}
		if (list->len <= eat) {
			/* Eaten as whole. */
			eat -= list->len;
			list = list->next;
			insp = list;
		} else {
			/* Eaten partially. */
			if (skb_shared(list)) {
				clone = skb_clone(list, gfp_mask);
				if (!clone)
					return -ENOMEM;
				insp = list->next;
				list = clone;
			} else {
				/* This may be pulled without problems. */
				insp = list;
			}
			if (klpp_pskb_carve(list, eat, gfp_mask) < 0) {
				kfree_skb(clone);
				return -ENOMEM;
			}
			break;
		}
	} while (eat);

	/* Free pulled out fragments. */
	while ((list = shinfo->frag_list) != insp) {
		shinfo->frag_list = list->next;
		consume_skb(list);
	}
	/* And insert new clone at head. */
	if (clone) {
		clone->next = list;
		shinfo->frag_list = clone;
	}
	return 0;
}

static int klpp_pskb_carve_inside_nonlinear(struct sk_buff *skb, const u32 off,
				       int pos, gfp_t gfp_mask)
{
	int i, k = 0;
	unsigned int size = skb_end_offset(skb);
	u8 *data;
	const int nfrags = skb_shinfo(skb)->nr_frags;
	struct skb_shared_info *shinfo;

	if (skb_pfmemalloc(skb))
		gfp_mask |= __GFP_MEMALLOC;

	data = kmalloc_reserve(&size, gfp_mask, NUMA_NO_NODE, NULL);
	if (!data)
		return -ENOMEM;
	size = SKB_WITH_OVERHEAD(size);

	memcpy((struct skb_shared_info *)(data + size),
	       skb_shinfo(skb), offsetof(struct skb_shared_info, frags[0]));
	if (skb_orphan_frags(skb, gfp_mask)) {
		skb_kfree_head(data, size);
		return -ENOMEM;
	}
	shinfo = (struct skb_shared_info *)(data + size);
	for (i = 0; i < nfrags; i++) {
		int fsize = skb_frag_size(&skb_shinfo(skb)->frags[i]);

		if (pos + fsize > off) {
			shinfo->frags[k] = skb_shinfo(skb)->frags[i];

			if (pos < off) {
				/* Split frag.
				 * We have two variants in this case:
				 * 1. Move all the frag to the second
				 *    part, if it is possible. F.e.
				 *    this approach is mandatory for TUX,
				 *    where splitting is expensive.
				 * 2. Split is accurately. We make this.
				 */
				skb_frag_off_add(&shinfo->frags[0], off - pos);
				skb_frag_size_sub(&shinfo->frags[0], off - pos);
			}
			skb_frag_ref(skb, i);
			k++;
		}
		pos += fsize;
	}
	shinfo->nr_frags = k;
	if (skb_has_frag_list(skb))
		skb_clone_fraglist(skb);

	/* split line is in frag list */
	if (k == 0 && klpr_pskb_carve_frag_list(skb, shinfo, off - pos, gfp_mask)) {
		/* skb_frag_unref() is not needed here as shinfo->nr_frags = 0. */
		if (skb_has_frag_list(skb))
			kfree_skb_list(skb_shinfo(skb)->frag_list);
		skb_kfree_head(data, size);
		return -ENOMEM;
	}
	if (skb_zcopy(skb))
		net_zcopy_get(skb_zcopy(skb));
	skb_release_data(skb, SKB_CONSUMED);

	skb->head = data;
	skb->head_frag = 0;
	skb->data = data;
	skb_set_end_offset(skb, size);
	skb_reset_tail_pointer(skb);
	skb_headers_offset_update(skb, 0);
	skb->cloned   = 0;
	skb->hdr_len  = 0;
	skb->nohdr    = 0;
	skb->len -= off;
	skb->data_len = skb->len;
	atomic_set(&skb_shinfo(skb)->dataref, 1);
	return 0;
}

int klpp_pskb_carve(struct sk_buff *skb, const u32 len, gfp_t gfp)
{
	int headlen = skb_headlen(skb);

	if (len < headlen)
		return klpp_pskb_carve_inside_header(skb, len, headlen, gfp);
	else
		return klpp_pskb_carve_inside_nonlinear(skb, len, headlen, gfp);
}


#include <linux/livepatch.h>

extern typeof(kmalloc_reserve) kmalloc_reserve
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, kmalloc_reserve);
extern typeof(skb_clone_fraglist) skb_clone_fraglist
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_clone_fraglist);
extern typeof(skb_free_head) skb_free_head
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_free_head);
extern typeof(skb_release_data) skb_release_data
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_release_data);
extern typeof(skb_small_head_cache) skb_small_head_cache
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, skb_small_head_cache);
