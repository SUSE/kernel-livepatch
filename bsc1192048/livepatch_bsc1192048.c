/*
 * livepatch_bsc1192048
 *
 * Fix for CVE-2021-0941, bsc#1192048
 *
 *  Upstream commit:
 *  6306c1189e77 ("bpf: Remove MTU check in __bpf_skb_max_len")
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  9de031534891e12a1f2f24407e55e39a6979fa52
 *
 *  SLE15-SP2 and -SP3 commit:
 *  2852a9350e88df56708c0adf69f17bf8dc5223db
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

/* klp-ccp: from net/core/filter.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/sock_diag.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/gfp.h>
#include <net/ip.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <linux/skmsg.h>
#include <net/sock.h>
#include <net/flow_dissector.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/uaccess.h>
#include <asm/unaligned.h>
#include <asm/cmpxchg.h>
#include <linux/filter.h>

/* klp-ccp: from include/linux/filter.h */
#define KLPP_BPF_CALL_x(x, name, ...)					       \
	static __always_inline						       \
	u64 klpp_____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__));   \
	u64 klpp_##name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));	       \
	u64 klpp_##name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))	       \
	{								       \
		return klpp_____##name(__BPF_MAP(x,__BPF_CAST,__BPF_N,__VA_ARGS__));\
	}								       \
	static __always_inline						       \
	u64 klpp_____##name(__BPF_MAP(x, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))

#define KLPP_BPF_CALL_3(name, ...)	KLPP_BPF_CALL_x(3, name, __VA_ARGS__)
#define KLPP_BPF_CALL_4(name, ...)	KLPP_BPF_CALL_x(4, name, __VA_ARGS__)

/* klp-ccp: from net/core/filter.c */
#include <linux/ratelimit.h>
#include <linux/seccomp.h>
#include <linux/if_vlan.h>
#include <linux/bpf.h>
#include <net/sch_generic.h>
#include <net/dst.h>
#include <net/tcp.h>

static inline int __bpf_try_make_writable(struct sk_buff *skb,
					  unsigned int write_len)
{
	return skb_ensure_writable(skb, write_len);
}

static int (*klpe_bpf_skb_generic_pop)(struct sk_buff *skb, u32 off, u32 len);

static int (*klpe_bpf_skb_net_hdr_push)(struct sk_buff *skb, u32 off, u32 len);

static int klpr_bpf_skb_net_hdr_pop(struct sk_buff *skb, u32 off, u32 len)
{
	bool trans_same = skb->transport_header == skb->network_header;
	int ret;

	/* Same here, __skb_push()/__skb_pull() pair not needed. */
	ret = (*klpe_bpf_skb_generic_pop)(skb, off, len);
	if (likely(!ret)) {
		skb->mac_header += len;
		skb->network_header += len;
		if (trans_same)
			skb->transport_header = skb->network_header;
	}

	return ret;
}

static u32 bpf_skb_net_base_len(const struct sk_buff *skb)
{
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		return sizeof(struct iphdr);
	case htons(ETH_P_IPV6):
		return sizeof(struct ipv6hdr);
	default:
		return ~0U;
	}
}

static int klpr_bpf_skb_net_grow(struct sk_buff *skb, u32 len_diff)
{
	u32 off = skb_mac_header_len(skb) + bpf_skb_net_base_len(skb);
	int ret;

	ret = skb_cow(skb, len_diff);
	if (unlikely(ret < 0))
		return ret;

	ret = (*klpe_bpf_skb_net_hdr_push)(skb, off, len_diff);
	if (unlikely(ret < 0))
		return ret;

	if (skb_is_gso(skb)) {
		/* Due to header grow, MSS needs to be downgraded. */
		skb_shinfo(skb)->gso_size -= len_diff;
		/* Header must be checked, and gso_segs recomputed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	return 0;
}

static int klpr_bpf_skb_net_shrink(struct sk_buff *skb, u32 len_diff)
{
	u32 off = skb_mac_header_len(skb) + bpf_skb_net_base_len(skb);
	int ret;

	ret = skb_unclone(skb, GFP_ATOMIC);
	if (unlikely(ret < 0))
		return ret;

	ret = klpr_bpf_skb_net_hdr_pop(skb, off, len_diff);
	if (unlikely(ret < 0))
		return ret;

	if (skb_is_gso(skb)) {
		/* Due to header shrink, MSS can be upgraded. */
		skb_shinfo(skb)->gso_size += len_diff;
		/* Header must be checked, and gso_segs recomputed. */
		skb_shinfo(skb)->gso_type |= SKB_GSO_DODGY;
		skb_shinfo(skb)->gso_segs = 0;
	}

	return 0;
}

/* New. */
#define BPF_SKB_MAX_LEN SKB_MAX_ALLOC

static int klpp_bpf_skb_adjust_net(struct sk_buff *skb, s32 len_diff)
{
	bool trans_same = skb->transport_header == skb->network_header;
	u32 len_cur, len_diff_abs = abs(len_diff);
	u32 len_min = bpf_skb_net_base_len(skb);
	/*
	 * Fix CVE-2021-0941
	 *  -1 line, +1 line
	 */
	u32 len_max = BPF_SKB_MAX_LEN;
	__be16 proto = skb->protocol;
	bool shrink = len_diff < 0;
	int ret;

	if (unlikely(len_diff_abs > 0xfffU))
		return -EFAULT;
	if (unlikely(proto != htons(ETH_P_IP) &&
		     proto != htons(ETH_P_IPV6)))
		return -ENOTSUPP;

	len_cur = skb->len - skb_network_offset(skb);
	if (skb_transport_header_was_set(skb) && !trans_same)
		len_cur = skb_network_header_len(skb);
	if ((shrink && (len_diff_abs >= len_cur ||
			len_cur - len_diff_abs < len_min)) ||
	    (!shrink && (skb->len + len_diff_abs > len_max &&
			 !skb_is_gso(skb))))
		return -ENOTSUPP;

	ret = shrink ? klpr_bpf_skb_net_shrink(skb, len_diff_abs) :
		       klpr_bpf_skb_net_grow(skb, len_diff_abs);

	bpf_compute_data_pointers(skb);
	return ret;
}

KLPP_BPF_CALL_4(bpf_skb_adjust_room, struct sk_buff *, skb, s32, len_diff,
	   u32, mode, u64, flags)
{
	if (unlikely(flags))
		return -EINVAL;
	if (likely(mode == BPF_ADJ_ROOM_NET))
		return klpp_bpf_skb_adjust_net(skb, len_diff);

	return -ENOTSUPP;
}

static u32 __bpf_skb_min_len(const struct sk_buff *skb)
{
	u32 min_len = skb_network_offset(skb);

	if (skb_transport_header_was_set(skb))
		min_len = skb_transport_offset(skb);
	if (skb->ip_summed == CHECKSUM_PARTIAL)
		min_len = skb_checksum_start_offset(skb) +
			  skb->csum_offset + sizeof(__sum16);
	return min_len;
}

static int bpf_skb_grow_rcsum(struct sk_buff *skb, unsigned int new_len)
{
	unsigned int old_len = skb->len;
	int ret;

	ret = __skb_grow_rcsum(skb, new_len);
	if (!ret)
		memset(skb->data + old_len, 0, new_len - old_len);
	return ret;
}

static int bpf_skb_trim_rcsum(struct sk_buff *skb, unsigned int new_len)
{
	return __skb_trim_rcsum(skb, new_len);
}

static inline int klpp___bpf_skb_change_tail(struct sk_buff *skb, u32 new_len,
					u64 flags)
{
	/*
	 * Fix CVE-2021-0941
	 *  -1 line, +1 line
	 */
	u32 max_len = BPF_SKB_MAX_LEN;
	u32 min_len = __bpf_skb_min_len(skb);
	int ret;

	if (unlikely(flags || new_len > max_len || new_len < min_len))
		return -EINVAL;
	if (skb->encapsulation)
		return -ENOTSUPP;

	/* The basic idea of this helper is that it's performing the
	 * needed work to either grow or trim an skb, and eBPF program
	 * rewrites the rest via helpers like bpf_skb_store_bytes(),
	 * bpf_lX_csum_replace() and others rather than passing a raw
	 * buffer here. This one is a slow path helper and intended
	 * for replies with control messages.
	 *
	 * Like in bpf_skb_change_proto(), we want to keep this rather
	 * minimal and without protocol specifics so that we are able
	 * to separate concerns as in bpf_skb_store_bytes() should only
	 * be the one responsible for writing buffers.
	 *
	 * It's really expected to be a slow path operation here for
	 * control message replies, so we're implicitly linearizing,
	 * uncloning and drop offloads from the skb by this.
	 */
	ret = __bpf_try_make_writable(skb, skb->len);
	if (!ret) {
		if (new_len > skb->len)
			ret = bpf_skb_grow_rcsum(skb, new_len);
		else if (new_len < skb->len)
			ret = bpf_skb_trim_rcsum(skb, new_len);
		if (!ret && skb_is_gso(skb))
			skb_gso_reset(skb);
	}
	return ret;
}

KLPP_BPF_CALL_3(bpf_skb_change_tail, struct sk_buff *, skb, u32, new_len,
	   u64, flags)
{
	int ret = klpp___bpf_skb_change_tail(skb, new_len, flags);

	bpf_compute_data_pointers(skb);
	return ret;
}

KLPP_BPF_CALL_3(sk_skb_change_tail, struct sk_buff *, skb, u32, new_len,
	   u64, flags)
{
	int ret = klpp___bpf_skb_change_tail(skb, new_len, flags);

	bpf_compute_data_end_sk_skb(skb);
	return ret;
}

static inline int klpp___bpf_skb_change_head(struct sk_buff *skb, u32 head_room,
					u64 flags)
{
	/*
	 * Fix CVE-2021-0941
	 *  -1 line, +1 line
	 */
	u32 max_len = BPF_SKB_MAX_LEN;
	u32 new_len = skb->len + head_room;
	int ret;

	if (unlikely(flags || (!skb_is_gso(skb) && new_len > max_len) ||
		     new_len < skb->len))
		return -EINVAL;

	ret = skb_cow(skb, head_room);
	if (likely(!ret)) {
		/* Idea for this helper is that we currently only
		 * allow to expand on mac header. This means that
		 * skb->protocol network header, etc, stay as is.
		 * Compared to bpf_skb_change_tail(), we're more
		 * flexible due to not needing to linearize or
		 * reset GSO. Intention for this helper is to be
		 * used by an L3 skb that needs to push mac header
		 * for redirection into L2 device.
		 */
		__skb_push(skb, head_room);
		memset(skb->data, 0, head_room);
		skb_reset_mac_header(skb);
	}

	return ret;
}

KLPP_BPF_CALL_3(bpf_skb_change_head, struct sk_buff *, skb, u32, head_room,
	   u64, flags)
{
	int ret = klpp___bpf_skb_change_head(skb, head_room, flags);

	bpf_compute_data_pointers(skb);
	return ret;
}

KLPP_BPF_CALL_3(sk_skb_change_head, struct sk_buff *, skb, u32, head_room,
	   u64, flags)
{
	int ret = klpp___bpf_skb_change_head(skb, head_room, flags);

	bpf_compute_data_end_sk_skb(skb);
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1192048.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bpf_skb_generic_pop", (void *)&klpe_bpf_skb_generic_pop },
	{ "bpf_skb_net_hdr_push", (void *)&klpe_bpf_skb_net_hdr_push },
};

int livepatch_bsc1192048_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
