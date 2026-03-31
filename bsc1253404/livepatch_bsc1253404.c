/*
 * livepatch_bsc1253404
 *
 * Fix for CVE-2025-40159, bsc#1253404
 *
 *  Copyright (c) 2026 SUSE
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


#include <linux/if_xdp.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/vmalloc.h>
#include <net/xdp_sock_drv.h>

/* klp-ccp: from include/net/xdp_sock_drv.h */
#ifndef CONFIG_XDP_SOCKETS
#error "klp-ccp: CONFIG_XDP_SOCKETS is not defined"
#endif /* CONFIG_XDP_SOCKETS */

/* klp-ccp: from net/xdp/xsk.c */
#include <net/xdp.h>
/* klp-ccp: from net/xdp/xsk_queue.h */
#include <linux/types.h>
#include <linux/if_xdp.h>
#include <net/xdp_sock.h>
#include <net/xsk_buff_pool.h>

/* klp-ccp: from net/xdp/xsk.h */
static inline struct xdp_sock *xdp_sk(struct sock *sk)
{
	return (struct xdp_sock *)sk;
}

/* klp-ccp: from net/xdp/xsk_queue.h */
struct xdp_ring {
	u32 producer ____cacheline_aligned_in_smp;
	/* Hinder the adjacent cache prefetcher to prefetch the consumer
	 * pointer if the producer pointer is touched and vice versa.
	 */
	u32 pad1 ____cacheline_aligned_in_smp;
	u32 consumer ____cacheline_aligned_in_smp;
	u32 pad2 ____cacheline_aligned_in_smp;
	u32 flags;
	u32 pad3 ____cacheline_aligned_in_smp;
};

struct xdp_rxtx_ring {
	struct xdp_ring ptrs;
	struct xdp_desc desc[] ____cacheline_aligned_in_smp;
};

struct xdp_umem_ring {
	struct xdp_ring ptrs;
	u64 desc[] ____cacheline_aligned_in_smp;
};

struct xsk_queue {
	u32 ring_mask;
	u32 nentries;
	u32 cached_prod;
	u32 cached_cons;
	struct xdp_ring *ring;
	u64 invalid_descs;
	u64 queue_empty_descs;
	size_t ring_vmalloc_size;
};

struct parsed_desc {
	u32 mb;
	u32 valid;
};

static inline bool xp_unused_options_set(u32 options)
{
	return options & ~(XDP_PKT_CONTD | XDP_TX_METADATA);
}

static inline bool xp_aligned_validate_desc(struct xsk_buff_pool *pool,
					    struct xdp_desc *desc)
{
	u64 len = desc->len;
	u64 addr, offset;

	if (!len)
		return false;

	/* Can overflow if desc->addr < pool->tx_metadata_len */
	if (check_sub_overflow(desc->addr, pool->tx_metadata_len, &addr))
		return false;

	offset = addr & (pool->chunk_size - 1);

	/*
	 * Can't overflow: @offset is guaranteed to be < ``U32_MAX``
	 * (pool->chunk_size is ``u32``), @len is guaranteed
	 * to be <= ``U32_MAX``.
	 */
	if (offset + len + pool->tx_metadata_len > pool->chunk_size)
		return false;

	if (addr >= pool->addrs_cnt)
		return false;

	if (xp_unused_options_set(desc->options))
		return false;

	return true;
}

static inline bool xp_unaligned_validate_desc(struct xsk_buff_pool *pool,
					      struct xdp_desc *desc)
{
	u64 len = desc->len;
	u64 addr, end;

	if (!len)
		return false;

	/* Can't overflow: @len is guaranteed to be <= ``U32_MAX`` */
	len += pool->tx_metadata_len;
	if (len > pool->chunk_size)
		return false;

	/* Can overflow if desc->addr is close to 0 */
	if (check_sub_overflow(xp_unaligned_add_offset_to_addr(desc->addr),
			       pool->tx_metadata_len, &addr))
		return false;

	if (addr >= pool->addrs_cnt)
		return false;

	/* Can overflow if pool->addrs_cnt is high enough */
	if (check_add_overflow(addr, len, &end) || end > pool->addrs_cnt)
		return false;

	if (xp_desc_crosses_non_contig_pg(pool, addr, len))
		return false;

	if (xp_unused_options_set(desc->options))
		return false;

	return true;
}

static inline bool xp_validate_desc(struct xsk_buff_pool *pool,
				    struct xdp_desc *desc)
{
	return pool->unaligned ? xp_unaligned_validate_desc(pool, desc) :
		xp_aligned_validate_desc(pool, desc);
}

static inline bool xskq_has_descs(struct xsk_queue *q)
{
	return q->cached_cons != q->cached_prod;
}

static inline bool xskq_cons_is_valid_desc(struct xsk_queue *q,
					   struct xdp_desc *d,
					   struct xsk_buff_pool *pool)
{
	if (!xp_validate_desc(pool, d)) {
		q->invalid_descs++;
		return false;
	}
	return true;
}

static inline bool xskq_cons_read_desc(struct xsk_queue *q,
				       struct xdp_desc *desc,
				       struct xsk_buff_pool *pool)
{
	if (q->cached_cons != q->cached_prod) {
		struct xdp_rxtx_ring *ring = (struct xdp_rxtx_ring *)q->ring;
		u32 idx = q->cached_cons & q->ring_mask;

		*desc = ring->desc[idx];
		return xskq_cons_is_valid_desc(q, desc, pool);
	}

	q->queue_empty_descs++;
	return false;
}

static inline void xskq_cons_release_n(struct xsk_queue *q, u32 cnt)
{
	q->cached_cons += cnt;
}

static inline void parse_desc(struct xsk_queue *q, struct xsk_buff_pool *pool,
			      struct xdp_desc *desc, struct parsed_desc *parsed)
{
	parsed->valid = xskq_cons_is_valid_desc(q, desc, pool);
	parsed->mb = xp_mb_desc(desc);
}

static inline
u32 xskq_cons_read_desc_batch(struct xsk_queue *q, struct xsk_buff_pool *pool,
			      u32 max)
{
	u32 cached_cons = q->cached_cons, nb_entries = 0;
	struct xdp_desc *descs = pool->tx_descs;
	u32 total_descs = 0, nr_frags = 0;

	/* track first entry, if stumble upon *any* invalid descriptor, rewind
	 * current packet that consists of frags and stop the processing
	 */
	while (cached_cons != q->cached_prod && nb_entries < max) {
		struct xdp_rxtx_ring *ring = (struct xdp_rxtx_ring *)q->ring;
		u32 idx = cached_cons & q->ring_mask;
		struct parsed_desc parsed;

		descs[nb_entries] = ring->desc[idx];
		cached_cons++;
		parse_desc(q, pool, &descs[nb_entries], &parsed);
		if (unlikely(!parsed.valid))
			break;

		if (likely(!parsed.mb)) {
			total_descs += (nr_frags + 1);
			nr_frags = 0;
		} else {
			nr_frags++;
			if (nr_frags == pool->netdev->xdp_zc_max_segs) {
				nr_frags = 0;
				break;
			}
		}
		nb_entries++;
	}

	cached_cons -= nr_frags;
	/* Release valid plus any invalid entries */
	xskq_cons_release_n(q, cached_cons - q->cached_cons);
	return total_descs;
}

static inline void __xskq_cons_release(struct xsk_queue *q)
{
	smp_store_release(&q->ring->consumer, q->cached_cons); /* D, matchees A */
}

static inline void __xskq_cons_peek(struct xsk_queue *q)
{
	/* Refresh the local pointer */
	q->cached_prod = smp_load_acquire(&q->ring->producer);  /* C, matches B */
}

static inline void xskq_cons_get_entries(struct xsk_queue *q)
{
	__xskq_cons_release(q);
	__xskq_cons_peek(q);
}

static inline u32 xskq_cons_nb_entries(struct xsk_queue *q, u32 max)
{
	u32 entries = q->cached_prod - q->cached_cons;

	if (entries >= max)
		return max;

	__xskq_cons_peek(q);
	entries = q->cached_prod - q->cached_cons;

	return entries >= max ? max : entries;
}

static inline bool xskq_cons_peek_desc(struct xsk_queue *q,
				       struct xdp_desc *desc,
				       struct xsk_buff_pool *pool)
{
	if (q->cached_prod == q->cached_cons)
		xskq_cons_get_entries(q);
	return xskq_cons_read_desc(q, desc, pool);
}

static inline void xskq_cons_release(struct xsk_queue *q)
{
	q->cached_cons++;
}

static inline void xskq_cons_cancel_n(struct xsk_queue *q, u32 cnt)
{
	q->cached_cons -= cnt;
}

static inline u32 xskq_cons_present_entries(struct xsk_queue *q)
{
	/* No barriers needed since data is not accessed */
	return READ_ONCE(q->ring->producer) - READ_ONCE(q->ring->consumer);
}

static inline u32 xskq_prod_nb_free(struct xsk_queue *q, u32 max)
{
	u32 free_entries = q->nentries - (q->cached_prod - q->cached_cons);

	if (free_entries >= max)
		return max;

	/* Refresh the local tail pointer */
	q->cached_cons = READ_ONCE(q->ring->consumer);
	free_entries = q->nentries - (q->cached_prod - q->cached_cons);

	return free_entries >= max ? max : free_entries;
}

static inline bool xskq_prod_is_full(struct xsk_queue *q)
{
	return xskq_prod_nb_free(q, 1) ? false : true;
}

static inline void xskq_prod_cancel_n(struct xsk_queue *q, u32 cnt)
{
	q->cached_prod -= cnt;
}

static inline int xskq_prod_reserve_addr(struct xsk_queue *q, u64 addr)
{
	struct xdp_umem_ring *ring = (struct xdp_umem_ring *)q->ring;

	if (xskq_prod_is_full(q))
		return -ENOSPC;

	/* A, matches D */
	ring->desc[q->cached_prod++ & q->ring_mask] = addr;
	return 0;
}

static inline void xskq_prod_write_addr_batch(struct xsk_queue *q, struct xdp_desc *descs,
					      u32 nb_entries)
{
	struct xdp_umem_ring *ring = (struct xdp_umem_ring *)q->ring;
	u32 i, cached_prod;

	/* A, matches D */
	cached_prod = q->cached_prod;
	for (i = 0; i < nb_entries; i++)
		ring->desc[cached_prod++ & q->ring_mask] = descs[i].addr;
	q->cached_prod = cached_prod;
}

/* klp-ccp: from net/xdp/xdp_umem.h */
#include <net/xdp_sock_drv.h>

#include "livepatch_bsc1253404.h"

/* klp-ccp: from net/xdp/xsk.c */
#define TX_BATCH_SIZE 32
#define MAX_PER_SOCKET_BUDGET (TX_BATCH_SIZE)

static bool xsk_tx_writeable(struct xdp_sock *xs)
{
	if (xskq_cons_present_entries(xs->tx) > xs->tx->nentries / 2)
		return false;

	return true;
}

static bool xsk_is_bound(struct xdp_sock *xs)
{
	if (READ_ONCE(xs->state) == XSK_BOUND) {
		/* Matches smp_wmb() in bind(). */
		smp_rmb();
		return true;
	}
	return false;
}

void xsk_tx_release(struct xsk_buff_pool *pool);

extern typeof(xsk_tx_release) xsk_tx_release;

bool klpp_xsk_tx_peek_desc(struct xsk_buff_pool *pool, struct xdp_desc *desc)
{
	bool budget_exhausted = false;
	struct xdp_sock *xs;

	rcu_read_lock();
again:
	list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list) {
		if (xs->tx_budget_spent >= MAX_PER_SOCKET_BUDGET) {
			budget_exhausted = true;
			continue;
		}

		if (!xskq_cons_peek_desc(xs->tx, desc, pool)) {
			if (xskq_has_descs(xs->tx))
				xskq_cons_release(xs->tx);
			continue;
		}

		xs->tx_budget_spent++;

		/* This is the backpressure mechanism for the Tx path.
		 * Reserve space in the completion queue and only proceed
		 * if there is space in it. This avoids having to implement
		 * any buffering in the Tx path.
		 */
		if (xskq_prod_reserve_addr(pool->cq, desc->addr))
			goto out;

		xskq_cons_release(xs->tx);
		rcu_read_unlock();
		return true;
	}

	if (budget_exhausted) {
		list_for_each_entry_rcu(xs, &pool->xsk_tx_list, tx_list)
			xs->tx_budget_spent = 0;

		budget_exhausted = false;
		goto again;
	}

out:
	rcu_read_unlock();
	return false;
}


static u32 klpr_xsk_tx_peek_release_fallback(struct xsk_buff_pool *pool, u32 max_entries)
{
	struct xdp_desc *descs = pool->tx_descs;
	u32 nb_pkts = 0;

	while (nb_pkts < max_entries && klpp_xsk_tx_peek_desc(pool, &descs[nb_pkts]))
		nb_pkts++;

	xsk_tx_release(pool);
	return nb_pkts;
}

u32 klpp_xsk_tx_peek_release_desc_batch(struct xsk_buff_pool *pool, u32 nb_pkts)
{
	struct xdp_sock *xs;

	rcu_read_lock();
	if (!list_is_singular(&pool->xsk_tx_list)) {
		/* Fallback to the non-batched version */
		rcu_read_unlock();
		return klpr_xsk_tx_peek_release_fallback(pool, nb_pkts);
	}

	xs = list_first_or_null_rcu(&pool->xsk_tx_list, struct xdp_sock, tx_list);
	if (!xs) {
		nb_pkts = 0;
		goto out;
	}

	nb_pkts = xskq_cons_nb_entries(xs->tx, nb_pkts);

	/* This is the backpressure mechanism for the Tx path. Try to
	 * reserve space in the completion queue for all packets, but
	 * if there are fewer slots available, just process that many
	 * packets. This avoids having to implement any buffering in
	 * the Tx path.
	 */
	nb_pkts = xskq_prod_nb_free(pool->cq, nb_pkts);
	if (!nb_pkts)
		goto out;

	nb_pkts = xskq_cons_read_desc_batch(xs->tx, pool, nb_pkts);
	if (!nb_pkts) {
		xs->tx->queue_empty_descs++;
		goto out;
	}

	__xskq_cons_release(xs->tx);
	xskq_prod_write_addr_batch(pool->cq, pool->tx_descs, nb_pkts);
	xs->sk.sk_write_space(&xs->sk);

out:
	rcu_read_unlock();
	return nb_pkts;
}

static int xsk_cq_reserve_addr_locked(struct xdp_sock *xs, u64 addr)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&xs->pool->cq_lock, flags);
	ret = xskq_prod_reserve_addr(xs->pool->cq, addr);
	spin_unlock_irqrestore(&xs->pool->cq_lock, flags);

	return ret;
}

static void xsk_cq_cancel_locked(struct xdp_sock *xs, u32 n)
{
	unsigned long flags;

	spin_lock_irqsave(&xs->pool->cq_lock, flags);
	xskq_prod_cancel_n(xs->pool->cq, n);
	spin_unlock_irqrestore(&xs->pool->cq_lock, flags);
}

static u32 xsk_get_num_desc(struct sk_buff *skb)
{
	return skb ? (long)skb_shinfo(skb)->destructor_arg : 0;
}

extern void xsk_destruct_skb(struct sk_buff *skb);

static void xsk_set_destructor_arg(struct sk_buff *skb)
{
	long num = xsk_get_num_desc(xdp_sk(skb->sk)->skb) + 1;

	skb_shinfo(skb)->destructor_arg = (void *)num;
}

static void xsk_consume_skb(struct sk_buff *skb)
{
	struct xdp_sock *xs = xdp_sk(skb->sk);

	skb->destructor = sock_wfree;
	xsk_cq_cancel_locked(xs, xsk_get_num_desc(skb));
	/* Free skb without triggering the perf drop trace */
	consume_skb(skb);
	xs->skb = NULL;
}

static void xsk_drop_skb(struct sk_buff *skb)
{
	xdp_sk(skb->sk)->tx->invalid_descs += xsk_get_num_desc(skb);
	xsk_consume_skb(skb);
}

static struct sk_buff *xsk_build_skb_zerocopy(struct xdp_sock *xs,
					      struct xdp_desc *desc)
{
	struct xsk_buff_pool *pool = xs->pool;
	u32 hr, len, ts, offset, copy, copied;
	struct sk_buff *skb = xs->skb;
	struct page *page;
	void *buffer;
	int err, i;
	u64 addr;

	if (!skb) {
		hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(xs->dev->needed_headroom));

		skb = sock_alloc_send_skb(&xs->sk, hr, 1, &err);
		if (unlikely(!skb))
			return ERR_PTR(err);

		skb_reserve(skb, hr);
	}

	addr = desc->addr;
	len = desc->len;
	ts = pool->unaligned ? len : pool->chunk_size;

	buffer = xsk_buff_raw_get_data(pool, addr);
	offset = offset_in_page(buffer);
	addr = buffer - pool->addrs;

	for (copied = 0, i = skb_shinfo(skb)->nr_frags; copied < len; i++) {
		if (unlikely(i >= MAX_SKB_FRAGS))
			return ERR_PTR(-EOVERFLOW);

		page = pool->umem->pgs[addr >> PAGE_SHIFT];
		get_page(page);

		copy = min_t(u32, PAGE_SIZE - offset, len - copied);
		skb_fill_page_desc(skb, i, page, offset, copy);

		copied += copy;
		addr += copy;
		offset = 0;
	}

	skb->len += len;
	skb->data_len += len;
	skb->truesize += ts;

	refcount_add(ts, &xs->sk.sk_wmem_alloc);

	return skb;
}

static struct sk_buff *xsk_build_skb(struct xdp_sock *xs,
				     struct xdp_desc *desc)
{
	struct xsk_tx_metadata *meta = NULL;
	struct net_device *dev = xs->dev;
	struct sk_buff *skb = xs->skb;
	bool first_frag = false;
	int err;

	if (dev->priv_flags & IFF_TX_SKB_NO_LINEAR) {
		skb = xsk_build_skb_zerocopy(xs, desc);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			goto free_err;
		}
	} else {
		u32 hr, tr, len;
		void *buffer;

		buffer = xsk_buff_raw_get_data(xs->pool, desc->addr);
		len = desc->len;

		if (!skb) {
			first_frag = true;

			hr = max(NET_SKB_PAD, L1_CACHE_ALIGN(dev->needed_headroom));
			tr = dev->needed_tailroom;
			skb = sock_alloc_send_skb(&xs->sk, hr + len + tr, 1, &err);
			if (unlikely(!skb))
				goto free_err;

			skb_reserve(skb, hr);
			skb_put(skb, len);

			err = skb_store_bits(skb, 0, buffer, len);
			if (unlikely(err))
				goto free_err;
		} else {
			int nr_frags = skb_shinfo(skb)->nr_frags;
			struct page *page;
			u8 *vaddr;

			if (unlikely(nr_frags == (MAX_SKB_FRAGS - 1) && xp_mb_desc(desc))) {
				err = -EOVERFLOW;
				goto free_err;
			}

			page = alloc_page(xs->sk.sk_allocation);
			if (unlikely(!page)) {
				err = -EAGAIN;
				goto free_err;
			}

			vaddr = kmap_local_page(page);
			memcpy(vaddr, buffer, len);
			kunmap_local(vaddr);

			skb_add_rx_frag(skb, nr_frags, page, 0, len, PAGE_SIZE);
			refcount_add(PAGE_SIZE, &xs->sk.sk_wmem_alloc);
		}

		if (first_frag && desc->options & XDP_TX_METADATA) {
			if (unlikely(xs->pool->tx_metadata_len == 0)) {
				err = -EINVAL;
				goto free_err;
			}

			meta = buffer - xs->pool->tx_metadata_len;
			if (unlikely(!xsk_buff_valid_tx_metadata(meta))) {
				err = -EINVAL;
				goto free_err;
			}

			if (meta->flags & XDP_TXMD_FLAGS_CHECKSUM) {
				if (unlikely(meta->request.csum_start +
					     meta->request.csum_offset +
					     sizeof(__sum16) > len)) {
					err = -EINVAL;
					goto free_err;
				}

				skb->csum_start = hr + meta->request.csum_start;
				skb->csum_offset = meta->request.csum_offset;
				skb->ip_summed = CHECKSUM_PARTIAL;

				if (unlikely(xs->pool->tx_sw_csum)) {
					err = skb_checksum_help(skb);
					if (err)
						goto free_err;
				}
			}
		}
	}

	skb->dev = dev;
	skb->priority = READ_ONCE(xs->sk.sk_priority);
	skb->mark = READ_ONCE(xs->sk.sk_mark);
	skb->destructor = xsk_destruct_skb;
	xsk_tx_metadata_to_compl(meta, &skb_shinfo(skb)->xsk_meta);
	xsk_set_destructor_arg(skb);

	return skb;

free_err:
	if (first_frag && skb)
		kfree_skb(skb);

	if (err == -EOVERFLOW) {
		/* Drop the packet */
		xsk_set_destructor_arg(xs->skb);
		xsk_drop_skb(xs->skb);
		xskq_cons_release(xs->tx);
	} else {
		/* Let application retry */
		xsk_cq_cancel_locked(xs, 1);
	}

	return ERR_PTR(err);
}

int klpp___xsk_generic_xmit(struct sock *sk)
{
	struct xdp_sock *xs = xdp_sk(sk);
	u32 max_batch = TX_BATCH_SIZE;
	bool sent_frame = false;
	struct xdp_desc desc;
	struct sk_buff *skb;
	int err = 0;

	mutex_lock(&xs->mutex);

	/* Since we dropped the RCU read lock, the socket state might have changed. */
	if (unlikely(!xsk_is_bound(xs))) {
		err = -ENXIO;
		goto out;
	}

	if (xs->queue_id >= xs->dev->real_num_tx_queues)
		goto out;

	while (xskq_cons_peek_desc(xs->tx, &desc, xs->pool)) {
		if (max_batch-- == 0) {
			err = -EAGAIN;
			goto out;
		}

		/* This is the backpressure mechanism for the Tx path.
		 * Reserve space in the completion queue and only proceed
		 * if there is space in it. This avoids having to implement
		 * any buffering in the Tx path.
		 */
		if (xsk_cq_reserve_addr_locked(xs, desc.addr))
			goto out;

		skb = xsk_build_skb(xs, &desc);
		if (IS_ERR(skb)) {
			err = PTR_ERR(skb);
			if (err != -EOVERFLOW)
				goto out;
			err = 0;
			continue;
		}

		xskq_cons_release(xs->tx);

		if (xp_mb_desc(&desc)) {
			xs->skb = skb;
			continue;
		}

		err = __dev_direct_xmit(skb, xs->queue_id);
		if  (err == NETDEV_TX_BUSY) {
			/* Tell user-space to retry the send */
			xskq_cons_cancel_n(xs->tx, xsk_get_num_desc(skb));
			xsk_consume_skb(skb);
			err = -EAGAIN;
			goto out;
		}

		/* Ignore NET_XMIT_CN as packet might have been sent */
		if (err == NET_XMIT_DROP) {
			/* SKB completed but not sent */
			err = -EBUSY;
			xs->skb = NULL;
			goto out;
		}

		sent_frame = true;
		xs->skb = NULL;
	}

	if (xskq_has_descs(xs->tx)) {
		if (xs->skb)
			xsk_drop_skb(xs->skb);
		xskq_cons_release(xs->tx);
	}

out:
	if (sent_frame)
		if (xsk_tx_writeable(xs))
			sk->sk_write_space(sk);

	mutex_unlock(&xs->mutex);
	return err;
}



#include <linux/livepatch.h>

extern typeof(xsk_destruct_skb) xsk_destruct_skb
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, xsk_destruct_skb);
