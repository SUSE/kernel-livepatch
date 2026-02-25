/*
 * livepatch_bsc1258139
 *
 * Fix for CVE-2025-38129, bsc#1258139
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



/* klp-ccp: from net/core/page_pool.c */
#include <linux/error-injection.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <net/page_pool/helpers.h>

/* klp-ccp: from include/net/page_pool/types.h */
void klpp_page_pool_put_unrefed_netmem(struct page_pool *pool, netmem_ref netmem,
				  unsigned int dma_sync_size,
				  bool allow_direct);

/* klp-ccp: from net/core/page_pool.c */
#include <net/xdp.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/page-flags.h>
#include <linux/mm.h> /* for put_page() */
#include <linux/poison.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <trace/events/page_pool.h>

/* klp-ccp: from net/core/page_pool_priv.h */
s32 page_pool_inflight(const struct page_pool *pool, bool strict);

void page_pool_unlist(struct page_pool *pool);

/* klp-ccp: from net/core/page_pool.c */
#define recycle_stat_inc(pool, __stat)							\
	do {										\
		struct page_pool_recycle_stats __percpu *s = pool->recycle_stats;	\
		this_cpu_inc(s->__stat);						\
	} while (0)

static bool page_pool_producer_lock(struct page_pool *pool)
	__acquires(&pool->ring.producer_lock)
{
	bool in_softirq = in_softirq();

	if (in_softirq)
		spin_lock(&pool->ring.producer_lock);
	else
		spin_lock_bh(&pool->ring.producer_lock);

	return in_softirq;
}

static void page_pool_producer_unlock(struct page_pool *pool,
				      bool in_softirq)
	__releases(&pool->ring.producer_lock)
{
	if (in_softirq)
		spin_unlock(&pool->ring.producer_lock);
	else
		spin_unlock_bh(&pool->ring.producer_lock);
}

extern void page_pool_uninit(struct page_pool *pool);

extern void page_pool_return_page(struct page_pool *pool, netmem_ref netmem);

static void __page_pool_dma_sync_for_device(const struct page_pool *pool,
					    netmem_ref netmem,
					    u32 dma_sync_size)
{
#if defined(CONFIG_HAS_DMA) && defined(CONFIG_DMA_NEED_SYNC)
	dma_addr_t dma_addr = page_pool_get_dma_addr_netmem(netmem);

	dma_sync_size = min(dma_sync_size, pool->p.max_len);
	__dma_sync_single_for_device(pool->p.dev, dma_addr + pool->p.offset,
				     dma_sync_size, pool->p.dma_dir);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

static __always_inline void
page_pool_dma_sync_for_device(const struct page_pool *pool,
			      netmem_ref netmem,
			      u32 dma_sync_size)
{
	if (pool->dma_sync && dma_dev_need_sync(pool->p.dev))
		__page_pool_dma_sync_for_device(pool, netmem, dma_sync_size);
}

s32 page_pool_inflight(const struct page_pool *pool, bool strict);

void page_pool_return_page(struct page_pool *pool, netmem_ref netmem);

static bool klpp_page_pool_recycle_in_ring(struct page_pool *pool, netmem_ref netmem)
{
	bool in_softirq, ret;

	/* BH protection not needed if current is softirq */
	in_softirq = page_pool_producer_lock(pool);
	ret = !__ptr_ring_produce(&pool->ring, (__force void *)netmem);
	if (ret)
		recycle_stat_inc(pool, ring);
	page_pool_producer_unlock(pool, in_softirq);

	return ret;
}

static bool page_pool_recycle_in_cache(netmem_ref netmem,
				       struct page_pool *pool)
{
	if (unlikely(pool->alloc.count == PP_ALLOC_CACHE_SIZE)) {
		recycle_stat_inc(pool, cache_full);
		return false;
	}

	/* Caller MUST have verified/know (page_ref_count(page) == 1) */
	pool->alloc.cache[pool->alloc.count++] = netmem;
	recycle_stat_inc(pool, cached);
	return true;
}

static bool __page_pool_page_can_be_recycled(netmem_ref netmem)
{
	return page_ref_count(netmem_to_page(netmem)) == 1 &&
	       !page_is_pfmemalloc(netmem_to_page(netmem));
}

static __always_inline netmem_ref
__page_pool_put_page(struct page_pool *pool, netmem_ref netmem,
		     unsigned int dma_sync_size, bool allow_direct)
{
	lockdep_assert_no_hardirq();

	/* This allocator is optimized for the XDP mode that uses
	 * one-frame-per-page, but have fallbacks that act like the
	 * regular page allocator APIs.
	 *
	 * refcnt == 1 means page_pool owns page, and can recycle it.
	 *
	 * page is NOT reusable when allocated when system is under
	 * some pressure. (page_is_pfmemalloc)
	 */
	if (likely(__page_pool_page_can_be_recycled(netmem))) {
		/* Read barrier done in page_ref_count / READ_ONCE */

		page_pool_dma_sync_for_device(pool, netmem, dma_sync_size);

		if (allow_direct && page_pool_recycle_in_cache(netmem, pool))
			return 0;

		/* Page found as candidate for recycling */
		return netmem;
	}
	/* Fallback/non-XDP mode: API user have elevated refcnt.
	 *
	 * Many drivers split up the page into fragments, and some
	 * want to keep doing this to save memory and do refcnt based
	 * recycling. Support this use case too, to ease drivers
	 * switching between XDP/non-XDP.
	 *
	 * In-case page_pool maintains the DMA mapping, API user must
	 * call page_pool_put_page once.  In this elevated refcnt
	 * case, the DMA is unmapped/released, as driver is likely
	 * doing refcnt based recycle tricks, meaning another process
	 * will be invoking put_page.
	 */
	recycle_stat_inc(pool, released_refcnt);
	page_pool_return_page(pool, netmem);

	return 0;
}

static bool page_pool_napi_local(const struct page_pool *pool)
{
	const struct napi_struct *napi;
	u32 cpuid;

	if (unlikely(!in_softirq()))
		return false;

	/* Allow direct recycle if we have reasons to believe that we are
	 * in the same context as the consumer would run, so there's
	 * no possible race.
	 * __page_pool_put_page() makes sure we're not in hardirq context
	 * and interrupts are enabled prior to accessing the cache.
	 */
	cpuid = smp_processor_id();
	if (READ_ONCE(pool->cpuid) == cpuid)
		return true;

	napi = READ_ONCE(pool->p.napi);

	return napi && READ_ONCE(napi->list_owner) == cpuid;
}

void klpp_page_pool_put_unrefed_netmem(struct page_pool *pool, netmem_ref netmem,
				  unsigned int dma_sync_size, bool allow_direct)
{
	if (!allow_direct)
		allow_direct = page_pool_napi_local(pool);

	netmem =
		__page_pool_put_page(pool, netmem, dma_sync_size, allow_direct);
	if (netmem && !klpp_page_pool_recycle_in_ring(pool, netmem)) {
		/* Cache full, fallback to free pages */
		recycle_stat_inc(pool, ring_full);
		page_pool_return_page(pool, netmem);
	}
}

typeof(klpp_page_pool_put_unrefed_netmem) klpp_page_pool_put_unrefed_netmem;

static void page_pool_empty_ring(struct page_pool *pool)
{
	netmem_ref netmem;

	/* Empty recycle ring */
	while ((netmem = (__force netmem_ref)ptr_ring_consume_bh(&pool->ring))) {
		/* Verify the refcnt invariant of cached pages */
		if (!(page_ref_count(netmem_to_page(netmem)) == 1))
			pr_crit("%s() page_pool refcnt %d violation\n",
				__func__, netmem_ref_count(netmem));

		page_pool_return_page(pool, netmem);
	}
}

static void __page_pool_destroy(struct page_pool *pool)
{
	if (pool->disconnect)
		pool->disconnect(pool);

	page_pool_unlist(pool);
	page_pool_uninit(pool);
	kfree(pool);
}

static void page_pool_empty_alloc_cache_once(struct page_pool *pool)
{
	netmem_ref netmem;

	if (pool->destroy_cnt)
		return;

	/* Empty alloc cache, assume caller made sure this is
	 * no-longer in use, and page_pool_alloc_pages() cannot be
	 * call concurrently.
	 */
	while (pool->alloc.count) {
		netmem = pool->alloc.cache[--pool->alloc.count];
		page_pool_return_page(pool, netmem);
	}
}

static void page_pool_scrub(struct page_pool *pool)
{
	page_pool_empty_alloc_cache_once(pool);
	pool->destroy_cnt++;

	/* No more consumers should exist, but producers could still
	 * be in-flight.
	 */
	page_pool_empty_ring(pool);
}

int klpp_page_pool_release(struct page_pool *pool)
{
	bool in_softirq;
	int inflight;

	page_pool_scrub(pool);
	inflight = page_pool_inflight(pool, true);
	/* Acquire producer lock to make sure producers have exited. */
	in_softirq = page_pool_producer_lock(pool);
	page_pool_producer_unlock(pool, in_softirq);
	if (!inflight)
		__page_pool_destroy(pool);

	return inflight;
}


#include "livepatch_bsc1258139.h"

#include <linux/livepatch.h>

extern typeof(page_pool_inflight) page_pool_inflight
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, page_pool_inflight);
extern typeof(page_pool_return_page) page_pool_return_page
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, page_pool_return_page);
extern typeof(page_pool_uninit) page_pool_uninit
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, page_pool_uninit);
extern typeof(page_pool_unlist) page_pool_unlist
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, page_pool_unlist);
