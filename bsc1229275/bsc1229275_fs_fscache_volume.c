/*
 * bsc1229275_fs_fscache_volume
 *
 * Fix for CVE-2024-41057, bsc#1229275
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from fs/fscache/volume.c */
#include <linux/export.h>
#include <linux/slab.h>

/* klp-ccp: from fs/fscache/internal.h */
#include <linux/slab.h>
#include <linux/fscache-cache.h>
#include <trace/events/fscache.h>
#include <linux/sched.h>
#include <linux/seq_file.h>

extern void fscache_put_cache(struct fscache_cache *cache, enum fscache_cache_trace where);

extern atomic_t fscache_n_volumes;

static inline void fscache_stat_d(atomic_t *stat)
{
	atomic_dec(stat);
}

/* klp-ccp: from fs/fscache/volume.c */
#define fscache_volume_hash_shift 10
extern struct hlist_bl_head fscache_volume_hash[1 << fscache_volume_hash_shift];

#include "../klp_trace.h"

KLPR_TRACE_EVENT(fscache, fscache_volume,
                 TP_PROTO(unsigned int volume_debug_id, int usage,
                          enum fscache_volume_trace where),
                 TP_ARGS(volume_debug_id, usage, where));

static void fscache_see_volume(struct fscache_volume *volume,
			       enum fscache_volume_trace where)
{
	int ref = refcount_read(&volume->ref);

	klpr_trace_fscache_volume(volume->debug_id, ref, where);
}

extern void __fscache_begin_volume_access(struct fscache_volume *volume,
					  struct fscache_cookie *cookie,
					  enum fscache_access_trace why);

extern void fscache_end_volume_access(struct fscache_volume *volume,
			       struct fscache_cookie *cookie,
			       enum fscache_access_trace why);

static bool fscache_volume_same(const struct fscache_volume *a,
				const struct fscache_volume *b)
{
	size_t klen;

	if (a->key_hash	!= b->key_hash ||
	    a->cache	!= b->cache ||
	    a->key[0]	!= b->key[0])
		return false;

	klen = round_up(a->key[0] + 1, sizeof(__le32));
	return memcmp(a->key, b->key, klen) == 0;
}

static void fscache_wake_pending_volume(struct fscache_volume *volume,
					struct hlist_bl_head *h)
{
	struct fscache_volume *cursor;
	struct hlist_bl_node *p;

	hlist_bl_for_each_entry(cursor, p, h, hash_link) {
		if (fscache_volume_same(cursor, volume)) {
			fscache_see_volume(cursor, fscache_volume_see_hash_wake);
			clear_and_wake_up_bit(FSCACHE_VOLUME_ACQUIRE_PENDING,
					      &cursor->flags);
			return;
		}
	}
}

static void fscache_unhash_volume(struct fscache_volume *volume)
{
	struct hlist_bl_head *h;
	unsigned int bucket;

	bucket = volume->key_hash & (ARRAY_SIZE(fscache_volume_hash) - 1);
	h = &fscache_volume_hash[bucket];

	hlist_bl_lock(h);
	hlist_bl_del(&volume->hash_link);
	if (test_bit(FSCACHE_VOLUME_COLLIDED_WITH, &volume->flags))
		fscache_wake_pending_volume(volume, h);
	hlist_bl_unlock(h);
}

static void fscache_free_volume(struct fscache_volume *volume)
{
	struct fscache_cache *cache = volume->cache;

	if (volume->cache_priv) {
		__fscache_begin_volume_access(volume, NULL,
					      fscache_access_relinquish_volume);
		if (volume->cache_priv)
			cache->ops->free_volume(volume);
		fscache_end_volume_access(volume, NULL,
					  fscache_access_relinquish_volume_end);
	}

	down_write(&fscache_addremove_sem);
	list_del_init(&volume->proc_link);
	atomic_dec(&volume->cache->n_volumes);
	up_write(&fscache_addremove_sem);

	if (!hlist_bl_unhashed(&volume->hash_link))
		fscache_unhash_volume(volume);

	klpr_trace_fscache_volume(volume->debug_id, 0, fscache_volume_free);
	kfree(volume->key);
	kfree(volume);
	fscache_stat_d(&fscache_n_volumes);
	fscache_put_cache(cache, fscache_cache_put_volume);
}

void klpp_fscache_put_volume(struct fscache_volume *volume)
{
	if (volume) {
		bool zero;
		int ref;

		zero = __refcount_dec_and_test(&volume->ref, &ref);
		if (zero)
			fscache_free_volume(volume);
	}
}


#include "livepatch_bsc1229275.h"

#include <linux/livepatch.h>

extern typeof(__traceiter_fscache_volume) __traceiter_fscache_volume
	 KLP_RELOC_SYMBOL(fscache, fscache, __traceiter_fscache_volume);
extern typeof(__fscache_begin_volume_access) __fscache_begin_volume_access
	 KLP_RELOC_SYMBOL(fscache, fscache, __fscache_begin_volume_access);
extern typeof(__tracepoint_fscache_volume) __tracepoint_fscache_volume
	 KLP_RELOC_SYMBOL(fscache, fscache, __tracepoint_fscache_volume);
extern typeof(fscache_addremove_sem) fscache_addremove_sem
	 KLP_RELOC_SYMBOL(fscache, fscache, fscache_addremove_sem);
extern typeof(fscache_end_volume_access) fscache_end_volume_access
	 KLP_RELOC_SYMBOL(fscache, fscache, fscache_end_volume_access);
extern typeof(fscache_n_volumes) fscache_n_volumes
	 KLP_RELOC_SYMBOL(fscache, fscache, fscache_n_volumes);
extern typeof(fscache_put_cache) fscache_put_cache
	 KLP_RELOC_SYMBOL(fscache, fscache, fscache_put_cache);
extern typeof(fscache_volume_hash) fscache_volume_hash
	 KLP_RELOC_SYMBOL(fscache, fscache, fscache_volume_hash);
