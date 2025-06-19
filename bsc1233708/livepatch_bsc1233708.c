/*
 * livepatch_bsc1233708
 *
 * Fix for CVE-2024-50279, bsc#1233708
 *
 *  Upstream commit:
 *  792227719725 ("dm cache: fix out-of-bounds access to the dirty bitset when resizing")
 *
 *  SLE12-SP5 commit:
 *  a5eeed109b22c747cdc4333dfbefad41aadd154b
 *
 *  SLE15-SP3 commit:
 *  921879be3677153464711f91ac45c1d42239a329
 *
 *  SLE15-SP4 and -SP5 commit:
 *  6c88f1496dd68015b3c352c6867474b8d521f85a
 *
 *  SLE15-SP6 commit:
 *  2080b2232ae4fe6e84dd1de7d72fcd8c7ed96d31
 *
 *  SLE MICRO-6-0 commit:
 *  2080b2232ae4fe6e84dd1de7d72fcd8c7ed96d31
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


/* klp-ccp: from drivers/md/dm.h */
#include <linux/fs.h>
#include <linux/device-mapper.h>

/* klp-ccp: from include/linux/device-mapper.h */
static const char *(*klpe_dm_device_name)(struct mapped_device *md);

static struct mapped_device *(*klpe_dm_table_get_md)(struct dm_table *t);

/* klp-ccp: from drivers/md/dm.h */
#include <linux/list.h>

#include <linux/blkdev.h>

#include <linux/completion.h>
#include <linux/kobject.h>
#include <linux/refcount.h>

/* klp-ccp: from drivers/md/dm-stats.h */
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/list.h>

/* klp-ccp: from drivers/md/persistent-data/dm-block-manager.h */
#include <linux/types.h>
#include <linux/blkdev.h>

typedef uint64_t dm_block_t;

/* klp-ccp: from drivers/md/dm-bio-prison-v2.h */
#include <linux/bio.h>
#include <linux/rbtree.h>
#include <linux/workqueue.h>

/* klp-ccp: from drivers/md/dm-bio-record.h */
#include <linux/bio.h>

/* klp-ccp: from drivers/md/dm-cache-block-types.h */
typedef dm_block_t __bitwise dm_oblock_t;
typedef uint32_t __bitwise dm_cblock_t;
typedef dm_block_t __bitwise dm_dblock_t;

static inline dm_cblock_t to_cblock(uint32_t b)
{
	return (__force dm_cblock_t) b;
}

static inline uint32_t from_cblock(dm_cblock_t b)
{
	return (__force uint32_t) b;
}

static inline dm_block_t from_dblock(dm_dblock_t b)
{
	return (__force dm_block_t) b;
}

/* klp-ccp: from drivers/md/dm-cache-policy-internal.h */
#include <linux/vmalloc.h>

/* klp-ccp: from drivers/md/dm-cache-policy.h */
#include <linux/device-mapper.h>

struct dm_cache_policy;

/* klp-ccp: from drivers/md/dm-cache-policy-internal.h */
static inline size_t bitset_size_in_bytes(unsigned nr_entries)
{
	return sizeof(unsigned long) * dm_div_up(nr_entries, BITS_PER_LONG);
}

static inline void clear_bitset(void *bitset, unsigned nr_entries)
{
	size_t s = bitset_size_in_bytes(nr_entries);
	memset(bitset, 0, s);
}

/* klp-ccp: from drivers/md/dm-cache-metadata.h */
struct dm_cache_metadata;

typedef int (*load_discard_fn)(void *context, sector_t discard_block_size,
			       dm_dblock_t dblock, bool discarded);
static int (*klpe_dm_cache_load_discards)(struct dm_cache_metadata *cmd,
			   load_discard_fn fn, void *context);

typedef int (*load_mapping_fn)(void *context, dm_oblock_t oblock,
			       dm_cblock_t cblock, bool dirty,
			       uint32_t hint, bool hint_valid);
static int (*klpe_dm_cache_load_mappings)(struct dm_cache_metadata *cmd,
			   struct dm_cache_policy *policy,
			   load_mapping_fn fn,
			   void *context);

/* klp-ccp: from drivers/md/dm-cache-target.c */
#include <linux/jiffies.h>
#include <linux/init.h>
#include <linux/mempool.h>

#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define DM_MSG_PREFIX "cache"

struct io_tracker {
	spinlock_t lock;

	/*
	 * Sectors of in-flight IO.
	 */
	sector_t in_flight;

	/*
	 * The time, in jiffies, when this device became idle (if it is
	 * indeed idle).
	 */
	unsigned long idle_time;
	unsigned long last_update_time;
};

struct batcher {
	/*
	 * The operation that everyone is waiting for.
	 */
	blk_status_t (*commit_op)(void *context);
	void *commit_context;

	/*
	 * This is how bios should be issued once the commit op is complete
	 * (accounted_request).
	 */
	void (*issue_op)(struct bio *bio, void *context);
	void *issue_context;

	/*
	 * Queued work gets put on here after commit.
	 */
	struct workqueue_struct *wq;

	spinlock_t lock;
	struct list_head work_items;
	struct bio_list bios;
	struct work_struct commit_work;

	bool commit_scheduled;
};

enum cache_metadata_mode {
	CM_WRITE,		/* metadata may be changed */
	CM_READ_ONLY,		/* metadata may not be changed */
	CM_FAIL
};

enum cache_io_mode {
	/*
	 * Data is written to cached blocks only.  These blocks are marked
	 * dirty.  If you lose the cache device you will lose data.
	 * Potential performance increase for both reads and writes.
	 */
	CM_IO_WRITEBACK,

	/*
	 * Data is written to both cache and origin.  Blocks are never
	 * dirty.  Potential performance benfit for reads only.
	 */
	CM_IO_WRITETHROUGH,

	/*
	 * A degraded mode useful for various cache coherency situations
	 * (eg, rolling back snapshots).  Reads and writes always go to the
	 * origin.  If a write goes to a cached oblock, then the cache
	 * block is invalidated.
	 */
	CM_IO_PASSTHROUGH
};

struct cache_features {
	enum cache_metadata_mode mode;
	enum cache_io_mode io_mode;
	unsigned metadata_version;
};

struct cache_stats {
	atomic_t read_hit;
	atomic_t read_miss;
	atomic_t write_hit;
	atomic_t write_miss;
	atomic_t demotion;
	atomic_t promotion;
	atomic_t writeback;
	atomic_t copies_avoided;
	atomic_t cache_cell_clash;
	atomic_t commit_count;
	atomic_t discard_count;
};

struct cache {
	struct dm_target *ti;
	spinlock_t lock;

	/*
	 * Fields for converting from sectors to blocks.
	 */
	int sectors_per_block_shift;
	sector_t sectors_per_block;

	struct dm_cache_metadata *cmd;

	/*
	 * Metadata is written to this device.
	 */
	struct dm_dev *metadata_dev;

	/*
	 * The slower of the two data devices.  Typically a spindle.
	 */
	struct dm_dev *origin_dev;

	/*
	 * The faster of the two data devices.  Typically an SSD.
	 */
	struct dm_dev *cache_dev;

	/*
	 * Size of the origin device in _complete_ blocks and native sectors.
	 */
	dm_oblock_t origin_blocks;
	sector_t origin_sectors;

	/*
	 * Size of the cache device in blocks.
	 */
	dm_cblock_t cache_size;

	/*
	 * Invalidation fields.
	 */
	spinlock_t invalidation_lock;
	struct list_head invalidation_requests;

	sector_t migration_threshold;
	wait_queue_head_t migration_wait;
	atomic_t nr_allocated_migrations;

	/*
	 * The number of in flight migrations that are performing
	 * background io. eg, promotion, writeback.
	 */
	atomic_t nr_io_migrations;

	struct bio_list deferred_bios;

	struct rw_semaphore quiesce_lock;

	struct dm_target_callbacks callbacks;

	/*
	 * origin_blocks entries, discarded if set.
	 */
	dm_dblock_t discard_nr_blocks;
	unsigned long *discard_bitset;
	uint32_t discard_block_size; /* a power of 2 times sectors per block */

	/*
	 * Rather than reconstructing the table line for the status we just
	 * save it and regurgitate.
	 */
	unsigned nr_ctr_args;
	const char **ctr_args;

	struct dm_kcopyd_client *copier;
	struct work_struct deferred_bio_worker;
	struct work_struct migration_worker;
	struct workqueue_struct *wq;
	struct delayed_work waker;
	struct dm_bio_prison_v2 *prison;
	/*
	 * cache_size entries, dirty if set
	 */
	unsigned long *dirty_bitset;
	atomic_t nr_dirty;
	unsigned policy_nr_args;
	struct dm_cache_policy *policy;

	/*
	 * Cache features such as write-through.
	 */
	struct cache_features features;

	struct cache_stats stats;
	bool need_tick_bio:1;
	bool sized:1;
	bool invalidate:1;
	bool commit_requested:1;
	bool loaded_mappings:1;
	bool loaded_discards:1;

	struct rw_semaphore background_work_lock;

	struct batcher committer;
	struct work_struct commit_ws;

	struct io_tracker tracker;

	mempool_t *migration_pool;

	struct bio_set *bs;
};

static bool is_dirty(struct cache *cache, dm_cblock_t b)
{
	return test_bit(from_cblock(b), cache->dirty_bitset);
}

static const char *klpr_cache_device_name(struct cache *cache)
{
	return (*klpe_dm_device_name)((*klpe_dm_table_get_md)(cache->ti->table));
}

static void (*klpe_metadata_operation_failed)(struct cache *cache, const char *op, int r);

static sector_t get_dev_size(struct dm_dev *dev)
{
	return i_size_read(dev->bdev->bd_inode) >> SECTOR_SHIFT;
}

static int (*klpe_load_mapping)(void *context, dm_oblock_t oblock, dm_cblock_t cblock,
			bool dirty, uint32_t hint, bool hint_valid);

struct discard_load_info {
	struct cache *cache;

	/*
	 * These blocks are sized using the on disk dblock size, rather
	 * than the current one.
	 */
	dm_block_t block_size;
	dm_block_t discard_begin, discard_end;
};

static void discard_load_info_init(struct cache *cache,
				   struct discard_load_info *li)
{
	li->cache = cache;
	li->discard_begin = li->discard_end = 0;
}

static void (*klpe_set_discard_range)(struct discard_load_info *li);

static int (*klpe_load_discard)(void *context, sector_t discard_block_size,
			dm_dblock_t dblock, bool discard);

static dm_cblock_t get_cache_dev_size(struct cache *cache)
{
	sector_t size = get_dev_size(cache->cache_dev);
	(void) sector_div(size, cache->sectors_per_block);
	return to_cblock(size);
}

static bool klpp_can_resize(struct cache *cache, dm_cblock_t new_size)
{
	if (from_cblock(new_size) > from_cblock(cache->cache_size)) {
		if (cache->sized) {
			DMERR("%s: unable to extend cache due to missing cache table reload",
			      klpr_cache_device_name(cache));
			return false;
		}
	}

	/*
	 * We can't drop a dirty block when shrinking the cache.
	 */
	while (from_cblock(new_size) < from_cblock(cache->cache_size)) {
		if (is_dirty(cache, new_size)) {
			DMERR("%s: unable to shrink cache; cache block %llu is dirty",
			      klpr_cache_device_name(cache),
			      (unsigned long long) from_cblock(new_size));
			return false;
		}
		new_size = to_cblock(from_cblock(new_size) + 1);
	}

	return true;
}

static int (*klpe_resize_cache_dev)(struct cache *cache, dm_cblock_t new_size);

int klpp_cache_preresume(struct dm_target *ti)
{
	int r = 0;
	struct cache *cache = ti->private;
	dm_cblock_t csize = get_cache_dev_size(cache);

	/*
	 * Check to see if the cache has resized.
	 */
	if (!cache->sized) {
		r = (*klpe_resize_cache_dev)(cache, csize);
		if (r)
			return r;

		cache->sized = true;

	} else if (csize != cache->cache_size) {
		if (!klpp_can_resize(cache, csize))
			return -EINVAL;

		r = (*klpe_resize_cache_dev)(cache, csize);
		if (r)
			return r;
	}

	if (!cache->loaded_mappings) {
		r = (*klpe_dm_cache_load_mappings)(cache->cmd, cache->policy,
					   (*klpe_load_mapping), cache);
		if (r) {
			DMERR("%s: could not load cache mappings", klpr_cache_device_name(cache));
			(*klpe_metadata_operation_failed)(cache, "dm_cache_load_mappings", r);
			return r;
		}

		cache->loaded_mappings = true;
	}

	if (!cache->loaded_discards) {
		struct discard_load_info li;

		/*
		 * The discard bitset could have been resized, or the
		 * discard block size changed.  To be safe we start by
		 * setting every dblock to not discarded.
		 */
		clear_bitset(cache->discard_bitset, from_dblock(cache->discard_nr_blocks));

		discard_load_info_init(cache, &li);
		r = (*klpe_dm_cache_load_discards)(cache->cmd, (*klpe_load_discard), &li);
		if (r) {
			DMERR("%s: could not load origin discards", klpr_cache_device_name(cache));
			(*klpe_metadata_operation_failed)(cache, "dm_cache_load_discards", r);
			return r;
		}
		(*klpe_set_discard_range)(&li);

		cache->loaded_discards = true;
	}

	return r;
}


#include "livepatch_bsc1233708.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "dm_cache"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "dm_cache_load_discards", (void *)&klpe_dm_cache_load_discards,
	  "dm_cache" },
	{ "dm_cache_load_mappings", (void *)&klpe_dm_cache_load_mappings,
	  "dm_cache" },
	{ "load_discard", (void *)&klpe_load_discard, "dm_cache" },
	{ "load_mapping", (void *)&klpe_load_mapping, "dm_cache" },
	{ "metadata_operation_failed", (void *)&klpe_metadata_operation_failed,
	  "dm_cache" },
	{ "resize_cache_dev", (void *)&klpe_resize_cache_dev, "dm_cache" },
	{ "set_discard_range", (void *)&klpe_set_discard_range, "dm_cache" },
	{ "dm_device_name", (void *)&klpe_dm_device_name, "dm_mod" },
	{ "dm_table_get_md", (void *)&klpe_dm_table_get_md, "dm_mod" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1233708_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1233708_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
