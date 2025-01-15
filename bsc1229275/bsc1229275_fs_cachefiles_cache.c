/*
 * bsc1229275_fs_cachefiles_cache
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

/* klp-ccp: from fs/cachefiles/cache.c */
#include <linux/slab.h>

#include <linux/namei.h>

#include <linux/fscache-cache.h>
#include <linux/cred.h>
#include <linux/xarray.h>

/* klp-ccp: from include/uapi/linux/cachefiles.h */
struct cachefiles_msg;

struct cachefiles_open;

struct cachefiles_read;

/* klp-ccp: from fs/cachefiles/internal.h */
enum cachefiles_content {
	/* These values are saved on disk */
	CACHEFILES_CONTENT_NO_DATA	= 0, /* No content stored */
	CACHEFILES_CONTENT_SINGLE	= 1, /* Content is monolithic, all is present */
	CACHEFILES_CONTENT_ALL		= 2, /* Content is all present, no map */
	CACHEFILES_CONTENT_BACKFS_MAP	= 3, /* Content is piecemeal, mapped through backing fs */
	CACHEFILES_CONTENT_DIRTY	= 4, /* Content is dirty (only seen on disk) */
	nr__cachefiles_content
};

struct cachefiles_volume {
	struct cachefiles_cache		*cache;
	struct list_head		cache_link;	/* Link in cache->volumes */
	struct fscache_volume		*vcookie;	/* The netfs's representation */
	struct dentry			*dentry;	/* The volume dentry */
	struct dentry			*fanout[256];	/* Fanout subdirs */
};

struct cachefiles_object {
	struct fscache_cookie		*cookie;	/* Netfs data storage object cookie */
	struct cachefiles_volume	*volume;	/* Cache volume that holds this object */
	struct list_head		cache_link;	/* Link in cache->*_list */
	struct file			*file;		/* The file representing this object */
	char				*d_name;	/* Backing file name */
	int				debug_id;
	spinlock_t			lock;
	refcount_t			ref;
	u8				d_name_len;	/* Length of filename */
	enum cachefiles_content		content_info:8;	/* Info about content presence */
	unsigned long			flags;

#ifdef CONFIG_CACHEFILES_ONDEMAND
#error "klp-ccp: non-taken branch"
#endif
};

struct cachefiles_cache {
	struct fscache_cache		*cache;		/* Cache cookie */
	struct vfsmount			*mnt;		/* mountpoint holding the cache */
	struct dentry			*store;		/* Directory into which live objects go */
	struct dentry			*graveyard;	/* directory into which dead objects go */
	struct file			*cachefilesd;	/* manager daemon handle */
	struct list_head		volumes;	/* List of volume objects */
	struct list_head		object_list;	/* List of active objects */
	spinlock_t			object_list_lock; /* Lock for volumes and object_list */
	const struct cred		*cache_cred;	/* security override for accessing cache */
	struct mutex			daemon_mutex;	/* command serialisation mutex */
	wait_queue_head_t		daemon_pollwq;	/* poll waitqueue for daemon */
	atomic_t			gravecounter;	/* graveyard uniquifier */
	atomic_t			f_released;	/* number of objects released lately */
	atomic_long_t			b_released;	/* number of blocks released lately */
	atomic_long_t			b_writing;	/* Number of blocks being written */
	unsigned			frun_percent;	/* when to stop culling (% files) */
	unsigned			fcull_percent;	/* when to start culling (% files) */
	unsigned			fstop_percent;	/* when to stop allocating (% files) */
	unsigned			brun_percent;	/* when to stop culling (% blocks) */
	unsigned			bcull_percent;	/* when to start culling (% blocks) */
	unsigned			bstop_percent;	/* when to stop allocating (% blocks) */
	unsigned			bsize;		/* cache's block size */
	unsigned			bshift;		/* ilog2(bsize) */
	uint64_t			frun;		/* when to stop culling */
	uint64_t			fcull;		/* when to start culling */
	uint64_t			fstop;		/* when to stop allocating */
	sector_t			brun;		/* when to stop culling */
	sector_t			bcull;		/* when to start culling */
	sector_t			bstop;		/* when to stop allocating */
	unsigned long			flags;

#define CACHEFILES_DEAD			1	/* T if cache dead */

#define CACHEFILES_ONDEMAND_MODE	4	/* T if in on-demand read mode */
	char				*rootdirname;	/* name of cache root directory */
	char				*secctx;	/* LSM security context */
	char				*tag;		/* cache binding tag */
	refcount_t			unbind_pincount;/* refcount to do daemon unbind */
	struct xarray			reqs;		/* xarray of pending on-demand requests */
	unsigned long			req_id_next;
	struct xarray			ondemand_ids;	/* xarray for ondemand_id allocation */
	u32				ondemand_id_next;
};

static inline bool cachefiles_in_ondemand_mode(struct cachefiles_cache *cache)
{
	return IS_ENABLED(CONFIG_CACHEFILES_ONDEMAND) &&
		test_bit(CACHEFILES_ONDEMAND_MODE, &cache->flags);
}

#include <trace/events/cachefiles.h>

extern void cachefiles_flush_reqs(struct cachefiles_cache *cache);

extern void cachefiles_see_object(struct cachefiles_object *object,
				  enum cachefiles_obj_ref_trace why);

static inline void cachefiles_begin_secure(struct cachefiles_cache *cache,
					   const struct cred **_saved_cred)
{
	*_saved_cred = override_creds(cache->cache_cred);
}

static inline void cachefiles_end_secure(struct cachefiles_cache *cache,
					 const struct cred *saved_cred)
{
	revert_creds(saved_cred);
}

void cachefiles_withdraw_volume(struct cachefiles_volume *volume);

#define cachefiles_io_error(___cache, FMT, ...)		\
do {							\
	pr_err("I/O Error: " FMT"\n", ##__VA_ARGS__);	\
	fscache_io_error((___cache)->cache);		\
	set_bit(CACHEFILES_DEAD, &(___cache)->flags);	\
	if (cachefiles_in_ondemand_mode(___cache))	\
		cachefiles_flush_reqs(___cache);	\
} while (0)

#define _enter(FMT, ...) no_printk("==> %s("FMT")", __func__, ##__VA_ARGS__)
#define _leave(FMT, ...) no_printk("<== %s()"FMT"", __func__, ##__VA_ARGS__)

/* klp-ccp: from fs/cachefiles/cache.c */
static void cachefiles_withdraw_objects(struct cachefiles_cache *cache)
{
	struct cachefiles_object *object;
	unsigned int count = 0;

	_enter("");

	spin_lock(&cache->object_list_lock);

	while (!list_empty(&cache->object_list)) {
		object = list_first_entry(&cache->object_list,
					  struct cachefiles_object, cache_link);
		cachefiles_see_object(object, cachefiles_obj_see_withdrawal);
		list_del_init(&object->cache_link);
		fscache_withdraw_cookie(object->cookie);
		count++;
		if ((count & 63) == 0) {
			spin_unlock(&cache->object_list_lock);
			cond_resched();
			spin_lock(&cache->object_list_lock);
		}
	}

	spin_unlock(&cache->object_list_lock);
	_leave(" [%u objs]", count);
}

struct fscache_volume *fscache_try_get_volume(struct fscache_volume *volume)
{
        int ref;

        if (!__refcount_inc_not_zero(&volume->ref, &ref))
                return NULL;

        return volume;
}

#include "livepatch_bsc1229275.h"

static void cachefiles_withdraw_volumes(struct cachefiles_cache *cache)
{
	_enter("");

	for (;;) {
		struct fscache_volume *vcookie = NULL;
		struct cachefiles_volume *volume = NULL;

		spin_lock(&cache->object_list_lock);
		if (!list_empty(&cache->volumes)) {
			volume = list_first_entry(&cache->volumes,
						  struct cachefiles_volume, cache_link);
			vcookie = fscache_try_get_volume(volume->vcookie);
			if (!vcookie) {
				spin_unlock(&cache->object_list_lock);
				cpu_relax();
				continue;
			}
			list_del_init(&volume->cache_link);
		}
		spin_unlock(&cache->object_list_lock);
		if (!volume)
			break;

		cachefiles_withdraw_volume(volume);
		klpp_fscache_put_volume(vcookie);
	}

	_leave("");
}

static void cachefiles_sync_cache(struct cachefiles_cache *cache)
{
	const struct cred *saved_cred;
	int ret;

	_enter("%s", cache->cache->name);

	/* make sure all pages pinned by operations on behalf of the netfs are
	 * written to disc */
	cachefiles_begin_secure(cache, &saved_cred);
	down_read(&cache->mnt->mnt_sb->s_umount);
	ret = sync_filesystem(cache->mnt->mnt_sb);
	up_read(&cache->mnt->mnt_sb->s_umount);
	cachefiles_end_secure(cache, saved_cred);

	if (ret == -EIO)
		cachefiles_io_error(cache,
				    "Attempt to sync backing fs superblock returned error %d",
				    ret);
}

/*
 * Withdraw volumes.
 * Withdraw fscache volumes.
 */
static void cachefiles_withdraw_fscache_volumes(struct cachefiles_cache *cache)
{
	struct list_head *cur;
	struct cachefiles_volume *volume;
	struct fscache_volume *vcookie;

	_enter("");
retry:
	spin_lock(&cache->object_list_lock);
	list_for_each(cur, &cache->volumes) {
		volume = list_entry(cur, struct cachefiles_volume, cache_link);

		if (atomic_read(&volume->vcookie->n_accesses) == 0)
			continue;

		vcookie = fscache_try_get_volume(volume->vcookie);
		if (vcookie) {
			spin_unlock(&cache->object_list_lock);
			fscache_withdraw_volume(vcookie);
			klpp_fscache_put_volume(vcookie);
			goto retry;
		}
	}
	spin_unlock(&cache->object_list_lock);

	_leave("");
}


void klpp_cachefiles_withdraw_cache(struct cachefiles_cache *cache)
{
	struct fscache_cache *fscache = cache->cache;

	pr_info("File cache on %s unregistering\n", fscache->name);

	fscache_withdraw_cache(fscache);
	cachefiles_withdraw_fscache_volumes(cache);

	/* we now have to destroy all the active objects pertaining to this
	 * cache - which we do by passing them off to thread pool to be
	 * disposed of */
	cachefiles_withdraw_objects(cache);
	fscache_wait_for_objects(fscache);

	cachefiles_withdraw_volumes(cache);
	cachefiles_sync_cache(cache);
	cache->cache = NULL;
	fscache_relinquish_cache(fscache);
}

#include <linux/livepatch.h>

extern typeof(cachefiles_see_object) cachefiles_see_object
	 KLP_RELOC_SYMBOL(cachefiles, cachefiles, cachefiles_see_object);
extern typeof(cachefiles_withdraw_volume) cachefiles_withdraw_volume
	 KLP_RELOC_SYMBOL(cachefiles, cachefiles, cachefiles_withdraw_volume);
extern typeof(fscache_clearance_waiters) fscache_clearance_waiters
	 KLP_RELOC_SYMBOL(cachefiles, fscache, fscache_clearance_waiters);
extern typeof(fscache_io_error) fscache_io_error
	 KLP_RELOC_SYMBOL(cachefiles, fscache, fscache_io_error);
extern typeof(fscache_relinquish_cache) fscache_relinquish_cache
	 KLP_RELOC_SYMBOL(cachefiles, fscache, fscache_relinquish_cache);
extern typeof(fscache_withdraw_cache) fscache_withdraw_cache
	 KLP_RELOC_SYMBOL(cachefiles, fscache, fscache_withdraw_cache);
extern typeof(fscache_withdraw_cookie) fscache_withdraw_cookie
	 KLP_RELOC_SYMBOL(cachefiles, fscache, fscache_withdraw_cookie);
 extern typeof(fscache_withdraw_volume) fscache_withdraw_volume
	 KLP_RELOC_SYMBOL(cachefiles, fscache, fscache_withdraw_volume);
