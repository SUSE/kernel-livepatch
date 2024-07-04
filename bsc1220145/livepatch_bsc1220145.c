/*
 * livepatch_bsc1220145
 *
 * Fix for CVE-2024-23307, bsc#1220145
 *
 *  Upstream commit:
 *  dfd2bf436709 ("md/raid5: fix atomicity violation in raid5_cache_count")
 *
 *  SLE12-SP5 commit:
 *  391774d109bfcdbed69d6a933a732258780d0b0b
 *
 *  SLE15-SP2 and -SP3 commit:
 *  b8048915b6db9c1c76bb7d04719e565a43cb82af
 *
 *  SLE15-SP4 and -SP5 commit:
 *  770938370c9283c8c7baa3d38288bba619a36207
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

/* klp-ccp: from drivers/md/raid5.c */
#include <linux/blkdev.h>
#include <linux/async_tx.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/nodemask.h>
/* klp-ccp: from drivers/md/md.h */
#include <linux/blkdev.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

/* klp-ccp: from drivers/md/md-cluster.h */
struct md_rdev;

/* klp-ccp: from drivers/md/md.h */
#define MaxSector (~(sector_t)0)

enum mddev_flags {
	MD_ARRAY_FIRST_USE,
	MD_CLOSING,
	MD_JOURNAL_CLEAN,
	MD_HAS_JOURNAL,
	MD_CLUSTER_RESYNC_LOCKED,
	MD_FAILFAST_SUPPORTED,
	MD_HAS_PPL,
	MD_HAS_MULTIPLE_PPLS,
	MD_ALLOW_SB_UPDATE,
	MD_UPDATING_SB,
	MD_NOT_READY,
	MD_BROKEN,
	MD_DELETED,
};

struct mddev {
	void				*private;
	struct md_personality		*pers;
	dev_t				unit;
	int				md_minor;
	struct list_head		disks;
	unsigned long			flags;
	unsigned long			sb_flags;

	int				suspended;
	atomic_t			active_io;
	int				ro;
	int				sysfs_active; /* set when sysfs deletes
						       * are happening, so run/
						       * takeover/stop are not safe
						       */
	struct gendisk			*gendisk;

	struct kobject			kobj;
	int				hold_active;

	/* Superblock information */
	int				major_version,
					minor_version,
					patch_version;
	int				persistent;
	int				external;	/* metadata is
							 * managed externally */
	char				metadata_type[17]; /* externally set*/
	int				chunk_sectors;
	time64_t			ctime, utime;
	int				level, layout;
	char				clevel[16];
	int				raid_disks;
	int				max_disks;
	sector_t			dev_sectors;	/* used size of
							 * component devices */
	sector_t			array_sectors; /* exported array size */
	int				external_size; /* size managed
							* externally */
	__u64				events;
	/* If the last 'event' was simply a clean->dirty transition, and
	 * we didn't write it to the spares, then it is safe and simple
	 * to just decrement the event count on a dirty->clean transition.
	 * So we record that possibility here.
	 */
	int				can_decrease_events;

	char				uuid[16];

	/* If the array is being reshaped, we need to record the
	 * new shape and an indication of where we are up to.
	 * This is written to the superblock.
	 * If reshape_position is MaxSector, then no reshape is happening (yet).
	 */
	sector_t			reshape_position;
	int				delta_disks, new_level, new_layout;
	int				new_chunk_sectors;
	int				reshape_backwards;

	struct md_thread		*thread;	/* management thread */
	struct md_thread		*sync_thread;	/* doing resync or reconstruct */

	/* 'last_sync_action' is initialized to "none".  It is set when a
	 * sync operation (i.e "data-check", "requested-resync", "resync",
	 * "recovery", or "reshape") is started.  It holds this value even
	 * when the sync thread is "frozen" (interrupted) or "idle" (stopped
	 * or finished).  It is overwritten when a new sync operation is begun.
	 */
	char				*last_sync_action;
	sector_t			curr_resync;	/* last block scheduled */
	/* As resync requests can complete out of order, we cannot easily track
	 * how much resync has been completed.  So we occasionally pause until
	 * everything completes, then set curr_resync_completed to curr_resync.
	 * As such it may be well behind the real resync mark, but it is a value
	 * we are certain of.
	 */
	sector_t			curr_resync_completed;
	unsigned long			resync_mark;	/* a recent timestamp */
	sector_t			resync_mark_cnt;/* blocks written at resync_mark */
	sector_t			curr_mark_cnt; /* blocks scheduled now */

	sector_t			resync_max_sectors; /* may be set by personality */

	atomic64_t			resync_mismatches; /* count of sectors where
							    * parity/replica mismatch found
							    */

	/* allow user-space to request suspension of IO to regions of the array */
	sector_t			suspend_lo;
	sector_t			suspend_hi;
	/* if zero, use the system-wide default */
	int				sync_speed_min;
	int				sync_speed_max;

	/* resync even though the same disks are shared among md-devices */
	int				parallel_resync;

	int				ok_start_degraded;

	unsigned long			recovery;
	/* If a RAID personality determines that recovery (of a particular
	 * device) will fail due to a read error on the source device, it
	 * takes a copy of this number and does not attempt recovery again
	 * until this number changes.
	 */
	int				recovery_disabled;

	int				in_sync;	/* know to not need resync */
	/* 'open_mutex' avoids races between 'md_open' and 'do_md_stop', so
	 * that we are never stopping an array while it is open.
	 * 'reconfig_mutex' protects all other reconfiguration.
	 * These locks are separate due to conflicting interactions
	 * with disk->open_mutex.
	 * Lock ordering is:
	 *  reconfig_mutex -> disk->open_mutex
	 *  disk->open_mutex -> open_mutex:  e.g. __blkdev_get -> md_open
	 */
	struct mutex			open_mutex;
	struct mutex			reconfig_mutex;
	atomic_t			active;		/* general refcount */
	atomic_t			openers;	/* number of active opens */

	int				changed;	/* True if we might need to
							 * reread partition info */
	int				degraded;	/* whether md should consider
							 * adding a spare
							 */

	atomic_t			recovery_active; /* blocks scheduled, but not written */
	wait_queue_head_t		recovery_wait;
	sector_t			recovery_cp;
	sector_t			resync_min;	/* user requested sync
							 * starts here */
	sector_t			resync_max;	/* resync should pause
							 * when it gets here */

	struct kernfs_node		*sysfs_state;	/* handle for 'array_state'
							 * file in sysfs.
							 */
	struct kernfs_node		*sysfs_action;  /* handle for 'sync_action' */
	struct kernfs_node		*sysfs_completed;	/*handle for 'sync_completed' */
	struct kernfs_node		*sysfs_degraded;	/*handle for 'degraded' */
	struct kernfs_node		*sysfs_level;		/*handle for 'level' */

	struct work_struct del_work;	/* used for delayed sysfs removal */

	/* "lock" protects:
	 *   flush_bio transition from NULL to !NULL
	 *   rdev superblocks, events
	 *   clearing MD_CHANGE_*
	 *   in_sync - and related safemode and MD_CHANGE changes
	 *   pers (also protected by reconfig_mutex and pending IO).
	 *   clearing ->bitmap
	 *   clearing ->bitmap_info.file
	 *   changing ->resync_{min,max}
	 *   setting MD_RECOVERY_RUNNING (which interacts with resync_{min,max})
	 */
	spinlock_t			lock;
	wait_queue_head_t		sb_wait;	/* for waiting on superblock updates */
	atomic_t			pending_writes;	/* number of active superblock writes */

	unsigned int			safemode;	/* if set, update "clean" superblock
							 * when no writes pending.
							 */
	unsigned int			safemode_delay;
	struct timer_list		safemode_timer;
	struct percpu_ref		writes_pending;
	int				sync_checkers;	/* # of threads checking writes_pending */
	struct request_queue		*queue;	/* for plugging ... */

	struct bitmap			*bitmap; /* the bitmap for the device */
	struct {
		struct file		*file; /* the bitmap file */
		loff_t			offset; /* offset from superblock of
						 * start of bitmap. May be
						 * negative, but not '0'
						 * For external metadata, offset
						 * from start of device.
						 */
		unsigned long		space; /* space available at this offset */
		loff_t			default_offset; /* this is the offset to use when
							 * hot-adding a bitmap.  It should
							 * eventually be settable by sysfs.
							 */
		unsigned long		default_space; /* space available at
							* default offset */
		struct mutex		mutex;
		unsigned long		chunksize;
		unsigned long		daemon_sleep; /* how many jiffies between updates? */
		unsigned long		max_write_behind; /* write-behind mode */
		int			external;
		int			nodes; /* Maximum number of nodes in the cluster */
		char                    cluster_name[64]; /* Name of the cluster */
	} bitmap_info;

	atomic_t			max_corr_read_errors; /* max read retries */
	struct list_head		all_mddevs;

	const struct attribute_group	*to_remove;

	struct bio_set			bio_set;
	struct bio_set			sync_set; /* for sync operations like
						   * metadata and bitmap writes
						   */
	struct bio_set			io_acct_set; /* for raid0 and raid5 io accounting */

	/* Generic flush handling.
	 * The last to finish preflush schedules a worker to submit
	 * the rest of the request (without the REQ_PREFLUSH flag).
	 */
	struct bio *flush_bio;
	atomic_t flush_pending;
	ktime_t start_flush, prev_flush_start; /* prev_flush_start is when the previous completed
						* flush was started.
						*/
	struct work_struct flush_work;
	struct work_struct event_work;	/* used by dm to report failure event */
	mempool_t *serial_info_pool;
	void (*sync_super)(struct mddev *mddev, struct md_rdev *rdev);
	struct md_cluster_info		*cluster_info;
	unsigned int			good_device_nr;	/* good device num within cluster raid */
	unsigned int			noio_flag; /* for memalloc scope API */

	bool	has_superblocks:1;
	bool	fail_last_dev:1;
	bool	serialize_policy:1;
};

static void (*klpe_md_allow_write)(struct mddev *mddev);

/* klp-ccp: from drivers/md/raid5.h */
#include <linux/dmaengine.h>
#include <linux/local_lock.h>

enum check_states {
	check_state_idle = 0,
	check_state_run, /* xor parity check */
	check_state_run_q, /* q-parity check */
	check_state_run_pq, /* pq dual parity check */
	check_state_check_result,
	check_state_compute_run, /* parity repair */
	check_state_compute_result,
};

enum reconstruct_states {
	reconstruct_state_idle = 0,
	reconstruct_state_prexor_drain_run,	/* prexor-write */
	reconstruct_state_drain_run,		/* write */
	reconstruct_state_run,			/* expand */
	reconstruct_state_prexor_drain_result,
	reconstruct_state_drain_result,
	reconstruct_state_result,
};

#define DEFAULT_STRIPE_SIZE	4096
struct stripe_head {
	struct hlist_node	hash;
	struct list_head	lru;	      /* inactive_list or handle_list */
	struct llist_node	release_list;
	struct r5conf		*raid_conf;
	short			generation;	/* increments with every
						 * reshape */
	sector_t		sector;		/* sector of this row */
	short			pd_idx;		/* parity disk index */
	short			qd_idx;		/* 'Q' disk index for raid6 */
	short			ddf_layout;/* use DDF ordering to calculate Q */
	short			hash_lock_index;
	unsigned long		state;		/* state flags */
	atomic_t		count;	      /* nr of active thread/requests */
	int			bm_seq;	/* sequence number for bitmap flushes */
	int			disks;		/* disks in stripe */
	int			overwrite_disks; /* total overwrite disks in stripe,
						  * this is only checked when stripe
						  * has STRIPE_BATCH_READY
						  */
	enum check_states	check_state;
	enum reconstruct_states reconstruct_state;
	spinlock_t		stripe_lock;
	int			cpu;
	struct r5worker_group	*group;

	struct stripe_head	*batch_head; /* protected by stripe lock */
	spinlock_t		batch_lock; /* only header's lock is useful */
	struct list_head	batch_list; /* protected by head's batch lock*/

	union {
		struct r5l_io_unit	*log_io;
		struct ppl_io_unit	*ppl_io;
	};

	struct list_head	log_list;
	sector_t		log_start; /* first meta block on the journal */
	struct list_head	r5c; /* for r5c_cache->stripe_in_journal */

	struct page		*ppl_page; /* partial parity of this stripe */
	/**
	 * struct stripe_operations
	 * @target - STRIPE_OP_COMPUTE_BLK target
	 * @target2 - 2nd compute target in the raid6 case
	 * @zero_sum_result - P and Q verification flags
	 * @request - async service request flags for raid_run_ops
	 */
	struct stripe_operations {
		int 		     target, target2;
		enum sum_check_flags zero_sum_result;
	} ops;

#if PAGE_SIZE != DEFAULT_STRIPE_SIZE
	/* These pages will be used by bios in dev[i] */
	struct page	**pages;
	int	nr_pages;	/* page array size */
	int	stripes_per_page;

#endif
	struct r5dev {
		/* rreq and rvec are used for the replacement device when
		 * writing data to both devices.
		 */
		struct bio	req, rreq;
		struct bio_vec	vec, rvec;
		struct page	*page, *orig_page;
		unsigned int    offset;     /* offset of the page */
		struct bio	*toread, *read, *towrite, *written;
		sector_t	sector;			/* sector of this page */
		unsigned long	flags;
		u32		log_checksum;
		unsigned short	write_hint;
	} dev[1]; /* allocated with extra space depending of RAID geometry */
};

#define NR_STRIPE_HASH_LOCKS 8
#define STRIPE_HASH_LOCKS_MASK (NR_STRIPE_HASH_LOCKS - 1)

struct r5conf {
	struct hlist_head	*stripe_hashtbl;
	/* only protect corresponding hash list and inactive_list */
	spinlock_t		hash_locks[NR_STRIPE_HASH_LOCKS];
	struct mddev		*mddev;
	int			chunk_sectors;
	int			level, algorithm, rmw_level;
	int			max_degraded;
	int			raid_disks;
	int			max_nr_stripes;
	int			min_nr_stripes;
#if PAGE_SIZE != DEFAULT_STRIPE_SIZE
	unsigned long	stripe_size;
	unsigned int	stripe_shift;
	unsigned long	stripe_sectors;
#endif
	sector_t		reshape_progress;
	/* reshape_safe is the trailing edge of a reshape.  We know that
	 * before (or after) this address, all reshape has completed.
	 */
	sector_t		reshape_safe;
	int			previous_raid_disks;
	int			prev_chunk_sectors;
	int			prev_algo;
	short			generation; /* increments with every reshape */
	seqcount_spinlock_t	gen_lock;	/* lock against generation changes */
	unsigned long		reshape_checkpoint; /* Time we last updated
						     * metadata */
	long long		min_offset_diff; /* minimum difference between
						  * data_offset and
						  * new_data_offset across all
						  * devices.  May be negative,
						  * but is closest to zero.
						  */

	struct list_head	handle_list; /* stripes needing handling */
	struct list_head	loprio_list; /* low priority stripes */
	struct list_head	hold_list; /* preread ready stripes */
	struct list_head	delayed_list; /* stripes that have plugged requests */
	struct list_head	bitmap_list; /* stripes delaying awaiting bitmap update */
	struct bio		*retry_read_aligned; /* currently retrying aligned bios   */
	unsigned int		retry_read_offset; /* sector offset into retry_read_aligned */
	struct bio		*retry_read_aligned_list; /* aligned bios retry list  */
	atomic_t		preread_active_stripes; /* stripes with scheduled io */
	atomic_t		active_aligned_reads;
	atomic_t		pending_full_writes; /* full write backlog */
	int			bypass_count; /* bypassed prereads */
	int			bypass_threshold; /* preread nice */
	int			skip_copy; /* Don't copy data from bio to stripe cache */
	struct list_head	*last_hold; /* detect hold_list promotions */

	atomic_t		reshape_stripes; /* stripes with pending writes for reshape */
	/* unfortunately we need two cache names as we temporarily have
	 * two caches.
	 */
	int			active_name;
	char			cache_name[2][32];
	struct kmem_cache	*slab_cache; /* for allocating stripes */
	struct mutex		cache_size_mutex; /* Protect changes to cache size */

	int			seq_flush, seq_write;
	int			quiesce;

	int			fullsync;  /* set to 1 if a full sync is needed,
					    * (fresh device added).
					    * Cleared when a sync completes.
					    */
	int			recovery_disabled;
	/* per cpu variables */
	struct raid5_percpu __percpu *percpu;
	int scribble_disks;
	int scribble_sectors;
	struct hlist_node node;

	/*
	 * Free stripes pool
	 */
	atomic_t		active_stripes;
	struct list_head	inactive_list[NR_STRIPE_HASH_LOCKS];

	atomic_t		r5c_cached_full_stripes;
	struct list_head	r5c_full_stripe_list;
	atomic_t		r5c_cached_partial_stripes;
	struct list_head	r5c_partial_stripe_list;
	atomic_t		r5c_flushing_full_stripes;
	atomic_t		r5c_flushing_partial_stripes;

	atomic_t		empty_inactive_list_nr;
	struct llist_head	released_stripes;
	wait_queue_head_t	wait_for_quiescent;
	wait_queue_head_t	wait_for_stripe;
	wait_queue_head_t	wait_for_overlap;
	unsigned long		cache_state;
	struct shrinker		shrinker;
	int			pool_size; /* number of disks in stripeheads in pool */
	spinlock_t		device_lock;
	struct disk_info	*disks;
	struct bio_set		bio_split;

	/* When taking over an array from a different personality, we store
	 * the new thread here until we fully activate the array.
	 */
	struct md_thread	*thread;
	struct list_head	temp_inactive_list[NR_STRIPE_HASH_LOCKS];
	struct r5worker_group	*worker_groups;
	int			group_cnt;
	int			worker_cnt_per_group;
	struct r5l_log		*log;
	void			*log_private;

	spinlock_t		pending_bios_lock;
	bool			batch_bio_dispatch;
	struct r5pending_data	*pending_data;
	struct list_head	free_list;
	struct list_head	pending_list;
	int			pending_data_cnt;
	struct r5pending_data	*next_pending_data;
};

static void (*klpe_raid5_release_stripe)(struct stripe_head *sh);

/* klp-ccp: from drivers/md/raid5-log.h */
static inline bool raid5_has_ppl(struct r5conf *conf)
{
	return test_bit(MD_HAS_PPL, &conf->mddev->flags);
}

static struct stripe_head *(*klpe_get_free_stripe)(struct r5conf *conf, int hash);

static void (*klpe_shrink_buffers)(struct stripe_head *sh);

#if PAGE_SIZE == DEFAULT_STRIPE_SIZE
#define RAID5_STRIPE_SIZE(conf)	STRIPE_SIZE
#define RAID5_STRIPE_SHIFT(conf)	STRIPE_SHIFT
#define RAID5_STRIPE_SECTORS(conf)	STRIPE_SECTORS
#else
#define RAID5_STRIPE_SIZE(conf)	((conf)->stripe_size)
#define RAID5_STRIPE_SHIFT(conf)	((conf)->stripe_shift)
#define RAID5_STRIPE_SECTORS(conf)	((conf)->stripe_sectors)
#endif

#if PAGE_SIZE != DEFAULT_STRIPE_SIZE
static void free_stripe_pages(struct stripe_head *sh)
{
	int i;
	struct page *p;

	/* Have not allocate page pool */
	if (!sh->pages)
		return;

	for (i = 0; i < sh->nr_pages; i++) {
		p = sh->pages[i];
		if (p)
			put_page(p);
		sh->pages[i] = NULL;
	}
}

static int alloc_stripe_pages(struct stripe_head *sh, gfp_t gfp)
{
	int i;
	struct page *p;

	for (i = 0; i < sh->nr_pages; i++) {
		/* The page have allocated. */
		if (sh->pages[i])
			continue;

		p = alloc_page(gfp);
		if (!p) {
			free_stripe_pages(sh);
			return -ENOMEM;
		}
		sh->pages[i] = p;
	}
	return 0;
}

static int
init_stripe_shared_pages(struct stripe_head *sh, struct r5conf *conf, int disks)
{
	int nr_pages, cnt;

	if (sh->pages)
		return 0;

	/* Each of the sh->dev[i] need one conf->stripe_size */
	cnt = PAGE_SIZE / conf->stripe_size;
	nr_pages = (disks + cnt - 1) / cnt;

	sh->pages = kcalloc(nr_pages, sizeof(struct page *), GFP_KERNEL);
	if (!sh->pages)
		return -ENOMEM;
	sh->nr_pages = nr_pages;
	sh->stripes_per_page = cnt;
	return 0;
}

/*
 * Return offset of the corresponding page for r5dev.
 */
static inline int raid5_get_page_offset(struct stripe_head *sh, int disk_idx)
{
	return (disk_idx % sh->stripes_per_page) * RAID5_STRIPE_SIZE(sh->raid_conf);
}

/*
 * Return corresponding page address for r5dev.
 */
static inline struct page *
raid5_get_dev_page(struct stripe_head *sh, int disk_idx)
{
	return sh->pages[disk_idx / sh->stripes_per_page];
}
#endif

static int grow_buffers(struct stripe_head *sh, gfp_t gfp)
{
	int i;
	int num = sh->raid_conf->pool_size;

#if PAGE_SIZE == DEFAULT_STRIPE_SIZE
	for (i = 0; i < num; i++) {
		struct page *page;

		if (!(page = alloc_page(gfp))) {
			return 1;
		}
		sh->dev[i].page = page;
		sh->dev[i].orig_page = page;
		sh->dev[i].offset = 0;
	}
#else
	if (alloc_stripe_pages(sh, gfp))
		return -ENOMEM;

	for (i = 0; i < num; i++) {
		sh->dev[i].page = raid5_get_dev_page(sh, i);
		sh->dev[i].orig_page = sh->dev[i].page;
		sh->dev[i].offset = raid5_get_page_offset(sh, i);
	}
#endif
	return 0;
}

static void (*klpe_free_stripe)(struct kmem_cache *sc, struct stripe_head *sh);

static struct stripe_head *klpr_alloc_stripe(struct kmem_cache *sc, gfp_t gfp,
	int disks, struct r5conf *conf)
{
	struct stripe_head *sh;

	sh = kmem_cache_zalloc(sc, gfp);
	if (sh) {
		spin_lock_init(&sh->stripe_lock);
		spin_lock_init(&sh->batch_lock);
		INIT_LIST_HEAD(&sh->batch_list);
		INIT_LIST_HEAD(&sh->lru);
		INIT_LIST_HEAD(&sh->r5c);
		INIT_LIST_HEAD(&sh->log_list);
		atomic_set(&sh->count, 1);
		sh->raid_conf = conf;
		sh->log_start = MaxSector;

		if (raid5_has_ppl(conf)) {
			sh->ppl_page = alloc_page(gfp);
			if (!sh->ppl_page) {
				(*klpe_free_stripe)(sc, sh);
				return NULL;
			}
		}
#if PAGE_SIZE != DEFAULT_STRIPE_SIZE
		if (init_stripe_shared_pages(sh, conf, disks)) {
			(*klpe_free_stripe)(sc, sh);
			return NULL;
		}
#endif
	}
	return sh;
}
int klpp_grow_one_stripe(struct r5conf *conf, gfp_t gfp)
{
	struct stripe_head *sh;

	sh = klpr_alloc_stripe(conf->slab_cache, gfp, conf->pool_size, conf);
	if (!sh)
		return 0;

	if (grow_buffers(sh, gfp)) {
		(*klpe_shrink_buffers)(sh);
		(*klpe_free_stripe)(conf->slab_cache, sh);
		return 0;
	}
	sh->hash_lock_index =
		conf->max_nr_stripes % NR_STRIPE_HASH_LOCKS;
	/* we just created an active stripe so... */
	atomic_inc(&conf->active_stripes);

	(*klpe_raid5_release_stripe)(sh);
	WRITE_ONCE(conf->max_nr_stripes, conf->max_nr_stripes + 1);
	return 1;
}

int klpp_drop_one_stripe(struct r5conf *conf)
{
	struct stripe_head *sh;
	int hash = (conf->max_nr_stripes - 1) & STRIPE_HASH_LOCKS_MASK;

	spin_lock_irq(conf->hash_locks + hash);
	sh = (*klpe_get_free_stripe)(conf, hash);
	spin_unlock_irq(conf->hash_locks + hash);
	if (!sh)
		return 0;
	BUG_ON(atomic_read(&sh->count));
	(*klpe_shrink_buffers)(sh);
	(*klpe_free_stripe)(conf->slab_cache, sh);
	atomic_dec(&conf->active_stripes);
	WRITE_ONCE(conf->max_nr_stripes, conf->max_nr_stripes - 1);
	return 1;
}

int
klpp_raid5_set_cache_size(struct mddev *mddev, int size)
{
	int result = 0;
	struct r5conf *conf = mddev->private;

	if (size <= 16 || size > 32768)
		return -EINVAL;

	WRITE_ONCE(conf->min_nr_stripes, size);
	mutex_lock(&conf->cache_size_mutex);
	while (size < conf->max_nr_stripes &&
	       klpp_drop_one_stripe(conf))
		;
	mutex_unlock(&conf->cache_size_mutex);

	(*klpe_md_allow_write)(mddev);

	mutex_lock(&conf->cache_size_mutex);
	while (size > conf->max_nr_stripes)
		if (!klpp_grow_one_stripe(conf, GFP_KERNEL)) {
			WRITE_ONCE(conf->min_nr_stripes, conf->max_nr_stripes);
			result = -ENOMEM;
			break;
		}
	mutex_unlock(&conf->cache_size_mutex);

	return result;
}

unsigned long klpp_raid5_cache_count(struct shrinker *shrink,
				       struct shrink_control *sc)
{
	struct r5conf *conf = container_of(shrink, struct r5conf, shrinker);
	int max_stripes = READ_ONCE(conf->max_nr_stripes);
	int min_stripes = READ_ONCE(conf->min_nr_stripes);

	if (max_stripes < min_stripes)
		/* unlikely, but not impossible */
		return 0;
	return max_stripes - min_stripes;
}


#include "livepatch_bsc1220145.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "raid456"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "free_stripe", (void *)&klpe_free_stripe, "raid456" },
	{ "get_free_stripe", (void *)&klpe_get_free_stripe, "raid456" },
	{ "raid5_release_stripe", (void *)&klpe_raid5_release_stripe,
	  "raid456" },
	{ "shrink_buffers", (void *)&klpe_shrink_buffers, "raid456" },
	{ "md_allow_write", (void *)&klpe_md_allow_write, "md_mod" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1220145_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1220145_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
