/*
 * livepatch_bsc1185847
 *
 * Fix for bsc#1185847
 *
 *  Upstream commit:
 *  2417b9869b81 ("md/raid1: properly indicate failure when ending a failed
 *                 write request")
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4 commit:
 *  d29842e061bfabe123508d8bb5677747208b0c23
 *
 *  SLE12-SP5 commit:
 *  97cfe4b0bd3dbf766e71430e9602b3e0f70d19de
 *
 *  SLE15 commit:
 *  not affected
 *
 *  SLE15-SP1 commit:
 *  eb7a0e7901f14283aa45b85df22fabe95efb83ab
 *
 *  SLE15-SP2 commit:
 *  67fde5a14a4142d1d69f87846ce35fa5eefce991
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

#if !IS_MODULE(CONFIG_MD_RAID1)
#error "Live patch supports only CONFIG_MD_RAID1=m"
#endif

/* klp-ccp: from drivers/md/raid1.c */
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/seq_file.h>
#include <linux/ratelimit.h>
/* klp-ccp: from drivers/md/md.h */
#include <linux/blkdev.h>
#include <linux/badblocks.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <uapi/linux/fcntl.h>

#define	MD_FAILFAST	(REQ_FAILFAST_DEV | REQ_FAILFAST_TRANSPORT)

struct md_rdev {
	struct list_head same_set;	/* RAID devices within the same set */

	sector_t sectors;		/* Device size (in 512bytes sectors) */
	struct mddev *mddev;		/* RAID array if running */
	int last_events;		/* IO event timestamp */

	/*
	 * If meta_bdev is non-NULL, it means that a separate device is
	 * being used to store the metadata (superblock/bitmap) which
	 * would otherwise be contained on the same device as the data (bdev).
	 */
	struct block_device *meta_bdev;
	struct block_device *bdev;	/* block device handle */

	struct page	*sb_page, *bb_page;
	int		sb_loaded;
	__u64		sb_events;
	sector_t	data_offset;	/* start of data in array */
	sector_t	new_data_offset;/* only relevant while reshaping */
	sector_t	sb_start;	/* offset of the super block (in 512byte sectors) */
	int		sb_size;	/* bytes in the superblock */
	int		preferred_minor;	/* autorun support */

	struct kobject	kobj;

	/* A device can be in one of three states based on two flags:
	 * Not working:   faulty==1 in_sync==0
	 * Fully working: faulty==0 in_sync==1
	 * Working, but not
	 * in sync with array
	 *                faulty==0 in_sync==0
	 *
	 * It can never have faulty==1, in_sync==1
	 * This reduces the burden of testing multiple flags in many cases
	 */

	unsigned long	flags;	/* bit set of 'enum flag_bits' bits. */
	wait_queue_head_t blocked_wait;

	int desc_nr;			/* descriptor index in the superblock */
	int raid_disk;			/* role of device in array */
	int new_raid_disk;		/* role that the device will have in
					 * the array after a level-change completes.
					 */
	int saved_raid_disk;		/* role that device used to have in the
					 * array and could again if we did a partial
					 * resync from the bitmap
					 */
	union {
		sector_t recovery_offset;/* If this device has been partially
					 * recovered, this is where we were
					 * up to.
					 */
		sector_t journal_tail;	/* If this device is a journal device,
					 * this is the journal tail (journal
					 * recovery start point)
					 */
	};

	atomic_t	nr_pending;	/* number of pending requests.
					 * only maintained for arrays that
					 * support hot removal
					 */
	atomic_t	read_errors;	/* number of consecutive read errors that
					 * we have tried to ignore.
					 */
	time64_t	last_read_error;	/* monotonic time since our
						 * last read error
						 */
	atomic_t	corrected_errors; /* number of corrected read errors,
					   * for reporting to userspace and storing
					   * in superblock.
					   */

	struct work_struct del_work;	/* used for delayed sysfs removal */

	struct kernfs_node *sysfs_state; /* handle for 'state'
					   * sysfs entry */

	struct badblocks badblocks;

	struct {
		short offset;	/* Offset from superblock to start of PPL.
				 * Not used by external metadata. */
		unsigned int size;	/* Size in sectors of the PPL space */
		sector_t sector;	/* First sector of the PPL space */
	} ppl;

#ifndef __GENKSYMS__
	struct list_head serial_list;
	spinlock_t serial_list_lock;
	wait_queue_head_t serial_io_wait;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};
enum flag_bits {
	Faulty,			/* device is known to have a fault */
	In_sync,		/* device is in_sync with rest of array */
	Bitmap_sync,		/* ..actually, not quite In_sync.  Need a
				 * bitmap-based recovery to get fully in sync.
				 * The bit is only meaningful before device
				 * has been passed to pers->hot_add_disk.
				 */
	WriteMostly,		/* Avoid reading if at all possible */
	AutoDetected,		/* added by auto-detect */
	Blocked,		/* An error occurred but has not yet
				 * been acknowledged by the metadata
				 * handler, so don't allow writes
				 * until it is cleared */
	WriteErrorSeen,		/* A write error has been seen on this
				 * device
				 */
	FaultRecorded,		/* Intermediate state for clearing
				 * Blocked.  The Fault is/will-be
				 * recorded in the metadata, but that
				 * metadata hasn't been stored safely
				 * on disk yet.
				 */
	BlockedBadBlocks,	/* A writer is blocked because they
				 * found an unacknowledged bad-block.
				 * This can safely be cleared at any
				 * time, and the writer will re-check.
				 * It may be set at any time, and at
				 * worst the writer will timeout and
				 * re-check.  So setting it as
				 * accurately as possible is good, but
				 * not absolutely critical.
				 */
	WantReplacement,	/* This device is a candidate to be
				 * hot-replaced, either because it has
				 * reported some faults, or because
				 * of explicit request.
				 */
	Replacement,		/* This device is a replacement for
				 * a want_replacement device with same
				 * raid_disk number.
				 */
	Candidate,		/* For clustered environments only:
				 * This device is seen locally but not
				 * by the whole cluster
				 */
	Journal,		/* This device is used as journal for
				 * raid-5/6.
				 * Usually, this device should be faster
				 * than other devices in the array
				 */
	ClusterRemove,
	RemoveSynchronized,	/* synchronize_rcu() was called after
				 * this device was known to be faulty,
				 * so it is safe to remove without
				 * another synchronize_rcu() call.
				 */
	ExternalBbl,            /* External metadata provides bad
				 * block management for a disk
				 */
	FailFast,		/* Minimal retries should be attempted on
				 * this device, so use REQ_FAILFAST_DEV.
				 * Also don't try to repair failed reads.
				 * It is expects that no bad block log
				 * is present.
				 */
	LastDev,		/* Seems to be the last working dev as
				 * it didn't fail, so don't use FailFast
				 * any more for metadata
				 */
	CollisionCheck,		/*
				 * check if there is collision between raid1
				 * serial bios.
				 */
	Timeout,		/* Device fault due to timeout.
				 * 'Faulty' is required to be set.
				 */
};

static inline int is_badblock(struct md_rdev *rdev, sector_t s, int sectors,
			      sector_t *first_bad, int *bad_sectors)
{
	if (unlikely(rdev->badblocks.count)) {
		int rv = badblocks_check(&rdev->badblocks, rdev->data_offset + s,
					sectors,
					first_bad, bad_sectors);
		if (rv)
			*first_bad -= rdev->data_offset;
		return rv;
	}
	return 0;
}

struct serial_info {
	sector_t lo;
	sector_t hi;
	struct list_head list;
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
	 * with bdev->bd_mutex.
	 * Lock ordering is:
	 *  reconfig_mutex -> bd_mutex : e.g. do_md_run -> revalidate_disk
	 *  bd_mutex -> open_mutex:  e.g. __blkdev_get -> md_open
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

	struct attribute_group		*to_remove;

	struct bio_set			*bio_set;
	struct bio_set			*sync_set; /* for sync operations like
						   * metadata and bitmap writes
						   */

	/* Generic flush handling.
	 * The last to finish preflush schedules a worker to submit
	 * the rest of the request (without the REQ_PREFLUSH flag).
	 */
	struct bio *flush_bio;
	atomic_t flush_pending;
	ktime_t start_flush, last_flush; /* last_flush is when the last completed
					  * flush was started.
					  */
	struct work_struct flush_work;
	struct work_struct event_work;	/* used by dm to report failure event */
	void (*sync_super)(struct mddev *mddev, struct md_rdev *rdev);
	struct md_cluster_info		*cluster_info;
	unsigned int			good_device_nr;	/* good device num within cluster raid */

	bool	has_superblocks:1;
#ifndef __GENKSYMS__
	mempool_t *serial_info_pool;
	unsigned int			noio_flag; /* for memalloc scope API */
	bool	fail_last_dev:1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

enum recovery_flags {
	/*
	 * If neither SYNC or RESHAPE are set, then it is a recovery.
	 */
	MD_RECOVERY_RUNNING,	/* a thread is running, or about to be started */
	MD_RECOVERY_SYNC,	/* actually doing a resync, not a recovery */
	MD_RECOVERY_RECOVER,	/* doing recovery, or need to try it. */
	MD_RECOVERY_INTR,	/* resync needs to be aborted for some reason */
	MD_RECOVERY_DONE,	/* thread is done and is waiting to be reaped */
	MD_RECOVERY_NEEDED,	/* we might need to start a resync/recover */
	MD_RECOVERY_REQUESTED,	/* user-space has requested a sync (used with SYNC) */
	MD_RECOVERY_CHECK,	/* user-space request for check-only, no repair */
	MD_RECOVERY_RESHAPE,	/* A reshape is happening */
	MD_RECOVERY_FROZEN,	/* User request to abort, and not restart, any action */
	MD_RECOVERY_ERROR,	/* sync-action interrupted because io-error */
	MD_RECOVERY_WAIT,	/* waiting for pers->start() to finish */
	MD_RESYNCING_REMOTE,	/* remote node is running resync thread */
};

static void (*klpe_md_wakeup_thread)(struct md_thread *thread);

static void (*klpe_md_error)(struct mddev *mddev, struct md_rdev *rdev);

static inline void klpr_rdev_dec_pending(struct md_rdev *rdev, struct mddev *mddev)
{
	int faulty = test_bit(Faulty, &rdev->flags);
	if (atomic_dec_and_test(&rdev->nr_pending) && faulty) {
		set_bit(MD_RECOVERY_NEEDED, &mddev->recovery);
		(*klpe_md_wakeup_thread)(mddev->thread);
	}
}

/* klp-ccp: from drivers/md/raid1.h */
struct raid1_info {
	struct md_rdev	*rdev;
	sector_t	head_position;

	/* When choose the best device for a read (read_balance())
	 * we try to keep sequential reads one the same device
	 */
	sector_t	next_seq_sect;
	sector_t	seq_start;
};

struct r1conf {
	struct mddev		*mddev;
	struct raid1_info	*mirrors;	/* twice 'raid_disks' to
						 * allow for replacements.
						 */
	int			raid_disks;

	spinlock_t		device_lock;

	/* list of 'struct r1bio' that need to be processed by raid1d,
	 * whether to retry a read, writeout a resync or recovery
	 * block, or anything else.
	 */
	struct list_head	retry_list;
	/* A separate list of r1bio which just need raid_end_bio_io called.
	 * This mustn't happen for writes which had any errors if the superblock
	 * needs to be written.
	 */
	struct list_head	bio_end_io_list;

	/* queue pending writes to be submitted on unplug */
	struct bio_list		pending_bio_list;
	int			pending_count;

	/* for use when syncing mirrors:
	 * We don't allow both normal IO and resync/recovery IO at
	 * the same time - resync/recovery can only happen when there
	 * is no other IO.  So when either is active, the other has to wait.
	 * See more details description in raid1.c near raise_barrier().
	 */
	wait_queue_head_t	wait_barrier;
	spinlock_t		resync_lock;
	atomic_t		nr_sync_pending;
	atomic_t		*nr_pending;
	atomic_t		*nr_waiting;
	atomic_t		*nr_queued;
	atomic_t		*barrier;
	int			array_frozen;

	/* Set to 1 if a full sync is needed, (fresh device added).
	 * Cleared when a sync completes.
	 */
	int			fullsync;

	/* When the same as mddev->recovery_disabled we don't allow
	 * recovery to be attempted as we expect a read error.
	 */
	int			recovery_disabled;

	/* poolinfo contains information about the content of the
	 * mempools - it changes when the array grows or shrinks
	 */
	struct pool_info	*poolinfo;
	mempool_t		*r1bio_pool;
	mempool_t		*r1buf_pool;

	struct bio_set		*bio_split;

	/* temporary buffer to synchronous IO when attempting to repair
	 * a read error.
	 */
	struct page		*tmppage;

	/* When taking over an array from a different personality, we store
	 * the new thread here until we fully activate the array.
	 */
	struct md_thread	*thread;

	/* Keep track of cluster resync window to send to other
	 * nodes.
	 */
	sector_t		cluster_sync_low;
	sector_t		cluster_sync_high;

};

struct r1bio {
	atomic_t		remaining; /* 'have we finished' count,
					    * used from IRQ handlers
					    */
	atomic_t		behind_remaining; /* number of write-behind ios remaining
						 * in this BehindIO request
						 */
	sector_t		sector;
	int			sectors;
	unsigned long		state;
	struct mddev		*mddev;
	/*
	 * original bio going to /dev/mdx
	 */
	struct bio		*master_bio;
	/*
	 * if the IO is in READ direction, then this is where we read
	 */
	int			read_disk;

	struct list_head	retry_list;

	/*
	 * When R1BIO_BehindIO is set, we store pages for write behind
	 * in behind_master_bio.
	 */
	struct bio		*behind_master_bio;

	/*
	 * if the IO is in WRITE direction, then multiple bios are used.
	 * We choose the number when they are allocated.
	 */
	struct bio		*bios[0];
	/* DO NOT PUT ANY NEW FIELDS HERE - bios array is contiguously alloced*/
};

enum r1bio_state {
	R1BIO_Uptodate,
	R1BIO_IsSync,
	R1BIO_Degraded,
	R1BIO_BehindIO,
/* Set ReadError on bios that experience a readerror so that
 * raid1d knows what to do with them.
 */
	R1BIO_ReadError,
/* For write-behind requests, we call bi_end_io when
 * the last non-write-behind device completes, providing
 * any write was successful.  Otherwise we call when
 * any write-behind write succeeds, otherwise we call
 * with failure when last write completes (and all failed).
 * Record that bi_end_io was called with this flag...
 */
	R1BIO_Returned,
/* If a write for this request means we can clear some
 * known-bad-block records, we set this flag
 */
	R1BIO_MadeGood,
	R1BIO_WriteError,
	R1BIO_FailFast,
};

/* klp-ccp: from drivers/md/raid1.c */
#define IO_MADE_GOOD ((struct bio *)2)

static void remove_serial(struct md_rdev *rdev, sector_t lo, sector_t hi)
{
	struct serial_info *wi;
	unsigned long flags;
	int found = 0;
	struct mddev *mddev = rdev->mddev;

	spin_lock_irqsave(&rdev->serial_list_lock, flags);
	list_for_each_entry(wi, &rdev->serial_list, list)
		if (hi == wi->hi && lo == wi->lo) {
			list_del(&wi->list);
			mempool_free(wi, mddev->serial_info_pool);
			found = 1;
			break;
		}

	if (!found)
		WARN(1, "The write IO is not recorded for serialization\n");
	spin_unlock_irqrestore(&rdev->serial_list_lock, flags);
	wake_up(&rdev->serial_io_wait);
}

static void (*klpe_call_bio_endio)(struct r1bio *r1_bio);

static int (*klpe_find_bio_disk)(struct r1bio *r1_bio, struct bio *bio);

static void (*klpe_r1_bio_write_done)(struct r1bio *r1_bio);

void klpp_raid1_end_write_request(struct bio *bio)
{
	struct r1bio *r1_bio = bio->bi_private;
	int behind = test_bit(R1BIO_BehindIO, &r1_bio->state);
	struct r1conf *conf = r1_bio->mddev->private;
	struct bio *to_put = NULL;
	int mirror = (*klpe_find_bio_disk)(r1_bio, bio);
	struct md_rdev *rdev = conf->mirrors[mirror].rdev;
	bool discard_error;

	discard_error = bio->bi_status && bio_op(bio) == REQ_OP_DISCARD;

	/*
	 * 'one mirror IO has finished' event handler:
	 */
	if (bio->bi_status && !discard_error) {
		set_bit(WriteErrorSeen,	&rdev->flags);
		if (!test_and_set_bit(WantReplacement, &rdev->flags))
			set_bit(MD_RECOVERY_NEEDED, &
				conf->mddev->recovery);

		if (test_bit(FailFast, &rdev->flags) &&
		    (bio->bi_opf & MD_FAILFAST) &&
		    /* We never try FailFast to WriteMostly devices */
		    !test_bit(WriteMostly, &rdev->flags)) {
			(*klpe_md_error)(r1_bio->mddev, rdev);
		}

		/*
		 * When the device is faulty, it is not necessary to
		 * handle write error.
		 * For failfast, this is the only remaining device,
		 * We need to retry the write without FailFast.
		 */
		if (!test_bit(Faulty, &rdev->flags))
			set_bit(R1BIO_WriteError, &r1_bio->state);
		else {
			/*
			 * Fix bsc#1185847
			 *  +2 lines
			 */
			/* Fail the request */
			set_bit(R1BIO_Degraded, &r1_bio->state);
			/* Finished with this branch */
			r1_bio->bios[mirror] = NULL;
			to_put = bio;
		}
	} else {
		/*
		 * Set R1BIO_Uptodate in our master bio, so that we
		 * will return a good error code for to the higher
		 * levels even if IO on some other mirrored buffer
		 * fails.
		 *
		 * The 'master' represents the composite IO operation
		 * to user-side. So if something waits for IO, then it
		 * will wait for the 'master' bio.
		 */
		sector_t first_bad;
		int bad_sectors;

		r1_bio->bios[mirror] = NULL;
		to_put = bio;
		/*
		 * Do not set R1BIO_Uptodate if the current device is
		 * rebuilding or Faulty. This is because we cannot use
		 * such device for properly reading the data back (we could
		 * potentially use it, if the current write would have felt
		 * before rdev->recovery_offset, but for simplicity we don't
		 * check this here.
		 */
		if (test_bit(In_sync, &rdev->flags) &&
		    !test_bit(Faulty, &rdev->flags))
			set_bit(R1BIO_Uptodate, &r1_bio->state);

		/* Maybe we can clear some bad blocks. */
		if (is_badblock(rdev, r1_bio->sector, r1_bio->sectors,
				&first_bad, &bad_sectors) && !discard_error) {
			r1_bio->bios[mirror] = IO_MADE_GOOD;
			set_bit(R1BIO_MadeGood, &r1_bio->state);
		}
	}

	if (behind) {
		if (test_bit(CollisionCheck, &rdev->flags)) {
			sector_t lo = r1_bio->sector;
			sector_t hi = r1_bio->sector + r1_bio->sectors;

			remove_serial(rdev, lo, hi);
		}
		if (test_bit(WriteMostly, &rdev->flags))
			atomic_dec(&r1_bio->behind_remaining);

		/*
		 * In behind mode, we ACK the master bio once the I/O
		 * has safely reached all non-writemostly
		 * disks. Setting the Returned bit ensures that this
		 * gets done only once -- we don't ever want to return
		 * -EIO here, instead we'll wait
		 */
		if (atomic_read(&r1_bio->behind_remaining) >= (atomic_read(&r1_bio->remaining)-1) &&
		    test_bit(R1BIO_Uptodate, &r1_bio->state)) {
			/* Maybe we can return now */
			if (!test_and_set_bit(R1BIO_Returned, &r1_bio->state)) {
				struct bio *mbio = r1_bio->master_bio;
				pr_debug("raid1: behind end write sectors"
					 " %llu-%llu\n",
					 (unsigned long long) mbio->bi_iter.bi_sector,
					 (unsigned long long) bio_end_sector(mbio) - 1);
				(*klpe_call_bio_endio)(r1_bio);
			}
		}
	}
	if (r1_bio->bios[mirror] == NULL)
		klpr_rdev_dec_pending(rdev, conf->mddev);

	/*
	 * Let's see if all mirrored write operations have finished
	 * already.
	 */
	(*klpe_r1_bio_write_done)(r1_bio);

	if (to_put)
		bio_put(to_put);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1185847.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "raid1"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "md_wakeup_thread", (void *)&klpe_md_wakeup_thread, "md_mod" },
	{ "md_error", (void *)&klpe_md_error, "md_mod" },
	{ "call_bio_endio", (void *)&klpe_call_bio_endio, "raid1" },
	{ "find_bio_disk", (void *)&klpe_find_bio_disk, "raid1" },
	{ "r1_bio_write_done", (void *)&klpe_r1_bio_write_done, "raid1" },
};

static int livepatch_bsc1185847_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1185847_module_nb = {
	.notifier_call = livepatch_bsc1185847_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1185847_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1185847_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1185847_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1185847_module_nb);
}
