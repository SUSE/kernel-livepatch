/*
 * livepatch_bsc1229273
 *
 * Fix for CVE-2024-35949, bsc#1229273
 *
 *  Upstream commit:
 *  e03418abde87 ("btrfs: make sure that WRITTEN is set on all metadata blocks")
 *
 *  SLE12-SP5 commit:
 *  6dc890dd6c5f31d52fee011a9b1b67ebbf68a832
 *
 *  SLE15-SP2, -SP3 and -SP4 commit:
 *  Not affected
 *
 *  SLE15-SP5 commit:
 *  c3c95152b5273060812a1ca5f910b733e1ebde32
 *
 *  SLE15-SP6 commit:
 *  78801791fc253928a732cf9d275d9c862998368d
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

/* klp-ccp: from fs/btrfs/tree-checker.c */
#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/error-injection.h>

/* klp-ccp: from fs/btrfs/messages.h */
#include <linux/types.h>

struct btrfs_fs_info;

#ifdef CONFIG_PRINTK

#define btrfs_printk(fs_info, fmt, args...)				\
	_btrfs_printk(fs_info, fmt, ##args)

__printf(2, 3)
void _btrfs_printk(const struct btrfs_fs_info *fs_info, const char *fmt, ...);

#else
#error "klp-ccp: non-taken branch"
#endif

#define btrfs_crit(fs_info, fmt, args...) \
	btrfs_printk(fs_info, KERN_CRIT fmt, ##args)

#ifdef CONFIG_BTRFS_ASSERT
void __noreturn btrfs_assertfail(const char *expr, const char *file, int line);

#define ASSERT(expr)						\
	(likely(expr) ? (void)0 : btrfs_assertfail(#expr, __FILE__, __LINE__))
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from fs/btrfs/ctree.h */
#include <linux/mm.h>
#include <linux/sched/signal.h>
#include <linux/highmem.h>
#include <linux/fs.h>
#include <linux/rwsem.h>
#include <linux/semaphore.h>
#include <linux/completion.h>
#include <linux/backing-dev.h>
#include <linux/wait.h>
#include <linux/slab.h>

/* klp-ccp: from include/trace/events/btrfs.h */
#if !defined(_TRACE_BTRFS_H) || defined(TRACE_HEADER_MULTI_READ)

struct extent_buffer;
struct btrfs_work;

#define BTRFS_FSID_SIZE 16

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_BTRFS_H */

/* klp-ccp: from fs/btrfs/ctree.h */
#include <asm/unaligned.h>

#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/workqueue.h>

#include <linux/sizes.h>
#include <linux/dynamic_debug.h>
#include <linux/refcount.h>

#include <linux/iomap.h>

/* klp-ccp: from fs/btrfs/misc.h */
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/math64.h>
#include <linux/rbtree.h>

static inline bool is_power_of_two_u64(u64 n)
{
	return n != 0 && (n & (n - 1)) == 0;
}

static inline bool has_single_bit_set(u64 n)
{
	return is_power_of_two_u64(n);
}

/* klp-ccp: from fs/btrfs/extent-io-tree.h */
struct extent_io_tree {
	struct rb_root state;
	struct btrfs_fs_info *fs_info;
	/* Inode associated with this tree, or NULL. */
	struct btrfs_inode *inode;

	/* Who owns this io tree, should be one of IO_TREE_* */
	u8 owner;

	spinlock_t lock;
};

/* klp-ccp: from fs/btrfs/extent_io.h */
#include <linux/rbtree.h>
#include <linux/refcount.h>

#include <linux/btrfs_tree.h>

/* klp-ccp: from fs/btrfs/compression.h */
#include <linux/sizes.h>

/* klp-ccp: from fs/btrfs/bio.h */
#include <linux/bio.h>
#include <linux/workqueue.h>

/* klp-ccp: from fs/btrfs/tree-checker.h */
#include <uapi/linux/btrfs_tree.h>

int btrfs_check_chunk_valid(struct extent_buffer *leaf,
			    struct btrfs_chunk *chunk, u64 logical);

/* klp-ccp: from fs/btrfs/compression.h */
enum btrfs_compression_type {
	BTRFS_COMPRESS_NONE  = 0,
	BTRFS_COMPRESS_ZLIB  = 1,
	BTRFS_COMPRESS_LZO   = 2,
	BTRFS_COMPRESS_ZSTD  = 3,
	BTRFS_NR_COMPRESS_TYPES = 4,
};

/* klp-ccp: from fs/btrfs/ulist.h */
#include <linux/list.h>
#include <linux/rbtree.h>

/* klp-ccp: from fs/btrfs/extent_io.h */
#define INLINE_EXTENT_BUFFER_PAGES     (BTRFS_MAX_METADATA_BLOCKSIZE / PAGE_SIZE)
struct extent_buffer {
	u64 start;
	unsigned long len;
	unsigned long bflags;
	struct btrfs_fs_info *fs_info;
	spinlock_t refs_lock;
	atomic_t refs;
	atomic_t io_pages;
	int read_mirror;
	struct rcu_head rcu_head;
	pid_t lock_owner;
	/* >= 0 if eb belongs to a log tree, -1 otherwise */
	s8 log_index;

	struct rw_semaphore lock;

	struct page *pages[INLINE_EXTENT_BUFFER_PAGES];
	struct list_head release_list;
#ifdef CONFIG_BTRFS_DEBUG
#error "klp-ccp: non-taken branch"
#endif
};

void read_extent_buffer(const struct extent_buffer *eb, void *dst,
			unsigned long start,
			unsigned long len);

/* klp-ccp: from fs/btrfs/extent_map.h */
#include <linux/rbtree.h>
#include <linux/refcount.h>

struct extent_map_tree {
	struct rb_root_cached map;
	struct list_head modified_extents;
	rwlock_t lock;
};

/* klp-ccp: from fs/btrfs/async-thread.h */
#include <linux/workqueue.h>

typedef void (*btrfs_func_t)(struct btrfs_work *arg);

struct btrfs_work {
	btrfs_func_t func;
	btrfs_func_t ordered_func;
	btrfs_func_t ordered_free;

	/* Don't touch things below */
	struct work_struct normal_work;
	struct list_head ordered_list;
	struct btrfs_workqueue *wq;
	unsigned long flags;
};

/* klp-ccp: from fs/btrfs/block-rsv.h */
enum btrfs_rsv_type {
	BTRFS_BLOCK_RSV_GLOBAL,
	BTRFS_BLOCK_RSV_DELALLOC,
	BTRFS_BLOCK_RSV_TRANS,
	BTRFS_BLOCK_RSV_CHUNK,
	BTRFS_BLOCK_RSV_DELOPS,
	BTRFS_BLOCK_RSV_DELREFS,
	BTRFS_BLOCK_RSV_EMPTY,
	BTRFS_BLOCK_RSV_TEMP,
};

struct btrfs_block_rsv {
	u64 size;
	u64 reserved;
	struct btrfs_space_info *space_info;
	spinlock_t lock;
	bool full;
	bool failfast;
	/* Block reserve type, one of BTRFS_BLOCK_RSV_* */
	enum btrfs_rsv_type type:8;

	/*
	 * Qgroup equivalent for @size @reserved
	 *
	 * Unlike normal @size/@reserved for inode rsv, qgroup doesn't care
	 * about things like csum size nor how many tree blocks it will need to
	 * reserve.
	 *
	 * Qgroup cares more about net change of the extent usage.
	 *
	 * So for one newly inserted file extent, in worst case it will cause
	 * leaf split and level increase, nodesize for each file extent is
	 * already too much.
	 *
	 * In short, qgroup_size/reserved is the upper limit of possible needed
	 * qgroup metadata reservation.
	 */
	u64 qgroup_rsv_size;
	u64 qgroup_rsv_reserved;
};

/* klp-ccp: from fs/btrfs/locking.h */
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/percpu_counter.h>

/* klp-ccp: from fs/btrfs/fs.h */
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/btrfs_tree.h>
#include <linux/sizes.h>

struct btrfs_dev_replace {
	/* See #define above */
	u64 replace_state;
	/* Seconds since 1-Jan-1970 */
	time64_t time_started;
	/* Seconds since 1-Jan-1970 */
	time64_t time_stopped;
	atomic64_t num_write_errors;
	atomic64_t num_uncorrectable_read_errors;

	u64 cursor_left;
	u64 committed_cursor_left;
	u64 cursor_left_last_write_of_item;
	u64 cursor_right;

	/* See #define above */
	u64 cont_reading_from_srcdev_mode;

	int is_valid;
	int item_needs_writeback;
	struct btrfs_device *srcdev;
	struct btrfs_device *tgtdev;

	struct mutex lock_finishing_cancel_unmount;
	struct rw_semaphore rwsem;

	struct btrfs_scrub_progress scrub_progress;

	struct percpu_counter bio_counter;
	wait_queue_head_t replace_wait;
};

struct btrfs_free_cluster {
	spinlock_t lock;
	spinlock_t refill_lock;
	struct rb_root root;

	/* Largest extent in this cluster */
	u64 max_size;

	/* First extent starting offset */
	u64 window_start;

	/* We did a full search and couldn't create a cluster */
	bool fragmented;

	struct btrfs_block_group *block_group;
	/*
	 * When a cluster is allocated from a block group, we put the cluster
	 * onto a list in the block group so that it can be freed before the
	 * block group is freed.
	 */
	struct list_head block_group_list;
};

#define BTRFS_NR_DISCARD_LISTS		3

struct btrfs_discard_ctl {
	struct workqueue_struct *discard_workers;
	struct delayed_work work;
	spinlock_t lock;
	struct btrfs_block_group *block_group;
	struct list_head discard_list[BTRFS_NR_DISCARD_LISTS];
	u64 prev_discard;
	u64 prev_discard_time;
	atomic_t discardable_extents;
	atomic64_t discardable_bytes;
	u64 max_discard_size;
	u64 delay_ms;
	u32 iops_limit;
	u32 kbps_limit;
	u64 discard_extent_bytes;
	u64 discard_bitmap_bytes;
	atomic64_t discard_bytes_saved;
};

enum btrfs_exclusive_operation {
	BTRFS_EXCLOP_NONE,
	BTRFS_EXCLOP_BALANCE_PAUSED,
	BTRFS_EXCLOP_BALANCE,
	BTRFS_EXCLOP_DEV_ADD,
	BTRFS_EXCLOP_DEV_REMOVE,
	BTRFS_EXCLOP_DEV_REPLACE,
	BTRFS_EXCLOP_RESIZE,
	BTRFS_EXCLOP_SWAP_ACTIVATE,
};

struct btrfs_commit_stats {
	/* Total number of commits */
	u64 commit_count;
	/* The maximum commit duration so far in ns */
	u64 max_commit_dur;
	/* The last commit duration in ns */
	u64 last_commit_dur;
	/* The total commit duration in ns */
	u64 total_commit_dur;
};

struct btrfs_fs_info {
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	unsigned long flags;
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *dev_root;
	struct btrfs_root *fs_root;
	struct btrfs_root *quota_root;
	struct btrfs_root *uuid_root;
	struct btrfs_root *data_reloc_root;
	struct btrfs_root *block_group_root;

	/* The log root tree is a directory of all the other log roots */
	struct btrfs_root *log_root_tree;

	/* The tree that holds the global roots (csum, extent, etc) */
	rwlock_t global_root_lock;
	struct rb_root global_root_tree;

	spinlock_t fs_roots_radix_lock;
	struct radix_tree_root fs_roots_radix;

	/* Block group cache stuff */
	rwlock_t block_group_cache_lock;
	struct rb_root_cached block_group_cache_tree;

	/* Keep track of unallocated space */
	atomic64_t free_chunk_space;

	/* Track ranges which are used by log trees blocks/logged data extents */
	struct extent_io_tree excluded_extents;

	/* logical->physical extent mapping */
	struct extent_map_tree mapping_tree;

	/*
	 * Block reservation for extent, checksum, root tree and delayed dir
	 * index item.
	 */
	struct btrfs_block_rsv global_block_rsv;
	/* Block reservation for metadata operations */
	struct btrfs_block_rsv trans_block_rsv;
	/* Block reservation for chunk tree */
	struct btrfs_block_rsv chunk_block_rsv;
	/* Block reservation for delayed operations */
	struct btrfs_block_rsv delayed_block_rsv;
	/* Block reservation for delayed refs */
	struct btrfs_block_rsv delayed_refs_rsv;

	struct btrfs_block_rsv empty_block_rsv;

	u64 generation;
	u64 last_trans_committed;
	/*
	 * Generation of the last transaction used for block group relocation
	 * since the filesystem was last mounted (or 0 if none happened yet).
	 * Must be written and read while holding btrfs_fs_info::commit_root_sem.
	 */
	u64 last_reloc_trans;

	/*
	 * This is updated to the current trans every time a full commit is
	 * required instead of the faster short fsync log commits
	 */
	u64 last_trans_log_full_commit;
	unsigned long mount_opt;

	unsigned long compress_type:4;
	unsigned int compress_level;
	u32 commit_interval;
	/*
	 * It is a suggestive number, the read side is safe even it gets a
	 * wrong number because we will write out the data into a regular
	 * extent. The write side(mount/remount) is under ->s_umount lock,
	 * so it is also safe.
	 */
	u64 max_inline;

	struct btrfs_transaction *running_transaction;
	wait_queue_head_t transaction_throttle;
	wait_queue_head_t transaction_wait;
	wait_queue_head_t transaction_blocked_wait;
	wait_queue_head_t async_submit_wait;

	/*
	 * Used to protect the incompat_flags, compat_flags, compat_ro_flags
	 * when they are updated.
	 *
	 * Because we do not clear the flags for ever, so we needn't use
	 * the lock on the read side.
	 *
	 * We also needn't use the lock when we mount the fs, because
	 * there is no other task which will update the flag.
	 */
	spinlock_t super_lock;
	struct btrfs_super_block *super_copy;
	struct btrfs_super_block *super_for_commit;
	struct super_block *sb;
	struct inode *btree_inode;
	struct mutex tree_log_mutex;
	struct mutex transaction_kthread_mutex;
	struct mutex cleaner_mutex;
	struct mutex chunk_mutex;

	/*
	 * This is taken to make sure we don't set block groups ro after the
	 * free space cache has been allocated on them.
	 */
	struct mutex ro_block_group_mutex;

	/*
	 * This is used during read/modify/write to make sure no two ios are
	 * trying to mod the same stripe at the same time.
	 */
	struct btrfs_stripe_hash_table *stripe_hash_table;

	/*
	 * This protects the ordered operations list only while we are
	 * processing all of the entries on it.  This way we make sure the
	 * commit code doesn't find the list temporarily empty because another
	 * function happens to be doing non-waiting preflush before jumping
	 * into the main commit.
	 */
	struct mutex ordered_operations_mutex;

	struct rw_semaphore commit_root_sem;

	struct rw_semaphore cleanup_work_sem;

	struct rw_semaphore subvol_sem;

	spinlock_t trans_lock;
	/*
	 * The reloc mutex goes with the trans lock, it is taken during commit
	 * to protect us from the relocation code.
	 */
	struct mutex reloc_mutex;

	struct list_head trans_list;
	struct list_head dead_roots;
	struct list_head caching_block_groups;

	spinlock_t delayed_iput_lock;
	struct list_head delayed_iputs;
	atomic_t nr_delayed_iputs;
	wait_queue_head_t delayed_iputs_wait;

	atomic64_t tree_mod_seq;

	/* This protects tree_mod_log and tree_mod_seq_list */
	rwlock_t tree_mod_log_lock;
	struct rb_root tree_mod_log;
	struct list_head tree_mod_seq_list;

	atomic_t async_delalloc_pages;

	/* This is used to protect the following list -- ordered_roots. */
	spinlock_t ordered_root_lock;

	/*
	 * All fs/file tree roots in which there are data=ordered extents
	 * pending writeback are added into this list.
	 *
	 * These can span multiple transactions and basically include every
	 * dirty data page that isn't from nodatacow.
	 */
	struct list_head ordered_roots;

	struct mutex delalloc_root_mutex;
	spinlock_t delalloc_root_lock;
	/* All fs/file tree roots that have delalloc inodes. */
	struct list_head delalloc_roots;

	/*
	 * There is a pool of worker threads for checksumming during writes and
	 * a pool for checksumming after reads.  This is because readers can
	 * run with FS locks held, and the writers may be waiting for those
	 * locks.  We don't want ordering in the pending list to cause
	 * deadlocks, and so the two are serviced separately.
	 *
	 * A third pool does submit_bio to avoid deadlocking with the other two.
	 */
	struct btrfs_workqueue *workers;
	struct btrfs_workqueue *hipri_workers;
	struct btrfs_workqueue *delalloc_workers;
	struct btrfs_workqueue *flush_workers;
	struct workqueue_struct *endio_workers;
	struct workqueue_struct *endio_meta_workers;
	struct workqueue_struct *rmw_workers;
	struct workqueue_struct *compressed_write_workers;
	struct btrfs_workqueue *endio_write_workers;
	struct btrfs_workqueue *endio_freespace_worker;
	struct btrfs_workqueue *caching_workers;

	/*
	 * Fixup workers take dirty pages that didn't properly go through the
	 * cow mechanism and make them safe to write.  It happens for the
	 * sys_munmap function call path.
	 */
	struct btrfs_workqueue *fixup_workers;
	struct btrfs_workqueue *delayed_workers;

	struct task_struct *transaction_kthread;
	struct task_struct *cleaner_kthread;
	u32 thread_pool_size;

	struct kobject *space_info_kobj;
	struct kobject *qgroups_kobj;
	struct kobject *discard_kobj;

	/* Used to keep from writing metadata until there is a nice batch */
	struct percpu_counter dirty_metadata_bytes;
	struct percpu_counter delalloc_bytes;
	struct percpu_counter ordered_bytes;
	s32 dirty_metadata_batch;
	s32 delalloc_batch;

	struct list_head dirty_cowonly_roots;

	struct btrfs_fs_devices *fs_devices;

	/*
	 * The space_info list is effectively read only after initial setup.
	 * It is populated at mount time and cleaned up after all block groups
	 * are removed.  RCU is used to protect it.
	 */
	struct list_head space_info;

	struct btrfs_space_info *data_sinfo;

	struct reloc_control *reloc_ctl;

	/* data_alloc_cluster is only used in ssd_spread mode */
	struct btrfs_free_cluster data_alloc_cluster;

	/* All metadata allocations go through this cluster. */
	struct btrfs_free_cluster meta_alloc_cluster;

	/* Auto defrag inodes go here. */
	spinlock_t defrag_inodes_lock;
	struct rb_root defrag_inodes;
	atomic_t defrag_running;

	/* Used to protect avail_{data, metadata, system}_alloc_bits */
	seqlock_t profiles_lock;
	/*
	 * These three are in extended format (availability of single chunks is
	 * denoted by BTRFS_AVAIL_ALLOC_BIT_SINGLE bit, other types are denoted
	 * by corresponding BTRFS_BLOCK_GROUP_* bits)
	 */
	u64 avail_data_alloc_bits;
	u64 avail_metadata_alloc_bits;
	u64 avail_system_alloc_bits;

	/* Balance state */
	spinlock_t balance_lock;
	struct mutex balance_mutex;
	atomic_t balance_pause_req;
	atomic_t balance_cancel_req;
	struct btrfs_balance_control *balance_ctl;
	wait_queue_head_t balance_wait_q;

	/* Cancellation requests for chunk relocation */
	atomic_t reloc_cancel_req;

	u32 data_chunk_allocations;
	u32 metadata_ratio;

	void *bdev_holder;

	/* Private scrub information */
	struct mutex scrub_lock;
	atomic_t scrubs_running;
	atomic_t scrub_pause_req;
	atomic_t scrubs_paused;
	atomic_t scrub_cancel_req;
	wait_queue_head_t scrub_pause_wait;
	/*
	 * The worker pointers are NULL iff the refcount is 0, ie. scrub is not
	 * running.
	 */
	refcount_t scrub_workers_refcnt;
	struct workqueue_struct *scrub_workers;
	struct workqueue_struct *scrub_wr_completion_workers;
	struct btrfs_subpage_info *subpage_info;

	struct btrfs_discard_ctl discard_ctl;

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
#error "klp-ccp: non-taken branch"
#endif
	u64 qgroup_flags;

	/* Holds configuration and tracking. Protected by qgroup_lock. */
	struct rb_root qgroup_tree;
	spinlock_t qgroup_lock;

	/*
	 * Used to avoid frequently calling ulist_alloc()/ulist_free()
	 * when doing qgroup accounting, it must be protected by qgroup_lock.
	 */
	struct ulist *qgroup_ulist;

	/*
	 * Protect user change for quota operations. If a transaction is needed,
	 * it must be started before locking this lock.
	 */
	struct mutex qgroup_ioctl_lock;

	/* List of dirty qgroups to be written at next commit. */
	struct list_head dirty_qgroups;

	/* Used by qgroup for an efficient tree traversal. */
	u64 qgroup_seq;

	/* Qgroup rescan items. */
	/* Protects the progress item */
	struct mutex qgroup_rescan_lock;
	struct btrfs_key qgroup_rescan_progress;
	struct btrfs_workqueue *qgroup_rescan_workers;
	struct completion qgroup_rescan_completion;
	struct btrfs_work qgroup_rescan_work;
	/* Protected by qgroup_rescan_lock */
	bool qgroup_rescan_running;
	u8 qgroup_drop_subtree_thres;

	/* Filesystem state */
	unsigned long fs_state;

	struct btrfs_delayed_root *delayed_root;

	/* Extent buffer radix tree */
	spinlock_t buffer_lock;
	/* Entries are eb->start / sectorsize */
	struct radix_tree_root buffer_radix;

	/* Next backup root to be overwritten */
	int backup_root_index;

	/* Device replace state */
	struct btrfs_dev_replace dev_replace;

	struct semaphore uuid_tree_rescan_sem;

	/* Used to reclaim the metadata space in the background. */
	struct work_struct async_reclaim_work;
	struct work_struct async_data_reclaim_work;
	struct work_struct preempt_reclaim_work;

	/* Reclaim partially filled block groups in the background */
	struct work_struct reclaim_bgs_work;
	struct list_head reclaim_bgs;
	int bg_reclaim_threshold;

	spinlock_t unused_bgs_lock;
	struct list_head unused_bgs;
	struct mutex unused_bg_unpin_mutex;
	/* Protect block groups that are going to be deleted */
	struct mutex reclaim_bgs_lock;

	/* Cached block sizes */
	u32 nodesize;
	u32 sectorsize;
	/* ilog2 of sectorsize, use to avoid 64bit division */
	u32 sectorsize_bits;
	u32 csum_size;
	u32 csums_per_leaf;
	u32 stripesize;

	/*
	 * Maximum size of an extent. BTRFS_MAX_EXTENT_SIZE on regular
	 * filesystem, on zoned it depends on the device constraints.
	 */
	u64 max_extent_size;

	/* Block groups and devices containing active swapfiles. */
	spinlock_t swapfile_pins_lock;
	struct rb_root swapfile_pins;

	struct crypto_shash *csum_shash;

	/* Type of exclusive operation running, protected by super_lock */
	enum btrfs_exclusive_operation exclusive_operation;

	/*
	 * Zone size > 0 when in ZONED mode, otherwise it's used for a check
	 * if the mode is enabled
	 */
	u64 zone_size;

	/* Constraints for ZONE_APPEND commands: */
	struct queue_limits limits;
	u64 max_zone_append_size;

	struct mutex zoned_meta_io_lock;
	spinlock_t treelog_bg_lock;
	u64 treelog_bg;

	/*
	 * Start of the dedicated data relocation block group, protected by
	 * relocation_bg_lock.
	 */
	spinlock_t relocation_bg_lock;
	u64 data_reloc_bg;
	struct mutex zoned_data_reloc_io_lock;

	u64 nr_global_roots;

	spinlock_t zone_active_bgs_lock;
	struct list_head zone_active_bgs;

	/* Updates are not protected by any lock */
	struct btrfs_commit_stats commit_stats;

	/*
	 * Last generation where we dropped a non-relocation root.
	 * Use btrfs_set_last_root_drop_gen() and btrfs_get_last_root_drop_gen()
	 * to change it and to read it, respectively.
	 */
	u64 last_root_drop_gen;

	/*
	 * Annotations for transaction events (structures are empty when
	 * compiled without lockdep).
	 */
	struct lockdep_map btrfs_trans_num_writers_map;
	struct lockdep_map btrfs_trans_num_extwriters_map;
	struct lockdep_map btrfs_state_change_map[4];
	struct lockdep_map btrfs_trans_pending_ordered_map;
	struct lockdep_map btrfs_ordered_extent_map;

#ifdef CONFIG_BTRFS_FS_REF_VERIFY
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_BTRFS_DEBUG
#error "klp-ccp: non-taken branch"
#endif
};

#define __btrfs_fs_incompat(fs_info, flags)				\
	(!!(btrfs_super_incompat_flags((fs_info)->super_copy) & (flags)))

#define btrfs_fs_incompat(fs_info, opt)					\
	__btrfs_fs_incompat((fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

/* klp-ccp: from fs/btrfs/ctree.h */
static inline u32 BTRFS_LEAF_DATA_SIZE(const struct btrfs_fs_info *info)
{
	return info->nodesize - sizeof(struct btrfs_header);
}

static inline u32 BTRFS_NODEPTRS_PER_BLOCK(const struct btrfs_fs_info *info)
{
	return BTRFS_LEAF_DATA_SIZE(info) / sizeof(struct btrfs_key_ptr);
}

int btrfs_comp_cpu_keys(const struct btrfs_key *k1, const struct btrfs_key *k2);

static inline int is_fstree(u64 rootid)
{
	if (rootid == BTRFS_FS_TREE_OBJECTID ||
	    ((s64)rootid >= (s64)BTRFS_FIRST_FREE_OBJECTID &&
	      !btrfs_qgroup_level(rootid)))
		return 1;
	return 0;
}

/* klp-ccp: from fs/btrfs/volumes.h */
#include <linux/btrfs.h>

static inline unsigned long btrfs_chunk_item_size(int num_stripes)
{
	ASSERT(num_stripes);
	return sizeof(struct btrfs_chunk) +
		sizeof(struct btrfs_stripe) * (num_stripes - 1);
}

/* klp-ccp: from fs/btrfs/btrfs_inode.h */
#include <linux/hash.h>
#include <linux/refcount.h>

/* klp-ccp: from fs/btrfs/delayed-inode.h */
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <linux/atomic.h>
#include <linux/refcount.h>

/* klp-ccp: from fs/btrfs/btrfs_inode.h */
static inline void btrfs_inode_split_flags(u64 inode_item_flags,
					   u32 *flags, u32 *ro_flags)
{
	*flags = (u32)inode_item_flags;
	*ro_flags = (u32)(inode_item_flags >> 32);
}

/* klp-ccp: from fs/btrfs/accessors.h */
static inline u8 get_unaligned_le8(const void *p)
{
       return *(u8 *)p;
}

#define read_eb_member(eb, ptr, type, member, result) (\
	read_extent_buffer(eb, (char *)(result),			\
			   ((unsigned long)(ptr)) +			\
			    offsetof(type, member),			\
			   sizeof(((type *)0)->member)))

u8 btrfs_get_8(const struct extent_buffer *eb, const void *ptr, unsigned long off);

u16 btrfs_get_16(const struct extent_buffer *eb, const void *ptr, unsigned long off);

u32 btrfs_get_32(const struct extent_buffer *eb, const void *ptr, unsigned long off);

u64 btrfs_get_64(const struct extent_buffer *eb, const void *ptr, unsigned long off);

static inline u64 btrfs_device_total_bytes(const struct extent_buffer *eb,
					   struct btrfs_dev_item *s)
{
	static_assert(sizeof(u64) ==
		      sizeof(((struct btrfs_dev_item *)0))->total_bytes);
	return btrfs_get_64(eb, s, offsetof(struct btrfs_dev_item,
					    total_bytes));
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/accessors.h */
static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_device_bytes_used(const struct extent_buffer *eb, const struct btrfs_dev_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_dev_item *)0))->bytes_used, "sizeof(u64) == sizeof(((struct btrfs_dev_item *)0))->bytes_used"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_dev_item, bytes_used)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_device_id(const struct extent_buffer *eb, const struct btrfs_dev_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_dev_item *)0))->devid, "sizeof(u64) == sizeof(((struct btrfs_dev_item *)0))->devid"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_dev_item, devid)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u16 btrfs_chunk_num_stripes(const struct extent_buffer *eb, const struct btrfs_chunk *s) { _Static_assert(sizeof(u16) == sizeof(((struct btrfs_chunk *)0))->num_stripes, "sizeof(u16) == sizeof(((struct btrfs_chunk *)0))->num_stripes"); return btrfs_get_16(eb, s, __builtin_offsetof(struct btrfs_chunk, num_stripes)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_stack_block_group_used(const struct btrfs_block_group_item *s) { return get_unaligned_le64(&s->used); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_stack_block_group_chunk_objectid(const struct btrfs_block_group_item *s) { return get_unaligned_le64(&s->chunk_objectid); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_stack_block_group_flags(const struct btrfs_block_group_item *s) { return get_unaligned_le64(&s->flags); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u16 btrfs_inode_ref_name_len(const struct extent_buffer *eb, const struct btrfs_inode_ref *s) { _Static_assert(sizeof(u16) == sizeof(((struct btrfs_inode_ref *)0))->name_len, "sizeof(u16) == sizeof(((struct btrfs_inode_ref *)0))->name_len"); return btrfs_get_16(eb, s, __builtin_offsetof(struct btrfs_inode_ref, name_len)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_inode_generation(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_inode_item *)0))->generation, "sizeof(u64) == sizeof(((struct btrfs_inode_item *)0))->generation"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_inode_item, generation)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_inode_transid(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_inode_item *)0))->transid, "sizeof(u64) == sizeof(((struct btrfs_inode_item *)0))->transid"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_inode_item, transid)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_inode_nlink(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { _Static_assert(sizeof(u32) == sizeof(((struct btrfs_inode_item *)0))->nlink, "sizeof(u32) == sizeof(((struct btrfs_inode_item *)0))->nlink"); return btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_inode_item, nlink)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_inode_mode(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { _Static_assert(sizeof(u32) == sizeof(((struct btrfs_inode_item *)0))->mode, "sizeof(u32) == sizeof(((struct btrfs_inode_item *)0))->mode"); return btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_inode_item, mode)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_inode_flags(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_inode_item *)0))->flags, "sizeof(u64) == sizeof(((struct btrfs_inode_item *)0))->flags"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_inode_item, flags)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_extent_refs(const struct extent_buffer *eb, const struct btrfs_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_extent_item *)0))->refs, "sizeof(u64) == sizeof(((struct btrfs_extent_item *)0))->refs"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_item, refs)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_extent_generation(const struct extent_buffer *eb, const struct btrfs_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_extent_item *)0))->generation, "sizeof(u64) == sizeof(((struct btrfs_extent_item *)0))->generation"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_item, generation)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_extent_flags(const struct extent_buffer *eb, const struct btrfs_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_extent_item *)0))->flags, "sizeof(u64) == sizeof(((struct btrfs_extent_item *)0))->flags"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_item, flags)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u8 btrfs_tree_block_level(const struct extent_buffer *eb, const struct btrfs_tree_block_info *s) { _Static_assert(sizeof(u8) == sizeof(((struct btrfs_tree_block_info *)0))->level, "sizeof(u8) == sizeof(((struct btrfs_tree_block_info *)0))->level"); return btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_tree_block_info, level)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_extent_data_ref_offset(const struct extent_buffer *eb, const struct btrfs_extent_data_ref *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_extent_data_ref *)0))->offset, "sizeof(u64) == sizeof(((struct btrfs_extent_data_ref *)0))->offset"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_data_ref, offset)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_extent_data_ref_count(const struct extent_buffer *eb, const struct btrfs_extent_data_ref *s) { _Static_assert(sizeof(u32) == sizeof(((struct btrfs_extent_data_ref *)0))->count, "sizeof(u32) == sizeof(((struct btrfs_extent_data_ref *)0))->count"); return btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_extent_data_ref, count)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_shared_data_ref_count(const struct extent_buffer *eb, const struct btrfs_shared_data_ref *s) { _Static_assert(sizeof(u32) == sizeof(((struct btrfs_shared_data_ref *)0))->count, "sizeof(u32) == sizeof(((struct btrfs_shared_data_ref *)0))->count"); return btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_shared_data_ref, count)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u8 btrfs_extent_inline_ref_type(const struct extent_buffer *eb, const struct btrfs_extent_inline_ref *s) { _Static_assert(sizeof(u8) == sizeof(((struct btrfs_extent_inline_ref *)0))->type, "sizeof(u8) == sizeof(((struct btrfs_extent_inline_ref *)0))->type"); return btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_extent_inline_ref, type)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_extent_inline_ref_offset(const struct extent_buffer *eb, const struct btrfs_extent_inline_ref *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_extent_inline_ref *)0))->offset, "sizeof(u64) == sizeof(((struct btrfs_extent_inline_ref *)0))->offset"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_inline_ref, offset)); }

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from fs/btrfs/accessors.h */
static inline u32 btrfs_extent_inline_ref_size(int type)
{
	if (type == BTRFS_TREE_BLOCK_REF_KEY ||
	    type == BTRFS_SHARED_BLOCK_REF_KEY)
		return sizeof(struct btrfs_extent_inline_ref);
	if (type == BTRFS_SHARED_DATA_REF_KEY)
		return sizeof(struct btrfs_shared_data_ref) +
		       sizeof(struct btrfs_extent_inline_ref);
	if (type == BTRFS_EXTENT_DATA_REF_KEY)
		return sizeof(struct btrfs_extent_data_ref) +
		       offsetof(struct btrfs_extent_inline_ref, offset);
	return 0;
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/accessors.h */
static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_key_blockptr(const struct extent_buffer *eb, const struct btrfs_key_ptr *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_key_ptr *)0))->blockptr, "sizeof(u64) == sizeof(((struct btrfs_key_ptr *)0))->blockptr"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_key_ptr, blockptr)); }

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from fs/btrfs/accessors.h */
static inline u64 btrfs_node_blockptr(const struct extent_buffer *eb, int nr)
{
	unsigned long ptr;

	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	return btrfs_key_blockptr(eb, (struct btrfs_key_ptr *)ptr);
}

void btrfs_node_key(const struct extent_buffer *eb,
		    struct btrfs_disk_key *disk_key, int nr);

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/accessors.h */
static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_raw_item_offset(const struct extent_buffer *eb, const struct btrfs_item *s) { _Static_assert(sizeof(u32) == sizeof(((struct btrfs_item *)0))->offset, "sizeof(u32) == sizeof(((struct btrfs_item *)0))->offset"); return btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_item, offset)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_raw_item_size(const struct extent_buffer *eb, const struct btrfs_item *s) { _Static_assert(sizeof(u32) == sizeof(((struct btrfs_item *)0))->size, "sizeof(u32) == sizeof(((struct btrfs_item *)0))->size"); return btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_item, size)); }

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from fs/btrfs/accessors.h */
static inline unsigned long btrfs_item_nr_offset(const struct extent_buffer *eb, int nr)
{
	return offsetof(struct btrfs_leaf, items) +
		sizeof(struct btrfs_item) * nr;
}

static inline struct btrfs_item *btrfs_item_nr(const struct extent_buffer *eb, int nr)
{
	return (struct btrfs_item *)btrfs_item_nr_offset(eb, nr);
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/accessors.h */
static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_item_offset(const struct extent_buffer *eb, int slot) { return btrfs_raw_item_offset(eb, btrfs_item_nr(eb, slot)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_item_size(const struct extent_buffer *eb, int slot) { return btrfs_raw_item_size(eb, btrfs_item_nr(eb, slot)); }

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from fs/btrfs/accessors.h */
static inline void btrfs_item_key(const struct extent_buffer *eb,
			   struct btrfs_disk_key *disk_key, int nr)
{
	struct btrfs_item *item = btrfs_item_nr(eb, nr);

	read_eb_member(eb, item, struct btrfs_item, key, disk_key);
}

#ifdef __LITTLE_ENDIAN

static inline void btrfs_node_key_to_cpu(const struct extent_buffer *eb,
					 struct btrfs_key *cpu_key, int nr)
{
	struct btrfs_disk_key *disk_key = (struct btrfs_disk_key *)cpu_key;

	btrfs_node_key(eb, disk_key, nr);
}

static inline void btrfs_item_key_to_cpu(const struct extent_buffer *eb,
					 struct btrfs_key *cpu_key, int nr)
{
	struct btrfs_disk_key *disk_key = (struct btrfs_disk_key *)cpu_key;

	btrfs_item_key(eb, disk_key, nr);
}

#else

static inline void btrfs_disk_key_to_cpu(struct btrfs_key *cpu,
                                         const struct btrfs_disk_key *disk)
{
        cpu->offset = le64_to_cpu(disk->offset);
        cpu->type = disk->type;
        cpu->objectid = le64_to_cpu(disk->objectid);
}

static inline void btrfs_node_key_to_cpu(const struct extent_buffer *eb,
					 struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	btrfs_node_key(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

static inline void btrfs_item_key_to_cpu(const struct extent_buffer *eb,
                                         struct btrfs_key *key, int nr)
{
        struct btrfs_disk_key disk_key;
        btrfs_item_key(eb, &disk_key, nr);
        btrfs_disk_key_to_cpu(key, &disk_key);
}

#endif

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/accessors.h */
static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_header_owner(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]) + ((unsigned long)(eb->start) & ~(~(((1UL) << 12)-1))); return get_unaligned_le64(&p->owner); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u32 btrfs_header_nritems(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]) + ((unsigned long)(eb->start) & ~(~(((1UL) << 12)-1))); return get_unaligned_le32(&p->nritems); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_header_flags(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]) + ((unsigned long)(eb->start) & ~(~(((1UL) << 12)-1))); return get_unaligned_le64(&p->flags); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u8 btrfs_header_level(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]) + ((unsigned long)(eb->start) & ~(~(((1UL) << 12)-1))); return get_unaligned_le8(&p->level); }

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from fs/btrfs/accessors.h */
static inline int btrfs_header_flag(const struct extent_buffer *eb, u64 flag)
{
	return (btrfs_header_flags(eb) & flag) == flag;
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/accessors.h */
static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_super_generation(const struct btrfs_super_block *s) { return get_unaligned_le64(&s->generation); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_super_incompat_flags(const struct btrfs_super_block *s) { return get_unaligned_le64(&s->incompat_flags); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u8 btrfs_file_extent_type(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u8) == sizeof(((struct btrfs_file_extent_item *)0))->type, "sizeof(u8) == sizeof(((struct btrfs_file_extent_item *)0))->type"); return btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, type)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_file_extent_disk_bytenr(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->disk_bytenr, "sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->disk_bytenr"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, disk_bytenr)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_file_extent_disk_num_bytes(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->disk_num_bytes, "sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->disk_num_bytes"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, disk_num_bytes)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_file_extent_offset(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->offset, "sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->offset"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, offset)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_file_extent_num_bytes(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->num_bytes, "sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->num_bytes"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, num_bytes)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u64 btrfs_file_extent_ram_bytes(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->ram_bytes, "sizeof(u64) == sizeof(((struct btrfs_file_extent_item *)0))->ram_bytes"); return btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, ram_bytes)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u8 btrfs_file_extent_compression(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u8) == sizeof(((struct btrfs_file_extent_item *)0))->compression, "sizeof(u8) == sizeof(((struct btrfs_file_extent_item *)0))->compression"); return btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, compression)); }

static inline __attribute__((__gnu_inline__)) __attribute__((__unused__)) __attribute__((no_instrument_function)) u8 btrfs_file_extent_encryption(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { _Static_assert(sizeof(u8) == sizeof(((struct btrfs_file_extent_item *)0))->encryption, "sizeof(u8) == sizeof(((struct btrfs_file_extent_item *)0))->encryption"); return btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, encryption)); }

#define btrfs_item_ptr(leaf, slot, type)				\
	((type *)(btrfs_item_nr_offset(leaf, 0) + btrfs_item_offset(leaf, slot)))

#define btrfs_item_ptr_offset(leaf, slot)				\
	((unsigned long)(btrfs_item_nr_offset(leaf, 0) + btrfs_item_offset(leaf, slot)))

/* klp-ccp: from fs/btrfs/file-item.h */
#define BTRFS_FILE_EXTENT_INLINE_DATA_START		\
		(offsetof(struct btrfs_file_extent_item, disk_bytenr))

/* klp-ccp: from fs/btrfs/tree-checker.c */
__printf(3, 4)
extern void generic_err(const struct extent_buffer *eb, int slot,
			const char *fmt, ...);

__printf(3, 4)
extern void file_extent_err(const struct extent_buffer *eb, int slot,
			    const char *fmt, ...);

#define CHECK_FE_ALIGNED(leaf, slot, fi, name, alignment)		      \
({									      \
	if (unlikely(!IS_ALIGNED(btrfs_file_extent_##name((leaf), (fi)),      \
				 (alignment))))				      \
		file_extent_err((leaf), (slot),				      \
	"invalid %s for file extent, have %llu, should be aligned to %u",     \
			(#name), btrfs_file_extent_##name((leaf), (fi)),      \
			(alignment));					      \
	(!IS_ALIGNED(btrfs_file_extent_##name((leaf), (fi)), (alignment)));   \
})

static u64 file_extent_end(struct extent_buffer *leaf,
			   struct btrfs_key *key,
			   struct btrfs_file_extent_item *extent)
{
	u64 end;
	u64 len;

	if (btrfs_file_extent_type(leaf, extent) == BTRFS_FILE_EXTENT_INLINE) {
		len = btrfs_file_extent_ram_bytes(leaf, extent);
		end = ALIGN(key->offset + len, leaf->fs_info->sectorsize);
	} else {
		len = btrfs_file_extent_num_bytes(leaf, extent);
		end = key->offset + len;
	}
	return end;
}

__printf(3, 4)
extern void dir_item_err(const struct extent_buffer *eb, int slot,
			 const char *fmt, ...);

static bool check_prev_ino(struct extent_buffer *leaf,
			   struct btrfs_key *key, int slot,
			   struct btrfs_key *prev_key)
{
	/* No prev key, skip check */
	if (slot == 0)
		return true;

	/* Only these key->types needs to be checked */
	ASSERT(key->type == BTRFS_XATTR_ITEM_KEY ||
	       key->type == BTRFS_INODE_REF_KEY ||
	       key->type == BTRFS_DIR_INDEX_KEY ||
	       key->type == BTRFS_DIR_ITEM_KEY ||
	       key->type == BTRFS_EXTENT_DATA_KEY);

	/*
	 * Only subvolume trees along with their reloc trees need this check.
	 * Things like log tree doesn't follow this ino requirement.
	 */
	if (!is_fstree(btrfs_header_owner(leaf)))
		return true;

	if (key->objectid == prev_key->objectid)
		return true;

	/* Error found */
	dir_item_err(leaf, slot,
		"invalid previous key objectid, have %llu expect %llu",
		prev_key->objectid, key->objectid);
	return false;
}
static int check_extent_data_item(struct extent_buffer *leaf,
				  struct btrfs_key *key, int slot,
				  struct btrfs_key *prev_key)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_file_extent_item *fi;
	u32 sectorsize = fs_info->sectorsize;
	u32 item_size = btrfs_item_size(leaf, slot);
	u64 extent_end;

	if (unlikely(!IS_ALIGNED(key->offset, sectorsize))) {
		file_extent_err(leaf, slot,
"unaligned file_offset for file extent, have %llu should be aligned to %u",
			key->offset, sectorsize);
		return -EUCLEAN;
	}

	/*
	 * Previous key must have the same key->objectid (ino).
	 * It can be XATTR_ITEM, INODE_ITEM or just another EXTENT_DATA.
	 * But if objectids mismatch, it means we have a missing
	 * INODE_ITEM.
	 */
	if (unlikely(!check_prev_ino(leaf, key, slot, prev_key)))
		return -EUCLEAN;

	fi = btrfs_item_ptr(leaf, slot, struct btrfs_file_extent_item);

	/*
	 * Make sure the item contains at least inline header, so the file
	 * extent type is not some garbage.
	 */
	if (unlikely(item_size < BTRFS_FILE_EXTENT_INLINE_DATA_START)) {
		file_extent_err(leaf, slot,
				"invalid item size, have %u expect [%zu, %u)",
				item_size, BTRFS_FILE_EXTENT_INLINE_DATA_START,
				SZ_4K);
		return -EUCLEAN;
	}
	if (unlikely(btrfs_file_extent_type(leaf, fi) >=
		     BTRFS_NR_FILE_EXTENT_TYPES)) {
		file_extent_err(leaf, slot,
		"invalid type for file extent, have %u expect range [0, %u]",
			btrfs_file_extent_type(leaf, fi),
			BTRFS_NR_FILE_EXTENT_TYPES - 1);
		return -EUCLEAN;
	}

	/*
	 * Support for new compression/encryption must introduce incompat flag,
	 * and must be caught in open_ctree().
	 */
	if (unlikely(btrfs_file_extent_compression(leaf, fi) >=
		     BTRFS_NR_COMPRESS_TYPES)) {
		file_extent_err(leaf, slot,
	"invalid compression for file extent, have %u expect range [0, %u]",
			btrfs_file_extent_compression(leaf, fi),
			BTRFS_NR_COMPRESS_TYPES - 1);
		return -EUCLEAN;
	}
	if (unlikely(btrfs_file_extent_encryption(leaf, fi))) {
		file_extent_err(leaf, slot,
			"invalid encryption for file extent, have %u expect 0",
			btrfs_file_extent_encryption(leaf, fi));
		return -EUCLEAN;
	}
	if (btrfs_file_extent_type(leaf, fi) == BTRFS_FILE_EXTENT_INLINE) {
		/* Inline extent must have 0 as key offset */
		if (unlikely(key->offset)) {
			file_extent_err(leaf, slot,
		"invalid file_offset for inline file extent, have %llu expect 0",
				key->offset);
			return -EUCLEAN;
		}

		/* Compressed inline extent has no on-disk size, skip it */
		if (btrfs_file_extent_compression(leaf, fi) !=
		    BTRFS_COMPRESS_NONE)
			return 0;

		/* Uncompressed inline extent size must match item size */
		if (unlikely(item_size != BTRFS_FILE_EXTENT_INLINE_DATA_START +
					  btrfs_file_extent_ram_bytes(leaf, fi))) {
			file_extent_err(leaf, slot,
	"invalid ram_bytes for uncompressed inline extent, have %u expect %llu",
				item_size, BTRFS_FILE_EXTENT_INLINE_DATA_START +
				btrfs_file_extent_ram_bytes(leaf, fi));
			return -EUCLEAN;
		}
		return 0;
	}

	/* Regular or preallocated extent has fixed item size */
	if (unlikely(item_size != sizeof(*fi))) {
		file_extent_err(leaf, slot,
	"invalid item size for reg/prealloc file extent, have %u expect %zu",
			item_size, sizeof(*fi));
		return -EUCLEAN;
	}
	if (unlikely(CHECK_FE_ALIGNED(leaf, slot, fi, ram_bytes, sectorsize) ||
		     CHECK_FE_ALIGNED(leaf, slot, fi, disk_bytenr, sectorsize) ||
		     CHECK_FE_ALIGNED(leaf, slot, fi, disk_num_bytes, sectorsize) ||
		     CHECK_FE_ALIGNED(leaf, slot, fi, offset, sectorsize) ||
		     CHECK_FE_ALIGNED(leaf, slot, fi, num_bytes, sectorsize)))
		return -EUCLEAN;

	/* Catch extent end overflow */
	if (unlikely(check_add_overflow(btrfs_file_extent_num_bytes(leaf, fi),
					key->offset, &extent_end))) {
		file_extent_err(leaf, slot,
	"extent end overflow, have file offset %llu extent num bytes %llu",
				key->offset,
				btrfs_file_extent_num_bytes(leaf, fi));
		return -EUCLEAN;
	}

	/*
	 * Check that no two consecutive file extent items, in the same leaf,
	 * present ranges that overlap each other.
	 */
	if (slot > 0 &&
	    prev_key->objectid == key->objectid &&
	    prev_key->type == BTRFS_EXTENT_DATA_KEY) {
		struct btrfs_file_extent_item *prev_fi;
		u64 prev_end;

		prev_fi = btrfs_item_ptr(leaf, slot - 1,
					 struct btrfs_file_extent_item);
		prev_end = file_extent_end(leaf, prev_key, prev_fi);
		if (unlikely(prev_end > key->offset)) {
			file_extent_err(leaf, slot - 1,
"file extent end range (%llu) goes beyond start offset (%llu) of the next file extent",
					prev_end, key->offset);
			return -EUCLEAN;
		}
	}

	return 0;
}

static int check_csum_item(struct extent_buffer *leaf, struct btrfs_key *key,
			   int slot, struct btrfs_key *prev_key)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	u32 sectorsize = fs_info->sectorsize;
	const u32 csumsize = fs_info->csum_size;

	if (unlikely(key->objectid != BTRFS_EXTENT_CSUM_OBJECTID)) {
		generic_err(leaf, slot,
		"invalid key objectid for csum item, have %llu expect %llu",
			key->objectid, BTRFS_EXTENT_CSUM_OBJECTID);
		return -EUCLEAN;
	}
	if (unlikely(!IS_ALIGNED(key->offset, sectorsize))) {
		generic_err(leaf, slot,
	"unaligned key offset for csum item, have %llu should be aligned to %u",
			key->offset, sectorsize);
		return -EUCLEAN;
	}
	if (unlikely(!IS_ALIGNED(btrfs_item_size(leaf, slot), csumsize))) {
		generic_err(leaf, slot,
	"unaligned item size for csum item, have %u should be aligned to %u",
			btrfs_item_size(leaf, slot), csumsize);
		return -EUCLEAN;
	}
	if (slot > 0 && prev_key->type == BTRFS_EXTENT_CSUM_KEY) {
		u64 prev_csum_end;
		u32 prev_item_size;

		prev_item_size = btrfs_item_size(leaf, slot - 1);
		prev_csum_end = (prev_item_size / csumsize) * sectorsize;
		prev_csum_end += prev_key->offset;
		if (unlikely(prev_csum_end > key->offset)) {
			generic_err(leaf, slot - 1,
"csum end range (%llu) goes beyond the start range (%llu) of the next csum item",
				    prev_csum_end, key->offset);
			return -EUCLEAN;
		}
	}
	return 0;
}

#define inode_item_err(eb, slot, fmt, ...)			\
	dir_item_err(eb, slot, fmt, __VA_ARGS__)

extern int check_inode_key(struct extent_buffer *leaf, struct btrfs_key *key,
			   int slot);

extern int check_dir_item(struct extent_buffer *leaf,
			  struct btrfs_key *key, struct btrfs_key *prev_key,
			  int slot);

__printf(3, 4)
extern void block_group_err(const struct extent_buffer *eb, int slot,
			    const char *fmt, ...);

static int check_block_group_item(struct extent_buffer *leaf,
				  struct btrfs_key *key, int slot)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_block_group_item bgi;
	u32 item_size = btrfs_item_size(leaf, slot);
	u64 chunk_objectid;
	u64 flags;
	u64 type;

	/*
	 * Here we don't really care about alignment since extent allocator can
	 * handle it.  We care more about the size.
	 */
	if (unlikely(key->offset == 0)) {
		block_group_err(leaf, slot,
				"invalid block group size 0");
		return -EUCLEAN;
	}

	if (unlikely(item_size != sizeof(bgi))) {
		block_group_err(leaf, slot,
			"invalid item size, have %u expect %zu",
				item_size, sizeof(bgi));
		return -EUCLEAN;
	}

	read_extent_buffer(leaf, &bgi, btrfs_item_ptr_offset(leaf, slot),
			   sizeof(bgi));
	chunk_objectid = btrfs_stack_block_group_chunk_objectid(&bgi);
	if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2)) {
		/*
		 * We don't init the nr_global_roots until we load the global
		 * roots, so this could be 0 at mount time.  If it's 0 we'll
		 * just assume we're fine, and later we'll check against our
		 * actual value.
		 */
		if (unlikely(fs_info->nr_global_roots &&
			     chunk_objectid >= fs_info->nr_global_roots)) {
			block_group_err(leaf, slot,
	"invalid block group global root id, have %llu, needs to be <= %llu",
					chunk_objectid,
					fs_info->nr_global_roots);
			return -EUCLEAN;
		}
	} else if (unlikely(chunk_objectid != BTRFS_FIRST_CHUNK_TREE_OBJECTID)) {
		block_group_err(leaf, slot,
		"invalid block group chunk objectid, have %llu expect %llu",
				btrfs_stack_block_group_chunk_objectid(&bgi),
				BTRFS_FIRST_CHUNK_TREE_OBJECTID);
		return -EUCLEAN;
	}

	if (unlikely(btrfs_stack_block_group_used(&bgi) > key->offset)) {
		block_group_err(leaf, slot,
			"invalid block group used, have %llu expect [0, %llu)",
				btrfs_stack_block_group_used(&bgi), key->offset);
		return -EUCLEAN;
	}

	flags = btrfs_stack_block_group_flags(&bgi);
	if (unlikely(hweight64(flags & BTRFS_BLOCK_GROUP_PROFILE_MASK) > 1)) {
		block_group_err(leaf, slot,
"invalid profile flags, have 0x%llx (%lu bits set) expect no more than 1 bit set",
			flags & BTRFS_BLOCK_GROUP_PROFILE_MASK,
			hweight64(flags & BTRFS_BLOCK_GROUP_PROFILE_MASK));
		return -EUCLEAN;
	}

	type = flags & BTRFS_BLOCK_GROUP_TYPE_MASK;
	if (unlikely(type != BTRFS_BLOCK_GROUP_DATA &&
		     type != BTRFS_BLOCK_GROUP_METADATA &&
		     type != BTRFS_BLOCK_GROUP_SYSTEM &&
		     type != (BTRFS_BLOCK_GROUP_METADATA |
			      BTRFS_BLOCK_GROUP_DATA))) {
		block_group_err(leaf, slot,
"invalid type, have 0x%llx (%lu bits set) expect either 0x%llx, 0x%llx, 0x%llx or 0x%llx",
			type, hweight64(type),
			BTRFS_BLOCK_GROUP_DATA, BTRFS_BLOCK_GROUP_METADATA,
			BTRFS_BLOCK_GROUP_SYSTEM,
			BTRFS_BLOCK_GROUP_METADATA | BTRFS_BLOCK_GROUP_DATA);
		return -EUCLEAN;
	}
	return 0;
}

__printf(4, 5)
extern void chunk_err(const struct extent_buffer *leaf,
		      const struct btrfs_chunk *chunk, u64 logical,
		      const char *fmt, ...);

int btrfs_check_chunk_valid(struct extent_buffer *leaf,
			    struct btrfs_chunk *chunk, u64 logical);

static int check_leaf_chunk_item(struct extent_buffer *leaf,
				 struct btrfs_chunk *chunk,
				 struct btrfs_key *key, int slot)
{
	int num_stripes;

	if (unlikely(btrfs_item_size(leaf, slot) < sizeof(struct btrfs_chunk))) {
		chunk_err(leaf, chunk, key->offset,
			"invalid chunk item size: have %u expect [%zu, %u)",
			btrfs_item_size(leaf, slot),
			sizeof(struct btrfs_chunk),
			BTRFS_LEAF_DATA_SIZE(leaf->fs_info));
		return -EUCLEAN;
	}

	num_stripes = btrfs_chunk_num_stripes(leaf, chunk);
	/* Let btrfs_check_chunk_valid() handle this error type */
	if (num_stripes == 0)
		goto out;

	if (unlikely(btrfs_chunk_item_size(num_stripes) !=
		     btrfs_item_size(leaf, slot))) {
		chunk_err(leaf, chunk, key->offset,
			"invalid chunk item size: have %u expect %lu",
			btrfs_item_size(leaf, slot),
			btrfs_chunk_item_size(num_stripes));
		return -EUCLEAN;
	}
out:
	return btrfs_check_chunk_valid(leaf, chunk, key->offset);
}

__printf(3, 4)
extern void dev_item_err(const struct extent_buffer *eb, int slot,
			 const char *fmt, ...);

static int check_dev_item(struct extent_buffer *leaf,
			  struct btrfs_key *key, int slot)
{
	struct btrfs_dev_item *ditem;
	const u32 item_size = btrfs_item_size(leaf, slot);

	if (unlikely(key->objectid != BTRFS_DEV_ITEMS_OBJECTID)) {
		dev_item_err(leaf, slot,
			     "invalid objectid: has=%llu expect=%llu",
			     key->objectid, BTRFS_DEV_ITEMS_OBJECTID);
		return -EUCLEAN;
	}

	if (unlikely(item_size != sizeof(*ditem))) {
		dev_item_err(leaf, slot, "invalid item size: has %u expect %zu",
			     item_size, sizeof(*ditem));
		return -EUCLEAN;
	}

	ditem = btrfs_item_ptr(leaf, slot, struct btrfs_dev_item);
	if (unlikely(btrfs_device_id(leaf, ditem) != key->offset)) {
		dev_item_err(leaf, slot,
			     "devid mismatch: key has=%llu item has=%llu",
			     key->offset, btrfs_device_id(leaf, ditem));
		return -EUCLEAN;
	}

	/*
	 * For device total_bytes, we don't have reliable way to check it, as
	 * it can be 0 for device removal. Device size check can only be done
	 * by dev extents check.
	 */
	if (unlikely(btrfs_device_bytes_used(leaf, ditem) >
		     btrfs_device_total_bytes(leaf, ditem))) {
		dev_item_err(leaf, slot,
			     "invalid bytes used: have %llu expect [0, %llu]",
			     btrfs_device_bytes_used(leaf, ditem),
			     btrfs_device_total_bytes(leaf, ditem));
		return -EUCLEAN;
	}
	/*
	 * Remaining members like io_align/type/gen/dev_group aren't really
	 * utilized.  Skip them to make later usage of them easier.
	 */
	return 0;
}

static int check_inode_item(struct extent_buffer *leaf,
			    struct btrfs_key *key, int slot)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_inode_item *iitem;
	u64 super_gen = btrfs_super_generation(fs_info->super_copy);
	u32 valid_mask = (S_IFMT | S_ISUID | S_ISGID | S_ISVTX | 0777);
	const u32 item_size = btrfs_item_size(leaf, slot);
	u32 mode;
	int ret;
	u32 flags;
	u32 ro_flags;

	ret = check_inode_key(leaf, key, slot);
	if (unlikely(ret < 0))
		return ret;

	if (unlikely(item_size != sizeof(*iitem))) {
		generic_err(leaf, slot, "invalid item size: has %u expect %zu",
			    item_size, sizeof(*iitem));
		return -EUCLEAN;
	}

	iitem = btrfs_item_ptr(leaf, slot, struct btrfs_inode_item);

	/* Here we use super block generation + 1 to handle log tree */
	if (unlikely(btrfs_inode_generation(leaf, iitem) > super_gen + 1)) {
		inode_item_err(leaf, slot,
			"invalid inode generation: has %llu expect (0, %llu]",
			       btrfs_inode_generation(leaf, iitem),
			       super_gen + 1);
		return -EUCLEAN;
	}
	/* Note for ROOT_TREE_DIR_ITEM, mkfs could set its transid 0 */
	if (unlikely(btrfs_inode_transid(leaf, iitem) > super_gen + 1)) {
		inode_item_err(leaf, slot,
			"invalid inode transid: has %llu expect [0, %llu]",
			       btrfs_inode_transid(leaf, iitem), super_gen + 1);
		return -EUCLEAN;
	}

	/*
	 * For size and nbytes it's better not to be too strict, as for dir
	 * item its size/nbytes can easily get wrong, but doesn't affect
	 * anything in the fs. So here we skip the check.
	 */
	mode = btrfs_inode_mode(leaf, iitem);
	if (unlikely(mode & ~valid_mask)) {
		inode_item_err(leaf, slot,
			       "unknown mode bit detected: 0x%x",
			       mode & ~valid_mask);
		return -EUCLEAN;
	}

	/*
	 * S_IFMT is not bit mapped so we can't completely rely on
	 * is_power_of_2/has_single_bit_set, but it can save us from checking
	 * FIFO/CHR/DIR/REG.  Only needs to check BLK, LNK and SOCKS
	 */
	if (!has_single_bit_set(mode & S_IFMT)) {
		if (unlikely(!S_ISLNK(mode) && !S_ISBLK(mode) && !S_ISSOCK(mode))) {
			inode_item_err(leaf, slot,
			"invalid mode: has 0%o expect valid S_IF* bit(s)",
				       mode & S_IFMT);
			return -EUCLEAN;
		}
	}
	if (unlikely(S_ISDIR(mode) && btrfs_inode_nlink(leaf, iitem) > 1)) {
		inode_item_err(leaf, slot,
		       "invalid nlink: has %u expect no more than 1 for dir",
			btrfs_inode_nlink(leaf, iitem));
		return -EUCLEAN;
	}
	btrfs_inode_split_flags(btrfs_inode_flags(leaf, iitem), &flags, &ro_flags);
	if (unlikely(flags & ~BTRFS_INODE_FLAG_MASK)) {
		inode_item_err(leaf, slot,
			       "unknown incompat flags detected: 0x%x", flags);
		return -EUCLEAN;
	}
	if (unlikely(!sb_rdonly(fs_info->sb) &&
		     (ro_flags & ~BTRFS_INODE_RO_FLAG_MASK))) {
		inode_item_err(leaf, slot,
			"unknown ro-compat flags detected on writeable mount: 0x%x",
			ro_flags);
		return -EUCLEAN;
	}
	return 0;
}

extern int check_root_item(struct extent_buffer *leaf, struct btrfs_key *key,
			   int slot);

__printf(3,4)
extern void extent_err(const struct extent_buffer *eb, int slot,
		       const char *fmt, ...);

static int check_extent_item(struct extent_buffer *leaf,
			     struct btrfs_key *key, int slot,
			     struct btrfs_key *prev_key)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_extent_item *ei;
	bool is_tree_block = false;
	unsigned long ptr;	/* Current pointer inside inline refs */
	unsigned long end;	/* Extent item end */
	const u32 item_size = btrfs_item_size(leaf, slot);
	u64 flags;
	u64 generation;
	u64 total_refs;		/* Total refs in btrfs_extent_item */
	u64 inline_refs = 0;	/* found total inline refs */

	if (unlikely(key->type == BTRFS_METADATA_ITEM_KEY &&
		     !btrfs_fs_incompat(fs_info, SKINNY_METADATA))) {
		generic_err(leaf, slot,
"invalid key type, METADATA_ITEM type invalid when SKINNY_METADATA feature disabled");
		return -EUCLEAN;
	}
	/* key->objectid is the bytenr for both key types */
	if (unlikely(!IS_ALIGNED(key->objectid, fs_info->sectorsize))) {
		generic_err(leaf, slot,
		"invalid key objectid, have %llu expect to be aligned to %u",
			   key->objectid, fs_info->sectorsize);
		return -EUCLEAN;
	}

	/* key->offset is tree level for METADATA_ITEM_KEY */
	if (unlikely(key->type == BTRFS_METADATA_ITEM_KEY &&
		     key->offset >= BTRFS_MAX_LEVEL)) {
		extent_err(leaf, slot,
			   "invalid tree level, have %llu expect [0, %u]",
			   key->offset, BTRFS_MAX_LEVEL - 1);
		return -EUCLEAN;
	}

	/*
	 * EXTENT/METADATA_ITEM consists of:
	 * 1) One btrfs_extent_item
	 *    Records the total refs, type and generation of the extent.
	 *
	 * 2) One btrfs_tree_block_info (for EXTENT_ITEM and tree backref only)
	 *    Records the first key and level of the tree block.
	 *
	 * 2) Zero or more btrfs_extent_inline_ref(s)
	 *    Each inline ref has one btrfs_extent_inline_ref shows:
	 *    2.1) The ref type, one of the 4
	 *         TREE_BLOCK_REF	Tree block only
	 *         SHARED_BLOCK_REF	Tree block only
	 *         EXTENT_DATA_REF	Data only
	 *         SHARED_DATA_REF	Data only
	 *    2.2) Ref type specific data
	 *         Either using btrfs_extent_inline_ref::offset, or specific
	 *         data structure.
	 */
	if (unlikely(item_size < sizeof(*ei))) {
		extent_err(leaf, slot,
			   "invalid item size, have %u expect [%zu, %u)",
			   item_size, sizeof(*ei),
			   BTRFS_LEAF_DATA_SIZE(fs_info));
		return -EUCLEAN;
	}
	end = item_size + btrfs_item_ptr_offset(leaf, slot);

	/* Checks against extent_item */
	ei = btrfs_item_ptr(leaf, slot, struct btrfs_extent_item);
	flags = btrfs_extent_flags(leaf, ei);
	total_refs = btrfs_extent_refs(leaf, ei);
	generation = btrfs_extent_generation(leaf, ei);
	if (unlikely(generation >
		     btrfs_super_generation(fs_info->super_copy) + 1)) {
		extent_err(leaf, slot,
			   "invalid generation, have %llu expect (0, %llu]",
			   generation,
			   btrfs_super_generation(fs_info->super_copy) + 1);
		return -EUCLEAN;
	}
	if (unlikely(!has_single_bit_set(flags & (BTRFS_EXTENT_FLAG_DATA |
						  BTRFS_EXTENT_FLAG_TREE_BLOCK)))) {
		extent_err(leaf, slot,
		"invalid extent flag, have 0x%llx expect 1 bit set in 0x%llx",
			flags, BTRFS_EXTENT_FLAG_DATA |
			BTRFS_EXTENT_FLAG_TREE_BLOCK);
		return -EUCLEAN;
	}
	is_tree_block = !!(flags & BTRFS_EXTENT_FLAG_TREE_BLOCK);
	if (is_tree_block) {
		if (unlikely(key->type == BTRFS_EXTENT_ITEM_KEY &&
			     key->offset != fs_info->nodesize)) {
			extent_err(leaf, slot,
				   "invalid extent length, have %llu expect %u",
				   key->offset, fs_info->nodesize);
			return -EUCLEAN;
		}
	} else {
		if (unlikely(key->type != BTRFS_EXTENT_ITEM_KEY)) {
			extent_err(leaf, slot,
			"invalid key type, have %u expect %u for data backref",
				   key->type, BTRFS_EXTENT_ITEM_KEY);
			return -EUCLEAN;
		}
		if (unlikely(!IS_ALIGNED(key->offset, fs_info->sectorsize))) {
			extent_err(leaf, slot,
			"invalid extent length, have %llu expect aligned to %u",
				   key->offset, fs_info->sectorsize);
			return -EUCLEAN;
		}
		if (unlikely(flags & BTRFS_BLOCK_FLAG_FULL_BACKREF)) {
			extent_err(leaf, slot,
			"invalid extent flag, data has full backref set");
			return -EUCLEAN;
		}
	}
	ptr = (unsigned long)(struct btrfs_extent_item *)(ei + 1);

	/* Check the special case of btrfs_tree_block_info */
	if (is_tree_block && key->type != BTRFS_METADATA_ITEM_KEY) {
		struct btrfs_tree_block_info *info;

		info = (struct btrfs_tree_block_info *)ptr;
		if (unlikely(btrfs_tree_block_level(leaf, info) >= BTRFS_MAX_LEVEL)) {
			extent_err(leaf, slot,
			"invalid tree block info level, have %u expect [0, %u]",
				   btrfs_tree_block_level(leaf, info),
				   BTRFS_MAX_LEVEL - 1);
			return -EUCLEAN;
		}
		ptr = (unsigned long)(struct btrfs_tree_block_info *)(info + 1);
	}

	/* Check inline refs */
	while (ptr < end) {
		struct btrfs_extent_inline_ref *iref;
		struct btrfs_extent_data_ref *dref;
		struct btrfs_shared_data_ref *sref;
		u64 dref_offset;
		u64 inline_offset;
		u8 inline_type;

		if (unlikely(ptr + sizeof(*iref) > end)) {
			extent_err(leaf, slot,
"inline ref item overflows extent item, ptr %lu iref size %zu end %lu",
				   ptr, sizeof(*iref), end);
			return -EUCLEAN;
		}
		iref = (struct btrfs_extent_inline_ref *)ptr;
		inline_type = btrfs_extent_inline_ref_type(leaf, iref);
		inline_offset = btrfs_extent_inline_ref_offset(leaf, iref);
		if (unlikely(ptr + btrfs_extent_inline_ref_size(inline_type) > end)) {
			extent_err(leaf, slot,
"inline ref item overflows extent item, ptr %lu iref size %u end %lu",
				   ptr, inline_type, end);
			return -EUCLEAN;
		}

		switch (inline_type) {
		/* inline_offset is subvolid of the owner, no need to check */
		case BTRFS_TREE_BLOCK_REF_KEY:
			inline_refs++;
			break;
		/* Contains parent bytenr */
		case BTRFS_SHARED_BLOCK_REF_KEY:
			if (unlikely(!IS_ALIGNED(inline_offset,
						 fs_info->sectorsize))) {
				extent_err(leaf, slot,
		"invalid tree parent bytenr, have %llu expect aligned to %u",
					   inline_offset, fs_info->sectorsize);
				return -EUCLEAN;
			}
			inline_refs++;
			break;
		/*
		 * Contains owner subvolid, owner key objectid, adjusted offset.
		 * The only obvious corruption can happen in that offset.
		 */
		case BTRFS_EXTENT_DATA_REF_KEY:
			dref = (struct btrfs_extent_data_ref *)(&iref->offset);
			dref_offset = btrfs_extent_data_ref_offset(leaf, dref);
			if (unlikely(!IS_ALIGNED(dref_offset,
						 fs_info->sectorsize))) {
				extent_err(leaf, slot,
		"invalid data ref offset, have %llu expect aligned to %u",
					   dref_offset, fs_info->sectorsize);
				return -EUCLEAN;
			}
			inline_refs += btrfs_extent_data_ref_count(leaf, dref);
			break;
		/* Contains parent bytenr and ref count */
		case BTRFS_SHARED_DATA_REF_KEY:
			sref = (struct btrfs_shared_data_ref *)(iref + 1);
			if (unlikely(!IS_ALIGNED(inline_offset,
						 fs_info->sectorsize))) {
				extent_err(leaf, slot,
		"invalid data parent bytenr, have %llu expect aligned to %u",
					   inline_offset, fs_info->sectorsize);
				return -EUCLEAN;
			}
			inline_refs += btrfs_shared_data_ref_count(leaf, sref);
			break;
		default:
			extent_err(leaf, slot, "unknown inline ref type: %u",
				   inline_type);
			return -EUCLEAN;
		}
		ptr += btrfs_extent_inline_ref_size(inline_type);
	}
	/* No padding is allowed */
	if (unlikely(ptr != end)) {
		extent_err(leaf, slot,
			   "invalid extent item size, padding bytes found");
		return -EUCLEAN;
	}

	/* Finally, check the inline refs against total refs */
	if (unlikely(inline_refs > total_refs)) {
		extent_err(leaf, slot,
			"invalid extent refs, have %llu expect >= inline %llu",
			   total_refs, inline_refs);
		return -EUCLEAN;
	}

	if ((prev_key->type == BTRFS_EXTENT_ITEM_KEY) ||
	    (prev_key->type == BTRFS_METADATA_ITEM_KEY)) {
		u64 prev_end = prev_key->objectid;

		if (prev_key->type == BTRFS_METADATA_ITEM_KEY)
			prev_end += fs_info->nodesize;
		else
			prev_end += prev_key->offset;

		if (unlikely(prev_end > key->objectid)) {
			extent_err(leaf, slot,
	"previous extent [%llu %u %llu] overlaps current extent [%llu %u %llu]",
				   prev_key->objectid, prev_key->type,
				   prev_key->offset, key->objectid, key->type,
				   key->offset);
			return -EUCLEAN;
		}
	}

	return 0;
}

static int check_simple_keyed_refs(struct extent_buffer *leaf,
				   struct btrfs_key *key, int slot)
{
	u32 expect_item_size = 0;

	if (key->type == BTRFS_SHARED_DATA_REF_KEY)
		expect_item_size = sizeof(struct btrfs_shared_data_ref);

	if (unlikely(btrfs_item_size(leaf, slot) != expect_item_size)) {
		generic_err(leaf, slot,
		"invalid item size, have %u expect %u for key type %u",
			    btrfs_item_size(leaf, slot),
			    expect_item_size, key->type);
		return -EUCLEAN;
	}
	if (unlikely(!IS_ALIGNED(key->objectid, leaf->fs_info->sectorsize))) {
		generic_err(leaf, slot,
"invalid key objectid for shared block ref, have %llu expect aligned to %u",
			    key->objectid, leaf->fs_info->sectorsize);
		return -EUCLEAN;
	}
	if (unlikely(key->type != BTRFS_TREE_BLOCK_REF_KEY &&
		     !IS_ALIGNED(key->offset, leaf->fs_info->sectorsize))) {
		extent_err(leaf, slot,
		"invalid tree parent bytenr, have %llu expect aligned to %u",
			   key->offset, leaf->fs_info->sectorsize);
		return -EUCLEAN;
	}
	return 0;
}

static int check_extent_data_ref(struct extent_buffer *leaf,
				 struct btrfs_key *key, int slot)
{
	struct btrfs_extent_data_ref *dref;
	unsigned long ptr = btrfs_item_ptr_offset(leaf, slot);
	const unsigned long end = ptr + btrfs_item_size(leaf, slot);

	if (unlikely(btrfs_item_size(leaf, slot) % sizeof(*dref) != 0)) {
		generic_err(leaf, slot,
	"invalid item size, have %u expect aligned to %zu for key type %u",
			    btrfs_item_size(leaf, slot),
			    sizeof(*dref), key->type);
		return -EUCLEAN;
	}
	if (unlikely(!IS_ALIGNED(key->objectid, leaf->fs_info->sectorsize))) {
		generic_err(leaf, slot,
"invalid key objectid for shared block ref, have %llu expect aligned to %u",
			    key->objectid, leaf->fs_info->sectorsize);
		return -EUCLEAN;
	}
	for (; ptr < end; ptr += sizeof(*dref)) {
		u64 offset;

		/*
		 * We cannot check the extent_data_ref hash due to possible
		 * overflow from the leaf due to hash collisions.
		 */
		dref = (struct btrfs_extent_data_ref *)ptr;
		offset = btrfs_extent_data_ref_offset(leaf, dref);
		if (unlikely(!IS_ALIGNED(offset, leaf->fs_info->sectorsize))) {
			extent_err(leaf, slot,
	"invalid extent data backref offset, have %llu expect aligned to %u",
				   offset, leaf->fs_info->sectorsize);
			return -EUCLEAN;
		}
	}
	return 0;
}

#define inode_ref_err(eb, slot, fmt, args...)			\
	inode_item_err(eb, slot, fmt, ##args)
static int check_inode_ref(struct extent_buffer *leaf,
			   struct btrfs_key *key, struct btrfs_key *prev_key,
			   int slot)
{
	struct btrfs_inode_ref *iref;
	unsigned long ptr;
	unsigned long end;

	if (unlikely(!check_prev_ino(leaf, key, slot, prev_key)))
		return -EUCLEAN;
	/* namelen can't be 0, so item_size == sizeof() is also invalid */
	if (unlikely(btrfs_item_size(leaf, slot) <= sizeof(*iref))) {
		inode_ref_err(leaf, slot,
			"invalid item size, have %u expect (%zu, %u)",
			btrfs_item_size(leaf, slot),
			sizeof(*iref), BTRFS_LEAF_DATA_SIZE(leaf->fs_info));
		return -EUCLEAN;
	}

	ptr = btrfs_item_ptr_offset(leaf, slot);
	end = ptr + btrfs_item_size(leaf, slot);
	while (ptr < end) {
		u16 namelen;

		if (unlikely(ptr + sizeof(iref) > end)) {
			inode_ref_err(leaf, slot,
			"inode ref overflow, ptr %lu end %lu inode_ref_size %zu",
				ptr, end, sizeof(iref));
			return -EUCLEAN;
		}

		iref = (struct btrfs_inode_ref *)ptr;
		namelen = btrfs_inode_ref_name_len(leaf, iref);
		if (unlikely(ptr + sizeof(*iref) + namelen > end)) {
			inode_ref_err(leaf, slot,
				"inode ref overflow, ptr %lu end %lu namelen %u",
				ptr, end, namelen);
			return -EUCLEAN;
		}

		/*
		 * NOTE: In theory we should record all found index numbers
		 * to find any duplicated indexes, but that will be too time
		 * consuming for inodes with too many hard links.
		 */
		ptr += sizeof(*iref) + namelen;
	}
	return 0;
}

static int check_leaf_item(struct extent_buffer *leaf,
			   struct btrfs_key *key, int slot,
			   struct btrfs_key *prev_key)
{
	int ret = 0;
	struct btrfs_chunk *chunk;

	switch (key->type) {
	case BTRFS_EXTENT_DATA_KEY:
		ret = check_extent_data_item(leaf, key, slot, prev_key);
		break;
	case BTRFS_EXTENT_CSUM_KEY:
		ret = check_csum_item(leaf, key, slot, prev_key);
		break;
	case BTRFS_DIR_ITEM_KEY:
	case BTRFS_DIR_INDEX_KEY:
	case BTRFS_XATTR_ITEM_KEY:
		ret = check_dir_item(leaf, key, prev_key, slot);
		break;
	case BTRFS_INODE_REF_KEY:
		ret = check_inode_ref(leaf, key, prev_key, slot);
		break;
	case BTRFS_BLOCK_GROUP_ITEM_KEY:
		ret = check_block_group_item(leaf, key, slot);
		break;
	case BTRFS_CHUNK_ITEM_KEY:
		chunk = btrfs_item_ptr(leaf, slot, struct btrfs_chunk);
		ret = check_leaf_chunk_item(leaf, chunk, key, slot);
		break;
	case BTRFS_DEV_ITEM_KEY:
		ret = check_dev_item(leaf, key, slot);
		break;
	case BTRFS_INODE_ITEM_KEY:
		ret = check_inode_item(leaf, key, slot);
		break;
	case BTRFS_ROOT_ITEM_KEY:
		ret = check_root_item(leaf, key, slot);
		break;
	case BTRFS_EXTENT_ITEM_KEY:
	case BTRFS_METADATA_ITEM_KEY:
		ret = check_extent_item(leaf, key, slot, prev_key);
		break;
	case BTRFS_TREE_BLOCK_REF_KEY:
	case BTRFS_SHARED_DATA_REF_KEY:
	case BTRFS_SHARED_BLOCK_REF_KEY:
		ret = check_simple_keyed_refs(leaf, key, slot);
		break;
	case BTRFS_EXTENT_DATA_REF_KEY:
		ret = check_extent_data_ref(leaf, key, slot);
		break;
	}
	return ret;
}

int klpp_check_leaf(struct extent_buffer *leaf, bool check_item_data)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	/* No valid key type is 0, so all key should be larger than this key */
	struct btrfs_key prev_key = {0, 0, 0};
	struct btrfs_key key;
	u32 nritems = btrfs_header_nritems(leaf);
	int slot;

	if (unlikely(btrfs_header_level(leaf) != 0)) {
		generic_err(leaf, 0,
			"invalid level for leaf, have %d expect 0",
			btrfs_header_level(leaf));
		return -EUCLEAN;
	}

	if (unlikely(!btrfs_header_flag(leaf, BTRFS_HEADER_FLAG_WRITTEN))) {
		generic_err(leaf, 0, "invalid flag for leaf, WRITTEN not set");
		return -EUCLEAN;
	}

	/*
	 * Extent buffers from a relocation tree have a owner field that
	 * corresponds to the subvolume tree they are based on. So just from an
	 * extent buffer alone we can not find out what is the id of the
	 * corresponding subvolume tree, so we can not figure out if the extent
	 * buffer corresponds to the root of the relocation tree or not. So
	 * skip this check for relocation trees.
	 */
	if (nritems == 0 && !btrfs_header_flag(leaf, BTRFS_HEADER_FLAG_RELOC)) {
		u64 owner = btrfs_header_owner(leaf);

		/* These trees must never be empty */
		if (unlikely(owner == BTRFS_ROOT_TREE_OBJECTID ||
			     owner == BTRFS_CHUNK_TREE_OBJECTID ||
			     owner == BTRFS_DEV_TREE_OBJECTID ||
			     owner == BTRFS_FS_TREE_OBJECTID ||
			     owner == BTRFS_DATA_RELOC_TREE_OBJECTID)) {
			generic_err(leaf, 0,
			"invalid root, root %llu must never be empty",
				    owner);
			return -EUCLEAN;
		}

		/* Unknown tree */
		if (unlikely(owner == 0)) {
			generic_err(leaf, 0,
				"invalid owner, root 0 is not defined");
			return -EUCLEAN;
		}

		/* EXTENT_TREE_V2 can have empty extent trees. */
		if (btrfs_fs_incompat(fs_info, EXTENT_TREE_V2))
			return 0;

		if (unlikely(owner == BTRFS_EXTENT_TREE_OBJECTID)) {
			generic_err(leaf, 0,
			"invalid root, root %llu must never be empty",
				    owner);
			return -EUCLEAN;
		}

		return 0;
	}

	if (unlikely(nritems == 0))
		return 0;

	/*
	 * Check the following things to make sure this is a good leaf, and
	 * leaf users won't need to bother with similar sanity checks:
	 *
	 * 1) key ordering
	 * 2) item offset and size
	 *    No overlap, no hole, all inside the leaf.
	 * 3) item content
	 *    If possible, do comprehensive sanity check.
	 *    NOTE: All checks must only rely on the item data itself.
	 */
	for (slot = 0; slot < nritems; slot++) {
		u32 item_end_expected;
		u64 item_data_end;
		int ret;

		btrfs_item_key_to_cpu(leaf, &key, slot);

		/* Make sure the keys are in the right order */
		if (unlikely(btrfs_comp_cpu_keys(&prev_key, &key) >= 0)) {
			generic_err(leaf, slot,
	"bad key order, prev (%llu %u %llu) current (%llu %u %llu)",
				prev_key.objectid, prev_key.type,
				prev_key.offset, key.objectid, key.type,
				key.offset);
			return -EUCLEAN;
		}

		item_data_end = (u64)btrfs_item_offset(leaf, slot) +
				btrfs_item_size(leaf, slot);
		/*
		 * Make sure the offset and ends are right, remember that the
		 * item data starts at the end of the leaf and grows towards the
		 * front.
		 */
		if (slot == 0)
			item_end_expected = BTRFS_LEAF_DATA_SIZE(fs_info);
		else
			item_end_expected = btrfs_item_offset(leaf,
								 slot - 1);
		if (unlikely(item_data_end != item_end_expected)) {
			generic_err(leaf, slot,
				"unexpected item end, have %llu expect %u",
				item_data_end, item_end_expected);
			return -EUCLEAN;
		}

		/*
		 * Check to make sure that we don't point outside of the leaf,
		 * just in case all the items are consistent to each other, but
		 * all point outside of the leaf.
		 */
		if (unlikely(item_data_end > BTRFS_LEAF_DATA_SIZE(fs_info))) {
			generic_err(leaf, slot,
			"slot end outside of leaf, have %llu expect range [0, %u]",
				item_data_end, BTRFS_LEAF_DATA_SIZE(fs_info));
			return -EUCLEAN;
		}

		/* Also check if the item pointer overlaps with btrfs item. */
		if (unlikely(btrfs_item_ptr_offset(leaf, slot) <
			     btrfs_item_nr_offset(leaf, slot) + sizeof(struct btrfs_item))) {
			generic_err(leaf, slot,
		"slot overlaps with its data, item end %lu data start %lu",
				btrfs_item_nr_offset(leaf, slot) +
				sizeof(struct btrfs_item),
				btrfs_item_ptr_offset(leaf, slot));
			return -EUCLEAN;
		}

		/* Check if the item size and content meet other criteria */
		ret = check_leaf_item(leaf, &key, slot, &prev_key);
		if (unlikely(ret < 0))
			return ret;

		prev_key.objectid = key.objectid;
		prev_key.type = key.type;
		prev_key.offset = key.offset;
	}

	return 0;
}

int klpp_btrfs_check_node(struct extent_buffer *node)
{
	struct btrfs_fs_info *fs_info = node->fs_info;
	unsigned long nr = btrfs_header_nritems(node);
	struct btrfs_key key, next_key;
	int slot;
	int level = btrfs_header_level(node);
	u64 bytenr;
	int ret = 0;

	if (unlikely(!btrfs_header_flag(node, BTRFS_HEADER_FLAG_WRITTEN))) {
		generic_err(node, 0, "invalid flag for node, WRITTEN not set");
		return -EUCLEAN;
	}

	if (unlikely(level <= 0 || level >= BTRFS_MAX_LEVEL)) {
		generic_err(node, 0,
			"invalid level for node, have %d expect [1, %d]",
			level, BTRFS_MAX_LEVEL - 1);
		return -EUCLEAN;
	}
	if (unlikely(nr == 0 || nr > BTRFS_NODEPTRS_PER_BLOCK(fs_info))) {
		btrfs_crit(fs_info,
"corrupt node: root=%llu block=%llu, nritems too %s, have %lu expect range [1,%u]",
			   btrfs_header_owner(node), node->start,
			   nr == 0 ? "small" : "large", nr,
			   BTRFS_NODEPTRS_PER_BLOCK(fs_info));
		return -EUCLEAN;
	}

	for (slot = 0; slot < nr - 1; slot++) {
		bytenr = btrfs_node_blockptr(node, slot);
		btrfs_node_key_to_cpu(node, &key, slot);
		btrfs_node_key_to_cpu(node, &next_key, slot + 1);

		if (unlikely(!bytenr)) {
			generic_err(node, slot,
				"invalid NULL node pointer");
			ret = -EUCLEAN;
			goto out;
		}
		if (unlikely(!IS_ALIGNED(bytenr, fs_info->sectorsize))) {
			generic_err(node, slot,
			"unaligned pointer, have %llu should be aligned to %u",
				bytenr, fs_info->sectorsize);
			ret = -EUCLEAN;
			goto out;
		}

		if (unlikely(btrfs_comp_cpu_keys(&key, &next_key) >= 0)) {
			generic_err(node, slot,
	"bad key order, current (%llu %u %llu) next (%llu %u %llu)",
				key.objectid, key.type, key.offset,
				next_key.objectid, next_key.type,
				next_key.offset);
			ret = -EUCLEAN;
			goto out;
		}
	}
out:
	return ret;
}


#include "livepatch_bsc1229273.h"

#include <linux/livepatch.h>

extern typeof(_btrfs_printk) _btrfs_printk
	 KLP_RELOC_SYMBOL(btrfs, btrfs, _btrfs_printk);
extern typeof(block_group_err) block_group_err
	 KLP_RELOC_SYMBOL(btrfs, btrfs, block_group_err);
extern typeof(btrfs_assertfail) btrfs_assertfail
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_assertfail);
extern typeof(btrfs_check_chunk_valid) btrfs_check_chunk_valid
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_check_chunk_valid);
extern typeof(btrfs_comp_cpu_keys) btrfs_comp_cpu_keys
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_comp_cpu_keys);
extern typeof(btrfs_get_16) btrfs_get_16
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_get_16);
extern typeof(btrfs_get_32) btrfs_get_32
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_get_32);
extern typeof(btrfs_get_64) btrfs_get_64
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_get_64);
extern typeof(btrfs_get_8) btrfs_get_8
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_get_8);
extern typeof(btrfs_node_key) btrfs_node_key
	 KLP_RELOC_SYMBOL(btrfs, btrfs, btrfs_node_key);
extern typeof(check_dir_item) check_dir_item
	 KLP_RELOC_SYMBOL(btrfs, btrfs, check_dir_item);
extern typeof(check_inode_key) check_inode_key
	 KLP_RELOC_SYMBOL(btrfs, btrfs, check_inode_key);
extern typeof(check_root_item) check_root_item
	 KLP_RELOC_SYMBOL(btrfs, btrfs, check_root_item);
extern typeof(chunk_err) chunk_err KLP_RELOC_SYMBOL(btrfs, btrfs, chunk_err);
extern typeof(dev_item_err) dev_item_err
	 KLP_RELOC_SYMBOL(btrfs, btrfs, dev_item_err);
extern typeof(dir_item_err) dir_item_err
	 KLP_RELOC_SYMBOL(btrfs, btrfs, dir_item_err);
extern typeof(extent_err) extent_err KLP_RELOC_SYMBOL(btrfs, btrfs, extent_err);
extern typeof(file_extent_err) file_extent_err
	 KLP_RELOC_SYMBOL(btrfs, btrfs, file_extent_err);
extern typeof(generic_err) generic_err
	 KLP_RELOC_SYMBOL(btrfs, btrfs, generic_err);
extern typeof(read_extent_buffer) read_extent_buffer
	 KLP_RELOC_SYMBOL(btrfs, btrfs, read_extent_buffer);
