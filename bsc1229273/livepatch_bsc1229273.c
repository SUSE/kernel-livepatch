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
#include <linux/kobject.h>

/* klp-ccp: from include/trace/events/btrfs.h */
#if !defined(_TRACE_BTRFS_H) || defined(TRACE_HEADER_MULTI_READ)

struct btrfs_work;

#define BTRFS_UUID_SIZE 16

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_BTRFS_H */

/* klp-ccp: from fs/btrfs/ctree.h */
#include <asm/kmap_types.h>
#include <linux/pagemap.h>
#include <linux/btrfs.h>
#include <linux/btrfs_tree.h>
#include <linux/workqueue.h>
#include <linux/security.h>
#include <linux/sizes.h>
#include <linux/dynamic_debug.h>
#include <linux/refcount.h>

/* klp-ccp: from fs/btrfs/extent_io.h */
#include <linux/rbtree.h>
#include <linux/refcount.h>

/* klp-ccp: from fs/btrfs/ulist.h */
#include <linux/list.h>
#include <linux/rbtree.h>

/* klp-ccp: from fs/btrfs/extent_io.h */
struct extent_io_tree {
	struct rb_root state;
	struct address_space *mapping;
	u64 dirty_bytes;
	int track_uptodate;
	/* Who owns this io tree, should be one of IO_TREE_* */
	u8 owner;
	spinlock_t lock;
	const struct extent_io_ops *ops;
};

#define INLINE_EXTENT_BUFFER_PAGES 16

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

	/* count of read lock holders on the extent buffer */
	atomic_t write_locks;
	atomic_t read_locks;
	atomic_t blocking_writers;
	atomic_t blocking_readers;
	atomic_t spinning_readers;
	atomic_t spinning_writers;
	short lock_nested;
	/* >= 0 if eb belongs to a log tree, -1 otherwise */
	short log_index;

	/* protects write locks */
	rwlock_t lock;

	/* readers use lock_wq while they wait for the write
	 * lock holders to unlock
	 */
	wait_queue_head_t write_lock_wq;

	/* writers use read_lock_wq while they wait for readers
	 * to unlock
	 */
	wait_queue_head_t read_lock_wq;
	struct page *pages[INLINE_EXTENT_BUFFER_PAGES];
#ifdef CONFIG_BTRFS_DEBUG
#error "klp-ccp: non-taken branch"
#endif
};

static void (*klpe_read_extent_buffer)(const struct extent_buffer *eb, void *dst,
			unsigned long start,
			unsigned long len);

/* klp-ccp: from fs/btrfs/extent_map.h */
#include <linux/rbtree.h>
#include <linux/refcount.h>

struct extent_map_tree {
	struct rb_root map;
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
	struct __btrfs_workqueue *wq;
	unsigned long flags;
};

/* klp-ccp: from fs/btrfs/block-rsv.h */
struct btrfs_block_rsv {
	u64 size;
	u64 reserved;
	struct btrfs_space_info *space_info;
	spinlock_t lock;
	unsigned short full;
	unsigned short type;
	unsigned short failfast;

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

/* klp-ccp: from fs/btrfs/ctree.h */
#define BTRFS_MAX_LEVEL 8

#define BTRFS_NAME_LEN 255

static const int btrfs_csum_sizes[] = { 4 };

struct btrfs_mapping_tree {
	struct extent_map_tree map_tree;
};

struct btrfs_header {
	/* these first four must match the super block */
	u8 csum[BTRFS_CSUM_SIZE];
	u8 fsid[BTRFS_FSID_SIZE]; /* FS specific uuid */
	__le64 bytenr; /* which block this node is supposed to live in */
	__le64 flags;

	/* allowed to be different from the super from here on down */
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	__le64 generation;
	__le64 owner;
	__le32 nritems;
	u8 level;
} __attribute__ ((__packed__));

#define BTRFS_SYSTEM_CHUNK_ARRAY_SIZE 2048

#define BTRFS_NUM_BACKUP_ROOTS 4
struct btrfs_root_backup {
	__le64 tree_root;
	__le64 tree_root_gen;

	__le64 chunk_root;
	__le64 chunk_root_gen;

	__le64 extent_root;
	__le64 extent_root_gen;

	__le64 fs_root;
	__le64 fs_root_gen;

	__le64 dev_root;
	__le64 dev_root_gen;

	__le64 csum_root;
	__le64 csum_root_gen;

	__le64 total_bytes;
	__le64 bytes_used;
	__le64 num_devices;
	/* future */
	__le64 unused_64[4];

	u8 tree_root_level;
	u8 chunk_root_level;
	u8 extent_root_level;
	u8 fs_root_level;
	u8 dev_root_level;
	u8 csum_root_level;
	/* future and to align */
	u8 unused_8[10];
} __attribute__ ((__packed__));

struct btrfs_super_block {
	u8 csum[BTRFS_CSUM_SIZE];
	/* the first 4 fields must match struct btrfs_header */
	u8 fsid[BTRFS_FSID_SIZE];    /* userfacing FS specific uuid */
	__le64 bytenr; /* this block number */
	__le64 flags;

	/* allowed to be different from the btrfs_header from here own down */
	__le64 magic;
	__le64 generation;
	__le64 root;
	__le64 chunk_root;
	__le64 log_root;

	/* this will help find the new super based on the log root */
	__le64 log_root_transid;
	__le64 total_bytes;
	__le64 bytes_used;
	__le64 root_dir_objectid;
	__le64 num_devices;
	__le32 sectorsize;
	__le32 nodesize;
	__le32 __unused_leafsize;
	__le32 stripesize;
	__le32 sys_chunk_array_size;
	__le64 chunk_root_generation;
	__le64 compat_flags;
	__le64 compat_ro_flags;
	__le64 incompat_flags;
	__le16 csum_type;
	u8 root_level;
	u8 chunk_root_level;
	u8 log_root_level;
	struct btrfs_dev_item dev_item;

	char label[BTRFS_LABEL_SIZE];

	__le64 cache_generation;
	__le64 uuid_tree_generation;

	/* The uuid written into btree blocks */
	u8 metadata_uuid[BTRFS_FSID_SIZE];

	/* future expansion */
	__le64 reserved[28];
	u8 sys_chunk_array[BTRFS_SYSTEM_CHUNK_ARRAY_SIZE];
	struct btrfs_root_backup super_roots[BTRFS_NUM_BACKUP_ROOTS];
} __attribute__ ((__packed__));

struct btrfs_item {
	struct btrfs_disk_key key;
	__le32 offset;
	__le32 size;
} __attribute__ ((__packed__));

struct btrfs_leaf {
	struct btrfs_header header;
	struct btrfs_item items[];
} __attribute__ ((__packed__));

struct btrfs_key_ptr {
	struct btrfs_disk_key key;
	__le64 blockptr;
	__le64 generation;
} __attribute__ ((__packed__));

struct btrfs_node {
	struct btrfs_header header;
	struct btrfs_key_ptr ptrs[];
} __attribute__ ((__packed__));

struct btrfs_dev_replace {
	u64 replace_state;	/* see #define above */
	u64 time_started;	/* seconds since 1-Jan-1970 */
	u64 time_stopped;	/* seconds since 1-Jan-1970 */
	atomic64_t num_write_errors;
	atomic64_t num_uncorrectable_read_errors;

	u64 cursor_left;
	u64 committed_cursor_left;
	u64 cursor_left_last_write_of_item;
	u64 cursor_right;

	u64 cont_reading_from_srcdev_mode;	/* see #define above */

	int is_valid;
	int item_needs_writeback;
	struct btrfs_device *srcdev;
	struct btrfs_device *tgtdev;

	pid_t lock_owner;
	atomic_t nesting_level;
	struct mutex lock_finishing_cancel_unmount;
	rwlock_t lock;
	atomic_t read_locks;
	atomic_t blocking_readers;
	wait_queue_head_t read_lock_wq;

	struct btrfs_scrub_progress scrub_progress;
};

struct btrfs_free_cluster {
	spinlock_t lock;
	spinlock_t refill_lock;
	struct rb_root root;

	/* largest extent in this cluster */
	u64 max_size;

	/* first extent starting offset */
	u64 window_start;

	/* We did a full search and couldn't create a cluster */
	bool fragmented;

	struct btrfs_block_group_cache *block_group;
	/*
	 * when a cluster is allocated from a block group, we put the
	 * cluster onto a list in the block group so that it can
	 * be freed before the block group is freed.
	 */
	struct list_head block_group_list;
};

struct btrfs_fs_info {
	u8 chunk_tree_uuid[BTRFS_UUID_SIZE];
	unsigned long flags;
	struct btrfs_root *extent_root;
	struct btrfs_root *tree_root;
	struct btrfs_root *chunk_root;
	struct btrfs_root *dev_root;
	struct btrfs_root *fs_root;
	struct btrfs_root *csum_root;
	struct btrfs_root *quota_root;
	struct btrfs_root *uuid_root;
	struct btrfs_root *free_space_root;

	/* the log root tree is a directory of all the other log roots */
	struct btrfs_root *log_root_tree;

	spinlock_t fs_roots_radix_lock;
	struct radix_tree_root fs_roots_radix;

	/* block group cache stuff */
	spinlock_t block_group_cache_lock;
	u64 first_logical_byte;
	struct rb_root block_group_cache_tree;

	/* keep track of unallocated space */
	atomic64_t free_chunk_space;

	struct extent_io_tree freed_extents[2];
	struct extent_io_tree *pinned_extents;

	/* logical->physical extent mapping */
	struct btrfs_mapping_tree mapping_tree;

	/*
	 * block reservation for extent, checksum, root tree and
	 * delayed dir index item
	 */
	struct btrfs_block_rsv global_block_rsv;
	/* block reservation for metadata operations */
	struct btrfs_block_rsv trans_block_rsv;
	/* block reservation for chunk tree */
	struct btrfs_block_rsv chunk_block_rsv;
	/* block reservation for delayed operations */
	struct btrfs_block_rsv delayed_block_rsv;
	/* block reservation for delayed refs */
	struct btrfs_block_rsv delayed_refs_rsv;

	struct btrfs_block_rsv empty_block_rsv;

	u64 generation;
	u64 last_trans_committed;
	u64 avg_delayed_ref_runtime;

	/*
	 * this is updated to the current trans every time a full commit
	 * is required instead of the faster short fsync log commits
	 */
	u64 last_trans_log_full_commit;
	unsigned long mount_opt;
	/*
	 * Track requests for actions that need to be done during transaction
	 * commit (like for some mount options).
	 */
	unsigned long pending_changes;
	unsigned long compress_type:4;
	int commit_interval;
	/*
	 * It is a suggestive number, the read side is safe even it gets a
	 * wrong number because we will write out the data into a regular
	 * extent. The write side(mount/remount) is under ->s_umount lock,
	 * so it is also safe.
	 */
	u64 max_inline;
	/*
	 * Protected by ->chunk_mutex and sb->s_umount.
	 *
	 * The reason that we use two lock to protect it is because only
	 * remount and mount operations can change it and these two operations
	 * are under sb->s_umount, but the read side (chunk allocation) can not
	 * acquire sb->s_umount or the deadlock would happen. So we use two
	 * locks to protect it. On the write side, we must acquire two locks,
	 * and on the read side, we just need acquire one of them.
	 */
	u64 alloc_start;
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
	struct mutex volume_mutex;

	/*
	 * this is taken to make sure we don't set block groups ro after
	 * the free space cache has been allocated on them
	 */
	struct mutex ro_block_group_mutex;

	/* this is used during read/modify/write to make sure
	 * no two ios are trying to mod the same stripe at the same
	 * time
	 */
	struct btrfs_stripe_hash_table *stripe_hash_table;

	/*
	 * this protects the ordered operations list only while we are
	 * processing all of the entries on it.  This way we make
	 * sure the commit code doesn't find the list temporarily empty
	 * because another function happens to be doing non-waiting preflush
	 * before jumping into the main commit.
	 */
	struct mutex ordered_operations_mutex;

	struct rw_semaphore commit_root_sem;

	struct rw_semaphore cleanup_work_sem;

	struct rw_semaphore subvol_sem;
	struct srcu_struct subvol_srcu;

	spinlock_t trans_lock;
	/*
	 * the reloc mutex goes with the trans lock, it is taken
	 * during commit to protect us from the relocation code
	 */
	struct mutex reloc_mutex;

	struct list_head trans_list;
	struct list_head dead_roots;
	spinlock_t caching_block_groups_lock;
	struct list_head caching_block_groups;

	spinlock_t delayed_iput_lock;
	struct list_head delayed_iputs;
	atomic_t nr_delayed_iputs;
	wait_queue_head_t delayed_iputs_wait;

	atomic64_t tree_mod_seq;

	/* this protects tree_mod_log and tree_mod_seq_list */
	rwlock_t tree_mod_log_lock;
	struct rb_root tree_mod_log;
	struct list_head tree_mod_seq_list;

	atomic_t async_delalloc_pages;
	atomic_t open_ioctl_trans;

	/*
	 * this is used to protect the following list -- ordered_roots.
	 */
	spinlock_t ordered_root_lock;

	/*
	 * all fs/file tree roots in which there are data=ordered extents
	 * pending writeback are added into this list.
	 *
	 * these can span multiple transactions and basically include
	 * every dirty data page that isn't from nodatacow
	 */
	struct list_head ordered_roots;

	struct mutex delalloc_root_mutex;
	spinlock_t delalloc_root_lock;
	/* all fs/file tree roots that have delalloc inodes. */
	struct list_head delalloc_roots;

	/*
	 * there is a pool of worker threads for checksumming during writes
	 * and a pool for checksumming after reads.  This is because readers
	 * can run with FS locks held, and the writers may be waiting for
	 * those locks.  We don't want ordering in the pending list to cause
	 * deadlocks, and so the two are serviced separately.
	 *
	 * A third pool does submit_bio to avoid deadlocking with the other
	 * two
	 */
	struct btrfs_workqueue *workers;
	struct btrfs_workqueue *delalloc_workers;
	struct btrfs_workqueue *flush_workers;
	struct btrfs_workqueue *endio_workers;
	struct btrfs_workqueue *endio_meta_workers;
	struct btrfs_workqueue *endio_raid56_workers;
	struct btrfs_workqueue *endio_repair_workers;
	struct btrfs_workqueue *rmw_workers;
	struct btrfs_workqueue *endio_meta_write_workers;
	struct btrfs_workqueue *endio_write_workers;
	struct btrfs_workqueue *endio_freespace_worker;
	struct btrfs_workqueue *submit_workers;
	struct btrfs_workqueue *caching_workers;
	struct btrfs_workqueue *readahead_workers;

	/*
	 * fixup workers take dirty pages that didn't properly go through
	 * the cow mechanism and make them safe to write.  It happens
	 * for the sys_munmap function call path
	 */
	struct btrfs_workqueue *fixup_workers;
	struct btrfs_workqueue *delayed_workers;

	/* the extent workers do delayed refs on the extent allocation tree */
	struct btrfs_workqueue *extent_workers;
	struct task_struct *transaction_kthread;
	struct task_struct *cleaner_kthread;
	int thread_pool_size;

	struct kobject *space_info_kobj;
	struct list_head pending_raid_kobjs;
	spinlock_t pending_raid_kobjs_lock; /* uncontended */

	u64 total_pinned;

	/* used to keep from writing metadata until there is a nice batch */
	struct percpu_counter dirty_metadata_bytes;
	struct percpu_counter delalloc_bytes;
	struct percpu_counter ordered_bytes;
	s32 dirty_metadata_batch;
	s32 delalloc_batch;

	struct list_head dirty_cowonly_roots;

	struct btrfs_fs_devices *fs_devices;

	/*
	 * The space_info list is effectively read only after initial
	 * setup.  It is populated at mount time and cleaned up after
	 * all block groups are removed.  RCU is used to protect it.
	 */
	struct list_head space_info;

	struct btrfs_space_info *data_sinfo;

	struct reloc_control *reloc_ctl;

	/* data_alloc_cluster is only used in ssd mode */
	struct btrfs_free_cluster data_alloc_cluster;

	/* all metadata allocations go through this cluster */
	struct btrfs_free_cluster meta_alloc_cluster;

	/* auto defrag inodes go here */
	spinlock_t defrag_inodes_lock;
	struct rb_root defrag_inodes;
	atomic_t defrag_running;

	/* Used to protect avail_{data, metadata, system}_alloc_bits */
	seqlock_t profiles_lock;
	/*
	 * these three are in extended format (availability of single
	 * chunks is denoted by BTRFS_AVAIL_ALLOC_BIT_SINGLE bit, other
	 * types are denoted by corresponding BTRFS_BLOCK_GROUP_* bits)
	 */
	u64 avail_data_alloc_bits;
	u64 avail_metadata_alloc_bits;
	u64 avail_system_alloc_bits;

	/* restriper state */
	spinlock_t balance_lock;
	struct mutex balance_mutex;
	atomic_t balance_pause_req;
	atomic_t balance_cancel_req;
	struct btrfs_balance_control *balance_ctl;
	wait_queue_head_t balance_wait_q;

	unsigned data_chunk_allocations;
	unsigned metadata_ratio;

	void *bdev_holder;

	/* private scrub information */
	struct mutex scrub_lock;
	atomic_t scrubs_running;
	atomic_t scrub_pause_req;
	atomic_t scrubs_paused;
	atomic_t scrub_cancel_req;
	wait_queue_head_t scrub_pause_wait;
	int scrub_workers_refcnt;
	struct btrfs_workqueue *scrub_workers;
	struct btrfs_workqueue *scrub_wr_completion_workers;
	struct btrfs_workqueue *scrub_nocow_workers;
	struct btrfs_workqueue *scrub_parity_workers;

#ifdef CONFIG_BTRFS_FS_CHECK_INTEGRITY
#error "klp-ccp: non-taken branch"
#endif
	u64 qgroup_flags;

	/* holds configuration and tracking. Protected by qgroup_lock */
	struct rb_root qgroup_tree;
	struct rb_root qgroup_op_tree;
	spinlock_t qgroup_lock;
	spinlock_t qgroup_op_lock;
	atomic_t qgroup_op_seq;

	/*
	 * used to avoid frequently calling ulist_alloc()/ulist_free()
	 * when doing qgroup accounting, it must be protected by qgroup_lock.
	 */
	struct ulist *qgroup_ulist;

	/* protect user change for quota operations */
	struct mutex qgroup_ioctl_lock;

	/* list of dirty qgroups to be written at next commit */
	struct list_head dirty_qgroups;

	/* used by qgroup for an efficient tree traversal */
	u64 qgroup_seq;

	/* qgroup rescan items */
	struct mutex qgroup_rescan_lock; /* protects the progress item */
	struct btrfs_key qgroup_rescan_progress;
	struct btrfs_workqueue *qgroup_rescan_workers;
	struct completion qgroup_rescan_completion;
	struct btrfs_work qgroup_rescan_work;
	/* qgroup rescan worker is running or queued to run */
	bool qgroup_rescan_ready;
	bool qgroup_rescan_running;	/* protected by qgroup_rescan_lock */

	/* filesystem state */
	unsigned long fs_state;

	struct btrfs_delayed_root *delayed_root;

	/* readahead tree */
	spinlock_t reada_lock;
	struct radix_tree_root reada_tree;

	/* readahead works cnt */
	atomic_t reada_works_cnt;

	/* Extent buffer radix tree */
	spinlock_t buffer_lock;
	struct radix_tree_root buffer_radix;

	/* next backup root to be overwritten */
	int backup_root_index;

	int num_tolerated_disk_barrier_failures;

	/* device replace state */
	struct btrfs_dev_replace dev_replace;

	struct percpu_counter bio_counter;
	wait_queue_head_t replace_wait;

	struct semaphore uuid_tree_rescan_sem;

	/* Used to reclaim the metadata space in the background. */
	struct work_struct async_reclaim_work;
	struct work_struct async_data_reclaim_work;
	struct work_struct preempt_reclaim_work;

	spinlock_t unused_bgs_lock;
	struct list_head unused_bgs;
	struct mutex unused_bg_unpin_mutex;
	struct mutex delete_unused_bgs_mutex;

	/* For btrfs to record security options */
	struct security_mnt_opts security_opts;

	/*
	 * Chunks that can't be freed yet (under a trim/discard operation)
	 * and will be latter freed. Protected by fs_info->chunk_mutex.
	 */
	struct list_head pinned_chunks;

	/* Used to record internally whether fs has been frozen */
	int fs_frozen;

	/* Cached block sizes */
	u32 nodesize;
	u32 sectorsize;
	u32 stripesize;

	/*
	 * Number of send operations in progress.
	 * Updated while holding fs_info::balance_mutex.
	 */
	int send_in_progress;

	/* Block groups and devices containing active swapfiles. */
	spinlock_t swapfile_pins_lock;
	struct rb_root swapfile_pins;
};

static inline u32 __BTRFS_LEAF_DATA_SIZE(u32 blocksize)
{
	return blocksize - sizeof(struct btrfs_header);
}

static inline u32 BTRFS_LEAF_DATA_SIZE(const struct btrfs_fs_info *info)
{
	return __BTRFS_LEAF_DATA_SIZE(info->nodesize);
}

static inline u32 BTRFS_MAX_ITEM_SIZE(const struct btrfs_fs_info *info)
{
	return BTRFS_LEAF_DATA_SIZE(info) - sizeof(struct btrfs_item);
}

static inline u32 BTRFS_NODEPTRS_PER_BLOCK(const struct btrfs_fs_info *info)
{
	return BTRFS_LEAF_DATA_SIZE(info) / sizeof(struct btrfs_key_ptr);
}

#define BTRFS_FILE_EXTENT_INLINE_DATA_START		\
		(offsetof(struct btrfs_file_extent_item, disk_bytenr))

static inline u32 BTRFS_MAX_XATTR_SIZE(const struct btrfs_fs_info *info)
{
	return BTRFS_MAX_ITEM_SIZE(info) - sizeof(struct btrfs_dir_item);
}

#define BTRFS_INODE_NODATASUM		(1 << 0)
#define BTRFS_INODE_NODATACOW		(1 << 1)
#define BTRFS_INODE_READONLY		(1 << 2)
#define BTRFS_INODE_NOCOMPRESS		(1 << 3)
#define BTRFS_INODE_PREALLOC		(1 << 4)
#define BTRFS_INODE_SYNC		(1 << 5)
#define BTRFS_INODE_IMMUTABLE		(1 << 6)
#define BTRFS_INODE_APPEND		(1 << 7)
#define BTRFS_INODE_NODUMP		(1 << 8)
#define BTRFS_INODE_NOATIME		(1 << 9)
#define BTRFS_INODE_DIRSYNC		(1 << 10)
#define BTRFS_INODE_COMPRESS		(1 << 11)

#define BTRFS_INODE_ROOT_ITEM_INIT	(1 << 31)

#define BTRFS_INODE_FLAG_MASK						\
	(BTRFS_INODE_NODATASUM |					\
	 BTRFS_INODE_NODATACOW |					\
	 BTRFS_INODE_READONLY |						\
	 BTRFS_INODE_NOCOMPRESS |					\
	 BTRFS_INODE_PREALLOC |						\
	 BTRFS_INODE_SYNC |						\
	 BTRFS_INODE_IMMUTABLE |					\
	 BTRFS_INODE_APPEND |						\
	 BTRFS_INODE_NODUMP |						\
	 BTRFS_INODE_NOATIME |						\
	 BTRFS_INODE_DIRSYNC |						\
	 BTRFS_INODE_COMPRESS |						\
	 BTRFS_INODE_ROOT_ITEM_INIT)

struct btrfs_map_token;

static u8 (*klpe_btrfs_get_token_8)(const struct extent_buffer *eb, const void *ptr, unsigned long off, struct btrfs_map_token *token);

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_get_8(const struct extent_buffer *eb, const void *ptr, unsigned long off) { return (*klpe_btrfs_get_token_8)(eb, ptr, off, ((void *)0)); }

static u16 (*klpe_btrfs_get_token_16)(const struct extent_buffer *eb, const void *ptr, unsigned long off, struct btrfs_map_token *token);

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u16 klpr_btrfs_get_16(const struct extent_buffer *eb, const void *ptr, unsigned long off) { return (*klpe_btrfs_get_token_16)(eb, ptr, off, ((void *)0)); }

static u32 (*klpe_btrfs_get_token_32)(const struct extent_buffer *eb, const void *ptr, unsigned long off, struct btrfs_map_token *token);

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_get_32(const struct extent_buffer *eb, const void *ptr, unsigned long off) { return (*klpe_btrfs_get_token_32)(eb, ptr, off, ((void *)0)); }

static u64 (*klpe_btrfs_get_token_64)(const struct extent_buffer *eb, const void *ptr, unsigned long off, struct btrfs_map_token *token);

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_get_64(const struct extent_buffer *eb, const void *ptr, unsigned long off) { return (*klpe_btrfs_get_token_64)(eb, ptr, off, ((void *)0)); }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline u64 klpr_btrfs_device_total_bytes(struct extent_buffer *eb,
					   struct btrfs_dev_item *s)
{
	BUILD_BUG_ON(sizeof(u64) !=
		     sizeof(((struct btrfs_dev_item *)0))->total_bytes);
	return klpr_btrfs_get_64(eb, s, offsetof(struct btrfs_dev_item,
					    total_bytes));
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_device_bytes_used(const struct extent_buffer *eb, const struct btrfs_dev_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_dev_item *)0))->bytes_used)); extern void __compiletime_assert_1495(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_dev_item *)0))->bytes_used"))); if (__cond) __compiletime_assert_1495(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_dev_item, bytes_used)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_device_id(const struct extent_buffer *eb, const struct btrfs_dev_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_dev_item *)0))->devid)); extern void __compiletime_assert_1501(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_dev_item *)0))->devid"))); if (__cond) __compiletime_assert_1501(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_dev_item, devid)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_block_group_used(const struct btrfs_block_group_item *s) { return le64_to_cpu(s->used); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_block_group_chunk_objectid(const struct btrfs_block_group_item *s) { return le64_to_cpu(s->chunk_objectid); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_block_group_flags(const struct btrfs_block_group_item *s) { return le64_to_cpu(s->flags); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_inode_generation(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_inode_item *)0))->generation)); extern void __compiletime_assert_1631(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_inode_item *)0))->generation"))); if (__cond) __compiletime_assert_1631(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_inode_item, generation)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_inode_transid(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_inode_item *)0))->transid)); extern void __compiletime_assert_1633(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_inode_item *)0))->transid"))); if (__cond) __compiletime_assert_1633(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_inode_item, transid)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_inode_nlink(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { do { bool __cond = !(!(sizeof(u32) != sizeof(((struct btrfs_inode_item *)0))->nlink)); extern void __compiletime_assert_1637(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u32) != sizeof(((struct btrfs_inode_item *)0))->nlink"))); if (__cond) __compiletime_assert_1637(); do { } while (0); } while (0); return klpr_btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_inode_item, nlink)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_inode_mode(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { do { bool __cond = !(!(sizeof(u32) != sizeof(((struct btrfs_inode_item *)0))->mode)); extern void __compiletime_assert_1640(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u32) != sizeof(((struct btrfs_inode_item *)0))->mode"))); if (__cond) __compiletime_assert_1640(); do { } while (0); } while (0); return klpr_btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_inode_item, mode)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_inode_flags(const struct extent_buffer *eb, const struct btrfs_inode_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_inode_item *)0))->flags)); extern void __compiletime_assert_1642(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_inode_item *)0))->flags"))); if (__cond) __compiletime_assert_1642(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_inode_item, flags)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_extent_refs(const struct extent_buffer *eb, const struct btrfs_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_extent_item *)0))->refs)); extern void __compiletime_assert_1680(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_extent_item *)0))->refs"))); if (__cond) __compiletime_assert_1680(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_item, refs)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_extent_generation(const struct extent_buffer *eb, const struct btrfs_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_extent_item *)0))->generation)); extern void __compiletime_assert_1681(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_extent_item *)0))->generation"))); if (__cond) __compiletime_assert_1681(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_item, generation)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_extent_flags(const struct extent_buffer *eb, const struct btrfs_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_extent_item *)0))->flags)); extern void __compiletime_assert_1683(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_extent_item *)0))->flags"))); if (__cond) __compiletime_assert_1683(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_item, flags)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_tree_block_level(const struct extent_buffer *eb, const struct btrfs_tree_block_info *s) { do { bool __cond = !(!(sizeof(u8) != sizeof(((struct btrfs_tree_block_info *)0))->level)); extern void __compiletime_assert_1688(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u8) != sizeof(((struct btrfs_tree_block_info *)0))->level"))); if (__cond) __compiletime_assert_1688(); do { } while (0); } while (0); return klpr_btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_tree_block_info, level)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_extent_data_ref_offset(const struct extent_buffer *eb, const struct btrfs_extent_data_ref *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_extent_data_ref *)0))->offset)); extern void __compiletime_assert_1708(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_extent_data_ref *)0))->offset"))); if (__cond) __compiletime_assert_1708(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_data_ref, offset)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_extent_data_ref_count(const struct extent_buffer *eb, const struct btrfs_extent_data_ref *s) { do { bool __cond = !(!(sizeof(u32) != sizeof(((struct btrfs_extent_data_ref *)0))->count)); extern void __compiletime_assert_1710(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u32) != sizeof(((struct btrfs_extent_data_ref *)0))->count"))); if (__cond) __compiletime_assert_1710(); do { } while (0); } while (0); return klpr_btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_extent_data_ref, count)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_shared_data_ref_count(const struct extent_buffer *eb, const struct btrfs_shared_data_ref *s) { do { bool __cond = !(!(sizeof(u32) != sizeof(((struct btrfs_shared_data_ref *)0))->count)); extern void __compiletime_assert_1713(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u32) != sizeof(((struct btrfs_shared_data_ref *)0))->count"))); if (__cond) __compiletime_assert_1713(); do { } while (0); } while (0); return klpr_btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_shared_data_ref, count)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_extent_inline_ref_type(const struct extent_buffer *eb, const struct btrfs_extent_inline_ref *s) { do { bool __cond = !(!(sizeof(u8) != sizeof(((struct btrfs_extent_inline_ref *)0))->type)); extern void __compiletime_assert_1716(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u8) != sizeof(((struct btrfs_extent_inline_ref *)0))->type"))); if (__cond) __compiletime_assert_1716(); do { } while (0); } while (0); return klpr_btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_extent_inline_ref, type)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_extent_inline_ref_offset(const struct extent_buffer *eb, const struct btrfs_extent_inline_ref *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_extent_inline_ref *)0))->offset)); extern void __compiletime_assert_1718(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_extent_inline_ref *)0))->offset"))); if (__cond) __compiletime_assert_1718(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_extent_inline_ref, offset)); }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
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

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_key_blockptr(const struct extent_buffer *eb, const struct btrfs_key_ptr *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_key_ptr *)0))->blockptr)); extern void __compiletime_assert_1742(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_key_ptr *)0))->blockptr"))); if (__cond) __compiletime_assert_1742(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_key_ptr, blockptr)); }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline u64 klpr_btrfs_node_blockptr(struct extent_buffer *eb, int nr)
{
	unsigned long ptr;
	ptr = offsetof(struct btrfs_node, ptrs) +
		sizeof(struct btrfs_key_ptr) * nr;
	return klpr_btrfs_key_blockptr(eb, (struct btrfs_key_ptr *)ptr);
}

static void (*klpe_btrfs_node_key)(const struct extent_buffer *eb,
		    struct btrfs_disk_key *disk_key, int nr);

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_item_offset(const struct extent_buffer *eb, const struct btrfs_item *s) { do { bool __cond = !(!(sizeof(u32) != sizeof(((struct btrfs_item *)0))->offset)); extern void __compiletime_assert_1802(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u32) != sizeof(((struct btrfs_item *)0))->offset"))); if (__cond) __compiletime_assert_1802(); do { } while (0); } while (0); return klpr_btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_item, offset)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 klpr_btrfs_item_size(const struct extent_buffer *eb, const struct btrfs_item *s) { do { bool __cond = !(!(sizeof(u32) != sizeof(((struct btrfs_item *)0))->size)); extern void __compiletime_assert_1803(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u32) != sizeof(((struct btrfs_item *)0))->size"))); if (__cond) __compiletime_assert_1803(); do { } while (0); } while (0); return klpr_btrfs_get_32(eb, s, __builtin_offsetof(struct btrfs_item, size)); }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline unsigned long btrfs_item_nr_offset(int nr)
{
	return offsetof(struct btrfs_leaf, items) +
		sizeof(struct btrfs_item) * nr;
}

static inline struct btrfs_item *btrfs_item_nr(int nr)
{
	return (struct btrfs_item *)btrfs_item_nr_offset(nr);
}

static inline u32 klpr_btrfs_item_end(const struct extent_buffer *eb,
				 struct btrfs_item *item)
{
	return klpr_btrfs_item_offset(eb, item) + klpr_btrfs_item_size(eb, item);
}

static inline u32 klpr_btrfs_item_end_nr(const struct extent_buffer *eb, int nr)
{
	return klpr_btrfs_item_end(eb, btrfs_item_nr(nr));
}

static inline u32 klpr_btrfs_item_offset_nr(const struct extent_buffer *eb, int nr)
{
	return klpr_btrfs_item_offset(eb, btrfs_item_nr(nr));
}

static inline u32 klpr_btrfs_item_size_nr(const struct extent_buffer *eb, int nr)
{
	return klpr_btrfs_item_size(eb, btrfs_item_nr(nr));
}

static inline void klpr_btrfs_item_key(const struct extent_buffer *eb,
			   struct btrfs_disk_key *disk_key, int nr)
{
	struct btrfs_item *item = btrfs_item_nr(nr);
	( (*klpe_read_extent_buffer)(eb, (char *)(disk_key), ((unsigned long)(item)) + __builtin_offsetof(struct btrfs_item, key), sizeof(((struct btrfs_item *)0)->key)));
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u16 klpr_btrfs_dir_data_len(const struct extent_buffer *eb, const struct btrfs_dir_item *s) { do { bool __cond = !(!(sizeof(u16) != sizeof(((struct btrfs_dir_item *)0))->data_len)); extern void __compiletime_assert_1863(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u16) != sizeof(((struct btrfs_dir_item *)0))->data_len"))); if (__cond) __compiletime_assert_1863(); do { } while (0); } while (0); return klpr_btrfs_get_16(eb, s, __builtin_offsetof(struct btrfs_dir_item, data_len)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_dir_type(const struct extent_buffer *eb, const struct btrfs_dir_item *s) { do { bool __cond = !(!(sizeof(u8) != sizeof(((struct btrfs_dir_item *)0))->type)); extern void __compiletime_assert_1864(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u8) != sizeof(((struct btrfs_dir_item *)0))->type"))); if (__cond) __compiletime_assert_1864(); do { } while (0); } while (0); return klpr_btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_dir_item, type)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u16 klpr_btrfs_dir_name_len(const struct extent_buffer *eb, const struct btrfs_dir_item *s) { do { bool __cond = !(!(sizeof(u16) != sizeof(((struct btrfs_dir_item *)0))->name_len)); extern void __compiletime_assert_1865(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u16) != sizeof(((struct btrfs_dir_item *)0))->name_len"))); if (__cond) __compiletime_assert_1865(); do { } while (0); } while (0); return klpr_btrfs_get_16(eb, s, __builtin_offsetof(struct btrfs_dir_item, name_len)); }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline void btrfs_disk_key_to_cpu(struct btrfs_key *cpu,
					 const struct btrfs_disk_key *disk)
{
	cpu->offset = le64_to_cpu(disk->offset);
	cpu->type = disk->type;
	cpu->objectid = le64_to_cpu(disk->objectid);
}

static inline void klpr_btrfs_node_key_to_cpu(const struct extent_buffer *eb,
					 struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	(*klpe_btrfs_node_key)(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

static inline void klpr_btrfs_item_key_to_cpu(const struct extent_buffer *eb,
					 struct btrfs_key *key, int nr)
{
	struct btrfs_disk_key disk_key;
	klpr_btrfs_item_key(eb, &disk_key, nr);
	btrfs_disk_key_to_cpu(key, &disk_key);
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_header_owner(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]); u64 res = le64_to_cpu(p->owner); return res; }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u32 btrfs_header_nritems(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]); u32 res = le32_to_cpu(p->nritems); return res; }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_header_flags(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]); u64 res = le64_to_cpu(p->flags); return res; }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 btrfs_header_level(const struct extent_buffer *eb) { const struct btrfs_header *p = lowmem_page_address(eb->pages[0]); u8 res = (p->level); return res; }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline int btrfs_header_flag(const struct extent_buffer *eb, u64 flag)
{
	return (btrfs_header_flags(eb) & flag) == flag;
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_super_generation(const struct btrfs_super_block *s) { return le64_to_cpu(s->generation); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 btrfs_super_incompat_flags(const struct btrfs_super_block *s) { return le64_to_cpu(s->incompat_flags); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u16 btrfs_super_csum_type(const struct btrfs_super_block *s) { return le16_to_cpu(s->csum_type); }

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline int btrfs_super_csum_size(const struct btrfs_super_block *s)
{
	u16 t = btrfs_super_csum_type(s);
	/*
	 * csum type is validated at mount time
	 */
	return btrfs_csum_sizes[t];
}

static inline unsigned long btrfs_leaf_data(struct extent_buffer *l)
{
	return offsetof(struct btrfs_leaf, items);
}

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/btrfs/ctree.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_file_extent_type(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u8) != sizeof(((struct btrfs_file_extent_item *)0))->type)); extern void __compiletime_assert_2312(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u8) != sizeof(((struct btrfs_file_extent_item *)0))->type"))); if (__cond) __compiletime_assert_2312(); do { } while (0); } while (0); return klpr_btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, type)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_file_extent_disk_bytenr(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->disk_bytenr)); extern void __compiletime_assert_2313(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->disk_bytenr"))); if (__cond) __compiletime_assert_2313(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, disk_bytenr)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_file_extent_disk_num_bytes(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->disk_num_bytes)); extern void __compiletime_assert_2317(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->disk_num_bytes"))); if (__cond) __compiletime_assert_2317(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, disk_num_bytes)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_file_extent_offset(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->offset)); extern void __compiletime_assert_2319(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->offset"))); if (__cond) __compiletime_assert_2319(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, offset)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_file_extent_num_bytes(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->num_bytes)); extern void __compiletime_assert_2321(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->num_bytes"))); if (__cond) __compiletime_assert_2321(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, num_bytes)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u64 klpr_btrfs_file_extent_ram_bytes(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->ram_bytes)); extern void __compiletime_assert_2323(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u64) != sizeof(((struct btrfs_file_extent_item *)0))->ram_bytes"))); if (__cond) __compiletime_assert_2323(); do { } while (0); } while (0); return klpr_btrfs_get_64(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, ram_bytes)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_file_extent_compression(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u8) != sizeof(((struct btrfs_file_extent_item *)0))->compression)); extern void __compiletime_assert_2325(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u8) != sizeof(((struct btrfs_file_extent_item *)0))->compression"))); if (__cond) __compiletime_assert_2325(); do { } while (0); } while (0); return klpr_btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, compression)); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) u8 klpr_btrfs_file_extent_encryption(const struct extent_buffer *eb, const struct btrfs_file_extent_item *s) { do { bool __cond = !(!(sizeof(u8) != sizeof(((struct btrfs_file_extent_item *)0))->encryption)); extern void __compiletime_assert_2327(void) __attribute__((error("BUILD_BUG_ON failed: " "sizeof(u8) != sizeof(((struct btrfs_file_extent_item *)0))->encryption"))); if (__cond) __compiletime_assert_2327(); do { } while (0); } while (0); return klpr_btrfs_get_8(eb, s, __builtin_offsetof(struct btrfs_file_extent_item, encryption)); }

static int (*klpe_btrfs_comp_cpu_keys)(const struct btrfs_key *k1, const struct btrfs_key *k2);

#ifdef CONFIG_PRINTK
static __printf(2, 3)
void (*klpe_btrfs_printk)(const struct btrfs_fs_info *fs_info, const char *fmt, ...);
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from fs/btrfs/ctree.h */
#define btrfs_fs_incompat(fs_info, opt) \
	__btrfs_fs_incompat((fs_info), BTRFS_FEATURE_INCOMPAT_##opt)

static inline bool __btrfs_fs_incompat(struct btrfs_fs_info *fs_info, u64 flag)
{
	struct btrfs_super_block *disk_super;
	disk_super = fs_info->super_copy;
	return !!(btrfs_super_incompat_flags(disk_super) & flag);
}

static int (*klpe_btrfs_check_chunk_valid)(struct btrfs_fs_info *fs_info,
			    struct extent_buffer *leaf,
			    struct btrfs_chunk *chunk, u64 logical);

/* klp-ccp: from fs/btrfs/compression.h */
enum btrfs_compression_type {
	BTRFS_COMPRESS_NONE  = 0,
	BTRFS_COMPRESS_ZLIB  = 1,
	BTRFS_COMPRESS_LZO   = 2,
	BTRFS_COMPRESS_ZSTD  = 3,
	BTRFS_COMPRESS_TYPES = 3,
	BTRFS_COMPRESS_LAST  = 4,
};

/* klp-ccp: from fs/btrfs/hash.h */
static u32 (*klpe_btrfs_crc32c)(u32 crc, const void *address, unsigned int length);

static inline u64 klpr_btrfs_name_hash(const char *name, int len)
{
	return (*klpe_btrfs_crc32c)((u32)~1, name, len);
}

/* klp-ccp: from fs/btrfs/volumes.h */
#include <linux/bio.h>

#include <linux/btrfs.h>

/* klp-ccp: from fs/btrfs/tree-checker.c */
__printf(3, 4)
static void (*klpe_generic_err)(const struct extent_buffer *eb, int slot,
			const char *fmt, ...);

__printf(3, 4)
static void (*klpe_file_extent_err)(const struct extent_buffer *eb, int slot,
			    const char *fmt, ...);

static u64 klpr_file_extent_end(struct extent_buffer *leaf,
			   struct btrfs_key *key,
			   struct btrfs_file_extent_item *extent)
{
	u64 end;
	u64 len;

	if (klpr_btrfs_file_extent_type(leaf, extent) == BTRFS_FILE_EXTENT_INLINE) {
		len = klpr_btrfs_file_extent_ram_bytes(leaf, extent);
		end = ALIGN(key->offset + len, leaf->fs_info->sectorsize);
	} else {
		len = klpr_btrfs_file_extent_num_bytes(leaf, extent);
		end = key->offset + len;
	}
	return end;
}

#define CHECK_FE_ALIGNED(fs_info, leaf, slot, fi, name, alignment)            \
({                                                                            \
        if (!IS_ALIGNED(klpr_btrfs_file_extent_##name((leaf), (fi)), (alignment))) \
                (*klpe_file_extent_err)((leaf), (slot),                               \
        "invalid %s for file extent, have %llu, should be aligned to %u",     \
                        (#name), klpr_btrfs_file_extent_##name((leaf), (fi)),      \
                        (alignment));                                         \
        (!IS_ALIGNED(klpr_btrfs_file_extent_##name((leaf), (fi)), (alignment)));   \
})

static int klpr_check_extent_data_item(struct extent_buffer *leaf,
				  struct btrfs_key *key, int slot,
				  struct btrfs_key *prev_key)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_file_extent_item *fi;
	u32 sectorsize = fs_info->sectorsize;
	u32 item_size = klpr_btrfs_item_size_nr(leaf, slot);

	if (!IS_ALIGNED(key->offset, sectorsize)) {
		(*klpe_file_extent_err)(leaf, slot,
"unaligned file_offset for file extent, have %llu should be aligned to %u",
			key->offset, sectorsize);
		return -EUCLEAN;
	}

	fi = ((struct btrfs_file_extent_item *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));

	if (klpr_btrfs_file_extent_type(leaf, fi) > BTRFS_FILE_EXTENT_TYPES) {
		(*klpe_file_extent_err)(leaf, slot,
		"invalid type for file extent, have %u expect range [0, %u]",
			klpr_btrfs_file_extent_type(leaf, fi),
			BTRFS_FILE_EXTENT_TYPES);
		return -EUCLEAN;
	}

	/*
	 * Support for new compression/encrption must introduce incompat flag,
	 * and must be caught in open_ctree().
	 */
	if (klpr_btrfs_file_extent_compression(leaf, fi) > BTRFS_COMPRESS_TYPES) {
		(*klpe_file_extent_err)(leaf, slot,
	"invalid compression for file extent, have %u expect range [0, %u]",
			klpr_btrfs_file_extent_compression(leaf, fi),
			BTRFS_COMPRESS_TYPES);
		return -EUCLEAN;
	}
	if (klpr_btrfs_file_extent_encryption(leaf, fi)) {
		(*klpe_file_extent_err)(leaf, slot,
			"invalid encryption for file extent, have %u expect 0",
			klpr_btrfs_file_extent_encryption(leaf, fi));
		return -EUCLEAN;
	}
	if (klpr_btrfs_file_extent_type(leaf, fi) == BTRFS_FILE_EXTENT_INLINE) {
		/* Inline extent must have 0 as key offset */
		if (key->offset) {
			(*klpe_file_extent_err)(leaf, slot,
		"invalid file_offset for inline file extent, have %llu expect 0",
				key->offset);
			return -EUCLEAN;
		}

		/* Compressed inline extent has no on-disk size, skip it */
		if (klpr_btrfs_file_extent_compression(leaf, fi) !=
		    BTRFS_COMPRESS_NONE)
			return 0;

		/* Uncompressed inline extent size must match item size */
		if (item_size != BTRFS_FILE_EXTENT_INLINE_DATA_START +
		    klpr_btrfs_file_extent_ram_bytes(leaf, fi)) {
			(*klpe_file_extent_err)(leaf, slot,
	"invalid ram_bytes for uncompressed inline extent, have %u expect %llu",
				item_size, BTRFS_FILE_EXTENT_INLINE_DATA_START +
				klpr_btrfs_file_extent_ram_bytes(leaf, fi));
			return -EUCLEAN;
		}
		return 0;
	}

	/* Regular or preallocated extent has fixed item size */
	if (item_size != sizeof(*fi)) {
		(*klpe_file_extent_err)(leaf, slot,
	"invalid item size for reg/prealloc file extent, have %u expect %zu",
			item_size, sizeof(*fi));
		return -EUCLEAN;
	}

	if (CHECK_FE_ALIGNED(fs_info, leaf, slot, fi, ram_bytes, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, leaf, slot, fi, disk_bytenr, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, leaf, slot, fi, disk_num_bytes, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, leaf, slot, fi, offset, sectorsize) ||
	    CHECK_FE_ALIGNED(fs_info, leaf, slot, fi, num_bytes, sectorsize))
		return -EUCLEAN;

	/*
	 * Check that no two consecutive file extent items, in the same leaf,
	 * present ranges that overlap each other.
	 */
	if (slot > 0 &&
	    prev_key->objectid == key->objectid &&
	    prev_key->type == BTRFS_EXTENT_DATA_KEY) {
		struct btrfs_file_extent_item *prev_fi;
		u64 prev_end;

		prev_fi = ((struct btrfs_file_extent_item *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot - 1)));
		prev_end = klpr_file_extent_end(leaf, prev_key, prev_fi);
		if (prev_end > key->offset) {
			(*klpe_file_extent_err)(leaf, slot - 1,
"file extent end range (%llu) goes beyond start offset (%llu) of the next file extent",
					prev_end, key->offset);
			return -EUCLEAN;
		}
	}

	return 0;
}

static int klpr_check_csum_item(struct extent_buffer *leaf, struct btrfs_key *key,
			   int slot, struct btrfs_key *prev_key)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	u32 sectorsize = fs_info->sectorsize;
	u32 csumsize = btrfs_super_csum_size(fs_info->super_copy);

	if (key->objectid != BTRFS_EXTENT_CSUM_OBJECTID) {
		(*klpe_generic_err)(leaf, slot,
		"invalid key objectid for csum item, have %llu expect %llu",
			key->objectid, BTRFS_EXTENT_CSUM_OBJECTID);
		return -EUCLEAN;
	}
	if (!IS_ALIGNED(key->offset, sectorsize)) {
		(*klpe_generic_err)(leaf, slot,
	"unaligned key offset for csum item, have %llu should be aligned to %u",
			key->offset, sectorsize);
		return -EUCLEAN;
	}
	if (!IS_ALIGNED(klpr_btrfs_item_size_nr(leaf, slot), csumsize)) {
		(*klpe_generic_err)(leaf, slot,
	"unaligned item size for csum item, have %u should be aligned to %u",
			klpr_btrfs_item_size_nr(leaf, slot), csumsize);
		return -EUCLEAN;
	}
	if (slot > 0 && prev_key->type == BTRFS_EXTENT_CSUM_KEY) {
		u64 prev_csum_end;
		u32 prev_item_size;

		prev_item_size = klpr_btrfs_item_size_nr(leaf, slot - 1);
		prev_csum_end = (prev_item_size / csumsize) * sectorsize;
		prev_csum_end += prev_key->offset;
		if (prev_csum_end > key->offset) {
			(*klpe_generic_err)(leaf, slot - 1,
"csum end range (%llu) goes beyond the start range (%llu) of the next csum item",
				    prev_csum_end, key->offset);
			return -EUCLEAN;
		}
	}
	return 0;
}

__printf(3, 4)
static void (*klpe_dir_item_err)(const struct extent_buffer *eb, int slot,
			 const char *fmt, ...);

static int klpr_check_dir_item(struct extent_buffer *leaf,
			  struct btrfs_key *key, int slot)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_dir_item *di;
	u32 item_size = klpr_btrfs_item_size_nr(leaf, slot);
	u32 cur = 0;

	di = ((struct btrfs_dir_item *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));
	while (cur < item_size) {
		char namebuf[max(BTRFS_NAME_LEN, XATTR_NAME_MAX)];
		u32 name_len;
		u32 data_len;
		u32 max_name_len;
		u32 total_size;
		u32 name_hash;
		u8 dir_type;

		/* header itself should not cross item boundary */
		if (cur + sizeof(*di) > item_size) {
			(*klpe_dir_item_err)(leaf, slot,
		"dir item header crosses item boundary, have %zu boundary %u",
				cur + sizeof(*di), item_size);
			return -EUCLEAN;
		}

		/* dir type check */
		dir_type = klpr_btrfs_dir_type(leaf, di);
		if (dir_type >= BTRFS_FT_MAX) {
			(*klpe_dir_item_err)(leaf, slot,
			"invalid dir item type, have %u expect [0, %u)",
				dir_type, BTRFS_FT_MAX);
			return -EUCLEAN;
		}

		if (key->type == BTRFS_XATTR_ITEM_KEY &&
		    dir_type != BTRFS_FT_XATTR) {
			(*klpe_dir_item_err)(leaf, slot,
		"invalid dir item type for XATTR key, have %u expect %u",
				dir_type, BTRFS_FT_XATTR);
			return -EUCLEAN;
		}
		if (dir_type == BTRFS_FT_XATTR &&
		    key->type != BTRFS_XATTR_ITEM_KEY) {
			(*klpe_dir_item_err)(leaf, slot,
			"xattr dir type found for non-XATTR key");
			return -EUCLEAN;
		}
		if (dir_type == BTRFS_FT_XATTR)
			max_name_len = XATTR_NAME_MAX;
		else
			max_name_len = BTRFS_NAME_LEN;

		/* Name/data length check */
		name_len = klpr_btrfs_dir_name_len(leaf, di);
		data_len = klpr_btrfs_dir_data_len(leaf, di);
		if (name_len > max_name_len) {
			(*klpe_dir_item_err)(leaf, slot,
			"dir item name len too long, have %u max %u",
				name_len, max_name_len);
			return -EUCLEAN;
		}
		if (name_len + data_len > BTRFS_MAX_XATTR_SIZE(fs_info)) {
			(*klpe_dir_item_err)(leaf, slot,
			"dir item name and data len too long, have %u max %u",
				name_len + data_len,
				BTRFS_MAX_XATTR_SIZE(fs_info));
			return -EUCLEAN;
		}

		if (data_len && dir_type != BTRFS_FT_XATTR) {
			(*klpe_dir_item_err)(leaf, slot,
			"dir item with invalid data len, have %u expect 0",
				data_len);
			return -EUCLEAN;
		}

		total_size = sizeof(*di) + name_len + data_len;

		/* header and name/data should not cross item boundary */
		if (cur + total_size > item_size) {
			(*klpe_dir_item_err)(leaf, slot,
		"dir item data crosses item boundary, have %u boundary %u",
				cur + total_size, item_size);
			return -EUCLEAN;
		}

		/*
		 * Special check for XATTR/DIR_ITEM, as key->offset is name
		 * hash, should match its name
		 */
		if (key->type == BTRFS_DIR_ITEM_KEY ||
		    key->type == BTRFS_XATTR_ITEM_KEY) {
			(*klpe_read_extent_buffer)(leaf, namebuf,
					(unsigned long)(di + 1), name_len);
			name_hash = klpr_btrfs_name_hash(namebuf, name_len);
			if (key->offset != name_hash) {
				(*klpe_dir_item_err)(leaf, slot,
		"name hash mismatch with key, have 0x%016x expect 0x%016llx",
					name_hash, key->offset);
				return -EUCLEAN;
			}
		}
		cur += total_size;
		di = (struct btrfs_dir_item *)((void *)di + total_size);
	}
	return 0;
}

__printf(3, 4)
static void (*klpe_block_group_err)(const struct extent_buffer *eb, int slot,
			    const char *fmt, ...);

static int klpr_check_block_group_item(struct extent_buffer *leaf,
				  struct btrfs_key *key, int slot)
{
	struct btrfs_block_group_item bgi;
	u32 item_size = klpr_btrfs_item_size_nr(leaf, slot);
	u64 flags;
	u64 type;

	/*
	 * Here we don't really care about alignment since extent allocator can
	 * handle it.  We care more about the size.
	 */
	if (key->offset == 0) {
		(*klpe_block_group_err)(leaf, slot,
				"invalid block group size 0");
		return -EUCLEAN;
	}

	if (item_size != sizeof(bgi)) {
		(*klpe_block_group_err)(leaf, slot,
			"invalid item size, have %u expect %zu",
				item_size, sizeof(bgi));
		return -EUCLEAN;
	}

	(*klpe_read_extent_buffer)(leaf, &bgi, ((unsigned long)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot))),
			   sizeof(bgi));
	if (btrfs_block_group_chunk_objectid(&bgi) !=
	    BTRFS_FIRST_CHUNK_TREE_OBJECTID) {
		(*klpe_block_group_err)(leaf, slot,
		"invalid block group chunk objectid, have %llu expect %llu",
				btrfs_block_group_chunk_objectid(&bgi),
				BTRFS_FIRST_CHUNK_TREE_OBJECTID);
		return -EUCLEAN;
	}

	if (btrfs_block_group_used(&bgi) > key->offset) {
		(*klpe_block_group_err)(leaf, slot,
			"invalid block group used, have %llu expect [0, %llu)",
				btrfs_block_group_used(&bgi), key->offset);
		return -EUCLEAN;
	}

	flags = btrfs_block_group_flags(&bgi);
	if (hweight64(flags & BTRFS_BLOCK_GROUP_PROFILE_MASK) > 1) {
		(*klpe_block_group_err)(leaf, slot,
"invalid profile flags, have 0x%llx (%lu bits set) expect no more than 1 bit set",
			flags & BTRFS_BLOCK_GROUP_PROFILE_MASK,
			hweight64(flags & BTRFS_BLOCK_GROUP_PROFILE_MASK));
		return -EUCLEAN;
	}

	type = flags & BTRFS_BLOCK_GROUP_TYPE_MASK;
	if (type != BTRFS_BLOCK_GROUP_DATA &&
	    type != BTRFS_BLOCK_GROUP_METADATA &&
	    type != BTRFS_BLOCK_GROUP_SYSTEM &&
	    type != (BTRFS_BLOCK_GROUP_METADATA |
			   BTRFS_BLOCK_GROUP_DATA)) {
		(*klpe_block_group_err)(leaf, slot,
"invalid type, have 0x%llx (%lu bits set) expect either 0x%llx, 0x%llx, 0x%llx or 0x%llx",
			type, hweight64(type),
			BTRFS_BLOCK_GROUP_DATA, BTRFS_BLOCK_GROUP_METADATA,
			BTRFS_BLOCK_GROUP_SYSTEM,
			BTRFS_BLOCK_GROUP_METADATA | BTRFS_BLOCK_GROUP_DATA);
		return -EUCLEAN;
	}
	return 0;
}

__printf(3, 4)
static void (*klpe_dev_item_err)(const struct extent_buffer *eb, int slot,
			 const char *fmt, ...);

static int klpr_check_dev_item(struct extent_buffer *leaf,
			  struct btrfs_key *key, int slot)
{
	struct btrfs_dev_item *ditem;

	if (key->objectid != BTRFS_DEV_ITEMS_OBJECTID) {
		(*klpe_dev_item_err)(leaf, slot,
			     "invalid objectid: has=%llu expect=%llu",
			     key->objectid, BTRFS_DEV_ITEMS_OBJECTID);
		return -EUCLEAN;
	}
	ditem = ((struct btrfs_dev_item *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));
	if (klpr_btrfs_device_id(leaf, ditem) != key->offset) {
		(*klpe_dev_item_err)(leaf, slot,
			     "devid mismatch: key has=%llu item has=%llu",
			     key->offset, klpr_btrfs_device_id(leaf, ditem));
		return -EUCLEAN;
	}

	/*
	 * For device total_bytes, we don't have reliable way to check it, as
	 * it can be 0 for device removal. Device size check can only be done
	 * by dev extents check.
	 */
	if (klpr_btrfs_device_bytes_used(leaf, ditem) >
	    klpr_btrfs_device_total_bytes(leaf, ditem)) {
		(*klpe_dev_item_err)(leaf, slot,
			     "invalid bytes used: have %llu expect [0, %llu]",
			     klpr_btrfs_device_bytes_used(leaf, ditem),
			     klpr_btrfs_device_total_bytes(leaf, ditem));
		return -EUCLEAN;
	}
	/*
	 * Remaining members like io_align/type/gen/dev_group aren't really
	 * utilized.  Skip them to make later usage of them easier.
	 */
	return 0;
}

static int klpr_check_inode_item(struct extent_buffer *leaf,
			    struct btrfs_key *key, int slot)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_inode_item *iitem;
	u64 super_gen = btrfs_super_generation(fs_info->super_copy);
	u32 valid_mask = (S_IFMT | S_ISUID | S_ISGID | S_ISVTX | 0777);
	u32 mode;

	if ((key->objectid < BTRFS_FIRST_FREE_OBJECTID ||
	     key->objectid > BTRFS_LAST_FREE_OBJECTID) &&
	    key->objectid != BTRFS_ROOT_TREE_DIR_OBJECTID &&
	    key->objectid != BTRFS_FREE_INO_OBJECTID) {
		(*klpe_generic_err)(leaf, slot,
	"invalid key objectid: has %llu expect %llu or [%llu, %llu] or %llu",
			    key->objectid, BTRFS_ROOT_TREE_DIR_OBJECTID,
			    BTRFS_FIRST_FREE_OBJECTID,
			    BTRFS_LAST_FREE_OBJECTID,
			    BTRFS_FREE_INO_OBJECTID);
		return -EUCLEAN;
	}
	if (key->offset != 0) {
		(*klpe_dir_item_err)(leaf, slot, "invalid key offset: has %llu expect 0", key->offset);
		return -EUCLEAN;
	}
	iitem = ((struct btrfs_inode_item *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));

	/* Here we use super block generation + 1 to handle log tree */
	if (klpr_btrfs_inode_generation(leaf, iitem) > super_gen + 1) {
		(*klpe_dir_item_err)(leaf, slot, "invalid inode generation: has %llu expect (0, %llu]", klpr_btrfs_inode_generation(leaf, iitem), super_gen + 1);
		return -EUCLEAN;
	}
	/* Note for ROOT_TREE_DIR_ITEM, mkfs could set its transid 0 */
	if (klpr_btrfs_inode_transid(leaf, iitem) > super_gen + 1) {
		(*klpe_dir_item_err)(leaf, slot, "invalid inode transid: has %llu expect [0, %llu]", klpr_btrfs_inode_transid(leaf, iitem), super_gen + 1);
		return -EUCLEAN;
	}

	/*
	 * For size and nbytes it's better not to be too strict, as for dir
	 * item its size/nbytes can easily get wrong, but doesn't affect
	 * anything in the fs. So here we skip the check.
	 */
	mode = klpr_btrfs_inode_mode(leaf, iitem);
	if (mode & ~valid_mask) {
		(*klpe_dir_item_err)(leaf, slot, "unknown mode bit detected: 0x%x", mode & ~valid_mask);
		return -EUCLEAN;
	}

	/*
	 * S_IFMT is not bit mapped so we can't completely rely on is_power_of_2,
	 * but is_power_of_2() can save us from checking FIFO/CHR/DIR/REG.
	 * Only needs to check BLK, LNK and SOCKS
	 */
	if (!is_power_of_2(mode & S_IFMT)) {
		if (!S_ISLNK(mode) && !S_ISBLK(mode) && !S_ISSOCK(mode)) {
			(*klpe_dir_item_err)(leaf, slot, "invalid mode: has 0%o expect valid S_IF* bit(s)", mode & 00170000);
			return -EUCLEAN;
		}
	}
	if (S_ISDIR(mode) && klpr_btrfs_inode_nlink(leaf, iitem) > 1) {
		(*klpe_dir_item_err)(leaf, slot, "invalid nlink: has %u expect no more than 1 for dir", klpr_btrfs_inode_nlink(leaf, iitem));
		return -EUCLEAN;
	}
	if (klpr_btrfs_inode_flags(leaf, iitem) & ~BTRFS_INODE_FLAG_MASK) {
		(*klpe_dir_item_err)(leaf, slot, "unknown flags detected: 0x%llx", klpr_btrfs_inode_flags(leaf, iitem) & ~((1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 11) | (1 << 31)));
		return -EUCLEAN;
	}
	return 0;
}

static int (*klpe_check_root_item)(struct extent_buffer *leaf, struct btrfs_key *key,
			   int slot);

__printf(3,4)
static void (*klpe_extent_err)(const struct extent_buffer *eb, int slot,
		       const char *fmt, ...);

static int klpr_check_extent_item(struct extent_buffer *leaf,
			     struct btrfs_key *key, int slot)
{
	struct btrfs_fs_info *fs_info = leaf->fs_info;
	struct btrfs_extent_item *ei;
	bool is_tree_block = false;
	unsigned long ptr;	/* Current pointer inside inline refs */
	unsigned long end;	/* Extent item end */
	const u32 item_size = klpr_btrfs_item_size_nr(leaf, slot);
	u64 flags;
	u64 generation;
	u64 total_refs;		/* Total refs in btrfs_extent_item */
	u64 inline_refs = 0;	/* found total inline refs */

	if (key->type == BTRFS_METADATA_ITEM_KEY &&
	    !btrfs_fs_incompat(fs_info, SKINNY_METADATA)) {
		(*klpe_generic_err)(leaf, slot,
"invalid key type, METADATA_ITEM type invalid when SKINNY_METADATA feature disabled");
		return -EUCLEAN;
	}
	/* key->objectid is the bytenr for both key types */
	if (!IS_ALIGNED(key->objectid, fs_info->sectorsize)) {
		(*klpe_generic_err)(leaf, slot,
		"invalid key objectid, have %llu expect to be aligned to %u",
			   key->objectid, fs_info->sectorsize);
		return -EUCLEAN;
	}

	/* key->offset is tree level for METADATA_ITEM_KEY */
	if (key->type == BTRFS_METADATA_ITEM_KEY &&
	    key->offset >= BTRFS_MAX_LEVEL) {
		(*klpe_extent_err)(leaf, slot,
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
	if (item_size < sizeof(*ei)) {
		(*klpe_extent_err)(leaf, slot,
			   "invalid item size, have %u expect [%zu, %u)",
			   item_size, sizeof(*ei),
			   BTRFS_LEAF_DATA_SIZE(fs_info));
		return -EUCLEAN;
	}
	end = item_size + ((unsigned long)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));

	/* Checks against extent_item */
	ei = ((struct btrfs_extent_item *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));
	flags = klpr_btrfs_extent_flags(leaf, ei);
	total_refs = klpr_btrfs_extent_refs(leaf, ei);
	generation = klpr_btrfs_extent_generation(leaf, ei);
	if (generation > btrfs_super_generation(fs_info->super_copy) + 1) {
		(*klpe_extent_err)(leaf, slot,
			   "invalid generation, have %llu expect (0, %llu]",
			   generation,
			   btrfs_super_generation(fs_info->super_copy) + 1);
		return -EUCLEAN;
	}
	if (!is_power_of_2(flags & (BTRFS_EXTENT_FLAG_DATA |
				    BTRFS_EXTENT_FLAG_TREE_BLOCK))) {
		(*klpe_extent_err)(leaf, slot,
		"invalid extent flag, have 0x%llx expect 1 bit set in 0x%llx",
			flags, BTRFS_EXTENT_FLAG_DATA |
			BTRFS_EXTENT_FLAG_TREE_BLOCK);
		return -EUCLEAN;
	}
	is_tree_block = !!(flags & BTRFS_EXTENT_FLAG_TREE_BLOCK);
	if (is_tree_block) {
		if (key->type == BTRFS_EXTENT_ITEM_KEY &&
		    key->offset != fs_info->nodesize) {
			(*klpe_extent_err)(leaf, slot,
				   "invalid extent length, have %llu expect %u",
				   key->offset, fs_info->nodesize);
			return -EUCLEAN;
		}
	} else {
		if (key->type != BTRFS_EXTENT_ITEM_KEY) {
			(*klpe_extent_err)(leaf, slot,
			"invalid key type, have %u expect %u for data backref",
				   key->type, BTRFS_EXTENT_ITEM_KEY);
			return -EUCLEAN;
		}
		if (!IS_ALIGNED(key->offset, fs_info->sectorsize)) {
			(*klpe_extent_err)(leaf, slot,
			"invalid extent length, have %llu expect aligned to %u",
				   key->offset, fs_info->sectorsize);
			return -EUCLEAN;
		}
		if (unlikely(flags & BTRFS_BLOCK_FLAG_FULL_BACKREF)) {
			(*klpe_extent_err)(leaf, slot,
			"invalid extent flag, data has full backref set");
			return -EUCLEAN;
		}
	}
	ptr = (unsigned long)(struct btrfs_extent_item *)(ei + 1);

	/* Check the special case of btrfs_tree_block_info */
	if (is_tree_block && key->type != BTRFS_METADATA_ITEM_KEY) {
		struct btrfs_tree_block_info *info;

		info = (struct btrfs_tree_block_info *)ptr;
		if (klpr_btrfs_tree_block_level(leaf, info) >= BTRFS_MAX_LEVEL) {
			(*klpe_extent_err)(leaf, slot,
			"invalid tree block info level, have %u expect [0, %u]",
				   klpr_btrfs_tree_block_level(leaf, info),
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

		if (ptr + sizeof(*iref) > end) {
			(*klpe_extent_err)(leaf, slot,
"inline ref item overflows extent item, ptr %lu iref size %zu end %lu",
				   ptr, sizeof(*iref), end);
			return -EUCLEAN;
		}
		iref = (struct btrfs_extent_inline_ref *)ptr;
		inline_type = klpr_btrfs_extent_inline_ref_type(leaf, iref);
		inline_offset = klpr_btrfs_extent_inline_ref_offset(leaf, iref);
		if (ptr + btrfs_extent_inline_ref_size(inline_type) > end) {
			(*klpe_extent_err)(leaf, slot,
"inline ref item overflows extent item, ptr %lu iref size %u end %lu",
				   ptr, btrfs_extent_inline_ref_size(inline_type), end);
			return -EUCLEAN;
		}

		switch (inline_type) {
		/* inline_offset is subvolid of the owner, no need to check */
		case BTRFS_TREE_BLOCK_REF_KEY:
			inline_refs++;
			break;
		/* Contains parent bytenr */
		case BTRFS_SHARED_BLOCK_REF_KEY:
			if (!IS_ALIGNED(inline_offset, fs_info->sectorsize)) {
				(*klpe_extent_err)(leaf, slot,
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
			dref_offset = klpr_btrfs_extent_data_ref_offset(leaf, dref);
			if (!IS_ALIGNED(dref_offset, fs_info->sectorsize)) {
				(*klpe_extent_err)(leaf, slot,
		"invalid data ref offset, have %llu expect aligned to %u",
					   dref_offset, fs_info->sectorsize);
				return -EUCLEAN;
			}
			inline_refs += klpr_btrfs_extent_data_ref_count(leaf, dref);
			break;
		/* Contains parent bytenr and ref count */
		case BTRFS_SHARED_DATA_REF_KEY:
			sref = (struct btrfs_shared_data_ref *)(iref + 1);
			if (!IS_ALIGNED(inline_offset, fs_info->sectorsize)) {
				(*klpe_extent_err)(leaf, slot,
		"invalid data parent bytenr, have %llu expect aligned to %u",
					   inline_offset, fs_info->sectorsize);
				return -EUCLEAN;
			}
			inline_refs += klpr_btrfs_shared_data_ref_count(leaf, sref);
			break;
		default:
			(*klpe_extent_err)(leaf, slot, "unknown inline ref type: %u",
				   inline_type);
			return -EUCLEAN;
		}
		ptr += btrfs_extent_inline_ref_size(inline_type);
	}
	/* No padding is allowed */
	if (ptr != end) {
		(*klpe_extent_err)(leaf, slot,
			   "invalid extent item size, padding bytes found");
		return -EUCLEAN;
	}

	/* Finally, check the inline refs against total refs */
	if (inline_refs > total_refs) {
		(*klpe_extent_err)(leaf, slot,
			"invalid extent refs, have %llu expect >= inline %llu",
			   total_refs, inline_refs);
		return -EUCLEAN;
	}
	return 0;
}

static int klpr_check_simple_keyed_refs(struct extent_buffer *leaf,
				   struct btrfs_key *key, int slot)
{
	u32 expect_item_size = 0;

	if (key->type == BTRFS_SHARED_DATA_REF_KEY)
		expect_item_size = sizeof(struct btrfs_shared_data_ref);

	if (klpr_btrfs_item_size_nr(leaf, slot) != expect_item_size) {
		(*klpe_generic_err)(leaf, slot,
		"invalid item size, have %u expect %u for key type %u",
			    klpr_btrfs_item_size_nr(leaf, slot),
			    expect_item_size, key->type);
		return -EUCLEAN;
	}
	if (!IS_ALIGNED(key->objectid, leaf->fs_info->sectorsize)) {
		(*klpe_generic_err)(leaf, slot,
"invalid key objectid for shared block ref, have %llu expect aligned to %u",
			    key->objectid, leaf->fs_info->sectorsize);
		return -EUCLEAN;
	}
	if (key->type != BTRFS_TREE_BLOCK_REF_KEY &&
	    !IS_ALIGNED(key->offset, leaf->fs_info->sectorsize)) {
		(*klpe_extent_err)(leaf, slot,
		"invalid tree parent bytenr, have %llu expect aligned to %u",
			   key->offset, leaf->fs_info->sectorsize);
		return -EUCLEAN;
	}
	return 0;
}

static int klpr_check_extent_data_ref(struct extent_buffer *leaf,
				 struct btrfs_key *key, int slot)
{
	struct btrfs_extent_data_ref *dref;
	unsigned long ptr = ((unsigned long)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));
	const unsigned long end = ptr + klpr_btrfs_item_size_nr(leaf, slot);

	if (klpr_btrfs_item_size_nr(leaf, slot) % sizeof(*dref) != 0) {
		(*klpe_generic_err)(leaf, slot,
	"invalid item size, have %u expect aligned to %zu for key type %u",
			    klpr_btrfs_item_size_nr(leaf, slot),
			    sizeof(*dref), key->type);
		return -EUCLEAN;
	}
	if (!IS_ALIGNED(key->objectid, leaf->fs_info->sectorsize)) {
		(*klpe_generic_err)(leaf, slot,
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
		offset = klpr_btrfs_extent_data_ref_offset(leaf, dref);
		if (!IS_ALIGNED(offset, leaf->fs_info->sectorsize)) {
			(*klpe_extent_err)(leaf, slot,
	"invalid extent data backref offset, have %llu expect aligned to %u",
				   offset, leaf->fs_info->sectorsize);
			return -EUCLEAN;
		}
	}
	return 0;
}

static int klpr_check_leaf_item(struct extent_buffer *leaf,
			   struct btrfs_key *key, int slot,
			   struct btrfs_key *prev_key)
{
	int ret = 0;
	struct btrfs_chunk *chunk;

	switch (key->type) {
	case BTRFS_EXTENT_DATA_KEY:
		ret = klpr_check_extent_data_item(leaf, key, slot, prev_key);
		break;
	case BTRFS_EXTENT_CSUM_KEY:
		ret = klpr_check_csum_item(leaf, key, slot, prev_key);
		break;
	case BTRFS_DIR_ITEM_KEY:
	case BTRFS_DIR_INDEX_KEY:
	case BTRFS_XATTR_ITEM_KEY:
		ret = klpr_check_dir_item(leaf, key, slot);
		break;
	case BTRFS_BLOCK_GROUP_ITEM_KEY:
		ret = klpr_check_block_group_item(leaf, key, slot);
		break;
	case BTRFS_CHUNK_ITEM_KEY:
		chunk = ((struct btrfs_chunk *)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)));
		ret = (*klpe_btrfs_check_chunk_valid)(leaf->fs_info, leaf, chunk,
					      key->offset);
		break;
	case BTRFS_DEV_ITEM_KEY:
		ret = klpr_check_dev_item(leaf, key, slot);
		break;
	case BTRFS_INODE_ITEM_KEY:
		ret = klpr_check_inode_item(leaf, key, slot);
		break;
	case BTRFS_ROOT_ITEM_KEY:
		ret = (*klpe_check_root_item)(leaf, key, slot);
		break;
	case BTRFS_EXTENT_ITEM_KEY:
	case BTRFS_METADATA_ITEM_KEY:
		ret = klpr_check_extent_item(leaf, key, slot);
		break;
	case BTRFS_TREE_BLOCK_REF_KEY:
	case BTRFS_SHARED_DATA_REF_KEY:
	case BTRFS_SHARED_BLOCK_REF_KEY:
		ret = klpr_check_simple_keyed_refs(leaf, key, slot);
		break;
	case BTRFS_EXTENT_DATA_REF_KEY:
		ret = klpr_check_extent_data_ref(leaf, key, slot);
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

	if (btrfs_header_level(leaf) != 0) {
		(*klpe_generic_err)(leaf, 0,
			"invalid level for leaf, have %d expect 0",
			btrfs_header_level(leaf));
		return -EUCLEAN;
	}

	if (unlikely(!btrfs_header_flag(leaf, BTRFS_HEADER_FLAG_WRITTEN))) {
		(*klpe_generic_err)(leaf, 0, "invalid flag for leaf, WRITTEN not set");
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
		if (owner == BTRFS_ROOT_TREE_OBJECTID ||
		    owner == BTRFS_CHUNK_TREE_OBJECTID ||
		    owner == BTRFS_EXTENT_TREE_OBJECTID ||
		    owner == BTRFS_DEV_TREE_OBJECTID ||
		    owner == BTRFS_FS_TREE_OBJECTID ||
		    owner == BTRFS_DATA_RELOC_TREE_OBJECTID) {
			(*klpe_generic_err)(leaf, 0,
			"invalid root, root %llu must never be empty",
				    owner);
			return -EUCLEAN;
		}
		return 0;
	}

	if (nritems == 0)
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
		int ret;

		klpr_btrfs_item_key_to_cpu(leaf, &key, slot);

		/* Make sure the keys are in the right order */
		if ((*klpe_btrfs_comp_cpu_keys)(&prev_key, &key) >= 0) {
			(*klpe_generic_err)(leaf, slot,
	"bad key order, prev (%llu %u %llu) current (%llu %u %llu)",
				prev_key.objectid, prev_key.type,
				prev_key.offset, key.objectid, key.type,
				key.offset);
			return -EUCLEAN;
		}

		/*
		 * Make sure the offset and ends are right, remember that the
		 * item data starts at the end of the leaf and grows towards the
		 * front.
		 */
		if (slot == 0)
			item_end_expected = BTRFS_LEAF_DATA_SIZE(fs_info);
		else
			item_end_expected = klpr_btrfs_item_offset_nr(leaf,
								 slot - 1);
		if (klpr_btrfs_item_end_nr(leaf, slot) != item_end_expected) {
			(*klpe_generic_err)(leaf, slot,
				"unexpected item end, have %u expect %u",
				klpr_btrfs_item_end_nr(leaf, slot),
				item_end_expected);
			return -EUCLEAN;
		}

		/*
		 * Check to make sure that we don't point outside of the leaf,
		 * just in case all the items are consistent to each other, but
		 * all point outside of the leaf.
		 */
		if (klpr_btrfs_item_end_nr(leaf, slot) >
		    BTRFS_LEAF_DATA_SIZE(fs_info)) {
			(*klpe_generic_err)(leaf, slot,
			"slot end outside of leaf, have %u expect range [0, %u]",
				klpr_btrfs_item_end_nr(leaf, slot),
				BTRFS_LEAF_DATA_SIZE(fs_info));
			return -EUCLEAN;
		}

		/* Also check if the item pointer overlaps with btrfs item. */
		if (btrfs_item_nr_offset(slot) + sizeof(struct btrfs_item) >
		    ((unsigned long)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot)))) {
			(*klpe_generic_err)(leaf, slot,
		"slot overlaps with its data, item end %lu data start %lu",
				btrfs_item_nr_offset(slot) +
				sizeof(struct btrfs_item),
				((unsigned long)(btrfs_leaf_data(leaf) + klpr_btrfs_item_offset_nr(leaf, slot))));
			return -EUCLEAN;
		}

		/* Check if the item size and content meet other criteria. */
		ret = klpr_check_leaf_item(leaf, &key, slot, &prev_key);
		if (ret < 0)
			return ret;

		prev_key.objectid = key.objectid;
		prev_key.type = key.type;
		prev_key.offset = key.offset;
	}

	return 0;
}

int klpp_btrfs_check_node(struct btrfs_fs_info *fs_info, struct extent_buffer *node)
{
	unsigned long nr = btrfs_header_nritems(node);
	struct btrfs_key key, next_key;
	int slot;
	int level = btrfs_header_level(node);
	u64 bytenr;
	int ret = 0;

	if (unlikely(!btrfs_header_flag(node, BTRFS_HEADER_FLAG_WRITTEN))) {
		(*klpe_generic_err)(node, 0, "invalid flag for node, WRITTEN not set");
		return -EUCLEAN;
	}

	if (level <= 0 || level >= BTRFS_MAX_LEVEL) {
		(*klpe_generic_err)(node, 0,
			"invalid level for node, have %d expect [1, %d]",
			level, BTRFS_MAX_LEVEL - 1);
		return -EUCLEAN;
	}
	if (nr == 0 || nr > BTRFS_NODEPTRS_PER_BLOCK(fs_info)) {
		(*klpe_btrfs_printk)(fs_info, "\001" "2" "corrupt node: root=%llu block=%llu, nritems too %s, have %lu expect range [1,%u]",btrfs_header_owner(node), node->start, nr == 0 ? "small" : "large", nr, BTRFS_NODEPTRS_PER_BLOCK(fs_info));
		return -EUCLEAN;
	}

	for (slot = 0; slot < nr - 1; slot++) {
		bytenr = klpr_btrfs_node_blockptr(node, slot);
		klpr_btrfs_node_key_to_cpu(node, &key, slot);
		klpr_btrfs_node_key_to_cpu(node, &next_key, slot + 1);

		if (!bytenr) {
			(*klpe_generic_err)(node, slot,
				"invalid NULL node pointer");
			ret = -EUCLEAN;
			goto out;
		}
		if (!IS_ALIGNED(bytenr, fs_info->sectorsize)) {
			(*klpe_generic_err)(node, slot,
			"unaligned pointer, have %llu should be aligned to %u",
				bytenr, fs_info->sectorsize);
			ret = -EUCLEAN;
			goto out;
		}

		if ((*klpe_btrfs_comp_cpu_keys)(&key, &next_key) >= 0) {
			(*klpe_generic_err)(node, slot,
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

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "btrfs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "block_group_err", (void *)&klpe_block_group_err, "btrfs" },
	{ "btrfs_check_chunk_valid", (void *)&klpe_btrfs_check_chunk_valid,
	  "btrfs" },
	{ "btrfs_comp_cpu_keys", (void *)&klpe_btrfs_comp_cpu_keys, "btrfs" },
	{ "btrfs_crc32c", (void *)&klpe_btrfs_crc32c, "btrfs" },
	{ "btrfs_get_token_16", (void *)&klpe_btrfs_get_token_16, "btrfs" },
	{ "btrfs_get_token_32", (void *)&klpe_btrfs_get_token_32, "btrfs" },
	{ "btrfs_get_token_64", (void *)&klpe_btrfs_get_token_64, "btrfs" },
	{ "btrfs_get_token_8", (void *)&klpe_btrfs_get_token_8, "btrfs" },
	{ "btrfs_node_key", (void *)&klpe_btrfs_node_key, "btrfs" },
	{ "btrfs_printk", (void *)&klpe_btrfs_printk, "btrfs" },
	{ "check_root_item", (void *)&klpe_check_root_item, "btrfs" },
	{ "dev_item_err", (void *)&klpe_dev_item_err, "btrfs" },
	{ "dir_item_err", (void *)&klpe_dir_item_err, "btrfs" },
	{ "extent_err", (void *)&klpe_extent_err, "btrfs" },
	{ "file_extent_err", (void *)&klpe_file_extent_err, "btrfs" },
	{ "generic_err", (void *)&klpe_generic_err, "btrfs" },
	{ "read_extent_buffer", (void *)&klpe_read_extent_buffer, "btrfs" },
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

int livepatch_bsc1229273_init(void)
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

void livepatch_bsc1229273_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
