/*
 * livepatch_bsc1219079
 *
 * Fix for CVE-2024-0775, bsc#1219079
 *
 *  Upstream commit:
 *  4c0b4818b1f6 ("ext4: improve error recovery code paths in __ext4_remount()")
 *
 *  SLE12-SP5 commit:
 *  0d0eedecc552e10d6a3c43b3d1a858ff007832e2
 *
 *  SLE15-SP2 and -SP3 commit:
 *  f05387101541813893eee2206e6c5ce6d49acc09
 *
 *  SLE15-SP4 and -SP5 commit:
 *  29aa4fc8fb9329a8b96674b86859f3e804669f7b
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

/* klp-ccp: from fs/ext4/super.c */
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/time.h>

/* klp-ccp: from include/linux/vmalloc.h */
struct vm_struct;

/* klp-ccp: from fs/ext4/super.c */
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>

/* klp-ccp: from fs/ext4/super.c */
#include <linux/quotaops.h>
#include <linux/seq_file.h>
#include <linux/log2.h>

/* klp-ccp: from include/linux/crc16.h */
static u16 (*klpe_crc16)(u16 crc, const u8 *buffer, size_t len);

/* klp-ccp: from fs/ext4/super.c */
#include <linux/uaccess.h>
#include <linux/kthread.h>
/* klp-ccp: from fs/ext4/ext4.h */
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/magic.h>
#include <linux/jbd2.h>

/* klp-ccp: from include/linux/jbd2.h */
#ifdef __KERNEL__

static int	 (*klpe_jbd2_journal_flush) (journal_t *);
static void	 (*klpe_jbd2_journal_lock_updates) (journal_t *);
static void	 (*klpe_jbd2_journal_unlock_updates) (journal_t *);

static void	   (*klpe_jbd2_journal_update_sb_errno)(journal_t *);

static int	   (*klpe_jbd2_journal_errno)      (journal_t *);

static int	   (*klpe_jbd2_journal_clear_err)  (journal_t *);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __KERNEL__   */

/* klp-ccp: from fs/ext4/ext4.h */
#include <linux/quota.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>
#include <linux/seqlock.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/percpu_counter.h>
#include <linux/ratelimit.h>
#include <crypto/hash.h>
#include <linux/percpu-rwsem.h>
#include <linux/module.h>

typedef unsigned long long ext4_fsblk_t;

typedef unsigned int ext4_group_t;

struct ext4_group_desc
{
	__le32	bg_block_bitmap_lo;	/* Blocks bitmap block */
	__le32	bg_inode_bitmap_lo;	/* Inodes bitmap block */
	__le32	bg_inode_table_lo;	/* Inodes table block */
	__le16	bg_free_blocks_count_lo;/* Free blocks count */
	__le16	bg_free_inodes_count_lo;/* Free inodes count */
	__le16	bg_used_dirs_count_lo;	/* Directories count */
	__le16	bg_flags;		/* EXT4_BG_flags (INODE_UNINIT, etc) */
	__le32  bg_exclude_bitmap_lo;   /* Exclude bitmap for snapshots */
	__le16  bg_block_bitmap_csum_lo;/* crc32c(s_uuid+grp_num+bbitmap) LE */
	__le16  bg_inode_bitmap_csum_lo;/* crc32c(s_uuid+grp_num+ibitmap) LE */
	__le16  bg_itable_unused_lo;	/* Unused inodes count */
	__le16  bg_checksum;		/* crc16(sb_uuid+group+desc) */
	__le32	bg_block_bitmap_hi;	/* Blocks bitmap block MSB */
	__le32	bg_inode_bitmap_hi;	/* Inodes bitmap block MSB */
	__le32	bg_inode_table_hi;	/* Inodes table block MSB */
	__le16	bg_free_blocks_count_hi;/* Free blocks count MSB */
	__le16	bg_free_inodes_count_hi;/* Free inodes count MSB */
	__le16	bg_used_dirs_count_hi;	/* Directories count MSB */
	__le16  bg_itable_unused_hi;    /* Unused inodes count MSB */
	__le32  bg_exclude_bitmap_hi;   /* Exclude bitmap block MSB */
	__le16  bg_block_bitmap_csum_hi;/* crc32c(s_uuid+grp_num+bbitmap) BE */
	__le16  bg_inode_bitmap_csum_hi;/* crc32c(s_uuid+grp_num+ibitmap) BE */
	__u32   bg_reserved;
};

#define EXT4_BG_INODE_ZEROED	0x0004 /* On-disk itable initialized to zero */

/* klp-ccp: from fs/ext4/extents_status.h */
struct ext4_es_stats {
	unsigned long es_stats_shrunk;
	unsigned long es_stats_cache_hits;
	unsigned long es_stats_cache_misses;
	u64 es_stats_scan_time;
	u64 es_stats_max_scan_time;
	struct percpu_counter es_stats_all_cnt;
	struct percpu_counter es_stats_shk_cnt;
};

/* klp-ccp: from fs/ext4/ext4.h */
#define	EXT4_VALID_FS			0x0001	/* Unmounted cleanly */
#define	EXT4_ERROR_FS			0x0002	/* Errors detected */

#define EXT4_MOUNT_DAX			0x00200	/* Direct Access */

#define EXT4_MOUNT_DATA_FLAGS		0x00C00	/* Mode for data writes: */
#define EXT4_MOUNT_JOURNAL_DATA		0x00400	/* Write data to journal */
#define EXT4_MOUNT_ORDERED_DATA		0x00800	/* Flush data before commit */

#define EXT4_MOUNT_POSIX_ACL		0x08000	/* POSIX Access Control Lists */

#define EXT4_MOUNT_BARRIER		0x20000 /* Use block barriers */

#define EXT4_MOUNT_DIOREAD_NOLOCK	0x400000 /* Enable support for dio read nolocking */
#define EXT4_MOUNT_JOURNAL_CHECKSUM	0x800000 /* Journal checksums */
#define EXT4_MOUNT_JOURNAL_ASYNC_COMMIT	0x1000000 /* Journal Async Commit */

#define EXT4_MOUNT_DATA_ERR_ABORT	0x10000000 /* Abort on file data write */

#define EXT4_MOUNT_INIT_INODE_TABLE	0x80000000 /* Initialize uninitialized itables */

#define EXT4_MOUNT2_EXPLICIT_DELALLOC	0x00000001 /* User explicitly
						      specified delalloc */

#define test_opt(sb, opt)		(EXT4_SB(sb)->s_mount_opt & \
					 EXT4_MOUNT_##opt)

#define test_opt2(sb, opt)		(EXT4_SB(sb)->s_mount_opt2 & \
					 EXT4_MOUNT2_##opt)

struct ext4_super_block {
/*00*/	__le32	s_inodes_count;		/* Inodes count */
	__le32	s_blocks_count_lo;	/* Blocks count */
	__le32	s_r_blocks_count_lo;	/* Reserved blocks count */
	__le32	s_free_blocks_count_lo;	/* Free blocks count */
/*10*/	__le32	s_free_inodes_count;	/* Free inodes count */
	__le32	s_first_data_block;	/* First Data Block */
	__le32	s_log_block_size;	/* Block size */
	__le32	s_log_cluster_size;	/* Allocation cluster size */
/*20*/	__le32	s_blocks_per_group;	/* # Blocks per group */
	__le32	s_clusters_per_group;	/* # Clusters per group */
	__le32	s_inodes_per_group;	/* # Inodes per group */
	__le32	s_mtime;		/* Mount time */
/*30*/	__le32	s_wtime;		/* Write time */
	__le16	s_mnt_count;		/* Mount count */
	__le16	s_max_mnt_count;	/* Maximal mount count */
	__le16	s_magic;		/* Magic signature */
	__le16	s_state;		/* File system state */
	__le16	s_errors;		/* Behaviour when detecting errors */
	__le16	s_minor_rev_level;	/* minor revision level */
/*40*/	__le32	s_lastcheck;		/* time of last check */
	__le32	s_checkinterval;	/* max. time between checks */
	__le32	s_creator_os;		/* OS */
	__le32	s_rev_level;		/* Revision level */
/*50*/	__le16	s_def_resuid;		/* Default uid for reserved blocks */
	__le16	s_def_resgid;		/* Default gid for reserved blocks */
	/*
	 * These fields are for EXT4_DYNAMIC_REV superblocks only.
	 *
	 * Note: the difference between the compatible feature set and
	 * the incompatible feature set is that if there is a bit set
	 * in the incompatible feature set that the kernel doesn't
	 * know about, it should refuse to mount the filesystem.
	 *
	 * e2fsck's requirements are more strict; if it doesn't know
	 * about a feature in either the compatible or incompatible
	 * feature set, it must abort and not try to meddle with
	 * things it doesn't understand...
	 */
	__le32	s_first_ino;		/* First non-reserved inode */
	__le16  s_inode_size;		/* size of inode structure */
	__le16	s_block_group_nr;	/* block group # of this superblock */
	__le32	s_feature_compat;	/* compatible feature set */
/*60*/	__le32	s_feature_incompat;	/* incompatible feature set */
	__le32	s_feature_ro_compat;	/* readonly-compatible feature set */
/*68*/	__u8	s_uuid[16];		/* 128-bit uuid for volume */
/*78*/	char	s_volume_name[16];	/* volume name */
/*88*/	char	s_last_mounted[64];	/* directory where last mounted */
/*C8*/	__le32	s_algorithm_usage_bitmap; /* For compression */
	/*
	 * Performance hints.  Directory preallocation should only
	 * happen if the EXT4_FEATURE_COMPAT_DIR_PREALLOC flag is on.
	 */
	__u8	s_prealloc_blocks;	/* Nr of blocks to try to preallocate*/
	__u8	s_prealloc_dir_blocks;	/* Nr to preallocate for dirs */
	__le16	s_reserved_gdt_blocks;	/* Per group desc for online growth */
	/*
	 * Journaling support valid if EXT4_FEATURE_COMPAT_HAS_JOURNAL set.
	 */
/*D0*/	__u8	s_journal_uuid[16];	/* uuid of journal superblock */
/*E0*/	__le32	s_journal_inum;		/* inode number of journal file */
	__le32	s_journal_dev;		/* device number of journal file */
	__le32	s_last_orphan;		/* start of list of inodes to delete */
	__le32	s_hash_seed[4];		/* HTREE hash seed */
	__u8	s_def_hash_version;	/* Default hash version to use */
	__u8	s_jnl_backup_type;
	__le16  s_desc_size;		/* size of group descriptor */
/*100*/	__le32	s_default_mount_opts;
	__le32	s_first_meta_bg;	/* First metablock block group */
	__le32	s_mkfs_time;		/* When the filesystem was created */
	__le32	s_jnl_blocks[17];	/* Backup of the journal inode */
	/* 64bit support valid if EXT4_FEATURE_COMPAT_64BIT */
/*150*/	__le32	s_blocks_count_hi;	/* Blocks count */
	__le32	s_r_blocks_count_hi;	/* Reserved blocks count */
	__le32	s_free_blocks_count_hi;	/* Free blocks count */
	__le16	s_min_extra_isize;	/* All inodes have at least # bytes */
	__le16	s_want_extra_isize; 	/* New inodes should reserve # bytes */
	__le32	s_flags;		/* Miscellaneous flags */
	__le16  s_raid_stride;		/* RAID stride */
	__le16  s_mmp_update_interval;  /* # seconds to wait in MMP checking */
	__le64  s_mmp_block;            /* Block for multi-mount protection */
	__le32  s_raid_stripe_width;    /* blocks on all data disks (N*stride)*/
	__u8	s_log_groups_per_flex;  /* FLEX_BG group size */
	__u8	s_checksum_type;	/* metadata checksum algorithm used */
	__u8	s_encryption_level;	/* versioning level for encryption */
	__u8	s_reserved_pad;		/* Padding to next 32bits */
	__le64	s_kbytes_written;	/* nr of lifetime kilobytes written */
	__le32	s_snapshot_inum;	/* Inode number of active snapshot */
	__le32	s_snapshot_id;		/* sequential ID of active snapshot */
	__le64	s_snapshot_r_blocks_count; /* reserved blocks for active
					      snapshot's future use */
	__le32	s_snapshot_list;	/* inode number of the head of the
					   on-disk snapshot list */
	__le32	s_error_count;		/* number of fs errors */
	__le32	s_first_error_time;	/* first time an error happened */
	__le32	s_first_error_ino;	/* inode involved in first error */
	__le64	s_first_error_block;	/* block involved of first error */
	__u8	s_first_error_func[32];	/* function where the error happened */
	__le32	s_first_error_line;	/* line number where error happened */
	__le32	s_last_error_time;	/* most recent time of an error */
	__le32	s_last_error_ino;	/* inode involved in last error */
	__le32	s_last_error_line;	/* line number where error happened */
	__le64	s_last_error_block;	/* block involved of last error */
	__u8	s_last_error_func[32];	/* function where the error happened */
	__u8	s_mount_opts[64];
	__le32	s_usr_quota_inum;	/* inode for tracking user quota */
	__le32	s_grp_quota_inum;	/* inode for tracking group quota */
	__le32	s_overhead_clusters;	/* overhead blocks/clusters in fs */
	__le32	s_backup_bgs[2];	/* groups with sparse_super2 SBs */
	__u8	s_encrypt_algos[4];	/* Encryption algorithms in use  */
	__u8	s_encrypt_pw_salt[16];	/* Salt used for string2key algorithm */
	__le32	s_lpf_ino;		/* Location of the lost+found inode */
	__le32	s_prj_quota_inum;	/* inode for tracking project quota */
	__le32	s_checksum_seed;	/* crc32c(uuid) if csum_seed set */
	__le32	s_reserved[98];		/* Padding to the end of the block */
	__le32	s_checksum;		/* crc32c(superblock) */
};

#ifdef __KERNEL__

#define EXT4_MF_FS_ABORTED		0x0002	/* Fatal error detected */

#define EXT4_MAXQUOTAS 3

struct ext4_sb_info {
	unsigned long s_desc_size;	/* Size of a group descriptor in bytes */
	unsigned long s_inodes_per_block;/* Number of inodes per block */
	unsigned long s_blocks_per_group;/* Number of blocks in a group */
	unsigned long s_clusters_per_group; /* Number of clusters in a group */
	unsigned long s_inodes_per_group;/* Number of inodes in a group */
	unsigned long s_itb_per_group;	/* Number of inode table blocks per group */
	unsigned long s_gdb_count;	/* Number of group descriptor blocks */
	unsigned long s_desc_per_block;	/* Number of group descriptors per block */
	ext4_group_t s_groups_count;	/* Number of groups in the fs */
	ext4_group_t s_blockfile_groups;/* Groups acceptable for non-extent files */
	unsigned long s_overhead;  /* # of fs overhead clusters */
	unsigned int s_cluster_ratio;	/* Number of blocks per cluster */
	unsigned int s_cluster_bits;	/* log2 of s_cluster_ratio */
	loff_t s_bitmap_maxbytes;	/* max bytes for bitmap files */
	struct buffer_head * s_sbh;	/* Buffer containing the super block */
	struct ext4_super_block *s_es;	/* Pointer to the super block in the buffer */
	struct buffer_head * __rcu *s_group_desc;
	unsigned int s_mount_opt;
	unsigned int s_mount_opt2;
	unsigned int s_mount_flags;
	unsigned int s_def_mount_opt;
	ext4_fsblk_t s_sb_block;
	atomic64_t s_resv_clusters;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned short s_mount_state;
	unsigned short s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	unsigned int s_inode_readahead_blks;
	unsigned int s_inode_goal;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	u32 s_hash_seed[4];
	int s_def_hash_version;
	int s_hash_unsigned;	/* 3 if hash should be signed, 0 if not */
	struct percpu_counter s_freeclusters_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct percpu_counter s_dirtyclusters_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	struct proc_dir_entry *s_proc;
	struct kobject s_kobj;
	struct completion s_kobj_unregister;
	struct super_block *s_sb;

	/* Journaling */
	struct journal_s *s_journal;
	struct list_head s_orphan;
	struct mutex s_orphan_lock;
	unsigned long s_ext4_flags;		/* Ext4 superblock flags */
	unsigned long s_commit_interval;
	u32 s_max_batch_time;
	u32 s_min_batch_time;
	struct block_device *journal_bdev;
#ifdef CONFIG_QUOTA
	char __rcu *s_qf_names[EXT4_MAXQUOTAS];
	int s_jquota_fmt;			/* Format of quota to use */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	unsigned int s_want_extra_isize; /* New inodes should reserve # bytes */
	struct rb_root system_blks;

#ifdef EXTENTS_STATS
#error "klp-ccp: non-taken branch"
#endif
	struct ext4_group_info ** __rcu *s_group_info;
	struct inode *s_buddy_cache;
	spinlock_t s_md_lock;
	unsigned short *s_mb_offsets;
	unsigned int *s_mb_maxs;
	unsigned int s_group_info_size;
	unsigned int s_mb_free_pending;

	/* tunables */
	unsigned long s_stripe;
	unsigned int s_mb_stream_request;
	unsigned int s_mb_max_to_scan;
	unsigned int s_mb_min_to_scan;
	unsigned int s_mb_stats;
	unsigned int s_mb_order2_reqs;
	unsigned int s_mb_group_prealloc;
	unsigned int s_max_dir_size_kb;
	/* where last allocation was done - for stream allocation */
	unsigned long s_mb_last_group;
	unsigned long s_mb_last_start;

	/* stats for buddy allocator */
	atomic_t s_bal_reqs;	/* number of reqs with len > 1 */
	atomic_t s_bal_success;	/* we found long enough chunks */
	atomic_t s_bal_allocated;	/* in blocks */
	atomic_t s_bal_ex_scanned;	/* total extents scanned */
	atomic_t s_bal_goals;	/* goal hits */
	atomic_t s_bal_breaks;	/* too long searches */
	atomic_t s_bal_2orders;	/* 2^order hits */
	spinlock_t s_bal_lock;
	unsigned long s_mb_buddies_generated;
	unsigned long long s_mb_generation_time;
	atomic_t s_mb_lost_chunks;
	atomic_t s_mb_preallocated;
	atomic_t s_mb_discarded;
	atomic_t s_lock_busy;

	/* locality groups */
	struct ext4_locality_group __percpu *s_locality_groups;

	/* for write statistics */
	unsigned long s_sectors_written_start;
	u64 s_kbytes_written;

	/* the size of zero-out chunk */
	unsigned int s_extent_max_zeroout_kb;

	unsigned int s_log_groups_per_flex;
	struct flex_groups * __rcu *s_flex_groups;
	ext4_group_t s_flex_groups_allocated;

	/* workqueue for reserved extent conversions (buffered io) */
	struct workqueue_struct *rsv_conversion_wq;

	/* timer for periodic error stats printing */
	struct timer_list s_err_report;

	/* Lazy inode table initialization info */
	struct ext4_li_request *s_li_request;
	/* Wait multiplier for lazy initialization thread */
	unsigned int s_li_wait_mult;

	/* Kernel thread for multiple mount protection */
	struct task_struct *s_mmp_tsk;

	/* record the last minlen when FITRIM is called. */
	atomic_t s_last_trim_minblks;

	/* Reference to checksum algorithm driver via cryptoapi */
	struct crypto_shash *s_chksum_driver;

	/* Precomputed FS UUID checksum for seeding other checksums */
	__u32 s_csum_seed;

	/* Reclaim extents from extent status tree */
	struct shrinker s_es_shrinker;
	struct list_head s_es_list;	/* List of inodes with reclaimable extents */
	long s_es_nr_inode;
	struct ext4_es_stats s_es_stats;
	struct mb_cache *s_mb_cache;
	spinlock_t s_es_lock ____cacheline_aligned_in_smp;

	/* Ratelimit ext4 messages. */
	struct ratelimit_state s_err_ratelimit_state;
	struct ratelimit_state s_warning_ratelimit_state;
	struct ratelimit_state s_msg_ratelimit_state;

	/*
	 * Barrier between writepages ops and changing any inode's JOURNAL_DATA
	 * or EXTENTS flag.
	 */
	struct percpu_rw_semaphore s_writepages_rwsem;
	struct dax_device *s_daxdev;
};

static inline struct ext4_sb_info *EXT4_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from fs/ext4/ext4.h */
static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_journal(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_compat & cpu_to_le32(0x0004)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_gdt_csum(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_ro_compat & cpu_to_le32(0x0010)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_quota(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_ro_compat & cpu_to_le32(0x0100)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_metadata_csum(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_ro_compat & cpu_to_le32(0x0400)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_readonly(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_ro_compat & cpu_to_le32(0x1000)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_journal_needs_recovery(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_incompat & cpu_to_le32(0x0004)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) void ext4_clear_feature_journal_needs_recovery(struct super_block *sb) { EXT4_SB(sb)->s_es->s_feature_incompat &= ~cpu_to_le32(0x0004); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_64bit(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_incompat & cpu_to_le32(0x0080)) != 0); }

static inline __attribute__((unused)) __attribute__((no_instrument_function)) bool ext4_has_feature_mmp(struct super_block *sb) { return ((EXT4_SB(sb)->s_es->s_feature_incompat & cpu_to_le32(0x0100)) != 0); }

/* klp-ccp: from fs/ext4/ext4.h */
static inline u32 ext4_chksum(struct ext4_sb_info *sbi, u32 crc,
			      const void *address, unsigned int length)
{
	struct {
		struct shash_desc shash;
		char ctx[4];
	} desc;
	int err;

	BUG_ON(crypto_shash_descsize(sbi->s_chksum_driver)!=sizeof(desc.ctx));

	desc.shash.tfm = sbi->s_chksum_driver;
	desc.shash.flags = 0;
	*(u32 *)desc.ctx = crc;

	err = crypto_shash_update(&desc.shash, address, length);
	BUG_ON(err);

	return *(u32 *)desc.ctx;
}

#ifdef __KERNEL__

struct ext4_lazy_init {
	unsigned long		li_state;
	struct list_head	li_request_list;
	struct mutex		li_list_mtx;
};

static struct ext4_group_desc * (*klpe_ext4_get_group_desc)(struct super_block * sb,
						    ext4_group_t block_group,
						    struct buffer_head ** bh);

static const char *(*klpe_ext4_decode_error)(struct super_block *sb, int errno,
				     char nbuf[16]);

static __printf(4, 5)
void (*klpe___ext4_abort)(struct super_block *, const char *, unsigned int,
		  const char *, ...);
static __printf(4, 5)
void (*klpe___ext4_warning)(struct super_block *, const char *, unsigned int,
		    const char *, ...);

static __printf(3, 4)
void (*klpe___ext4_msg)(struct super_block *, const char *, const char *, ...);

#define klpr_ext4_abort(sb, fmt, ...)					\
	(*klpe___ext4_abort)(sb, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define klpr_ext4_warning(sb, fmt, ...)					\
	(*klpe___ext4_warning)(sb, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define klpr_ext4_msg(sb, level, fmt, ...)				\
	(*klpe___ext4_msg)(sb, level, fmt, ##__VA_ARGS__)

static int (*klpe_ext4_group_desc_csum_verify)(struct super_block *sb, __u32 group,
				       struct ext4_group_desc *gdp);

static int (*klpe_ext4_register_li_request)(struct super_block *sb,
				    ext4_group_t first_not_zeroed);

static inline int ext4_has_metadata_csum(struct super_block *sb)
{
	WARN_ON_ONCE(ext4_has_feature_metadata_csum(sb) &&
		     !EXT4_SB(sb)->s_chksum_driver);

	return ext4_has_feature_metadata_csum(sb) &&
	       (EXT4_SB(sb)->s_chksum_driver != NULL);
}

static inline int ext4_has_group_desc_csum(struct super_block *sb)
{
	return ext4_has_feature_gdt_csum(sb) || ext4_has_metadata_csum(sb);
}

static int (*klpe_ext4_setup_system_zone)(struct super_block *sb);

static int (*klpe_ext4_multi_mount_protect)(struct super_block *, ext4_fsblk_t);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif	/* __KERNEL__ */

/* klp-ccp: from fs/ext4/ext4_jbd2.h */
#include <linux/fs.h>
#include <linux/jbd2.h>
/* klp-ccp: from fs/ext4/mballoc.h */
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <linux/mutex.h>

/* klp-ccp: from fs/ext4/super.c */
static struct ext4_lazy_init *(*klpe_ext4_li_info);
static struct mutex (*klpe_ext4_li_mtx);

static int (*klpe_ext4_commit_super)(struct super_block *sb, int sync);
static void klpr_ext4_mark_recovery_complete(struct super_block *sb,
					struct ext4_super_block *es);
static void klpr_ext4_clear_journal_err(struct super_block *sb,
				   struct ext4_super_block *es);

static int (*klpe_ext4_feature_set_ok)(struct super_block *sb, int readonly);

static void klpr_ext4_unregister_li_request(struct super_block *sb);

#ifdef CONFIG_QUOTA

static inline char *get_qf_name(struct super_block *sb,
				struct ext4_sb_info *sbi,
				int type)
{
	return rcu_dereference_protected(sbi->s_qf_names[type],
					 lockdep_is_held(&sb->s_umount));
}
#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_QUOTA

static int (*klpe_ext4_enable_quotas)(struct super_block *sb);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define DEFAULT_JOURNAL_IOPRIO (IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 3))

static int (*klpe_parse_options)(char *options, struct super_block *sb,
			 unsigned long *journal_devnum,
			 unsigned int *journal_ioprio,
			 int is_remount);

static int (*klpe_ext4_setup_super)(struct super_block *sb, struct ext4_super_block *es,
			    int read_only);

static __le16 klpr_ext4_group_desc_csum(struct super_block *sb, __u32 block_group,
				   struct ext4_group_desc *gdp)
{
	int offset = offsetof(struct ext4_group_desc, bg_checksum);
	__u16 crc = 0;
	__le32 le_group = cpu_to_le32(block_group);
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (ext4_has_metadata_csum(sbi->s_sb)) {
		/* Use new metadata_csum algorithm */
		__u32 csum32;
		__u16 dummy_csum = 0;

		csum32 = ext4_chksum(sbi, sbi->s_csum_seed, (__u8 *)&le_group,
				     sizeof(le_group));
		csum32 = ext4_chksum(sbi, csum32, (__u8 *)gdp, offset);
		csum32 = ext4_chksum(sbi, csum32, (__u8 *)&dummy_csum,
				     sizeof(dummy_csum));
		offset += sizeof(dummy_csum);
		if (offset < sbi->s_desc_size)
			csum32 = ext4_chksum(sbi, csum32, (__u8 *)gdp + offset,
					     sbi->s_desc_size - offset);

		crc = csum32 & 0xFFFF;
		goto out;
	}

	/* old crc16 code */
	if (!ext4_has_feature_gdt_csum(sb))
		return 0;

	crc = (*klpe_crc16)(~0, sbi->s_es->s_uuid, sizeof(sbi->s_es->s_uuid));
	crc = (*klpe_crc16)(crc, (__u8 *)&le_group, sizeof(le_group));
	crc = (*klpe_crc16)(crc, (__u8 *)gdp, offset);
	offset += sizeof(gdp->bg_checksum); /* skip checksum */
	/* for checksum of struct ext4_group_desc do the rest...*/
	if (ext4_has_feature_64bit(sb) &&
	    offset < le16_to_cpu(sbi->s_es->s_desc_size))
		crc = (*klpe_crc16)(crc, (__u8 *)gdp + offset,
			    le16_to_cpu(sbi->s_es->s_desc_size) -
				offset);

out:
	return cpu_to_le16(crc);
}

static int (*klpe_ext4_feature_set_ok)(struct super_block *sb, int readonly);

static void (*klpe_ext4_remove_li_request)(struct ext4_li_request *elr);

static void klpr_ext4_unregister_li_request(struct super_block *sb)
{
	mutex_lock(&(*klpe_ext4_li_mtx));
	if (!(*klpe_ext4_li_info)) {
		mutex_unlock(&(*klpe_ext4_li_mtx));
		return;
	}

	mutex_lock(&(*klpe_ext4_li_info)->li_list_mtx);
	(*klpe_ext4_remove_li_request)(EXT4_SB(sb)->s_li_request);
	mutex_unlock(&(*klpe_ext4_li_info)->li_list_mtx);
	mutex_unlock(&(*klpe_ext4_li_mtx));
}

static ext4_group_t klpr_ext4_has_uninit_itable(struct super_block *sb)
{
	ext4_group_t group, ngroups = EXT4_SB(sb)->s_groups_count;
	struct ext4_group_desc *gdp = NULL;

	if (!ext4_has_group_desc_csum(sb))
		return ngroups;

	for (group = 0; group < ngroups; group++) {
		gdp = (*klpe_ext4_get_group_desc)(sb, group, NULL);
		if (!gdp)
			continue;

		if (!(gdp->bg_flags & cpu_to_le16(EXT4_BG_INODE_ZEROED)))
			break;
	}

	return group;
}

static void ext4_init_journal_params(struct super_block *sb, journal_t *journal)
{
	struct ext4_sb_info *sbi = EXT4_SB(sb);

	journal->j_commit_interval = sbi->s_commit_interval;
	journal->j_min_batch_time = sbi->s_min_batch_time;
	journal->j_max_batch_time = sbi->s_max_batch_time;

	write_lock(&journal->j_state_lock);
	if (test_opt(sb, BARRIER))
		journal->j_flags |= JBD2_BARRIER;
	else
		journal->j_flags &= ~JBD2_BARRIER;
	if (test_opt(sb, DATA_ERR_ABORT))
		journal->j_flags |= JBD2_ABORT_ON_SYNCDATA_ERR;
	else
		journal->j_flags &= ~JBD2_ABORT_ON_SYNCDATA_ERR;
	write_unlock(&journal->j_state_lock);
}

static int (*klpe_ext4_commit_super)(struct super_block *sb, int sync);

static void klpr_ext4_mark_recovery_complete(struct super_block *sb,
					struct ext4_super_block *es)
{
	journal_t *journal = EXT4_SB(sb)->s_journal;

	if (!ext4_has_feature_journal(sb)) {
		BUG_ON(journal != NULL);
		return;
	}
	(*klpe_jbd2_journal_lock_updates)(journal);
	if ((*klpe_jbd2_journal_flush)(journal) < 0)
		goto out;

	if (ext4_has_feature_journal_needs_recovery(sb) &&
	    sb->s_flags & MS_RDONLY) {
		ext4_clear_feature_journal_needs_recovery(sb);
		(*klpe_ext4_commit_super)(sb, 1);
	}

out:
	(*klpe_jbd2_journal_unlock_updates)(journal);
}

static void klpr_ext4_clear_journal_err(struct super_block *sb,
				   struct ext4_super_block *es)
{
	journal_t *journal;
	int j_errno;
	const char *errstr;

	BUG_ON(!ext4_has_feature_journal(sb));

	journal = EXT4_SB(sb)->s_journal;

	/*
	 * Now check for any error status which may have been recorded in the
	 * journal by a prior ext4_error() or ext4_abort()
	 */

	j_errno = (*klpe_jbd2_journal_errno)(journal);
	if (j_errno) {
		char nbuf[16];

		errstr = (*klpe_ext4_decode_error)(sb, j_errno, nbuf);
		klpr_ext4_warning(sb, "Filesystem error recorded "
			     "from previous mount: %s", errstr);
		klpr_ext4_warning(sb, "Marking fs in need of filesystem check.");

		EXT4_SB(sb)->s_mount_state |= EXT4_ERROR_FS;
		es->s_state |= cpu_to_le16(EXT4_ERROR_FS);
		(*klpe_ext4_commit_super)(sb, 1);

		(*klpe_jbd2_journal_clear_err)(journal);
		(*klpe_jbd2_journal_update_sb_errno)(journal);
	}
}

struct ext4_mount_options {
	unsigned long s_mount_opt;
	unsigned long s_mount_opt2;
	kuid_t s_resuid;
	kgid_t s_resgid;
	unsigned long s_commit_interval;
	u32 s_min_batch_time, s_max_batch_time;
#ifdef CONFIG_QUOTA
	int s_jquota_fmt;
	char *s_qf_names[EXT4_MAXQUOTAS];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

int klpp_ext4_remount(struct super_block *sb, int *flags, char *data)
{
	struct ext4_super_block *es;
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	unsigned long old_sb_flags;
	struct ext4_mount_options old_opts;
	int enable_quota = 0;
	ext4_group_t g;
	unsigned int journal_ioprio = DEFAULT_JOURNAL_IOPRIO;
	int err = 0;
#ifdef CONFIG_QUOTA
	int i, j;
	char *to_free[EXT4_MAXQUOTAS];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	char *orig_data = kstrdup(data, GFP_KERNEL);

	/* Store the original options */
	old_sb_flags = sb->s_flags;
	old_opts.s_mount_opt = sbi->s_mount_opt;
	old_opts.s_mount_opt2 = sbi->s_mount_opt2;
	old_opts.s_resuid = sbi->s_resuid;
	old_opts.s_resgid = sbi->s_resgid;
	old_opts.s_commit_interval = sbi->s_commit_interval;
	old_opts.s_min_batch_time = sbi->s_min_batch_time;
	old_opts.s_max_batch_time = sbi->s_max_batch_time;
#ifdef CONFIG_QUOTA
	old_opts.s_jquota_fmt = sbi->s_jquota_fmt;
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		if (sbi->s_qf_names[i]) {
			char *qf_name = get_qf_name(sb, sbi, i);

			old_opts.s_qf_names[i] = kstrdup(qf_name, GFP_KERNEL);
			if (!old_opts.s_qf_names[i]) {
				for (j = 0; j < i; j++)
					kfree(old_opts.s_qf_names[j]);
				kfree(orig_data);
				return -ENOMEM;
			}
		} else
			old_opts.s_qf_names[i] = NULL;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (sbi->s_journal && sbi->s_journal->j_task->io_context)
		journal_ioprio = sbi->s_journal->j_task->io_context->ioprio;

	if (!(*klpe_parse_options)(data, sb, NULL, &journal_ioprio, 1)) {
		err = -EINVAL;
		goto restore_opts;
	}

	if ((old_opts.s_mount_opt & EXT4_MOUNT_JOURNAL_CHECKSUM) ^
	    test_opt(sb, JOURNAL_CHECKSUM)) {
		klpr_ext4_msg(sb, KERN_ERR, "changing journal_checksum "
			 "during remount not supported; ignoring");
		sbi->s_mount_opt ^= EXT4_MOUNT_JOURNAL_CHECKSUM;
	}

	if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_JOURNAL_DATA) {
		if (test_opt2(sb, EXPLICIT_DELALLOC)) {
			klpr_ext4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and delalloc");
			err = -EINVAL;
			goto restore_opts;
		}
		if (test_opt(sb, DIOREAD_NOLOCK)) {
			klpr_ext4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dioread_nolock");
			err = -EINVAL;
			goto restore_opts;
		}
		if (test_opt(sb, DAX)) {
			klpr_ext4_msg(sb, KERN_ERR, "can't mount with "
				 "both data=journal and dax");
			err = -EINVAL;
			goto restore_opts;
		}
	} else if (test_opt(sb, DATA_FLAGS) == EXT4_MOUNT_ORDERED_DATA) {
		if (test_opt(sb, JOURNAL_ASYNC_COMMIT)) {
			klpr_ext4_msg(sb, KERN_ERR, "can't mount with "
				"journal_async_commit in data=ordered mode");
			err = -EINVAL;
			goto restore_opts;
		}
	}

	if ((sbi->s_mount_opt ^ old_opts.s_mount_opt) & EXT4_MOUNT_DAX) {
		klpr_ext4_msg(sb, KERN_WARNING, "warning: refusing change of "
			"dax flag with busy inodes while remounting");
		sbi->s_mount_opt ^= EXT4_MOUNT_DAX;
	}

	if (sbi->s_mount_flags & EXT4_MF_FS_ABORTED)
		klpr_ext4_abort(sb, "Abort forced by user");

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		(test_opt(sb, POSIX_ACL) ? MS_POSIXACL : 0);

	es = sbi->s_es;

	if (sbi->s_journal) {
		ext4_init_journal_params(sb, sbi->s_journal);
		set_task_ioprio(sbi->s_journal->j_task, journal_ioprio);
	}

	if (*flags & MS_LAZYTIME)
		sb->s_flags |= MS_LAZYTIME;

	if ((*flags & MS_RDONLY) != (sb->s_flags & MS_RDONLY)) {
		if (sbi->s_mount_flags & EXT4_MF_FS_ABORTED) {
			err = -EROFS;
			goto restore_opts;
		}

		if (*flags & MS_RDONLY) {
			err = sync_filesystem(sb);
			if (err < 0)
				goto restore_opts;
			err = dquot_suspend(sb, -1);
			if (err < 0)
				goto restore_opts;

			/*
			 * First of all, the unconditional stuff we have to do
			 * to disable replay of the journal when we next remount
			 */
			sb->s_flags |= MS_RDONLY;

			/*
			 * OK, test if we are remounting a valid rw partition
			 * readonly, and if so set the rdonly flag and then
			 * mark the partition as valid again.
			 */
			if (!(es->s_state & cpu_to_le16(EXT4_VALID_FS)) &&
			    (sbi->s_mount_state & EXT4_VALID_FS))
				es->s_state = cpu_to_le16(sbi->s_mount_state);

			if (sbi->s_journal)
				klpr_ext4_mark_recovery_complete(sb, es);
			if (sbi->s_mmp_tsk)
				kthread_stop(sbi->s_mmp_tsk);
		} else {
			/* Make sure we can mount this feature set readwrite */
			if (ext4_has_feature_readonly(sb) ||
			    !(*klpe_ext4_feature_set_ok)(sb, 0)) {
				err = -EROFS;
				goto restore_opts;
			}
			/*
			 * Make sure the group descriptor checksums
			 * are sane.  If they aren't, refuse to remount r/w.
			 */
			for (g = 0; g < sbi->s_groups_count; g++) {
				struct ext4_group_desc *gdp =
					(*klpe_ext4_get_group_desc)(sb, g, NULL);

				if (!(*klpe_ext4_group_desc_csum_verify)(sb, g, gdp)) {
					klpr_ext4_msg(sb, KERN_ERR,
	       "ext4_remount: Checksum for group %u failed (%u!=%u)",
		g, le16_to_cpu(klpr_ext4_group_desc_csum(sb, g, gdp)),
					       le16_to_cpu(gdp->bg_checksum));
					err = -EFSBADCRC;
					goto restore_opts;
				}
			}

			/*
			 * If we have an unprocessed orphan list hanging
			 * around from a previously readonly bdev mount,
			 * require a full umount/remount for now.
			 */
			if (es->s_last_orphan) {
				klpr_ext4_msg(sb, KERN_WARNING, "Couldn't "
				       "remount RDWR because of unprocessed "
				       "orphan inode list.  Please "
				       "umount/remount instead");
				err = -EINVAL;
				goto restore_opts;
			}

			/*
			 * Mounting a RDONLY partition read-write, so reread
			 * and store the current valid flag.  (It may have
			 * been changed by e2fsck since we originally mounted
			 * the partition.)
			 */
			if (sbi->s_journal)
				klpr_ext4_clear_journal_err(sb, es);
			sbi->s_mount_state = le16_to_cpu(es->s_state);
			if (!(*klpe_ext4_setup_super)(sb, es, 0))
				sb->s_flags &= ~MS_RDONLY;
			if (ext4_has_feature_mmp(sb))
				if ((*klpe_ext4_multi_mount_protect)(sb,
						le64_to_cpu(es->s_mmp_block))) {
					err = -EROFS;
					goto restore_opts;
				}
			enable_quota = 1;
		}
	}

	/*
	 * Reinitialize lazy itable initialization thread based on
	 * current settings
	 */
	if ((sb->s_flags & MS_RDONLY) || !test_opt(sb, INIT_INODE_TABLE))
		klpr_ext4_unregister_li_request(sb);
	else {
		ext4_group_t first_not_zeroed;
		first_not_zeroed = klpr_ext4_has_uninit_itable(sb);
		(*klpe_ext4_register_li_request)(sb, first_not_zeroed);
	}

	err = (*klpe_ext4_setup_system_zone)(sb);
	if (err)
		goto restore_opts;

	if (sbi->s_journal == NULL && !(old_sb_flags & MS_RDONLY))
		(*klpe_ext4_commit_super)(sb, 1);

#ifdef CONFIG_QUOTA
	if (enable_quota) {
		if (sb_any_quota_suspended(sb))
			dquot_resume(sb, -1);
		else if (ext4_has_feature_quota(sb)) {
			err = (*klpe_ext4_enable_quotas)(sb);
			if (err)
				goto restore_opts;
		}
	}
	/* Release old quota file names */
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(old_opts.s_qf_names[i]);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	*flags = (*flags & ~MS_LAZYTIME) | (sb->s_flags & MS_LAZYTIME);
	klpr_ext4_msg(sb, KERN_INFO, "re-mounted. Opts: %s", orig_data);
	kfree(orig_data);
	return 0;

restore_opts:
	/*
	 * If there was a failing r/w to ro transition, we may need to
	 * re-enable quota
	 */
	if ((sb->s_flags & MS_RDONLY) && !(old_sb_flags & MS_RDONLY) &&
	    sb_any_quota_suspended(sb))
		dquot_resume(sb, -1);
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_opts.s_mount_opt;
	sbi->s_mount_opt2 = old_opts.s_mount_opt2;
	sbi->s_resuid = old_opts.s_resuid;
	sbi->s_resgid = old_opts.s_resgid;
	sbi->s_commit_interval = old_opts.s_commit_interval;
	sbi->s_min_batch_time = old_opts.s_min_batch_time;
	sbi->s_max_batch_time = old_opts.s_max_batch_time;
#ifdef CONFIG_QUOTA
	sbi->s_jquota_fmt = old_opts.s_jquota_fmt;
	for (i = 0; i < EXT4_MAXQUOTAS; i++) {
		to_free[i] = get_qf_name(sb, sbi, i);
		rcu_assign_pointer(sbi->s_qf_names[i], old_opts.s_qf_names[i]);
	}
	synchronize_rcu();
	for (i = 0; i < EXT4_MAXQUOTAS; i++)
		kfree(to_free[i]);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	kfree(orig_data);
	return err;
}



#include "livepatch_bsc1219079.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ext4"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__ext4_abort", (void *)&klpe___ext4_abort, "ext4" },
	{ "__ext4_msg", (void *)&klpe___ext4_msg, "ext4" },
	{ "__ext4_warning", (void *)&klpe___ext4_warning, "ext4" },
	{ "ext4_commit_super", (void *)&klpe_ext4_commit_super, "ext4" },
	{ "ext4_decode_error", (void *)&klpe_ext4_decode_error, "ext4" },
	{ "ext4_enable_quotas", (void *)&klpe_ext4_enable_quotas, "ext4" },
	{ "ext4_feature_set_ok", (void *)&klpe_ext4_feature_set_ok, "ext4" },
	{ "ext4_get_group_desc", (void *)&klpe_ext4_get_group_desc, "ext4" },
	{ "ext4_group_desc_csum_verify",
	  (void *)&klpe_ext4_group_desc_csum_verify, "ext4" },
	{ "ext4_li_info", (void *)&klpe_ext4_li_info, "ext4" },
	{ "ext4_li_mtx", (void *)&klpe_ext4_li_mtx, "ext4" },
	{ "ext4_multi_mount_protect", (void *)&klpe_ext4_multi_mount_protect,
	  "ext4" },
	{ "ext4_register_li_request", (void *)&klpe_ext4_register_li_request,
	  "ext4" },
	{ "ext4_remove_li_request", (void *)&klpe_ext4_remove_li_request,
	  "ext4" },
	{ "ext4_setup_super", (void *)&klpe_ext4_setup_super, "ext4" },
	{ "ext4_setup_system_zone", (void *)&klpe_ext4_setup_system_zone,
	  "ext4" },
	{ "parse_options", (void *)&klpe_parse_options, "ext4" },
	{ "crc16", (void *)&klpe_crc16, "crc16" },
	{ "jbd2_journal_clear_err", (void *)&klpe_jbd2_journal_clear_err,
	  "jbd2" },
	{ "jbd2_journal_errno", (void *)&klpe_jbd2_journal_errno, "jbd2" },
	{ "jbd2_journal_flush", (void *)&klpe_jbd2_journal_flush, "jbd2" },
	{ "jbd2_journal_lock_updates", (void *)&klpe_jbd2_journal_lock_updates,
	  "jbd2" },
	{ "jbd2_journal_unlock_updates",
	  (void *)&klpe_jbd2_journal_unlock_updates, "jbd2" },
	{ "jbd2_journal_update_sb_errno",
	  (void *)&klpe_jbd2_journal_update_sb_errno, "jbd2" },
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

int livepatch_bsc1219079_init(void)
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

void livepatch_bsc1219079_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
