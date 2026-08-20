/*
 * livepatch_bsc1271543
 *
 * Fix for CVE-2026-64600, bsc#1271543
 *
 *  Copyright (c) 2026 SUSE
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


#include "livepatch_bsc1271543.h"


/* klp-ccp: from fs/xfs/xfs_linux.h */
#include <linux/types.h>
#include <linux/uuid.h>

typedef unsigned long long	xfs_ino_t;
typedef __s64			xfs_daddr_t;

/* klp-ccp: from fs/xfs/libxfs/xfs_types.h */
typedef uint32_t	prid_t;

typedef uint32_t	xfs_agblock_t;
typedef uint32_t	xfs_agino_t;
typedef uint32_t	xfs_extlen_t;
typedef uint32_t	xfs_agnumber_t;
typedef uint64_t	xfs_extnum_t;

typedef int64_t		xfs_fsize_t;

typedef int64_t		xfs_lsn_t;

typedef uint64_t	xfs_fsblock_t;
typedef uint64_t	xfs_rfsblock_t;
typedef uint64_t	xfs_rtblock_t;
typedef uint64_t	xfs_fileoff_t;
typedef uint64_t	xfs_filblks_t;

#define	XFS_DATA_FORK	0

typedef enum {
	XFS_EXT_NORM, XFS_EXT_UNWRITTEN,
} xfs_exntst_t;

struct xfs_bmbt_irec
{
	xfs_fileoff_t	br_startoff;	/* starting file offset */
	xfs_fsblock_t	br_startblock;	/* starting block number */
	xfs_filblks_t	br_blockcount;	/* number of blocks */
	xfs_exntst_t	br_state;	/* extent state */
};

/* klp-ccp: from fs/xfs/kmem.h */
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
/* klp-ccp: from fs/xfs/mrlock.h */
#include <linux/rwsem.h>

typedef struct {
	struct rw_semaphore	mr_lock;
#if defined(DEBUG) || defined(XFS_WARN)
#error "klp-ccp: non-taken branch"
#endif
} mrlock_t;

/* klp-ccp: from fs/xfs/xfs_linux.h */
#include <linux/semaphore.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/file.h>
#include <linux/filelock.h>
#include <linux/swap.h>
#include <linux/errno.h>
#include <linux/sched/signal.h>
#include <linux/bitops.h>
#include <linux/major.h>
#include <linux/pagemap.h>
#include <linux/vfs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/sort.h>
#include <linux/cpu.h>
#include <linux/notifier.h>
#include <linux/delay.h>
#include <linux/log2.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/ctype.h>
#include <linux/writeback.h>
#include <linux/capability.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/list_sort.h>
#include <linux/ratelimit.h>
#include <linux/rhashtable.h>
#include <linux/xattr.h>
#include <linux/mnt_idmapping.h>
#include <asm/page.h>
#include <asm/div64.h>
#include <asm/param.h>
#include <linux/uaccess.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>
/* klp-ccp: from fs/xfs/xfs_stats.h */
#include <linux/percpu.h>
/* klp-ccp: from fs/xfs/xfs_sysctl.h */
#include <linux/sysctl.h>
/* klp-ccp: from fs/xfs/xfs_super.h */
#include <linux/exportfs.h>
/* klp-ccp: from fs/xfs/xfs_buf.h */
#include <linux/list.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/uio.h>
#include <linux/list_lru.h>

typedef struct xfs_buftarg xfs_buftarg_t;

/* klp-ccp: from fs/xfs/xfs_message.h */
#include <linux/once_lite.h>

/* klp-ccp: from fs/xfs/xfs_linux.h */
#define EFSCORRUPTED	EUCLEAN		/* Filesystem is corrupted */

struct xfs_kobj {
	struct kobject		kobject;
	struct completion	complete;
};

struct xstats {
	struct xfsstats __percpu	*xs_stats;
	struct xfs_kobj			xs_kobj;
};

#define ASSERT(expr)		((void)0)

/* klp-ccp: from fs/xfs/libxfs/xfs_shared.h */
struct xfs_ino_geometry {
	/* Maximum inode count in this filesystem. */
	uint64_t	maxicount;

	/* Actual inode cluster buffer size, in bytes. */
	unsigned int	inode_cluster_size;

	/*
	 * Desired inode cluster buffer size, in bytes.  This value is not
	 * rounded up to at least one filesystem block, which is necessary for
	 * the sole purpose of validating sb_spino_align.  Runtime code must
	 * only ever use inode_cluster_size.
	 */
	unsigned int	inode_cluster_size_raw;

	/* Inode cluster sizes, adjusted to be at least 1 fsb. */
	unsigned int	inodes_per_cluster;
	unsigned int	blocks_per_cluster;

	/* Inode cluster alignment. */
	unsigned int	cluster_align;
	unsigned int	cluster_align_inodes;
	unsigned int	inoalign_mask;	/* mask sb_inoalignmt if used */

	unsigned int	inobt_mxr[2]; /* max inobt btree records */
	unsigned int	inobt_mnr[2]; /* min inobt btree records */
	unsigned int	inobt_maxlevels; /* max inobt btree levels. */

	/* Size of inode allocations under normal operation. */
	unsigned int	ialloc_inos;
	unsigned int	ialloc_blks;

	/* Minimum inode blocks for a sparse allocation. */
	unsigned int	ialloc_min_blks;

	/* stripe unit inode alignment */
	unsigned int	ialloc_align;

	unsigned int	agino_log;	/* #bits for agino in inum */

	/* precomputed default inode attribute fork offset */
	unsigned int	attr_fork_offset;

	/* precomputed value for di_flags2 */
	uint64_t	new_diflags2;

};

/* klp-ccp: from fs/xfs/libxfs/xfs_format.h */
#define XFSLABEL_MAX			12

struct xfs_sb {
	uint32_t	sb_magicnum;	/* magic number == XFS_SB_MAGIC */
	uint32_t	sb_blocksize;	/* logical block size, bytes */
	xfs_rfsblock_t	sb_dblocks;	/* number of data blocks */
	xfs_rfsblock_t	sb_rblocks;	/* number of realtime blocks */
	xfs_rtblock_t	sb_rextents;	/* number of realtime extents */
	uuid_t		sb_uuid;	/* user-visible file system unique id */
	xfs_fsblock_t	sb_logstart;	/* starting block of log if internal */
	xfs_ino_t	sb_rootino;	/* root inode number */
	xfs_ino_t	sb_rbmino;	/* bitmap inode for realtime extents */
	xfs_ino_t	sb_rsumino;	/* summary inode for rt bitmap */
	xfs_agblock_t	sb_rextsize;	/* realtime extent size, blocks */
	xfs_agblock_t	sb_agblocks;	/* size of an allocation group */
	xfs_agnumber_t	sb_agcount;	/* number of allocation groups */
	xfs_extlen_t	sb_rbmblocks;	/* number of rt bitmap blocks */
	xfs_extlen_t	sb_logblocks;	/* number of log blocks */
	uint16_t	sb_versionnum;	/* header version == XFS_SB_VERSION */
	uint16_t	sb_sectsize;	/* volume sector size, bytes */
	uint16_t	sb_inodesize;	/* inode size, bytes */
	uint16_t	sb_inopblock;	/* inodes per block */
	char		sb_fname[XFSLABEL_MAX]; /* file system name */
	uint8_t		sb_blocklog;	/* log2 of sb_blocksize */
	uint8_t		sb_sectlog;	/* log2 of sb_sectsize */
	uint8_t		sb_inodelog;	/* log2 of sb_inodesize */
	uint8_t		sb_inopblog;	/* log2 of sb_inopblock */
	uint8_t		sb_agblklog;	/* log2 of sb_agblocks (rounded up) */
	uint8_t		sb_rextslog;	/* log2 of sb_rextents */
	uint8_t		sb_inprogress;	/* mkfs is in progress, don't mount */
	uint8_t		sb_imax_pct;	/* max % of fs for inode space */
					/* statistics */
	/*
	 * These fields must remain contiguous.  If you really
	 * want to change their layout, make sure you fix the
	 * code in xfs_trans_apply_sb_deltas().
	 */
	uint64_t	sb_icount;	/* allocated inodes */
	uint64_t	sb_ifree;	/* free inodes */
	uint64_t	sb_fdblocks;	/* free data blocks */
	uint64_t	sb_frextents;	/* free realtime extents */
	/*
	 * End contiguous fields.
	 */
	xfs_ino_t	sb_uquotino;	/* user quota inode */
	xfs_ino_t	sb_gquotino;	/* group quota inode */
	uint16_t	sb_qflags;	/* quota flags */
	uint8_t		sb_flags;	/* misc. flags */
	uint8_t		sb_shared_vn;	/* shared version number */
	xfs_extlen_t	sb_inoalignmt;	/* inode chunk alignment, fsblocks */
	uint32_t	sb_unit;	/* stripe or raid unit */
	uint32_t	sb_width;	/* stripe or raid width */
	uint8_t		sb_dirblklog;	/* log2 of dir block size (fsbs) */
	uint8_t		sb_logsectlog;	/* log2 of the log sector size */
	uint16_t	sb_logsectsize;	/* sector size for the log, bytes */
	uint32_t	sb_logsunit;	/* stripe unit size for the log */
	uint32_t	sb_features2;	/* additional feature bits */

	/*
	 * bad features2 field as a result of failing to pad the sb structure to
	 * 64 bits. Some machines will be using this field for features2 bits.
	 * Easiest just to mark it bad and not use it for anything else.
	 *
	 * This is not kept up to date in memory; it is always overwritten by
	 * the value in sb_features2 when formatting the incore superblock to
	 * the disk buffer.
	 */
	uint32_t	sb_bad_features2;

	/* version 5 superblock fields start here */

	/* feature masks */
	uint32_t	sb_features_compat;
	uint32_t	sb_features_ro_compat;
	uint32_t	sb_features_incompat;
	uint32_t	sb_features_log_incompat;

	uint32_t	sb_crc;		/* superblock crc */
	xfs_extlen_t	sb_spino_align;	/* sparse inode chunk alignment */

	xfs_ino_t	sb_pquotino;	/* project quota inode */
	xfs_lsn_t	sb_lsn;		/* last write sequence */
	uuid_t		sb_meta_uuid;	/* metadata file system unique id */

	/* must be padded to 64 bit alignment */
};

#define STARTBLOCKVALBITS	17
#define STARTBLOCKMASKBITS	(15 + 20)
#define STARTBLOCKMASK		\
	(((((xfs_fsblock_t)1) << STARTBLOCKMASKBITS) - 1) << STARTBLOCKVALBITS)

static inline int isnullstartblock(xfs_fsblock_t x)
{
	return ((x) & STARTBLOCKMASK) == STARTBLOCKMASK;
}

/* klp-ccp: from fs/xfs/libxfs/xfs_trans_resv.h */
struct xfs_trans_res {
	uint	tr_logres;	/* log space unit in bytes per log ticket */
	int	tr_logcount;	/* number of log operations per log ticket */
	int	tr_logflags;	/* log flags, currently only used for indicating
				 * a reservation request is permanent or not */
};

struct xfs_trans_resv {
	struct xfs_trans_res	tr_write;	/* extent alloc trans */
	struct xfs_trans_res	tr_itruncate;	/* truncate trans */
	struct xfs_trans_res	tr_rename;	/* rename trans */
	struct xfs_trans_res	tr_link;	/* link trans */
	struct xfs_trans_res	tr_remove;	/* unlink trans */
	struct xfs_trans_res	tr_symlink;	/* symlink trans */
	struct xfs_trans_res	tr_create;	/* create trans */
	struct xfs_trans_res	tr_create_tmpfile; /* create O_TMPFILE trans */
	struct xfs_trans_res	tr_mkdir;	/* mkdir trans */
	struct xfs_trans_res	tr_ifree;	/* inode free trans */
	struct xfs_trans_res	tr_ichange;	/* inode update trans */
	struct xfs_trans_res	tr_growdata;	/* fs data section grow trans */
	struct xfs_trans_res	tr_addafork;	/* add inode attr fork trans */
	struct xfs_trans_res	tr_writeid;	/* write setuid/setgid file */
	struct xfs_trans_res	tr_attrinval;	/* attr fork buffer
						 * invalidation */
	struct xfs_trans_res	tr_attrsetm;	/* set/create an attribute at
						 * mount time */
	struct xfs_trans_res	tr_attrsetrt;	/* set/create an attribute at
						 * runtime */
	struct xfs_trans_res	tr_attrrm;	/* remove an attribute */
	struct xfs_trans_res	tr_clearagi;	/* clear agi unlinked bucket */
	struct xfs_trans_res	tr_growrtalloc;	/* grow realtime allocations */
	struct xfs_trans_res	tr_growrtzero;	/* grow realtime zeroing */
	struct xfs_trans_res	tr_growrtfree;	/* grow realtime freeing */
	struct xfs_trans_res	tr_qm_setqlim;	/* adjust quota limits */
	struct xfs_trans_res	tr_qm_dqalloc;	/* allocate quota on disk */
	struct xfs_trans_res	tr_sb;		/* modify superblock */
	struct xfs_trans_res	tr_fsyncts;	/* update timestamps on fsync */
};

#define M_RES(mp)	(&(mp)->m_resv)

/* klp-ccp: from fs/xfs/xfs_mount.h */
enum {
	XFS_LOWSP_1_PCNT = 0,
	XFS_LOWSP_2_PCNT,
	XFS_LOWSP_3_PCNT,
	XFS_LOWSP_4_PCNT,
	XFS_LOWSP_5_PCNT,
	XFS_LOWSP_MAX,
};

enum {
	XFS_ERR_METADATA,
	XFS_ERR_CLASS_MAX,
};
enum {
	XFS_ERR_DEFAULT,
	XFS_ERR_EIO,
	XFS_ERR_ENOSPC,
	XFS_ERR_ENODEV,
	XFS_ERR_ERRNO_MAX,
};

struct xfs_error_cfg {
	struct xfs_kobj	kobj;
	int		max_retries;
	long		retry_timeout;	/* in jiffies, -1 = infinite */
};

struct xfs_mount {
	struct xfs_sb		m_sb;		/* copy of fs superblock */
	struct super_block	*m_super;
	struct xfs_ail		*m_ail;		/* fs active log item list */
	struct xfs_buf		*m_sb_bp;	/* buffer for superblock */
	char			*m_rtname;	/* realtime device name */
	char			*m_logname;	/* external log device name */
	struct xfs_da_geometry	*m_dir_geo;	/* directory block geometry */
	struct xfs_da_geometry	*m_attr_geo;	/* attribute block geometry */
	struct xlog		*m_log;		/* log specific stuff */
	struct xfs_inode	*m_rbmip;	/* pointer to bitmap inode */
	struct xfs_inode	*m_rsumip;	/* pointer to summary inode */
	struct xfs_inode	*m_rootip;	/* pointer to root directory */
	struct xfs_quotainfo	*m_quotainfo;	/* disk quota information */
	xfs_buftarg_t		*m_ddev_targp;	/* saves taking the address */
	xfs_buftarg_t		*m_logdev_targp;/* ptr to log device */
	xfs_buftarg_t		*m_rtdev_targp;	/* ptr to rt device */
	void __percpu		*m_inodegc;	/* percpu inodegc structures */

	/*
	 * Optional cache of rt summary level per bitmap block with the
	 * invariant that m_rsum_cache[bbno] <= the minimum i for which
	 * rsum[i][bbno] != 0. Reads and writes are serialized by the rsumip
	 * inode lock.
	 */
	uint8_t			*m_rsum_cache;
	struct xfs_mru_cache	*m_filestream;  /* per-mount filestream data */
	struct workqueue_struct *m_buf_workqueue;
	struct workqueue_struct	*m_unwritten_workqueue;
	struct workqueue_struct	*m_reclaim_workqueue;
	struct workqueue_struct	*m_sync_workqueue;
	struct workqueue_struct *m_blockgc_wq;
	struct workqueue_struct *m_inodegc_wq;

	int			m_bsize;	/* fs logical block size */
	uint8_t			m_blkbit_log;	/* blocklog + NBBY */
	uint8_t			m_blkbb_log;	/* blocklog - BBSHIFT */
	uint8_t			m_agno_log;	/* log #ag's */
	uint8_t			m_sectbb_log;	/* sectlog - BBSHIFT */
	uint			m_blockmask;	/* sb_blocksize-1 */
	uint			m_blockwsize;	/* sb_blocksize in words */
	uint			m_blockwmask;	/* blockwsize-1 */
	uint			m_alloc_mxr[2];	/* max alloc btree records */
	uint			m_alloc_mnr[2];	/* min alloc btree records */
	uint			m_bmap_dmxr[2];	/* max bmap btree records */
	uint			m_bmap_dmnr[2];	/* min bmap btree records */
	uint			m_rmap_mxr[2];	/* max rmap btree records */
	uint			m_rmap_mnr[2];	/* min rmap btree records */
	uint			m_refc_mxr[2];	/* max refc btree records */
	uint			m_refc_mnr[2];	/* min refc btree records */
	uint			m_alloc_maxlevels; /* max alloc btree levels */
	uint			m_bm_maxlevels[2]; /* max bmap btree levels */
	uint			m_rmap_maxlevels; /* max rmap btree levels */
	uint			m_refc_maxlevels; /* max refcount btree level */
	unsigned int		m_agbtree_maxlevels; /* max level of all AG btrees */
	xfs_extlen_t		m_ag_prealloc_blocks; /* reserved ag blocks */
	uint			m_alloc_set_aside; /* space we can't use */
	uint			m_ag_max_usable; /* max space per AG */
	int			m_dalign;	/* stripe unit */
	int			m_swidth;	/* stripe width */
	xfs_agnumber_t		m_maxagi;	/* highest inode alloc group */
	uint			m_allocsize_log;/* min write size log bytes */
	uint			m_allocsize_blocks; /* min write size blocks */
	int			m_logbufs;	/* number of log buffers */
	int			m_logbsize;	/* size of each log buffer */
	uint			m_rsumlevels;	/* rt summary levels */
	uint			m_rsumsize;	/* size of rt summary, bytes */
	int			m_fixedfsid[2];	/* unchanged for life of FS */
	uint			m_qflags;	/* quota status flags */
	uint64_t		m_features;	/* active filesystem features */
	uint64_t		m_low_space[XFS_LOWSP_MAX];
	uint64_t		m_low_rtexts[XFS_LOWSP_MAX];
	struct xfs_ino_geometry	m_ino_geo;	/* inode geometry */
	struct xfs_trans_resv	m_resv;		/* precomputed res values */
						/* low free space thresholds */
	unsigned long		m_opstate;	/* dynamic state flags */
	bool			m_always_cow;
	bool			m_fail_unmount;
	bool			m_finobt_nores; /* no per-AG finobt resv. */
	bool			m_update_sb;	/* sb needs update in mount */

	/*
	 * Bitsets of per-fs metadata that have been checked and/or are sick.
	 * Callers must hold m_sb_lock to access these two fields.
	 */
	uint8_t			m_fs_checked;
	uint8_t			m_fs_sick;
	/*
	 * Bitsets of rt metadata that have been checked and/or are sick.
	 * Callers must hold m_sb_lock to access this field.
	 */
	uint8_t			m_rt_checked;
	uint8_t			m_rt_sick;

	/*
	 * End of read-mostly variables. Frequently written variables and locks
	 * should be placed below this comment from now on. The first variable
	 * here is marked as cacheline aligned so they it is separated from
	 * the read-mostly variables.
	 */

	spinlock_t ____cacheline_aligned m_sb_lock; /* sb counter lock */
	struct percpu_counter	m_icount;	/* allocated inodes counter */
	struct percpu_counter	m_ifree;	/* free inodes counter */
	struct percpu_counter	m_fdblocks;	/* free block counter */
	struct percpu_counter	m_frextents;	/* free rt extent counter */

	/*
	 * Count of data device blocks reserved for delayed allocations,
	 * including indlen blocks.  Does not include allocated CoW staging
	 * extents or anything related to the rt device.
	 */
	struct percpu_counter	m_delalloc_blks;
	/*
	 * Global count of allocation btree blocks in use across all AGs. Only
	 * used when perag reservation is enabled. Helps prevent block
	 * reservation from attempting to reserve allocation btree blocks.
	 */
	atomic64_t		m_allocbt_blks;

	struct radix_tree_root	m_perag_tree;	/* per-ag accounting info */
	spinlock_t		m_perag_lock;	/* lock for m_perag_tree */
	uint64_t		m_resblks;	/* total reserved blocks */
	uint64_t		m_resblks_avail;/* available reserved blocks */
	uint64_t		m_resblks_save;	/* reserved blks @ remount,ro */
	struct delayed_work	m_reclaim_work;	/* background inode reclaim */
	struct xfs_kobj		m_kobj;
	struct xfs_kobj		m_error_kobj;
	struct xfs_kobj		m_error_meta_kobj;
	struct xfs_error_cfg	m_error_cfg[XFS_ERR_CLASS_MAX][XFS_ERR_ERRNO_MAX];
	struct xstats		m_stats;	/* per-fs stats */
	xfs_agnumber_t		m_agfrotor;	/* last ag where space found */
	atomic_t		m_agirotor;	/* last ag dir inode alloced */

	/* Memory shrinker to throttle and reprioritize inodegc */
	struct shrinker		m_inodegc_shrinker;
	/*
	 * Workqueue item so that we can coalesce multiple inode flush attempts
	 * into a single flush.
	 */
	struct work_struct	m_flush_inodes_work;

	/*
	 * Generation of the filesysyem layout.  This is incremented by each
	 * growfs, and used by the pNFS server to ensure the client updates
	 * its view of the block device once it gets a layout that might
	 * reference the newly added blocks.  Does not need to be persistent
	 * as long as we only allow file system size increments, but if we
	 * ever support shrinks it would have to be persisted in addition
	 * to various other kinds of pain inflicted on the pNFS server.
	 */
	uint32_t		m_generation;
	struct mutex		m_growlock;	/* growfs mutex */

#ifdef DEBUG
#error "klp-ccp: non-taken branch"
#endif
	struct cpumask		m_inodegc_cpumask;
};

/* klp-ccp: from fs/xfs/libxfs/xfs_inode_buf.h */
struct xfs_imap {
	xfs_daddr_t	im_blkno;	/* starting BB of inode chunk */
	unsigned short	im_len;		/* length in BBs of inode chunk */
	unsigned short	im_boffset;	/* inode offset in block in bytes */
};

/* klp-ccp: from fs/xfs/libxfs/xfs_inode_fork.h */
struct xfs_ifork {
	int64_t			if_bytes;	/* bytes in if_u1 */
	struct xfs_btree_block	*if_broot;	/* file's incore btree root */
	unsigned int		if_seq;		/* fork mod counter */
	int			if_height;	/* height of the extent tree */
	union {
		void		*if_root;	/* extent tree root */
		char		*if_data;	/* inline file data */
	} if_u1;
	xfs_extnum_t		if_nextents;	/* # of extents in this fork */
	short			if_broot_bytes;	/* bytes allocated for root */
	int8_t			if_format;	/* format of this fork */
	uint8_t			if_needextents;	/* extents have not been read */
};

extern void xfs_ifork_init_cow(struct xfs_inode *ip);

/* klp-ccp: from fs/xfs/xfs_inode.h */
typedef struct xfs_inode {
	/* Inode linking and identification information. */
	struct xfs_mount	*i_mount;	/* fs mount struct ptr */
	struct xfs_dquot	*i_udquot;	/* user dquot */
	struct xfs_dquot	*i_gdquot;	/* group dquot */
	struct xfs_dquot	*i_pdquot;	/* project dquot */

	/* Inode location stuff */
	xfs_ino_t		i_ino;		/* inode number (agno/agino)*/
	struct xfs_imap		i_imap;		/* location for xfs_imap() */

	/* Extent information. */
	struct xfs_ifork	*i_cowfp;	/* copy on write extents */
	struct xfs_ifork	i_df;		/* data fork */
	struct xfs_ifork	i_af;		/* attribute fork */

	/* Transaction and locking information. */
	struct xfs_inode_log_item *i_itemp;	/* logging information */
	mrlock_t		i_lock;		/* inode lock */
	atomic_t		i_pincount;	/* inode pin count */
	struct llist_node	i_gclist;	/* deferred inactivation list */

	/*
	 * Bitsets of inode metadata that have been checked and/or are sick.
	 * Callers must hold i_flags_lock before accessing this field.
	 */
	uint16_t		i_checked;
	uint16_t		i_sick;

	spinlock_t		i_flags_lock;	/* inode i_flags lock */
	/* Miscellaneous state. */
	unsigned long		i_flags;	/* see defined flags below */
	uint64_t		i_delayed_blks;	/* count of delay alloc blks */
	xfs_fsize_t		i_disk_size;	/* number of bytes in file */
	xfs_rfsblock_t		i_nblocks;	/* # of direct & btree blocks */
	prid_t			i_projid;	/* owner's project id */
	xfs_extlen_t		i_extsize;	/* basic/minimum extent size */
	/* cowextsize is only used for v3 inodes, flushiter for v1/2 */
	union {
		xfs_extlen_t	i_cowextsize;	/* basic cow extent size */
		uint16_t	i_flushiter;	/* incremented on flush */
	};
	uint8_t			i_forkoff;	/* attr fork offset >> 3 */
	uint16_t		i_diflags;	/* XFS_DIFLAG_... */
	uint64_t		i_diflags2;	/* XFS_DIFLAG2_... */
	struct timespec64	i_crtime;	/* time created */

	/*
	 * Unlinked list pointers.  These point to the next and previous inodes
	 * in the AGI unlinked bucket list, respectively.  These fields can
	 * only be updated with the AGI locked.
	 *
	 * i_next_unlinked caches di_next_unlinked.
	 */
	xfs_agino_t		i_next_unlinked;

	/*
	 * If the inode is not on an unlinked list, this field is zero.  If the
	 * inode is the first element in an unlinked list, this field is
	 * NULLAGINO.  Otherwise, i_prev_unlinked points to the previous inode
	 * in the unlinked list.
	 */
	xfs_agino_t		i_prev_unlinked;

	/* VFS inode */
	struct inode		i_vnode;	/* embedded VFS inode */

	/* pending io completions */
	spinlock_t		i_ioend_lock;
	struct work_struct	i_ioend_work;
	struct list_head	i_ioend_list;
} xfs_inode_t;

#define	XFS_ILOCK_EXCL		(1u << 2)

void		xfs_iunlock(xfs_inode_t *, uint);

xfs_extlen_t	xfs_get_cowextsz_hint(struct xfs_inode *ip);

/* klp-ccp: from fs/xfs/xfs_trans.h */
typedef struct xfs_trans xfs_trans_t;

int		xfs_trans_commit(struct xfs_trans *);

void		xfs_trans_cancel(xfs_trans_t *);

int xfs_trans_alloc_inode(struct xfs_inode *ip, struct xfs_trans_res *resv,
		unsigned int dblocks, unsigned int rblocks, bool force,
		struct xfs_trans **tpp);

/* klp-ccp: from fs/xfs/libxfs/xfs_bmap.h */
#define XFS_BMAPI_PREALLOC	(1u << 3) /* preallocating unwritten space */

#define XFS_BMAPI_COWFORK	(1u << 8)

#define	DELAYSTARTBLOCK		((xfs_fsblock_t)-1LL)

void	xfs_trim_extent(struct xfs_bmbt_irec *irec, xfs_fileoff_t bno,
		xfs_filblks_t len);

int	xfs_bmapi_read(struct xfs_inode *ip, xfs_fileoff_t bno,
		xfs_filblks_t len, struct xfs_bmbt_irec *mval,
		int *nmap, uint32_t flags);
int	xfs_bmapi_write(struct xfs_trans *tp, struct xfs_inode *ip,
		xfs_fileoff_t bno, xfs_filblks_t len, uint32_t flags,
		xfs_extlen_t total, struct xfs_bmbt_irec *mval, int *nmap);

/* klp-ccp: from fs/xfs/xfs_trace.h */
#if !defined(_TRACE_XFS_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

/* klp-ccp: not from file */
#undef inline

#include "../klp_trace.h"

/* klp-ccp: from fs/xfs/xfs_trace.h */
KLPR_TRACE_EVENT(xfs, xfs_reflink_convert_cow, \
		TP_PROTO(struct xfs_inode *ip, struct xfs_bmbt_irec *irec), \
		TP_ARGS(ip, irec));

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_XFS_H */

#include <trace/define_trace.h>

/* klp-ccp: from fs/xfs/xfs_icache.h */
void xfs_inode_set_cowblocks_tag(struct xfs_inode *ip);

/* klp-ccp: from fs/xfs/libxfs/xfs_bmap_btree.h */
#define XFS_BM_MAXLEVELS(mp,w)		((mp)->m_bm_maxlevels[(w)])

/* klp-ccp: from fs/xfs/libxfs/xfs_trans_space.h */
#define	XFS_EXTENTADD_SPACE_RES(mp,w)	(XFS_BM_MAXLEVELS(mp,w) - 1)

#define	XFS_DIOSTRAT_SPACE_RES(mp, v)	\
	(XFS_EXTENTADD_SPACE_RES(mp, XFS_DATA_FORK) + (v))

/* klp-ccp: from fs/xfs/xfs_reflink.h */
int klpp_xfs_reflink_allocate_cow(struct xfs_inode *ip, struct xfs_bmbt_irec *imap,
		struct xfs_bmbt_irec *cmap, bool *shared, uint *lockmode,
		bool convert_now);

/* klp-ccp: from include/linux/compiler_types.h */
#define inline inline __gnu_inline __inline_maybe_unused notrace

/* klp-ccp: from fs/xfs/xfs_iomap.h */
#include <linux/iomap.h>

static inline xfs_filblks_t
xfs_aligned_fsb_count(
	xfs_fileoff_t		offset_fsb,
	xfs_filblks_t		count_fsb,
	xfs_extlen_t		extsz)
{
	if (extsz) {
		xfs_extlen_t	align;

		div_u64_rem(offset_fsb, extsz, &align);
		if (align)
			count_fsb += align;
		div_u64_rem(count_fsb, extsz, &align);
		if (align)
			count_fsb += extsz - align;
	}

	return count_fsb;
}

/* klp-ccp: from fs/xfs/xfs_reflink.c */
extern int
xfs_reflink_convert_cow_locked(
	struct xfs_inode	*ip,
	xfs_fileoff_t		offset_fsb,
	xfs_filblks_t		count_fsb);

extern int
xfs_find_trim_cow_extent(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	struct xfs_bmbt_irec	*cmap,
	bool			*shared,
	bool			*found);

static int
xfs_reflink_convert_unwritten(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	struct xfs_bmbt_irec	*cmap,
	bool			convert_now)
{
	xfs_fileoff_t		offset_fsb = imap->br_startoff;
	xfs_filblks_t		count_fsb = imap->br_blockcount;
	int			error;

	/*
	 * cmap might larger than imap due to cowextsize hint.
	 */
	xfs_trim_extent(cmap, offset_fsb, count_fsb);

	/*
	 * COW fork extents are supposed to remain unwritten until we're ready
	 * to initiate a disk write.  For direct I/O we are going to write the
	 * data and need the conversion, but for buffered writes we're done.
	 */
	if (!convert_now || cmap->br_state == XFS_EXT_NORM)
		return 0;

	klpr_trace_xfs_reflink_convert_cow(ip, cmap);

	error = xfs_reflink_convert_cow_locked(ip, offset_fsb, count_fsb);
	if (!error)
		cmap->br_state = XFS_EXT_NORM;

	return error;
}

static int
klpp_xfs_reflink_fill_cow_hole(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	struct xfs_bmbt_irec	*cmap,
	bool			*shared,
	uint			*lockmode,
	bool			convert_now)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	xfs_filblks_t		resaligned;
	xfs_extlen_t		resblks;
	unsigned int		seq_before = READ_ONCE(ip->i_df.if_seq);
	int			nimaps;
	int			error;
	bool			found;

	resaligned = xfs_aligned_fsb_count(imap->br_startoff,
		imap->br_blockcount, xfs_get_cowextsz_hint(ip));
	resblks = XFS_DIOSTRAT_SPACE_RES(mp, resaligned);

	xfs_iunlock(ip, *lockmode);
	*lockmode = 0;

	error = xfs_trans_alloc_inode(ip, &M_RES(mp)->tr_write, resblks, 0,
			false, &tp);
	if (error)
		return error;

	*lockmode = XFS_ILOCK_EXCL;

	/*
	 * The data fork mapping may have changed while we dropped the ILOCK
	 * (a racing O_DIRECT writer under IOLOCK_SHARED can complete a full
	 * CoW cycle including xfs_reflink_end_cow(), which remaps this offset
	 * and drops the refcount of the old shared block).  Re-read it so the
	 * shared-status recheck below and the caller's in-place iomap both
	 * operate on the current mapping rather than a stale physical block.
	 */
	if (seq_before != READ_ONCE(ip->i_df.if_seq)) {
		nimaps = 1;
		error = xfs_bmapi_read(ip, imap->br_startoff,
				imap->br_blockcount, imap, &nimaps, 0);
		if (error)
			goto out_trans_cancel;
	}

	error = xfs_find_trim_cow_extent(ip, imap, cmap, shared, &found);
	if (error || !*shared)
		goto out_trans_cancel;

	if (found) {
		xfs_trans_cancel(tp);
		goto convert;
	}

	/* Allocate the entire reservation as unwritten blocks. */
	nimaps = 1;
	error = xfs_bmapi_write(tp, ip, imap->br_startoff, imap->br_blockcount,
			XFS_BMAPI_COWFORK | XFS_BMAPI_PREALLOC, 0, cmap,
			&nimaps);
	if (error)
		goto out_trans_cancel;

	xfs_inode_set_cowblocks_tag(ip);
	error = xfs_trans_commit(tp);
	if (error)
		return error;

	/*
	 * Allocation succeeded but the requested range was not even partially
	 * satisfied?  Bail out!
	 */
	if (nimaps == 0)
		return -ENOSPC;

convert:
	return xfs_reflink_convert_unwritten(ip, imap, cmap, convert_now);

out_trans_cancel:
	xfs_trans_cancel(tp);
	return error;
}

static int
klpp_xfs_reflink_fill_delalloc(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	struct xfs_bmbt_irec	*cmap,
	bool			*shared,
	uint			*lockmode,
	bool			convert_now)
{
	struct xfs_mount	*mp = ip->i_mount;
	struct xfs_trans	*tp;
	int			nimaps;
	int			error;
	bool			found;

	do {
		unsigned int	seq_before = READ_ONCE(ip->i_df.if_seq);

		xfs_iunlock(ip, *lockmode);
		*lockmode = 0;

		error = xfs_trans_alloc_inode(ip, &M_RES(mp)->tr_write, 0, 0,
				false, &tp);
		if (error)
			return error;

		*lockmode = XFS_ILOCK_EXCL;

		/*
		 * The data fork mapping may have changed while we dropped the
		 * ILOCK (a racing O_DIRECT writer under IOLOCK_SHARED can
		 * complete a full CoW cycle including xfs_reflink_end_cow(),
		 * which remaps this offset and drops the refcount of the old
		 * shared block).  Re-read it so the shared-status recheck
		 * below and the caller's in-place iomap both operate on the
		 * current mapping rather than a stale physical block.
		 */
		if (seq_before != READ_ONCE(ip->i_df.if_seq)) {
			nimaps = 1;
			error = xfs_bmapi_read(ip, imap->br_startoff,
					imap->br_blockcount, imap, &nimaps, 0);
			if (error)
				goto out_trans_cancel;
		}

		error = xfs_find_trim_cow_extent(ip, imap, cmap, shared,
				&found);
		if (error || !*shared)
			goto out_trans_cancel;

		if (found) {
			xfs_trans_cancel(tp);
			break;
		}

		ASSERT(isnullstartblock(cmap->br_startblock) ||
		       cmap->br_startblock == DELAYSTARTBLOCK);

		/*
		 * Replace delalloc reservation with an unwritten extent.
		 */
		nimaps = 1;
		error = xfs_bmapi_write(tp, ip, cmap->br_startoff,
				cmap->br_blockcount,
				XFS_BMAPI_COWFORK | XFS_BMAPI_PREALLOC, 0,
				cmap, &nimaps);
		if (error)
			goto out_trans_cancel;

		xfs_inode_set_cowblocks_tag(ip);
		error = xfs_trans_commit(tp);
		if (error)
			return error;

		/*
		 * Allocation succeeded but the requested range was not even
		 * partially satisfied?  Bail out!
		 */
		if (nimaps == 0)
			return -ENOSPC;
	} while (cmap->br_startoff + cmap->br_blockcount <= imap->br_startoff);

	return xfs_reflink_convert_unwritten(ip, imap, cmap, convert_now);

out_trans_cancel:
	xfs_trans_cancel(tp);
	return error;
}

int
klpp_xfs_reflink_allocate_cow(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	struct xfs_bmbt_irec	*cmap,
	bool			*shared,
	uint			*lockmode,
	bool			convert_now)
{
	int			error;
	bool			found;

	ASSERT(xfs_isilocked(ip, XFS_ILOCK_EXCL));
	if (!ip->i_cowfp) {
		ASSERT(!xfs_is_reflink_inode(ip));
		xfs_ifork_init_cow(ip);
	}

	error = xfs_find_trim_cow_extent(ip, imap, cmap, shared, &found);
	if (error || !*shared)
		return error;

	/* CoW fork has a real extent */
	if (found)
		return xfs_reflink_convert_unwritten(ip, imap, cmap,
				convert_now);

	/*
	 * CoW fork does not have an extent and data extent is shared.
	 * Allocate a real extent in the CoW fork.
	 */
	if (cmap->br_startoff > imap->br_startoff)
		return klpp_xfs_reflink_fill_cow_hole(ip, imap, cmap, shared,
				lockmode, convert_now);

	/*
	 * CoW fork has a delalloc reservation. Replace it with a real extent.
	 * There may or may not be a data fork mapping.
	 */
	if (isnullstartblock(cmap->br_startblock) ||
	    cmap->br_startblock == DELAYSTARTBLOCK)
		return klpp_xfs_reflink_fill_delalloc(ip, imap, cmap, shared,
				lockmode, convert_now);

	/* Shouldn't get here. */
	ASSERT(0);
	return -EFSCORRUPTED;
}


#include <linux/livepatch.h>

extern typeof(__traceiter_xfs_reflink_convert_cow)
	 __traceiter_xfs_reflink_convert_cow
	 KLP_RELOC_SYMBOL(xfs, xfs, __traceiter_xfs_reflink_convert_cow);
extern typeof(__tracepoint_xfs_reflink_convert_cow)
	 __tracepoint_xfs_reflink_convert_cow
	 KLP_RELOC_SYMBOL(xfs, xfs, __tracepoint_xfs_reflink_convert_cow);
extern typeof(xfs_bmapi_read) xfs_bmapi_read
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_bmapi_read);
extern typeof(xfs_bmapi_write) xfs_bmapi_write
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_bmapi_write);
extern typeof(xfs_find_trim_cow_extent) xfs_find_trim_cow_extent
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_find_trim_cow_extent);
extern typeof(xfs_get_cowextsz_hint) xfs_get_cowextsz_hint
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_get_cowextsz_hint);
extern typeof(xfs_ifork_init_cow) xfs_ifork_init_cow
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_ifork_init_cow);
extern typeof(xfs_inode_set_cowblocks_tag) xfs_inode_set_cowblocks_tag
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_inode_set_cowblocks_tag);
extern typeof(xfs_iunlock) xfs_iunlock KLP_RELOC_SYMBOL(xfs, xfs, xfs_iunlock);
extern typeof(xfs_reflink_convert_cow_locked) xfs_reflink_convert_cow_locked
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_reflink_convert_cow_locked);
extern typeof(xfs_trans_alloc_inode) xfs_trans_alloc_inode
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_trans_alloc_inode);
extern typeof(xfs_trans_cancel) xfs_trans_cancel
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_trans_cancel);
extern typeof(xfs_trans_commit) xfs_trans_commit
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_trans_commit);
extern typeof(xfs_trim_extent) xfs_trim_extent
	 KLP_RELOC_SYMBOL(xfs, xfs, xfs_trim_extent);
