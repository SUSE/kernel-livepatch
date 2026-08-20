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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from fs/xfs/xfs_linux.h */
#include <linux/types.h>
#include <linux/uuid.h>

typedef unsigned long long	xfs_ino_t;
typedef __s64			xfs_daddr_t;

/* klp-ccp: from fs/xfs/libxfs/xfs_types.h */
typedef uint32_t	xfs_agblock_t;

typedef uint32_t	xfs_extlen_t;
typedef uint32_t	xfs_agnumber_t;
typedef int32_t		xfs_extnum_t;
typedef int16_t		xfs_aextnum_t;
typedef int64_t		xfs_fsize_t;

typedef int64_t		xfs_lsn_t;
typedef int32_t		xfs_tid_t;

typedef uint64_t	xfs_fsblock_t;
typedef uint64_t	xfs_rfsblock_t;
typedef uint64_t	xfs_rtblock_t;
typedef uint64_t	xfs_fileoff_t;
typedef uint64_t	xfs_filblks_t;

#define	XFS_DATA_FORK	0

struct xfs_iext_cursor {
	struct xfs_iext_leaf	*leaf;
	int			pos;
};

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
#include <linux/buffer_head.h>
#include <linux/uio.h>
#include <linux/list_lru.h>

typedef struct xfs_buftarg xfs_buftarg_t;

/* klp-ccp: from fs/xfs/xfs_linux.h */
struct xfs_kobj {
	struct kobject		kobject;
	struct completion	complete;
};

struct xstats {
	struct xfsstats __percpu	*xs_stats;
	struct xfs_kobj			xs_kobj;
};

static inline __u32 xfs_do_mod(void *a, __u32 b, int n)
{
	switch (n) {
		case 4:
			return *(__u32 *)a % b;
		case 8:
			{
			__u64	c = *(__u64 *)a;
			return do_div(c, b);
			}
	}

	/* NOTREACHED */
	return 0;
}

#define do_mod(a, b)	xfs_do_mod(&(a), (b), sizeof(a))

#define ASSERT(expr)	((void)0)

# define STATIC static

/* klp-ccp: from fs/xfs/libxfs/xfs_shared.h */
struct xfs_trans;

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
	struct xfs_trans_res	tr_qm_quotaoff;	/* turn quota off */
	struct xfs_trans_res	tr_qm_equotaoff;/* end of turn quota off */
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
	struct super_block	*m_super;
	xfs_tid_t		m_tid;		/* next unused tid for fs */
	struct xfs_ail		*m_ail;		/* fs active log item list */

	struct xfs_sb		m_sb;		/* copy of fs superblock */
	spinlock_t		m_sb_lock;	/* sb counter lock */
	struct percpu_counter	m_icount;	/* allocated inodes counter */
	struct percpu_counter	m_ifree;	/* free inodes counter */
	struct percpu_counter	m_fdblocks;	/* free block counter */

	struct xfs_buf		*m_sb_bp;	/* buffer for superblock */
	char			*m_fsname;	/* filesystem name */
	int			m_fsname_len;	/* strlen of fs name */
	char			*m_rtname;	/* realtime device name */
	char			*m_logname;	/* external log device name */
	int			m_bsize;	/* fs logical block size */
	xfs_agnumber_t		m_agfrotor;	/* last ag where space found */
	xfs_agnumber_t		m_agirotor;	/* last ag dir inode alloced */
	spinlock_t		m_agirotor_lock;/* .. and lock protecting it */
	xfs_agnumber_t		m_maxagi;	/* highest inode alloc group */
	uint			m_readio_log;	/* min read size log bytes */
	uint			m_readio_blocks; /* min read size blocks */
	uint			m_writeio_log;	/* min write size log bytes */
	uint			m_writeio_blocks; /* min write size blocks */
	struct xfs_da_geometry	*m_dir_geo;	/* directory block geometry */
	struct xfs_da_geometry	*m_attr_geo;	/* attribute block geometry */
	struct xlog		*m_log;		/* log specific stuff */
	int			m_logbufs;	/* number of log buffers */
	int			m_logbsize;	/* size of each log buffer */
	uint			m_rsumlevels;	/* rt summary levels */
	uint			m_rsumsize;	/* size of rt summary, bytes */
	struct xfs_inode	*m_rbmip;	/* pointer to bitmap inode */
	struct xfs_inode	*m_rsumip;	/* pointer to summary inode */
	struct xfs_inode	*m_rootip;	/* pointer to root directory */
	struct xfs_quotainfo	*m_quotainfo;	/* disk quota information */
	xfs_buftarg_t		*m_ddev_targp;	/* saves taking the address */
	xfs_buftarg_t		*m_logdev_targp;/* ptr to log device */
	xfs_buftarg_t		*m_rtdev_targp;	/* ptr to rt device */
	uint8_t			m_blkbit_log;	/* blocklog + NBBY */
	uint8_t			m_blkbb_log;	/* blocklog - BBSHIFT */
	uint8_t			m_agno_log;	/* log #ag's */
	uint8_t			m_agino_log;	/* #bits for agino in inum */
	uint			m_inode_cluster_size;/* min inode buf size */
	uint			m_blockmask;	/* sb_blocksize-1 */
	uint			m_blockwsize;	/* sb_blocksize in words */
	uint			m_blockwmask;	/* blockwsize-1 */
	uint			m_alloc_mxr[2];	/* max alloc btree records */
	uint			m_alloc_mnr[2];	/* min alloc btree records */
	uint			m_bmap_dmxr[2];	/* max bmap btree records */
	uint			m_bmap_dmnr[2];	/* min bmap btree records */
	uint			m_inobt_mxr[2];	/* max inobt btree records */
	uint			m_inobt_mnr[2];	/* min inobt btree records */
	uint			m_rmap_mxr[2];	/* max rmap btree records */
	uint			m_rmap_mnr[2];	/* min rmap btree records */
	uint			m_refc_mxr[2];	/* max refc btree records */
	uint			m_refc_mnr[2];	/* min refc btree records */
	uint			m_ag_maxlevels;	/* XFS_AG_MAXLEVELS */
	uint			m_bm_maxlevels[2]; /* XFS_BM_MAXLEVELS */
	uint			m_in_maxlevels;	/* max inobt btree levels. */
	uint			m_rmap_maxlevels; /* max rmap btree levels */
	uint			m_refc_maxlevels; /* max refcount btree level */
	xfs_extlen_t		m_ag_prealloc_blocks; /* reserved ag blocks */
	uint			m_alloc_set_aside; /* space we can't use */
	uint			m_ag_max_usable; /* max space per AG */
	struct radix_tree_root	m_perag_tree;	/* per-ag accounting info */
	spinlock_t		m_perag_lock;	/* lock for m_perag_tree */
	struct mutex		m_growlock;	/* growfs mutex */
	int			m_fixedfsid[2];	/* unchanged for life of FS */
	uint			m_dmevmask;	/* DMI events for this FS */
	uint64_t		m_flags;	/* global mount flags */
	bool			m_inotbt_nores; /* no per-AG finobt resv. */
	int			m_ialloc_inos;	/* inodes in inode allocation */
	int			m_ialloc_blks;	/* blocks in inode allocation */
	int			m_ialloc_min_blks;/* min blocks in sparse inode
						   * allocation */
	int			m_inoalign_mask;/* mask sb_inoalignmt if used */
	uint			m_qflags;	/* quota status flags */
	struct xfs_trans_resv	m_resv;		/* precomputed res values */
	uint64_t		m_maxicount;	/* maximum inode count */
	uint64_t		m_resblks;	/* total reserved blocks */
	uint64_t		m_resblks_avail;/* available reserved blocks */
	uint64_t		m_resblks_save;	/* reserved blks @ remount,ro */
	int			m_dalign;	/* stripe unit */
	int			m_swidth;	/* stripe width */
	int			m_sinoalign;	/* stripe unit inode alignment */
	uint8_t			m_sectbb_log;	/* sectlog - BBSHIFT */
	const struct xfs_nameops *m_dirnameops;	/* vector of dir name ops */
	const struct xfs_dir_ops *m_dir_inode_ops; /* vector of dir inode ops */
	const struct xfs_dir_ops *m_nondir_inode_ops; /* !dir inode ops */
	uint			m_chsize;	/* size of next field */
	atomic_t		m_active_trans;	/* number trans frozen */
	struct xfs_mru_cache	*m_filestream;  /* per-mount filestream data */
	struct delayed_work	m_reclaim_work;	/* background inode reclaim */
	struct delayed_work	m_eofblocks_work; /* background eof blocks
						     trimming */
	struct delayed_work	m_cowblocks_work; /* background cow blocks
						     trimming */
	bool			m_update_sb;	/* sb needs update in mount */
	int64_t			m_low_space[XFS_LOWSP_MAX];
						/* low free space thresholds */
	struct xfs_kobj		m_kobj;
	struct xfs_kobj		m_error_kobj;
	struct xfs_kobj		m_error_meta_kobj;
	struct xfs_error_cfg	m_error_cfg[XFS_ERR_CLASS_MAX][XFS_ERR_ERRNO_MAX];
	struct xstats		m_stats;	/* per-fs stats */

	struct workqueue_struct *m_buf_workqueue;
	struct workqueue_struct	*m_data_workqueue;
	struct workqueue_struct	*m_unwritten_workqueue;
	struct workqueue_struct	*m_cil_workqueue;
	struct workqueue_struct	*m_reclaim_workqueue;
	struct workqueue_struct	*m_log_workqueue;
	struct workqueue_struct *m_eofblocks_workqueue;
	struct workqueue_struct	*m_sync_workqueue;

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

	bool			m_fail_unmount;
#ifdef DEBUG
#error "klp-ccp: non-taken branch"
#endif
};

/* klp-ccp: from fs/xfs/libxfs/xfs_defer.h */
#define XFS_DEFER_OPS_NR_INODES	2	/* join up to two inodes */
#define XFS_DEFER_OPS_NR_BUFS	2	/* join up to two buffers */

struct xfs_defer_ops {
	bool			dop_committed;	/* did any trans commit? */
	bool			dop_low;	/* alloc in low mode */
	struct list_head	dop_intake;	/* unlogged pending work */
	struct list_head	dop_pending;	/* logged pending work */

	/* relog these with each roll */
	struct xfs_inode	*dop_inodes[XFS_DEFER_OPS_NR_INODES];
	struct xfs_buf		*dop_bufs[XFS_DEFER_OPS_NR_BUFS];
};

static int (*klpe_xfs_defer_finish)(struct xfs_trans **tp, struct xfs_defer_ops *dop);
static void (*klpe_xfs_defer_cancel)(struct xfs_defer_ops *dop);
static void (*klpe_xfs_defer_init)(struct xfs_defer_ops *dop, xfs_fsblock_t *fbp);

/* klp-ccp: from fs/xfs/libxfs/xfs_inode_buf.h */
struct xfs_icdinode {
	int8_t		di_version;	/* inode version */
	int8_t		di_format;	/* format of di_c data */
	uint16_t	di_flushiter;	/* incremented on flush */
	uint16_t	di_projid_lo;	/* lower part of owner's project id */
	uint16_t	di_projid_hi;	/* higher part of owner's project id */
	xfs_fsize_t	di_size;	/* number of bytes in file */
	xfs_rfsblock_t	di_nblocks;	/* # of direct & btree blocks used */
	xfs_extlen_t	di_extsize;	/* basic/minimum extent size for file */
	xfs_extnum_t	di_nextents;	/* number of extents in data fork */
	xfs_aextnum_t	di_anextents;	/* number of extents in attribute fork*/
	uint8_t		di_forkoff;	/* attr fork offs, <<3 for 64b align */
	int8_t		di_aformat;	/* format of attr fork's data */
	uint32_t	di_dmevmask;	/* DMIG event mask */
	uint16_t	di_dmstate;	/* DMIG state info */
	uint16_t	di_flags;	/* random flags, XFS_DIFLAG_... */

	uint64_t	di_flags2;	/* more random flags */
	uint32_t	di_cowextsize;	/* basic cow extent size for file */

	struct timespec64 di_crtime;	/* time created */
};

struct xfs_imap {
	xfs_daddr_t	im_blkno;	/* starting BB of inode chunk */
	unsigned short	im_len;		/* length in BBs of inode chunk */
	unsigned short	im_boffset;	/* inode offset in block in bytes */
};

/* klp-ccp: from fs/xfs/libxfs/xfs_inode_fork.h */
typedef struct xfs_ifork {
	int			if_bytes;	/* bytes in if_u1 */
	int			if_real_bytes;	/* bytes allocated in if_u1 */
	struct xfs_btree_block	*if_broot;	/* file's incore btree root */
	short			if_broot_bytes;	/* bytes allocated for root */
	unsigned char		if_flags;	/* per-fork flags */
	int			if_height;	/* height of the extent tree */
	union {
		void		*if_root;	/* extent tree root */
		char		*if_data;	/* inline file data */
	} if_u1;
} xfs_ifork_t;

static bool		(*klpe_xfs_iext_lookup_extent)(struct xfs_inode *ip,
			struct xfs_ifork *ifp, xfs_fileoff_t bno,
			struct xfs_iext_cursor *cur,
			struct xfs_bmbt_irec *gotp);

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
	xfs_ifork_t		*i_afp;		/* attribute fork pointer */
	xfs_ifork_t		*i_cowfp;	/* copy on write extents */
	xfs_ifork_t		i_df;		/* data fork */

	/* operations vectors */
	const struct xfs_dir_ops *d_ops;		/* directory ops vector */

	/* Transaction and locking information. */
	struct xfs_inode_log_item *i_itemp;	/* logging information */
	mrlock_t		i_lock;		/* inode lock */
	mrlock_t		i_mmaplock;	/* inode mmap IO lock */
	atomic_t		i_pincount;	/* inode pin count */
	spinlock_t		i_flags_lock;	/* inode i_flags lock */
	/* Miscellaneous state. */
	unsigned long		i_flags;	/* see defined flags below */
	unsigned int		i_delayed_blks;	/* count of delay alloc blks */

	struct xfs_icdinode	i_d;		/* most of ondisk inode */

	xfs_extnum_t		i_cnextents;	/* # of extents in cow fork */
	unsigned int		i_cformat;	/* format of cow fork */

	/* VFS inode */
	struct inode		i_vnode;	/* embedded VFS inode */
} xfs_inode_t;

#define	XFS_ILOCK_EXCL		(1<<2)

static void		(*klpe_xfs_ilock)(xfs_inode_t *, uint);

static void		(*klpe_xfs_iunlock)(xfs_inode_t *, uint);

static xfs_extlen_t	(*klpe_xfs_get_cowextsz_hint)(struct xfs_inode *ip);

/* klp-ccp: from fs/xfs/xfs_trans.h */
typedef struct xfs_trans 

#if defined(DEBUG) || defined(XFS_WARN)
#error "klp-ccp: non-taken branch"
#endif
 xfs_trans_t;

static int		(*klpe_xfs_trans_alloc)(struct xfs_mount *mp, struct xfs_trans_res *resp,
			uint blocks, uint rtextents, uint flags,
			struct xfs_trans **tpp);

static void		(*klpe_xfs_trans_ijoin)(struct xfs_trans *, struct xfs_inode *, uint);

static int		(*klpe_xfs_trans_commit)(struct xfs_trans *);

static void		(*klpe_xfs_trans_cancel)(xfs_trans_t *);

/* klp-ccp: from fs/xfs/libxfs/xfs_bmap.h */
#define XFS_BMAPI_PREALLOC	0x008	/* preallocation op: unwritten space */

#define XFS_BMAPI_COWFORK	0x200

static void	(*klpe_xfs_trim_extent)(struct xfs_bmbt_irec *irec, xfs_fileoff_t bno,
		xfs_filblks_t len);

static int	(*klpe_xfs_bmapi_read)(struct xfs_inode *ip, xfs_fileoff_t bno,
		xfs_filblks_t len, struct xfs_bmbt_irec *mval,
		int *nmap, int flags);
static int	(*klpe_xfs_bmapi_write)(struct xfs_trans *tp, struct xfs_inode *ip,
		xfs_fileoff_t bno, xfs_filblks_t len, int flags,
		xfs_fsblock_t *firstblock, xfs_extlen_t total,
		struct xfs_bmbt_irec *mval, int *nmap,
		struct xfs_defer_ops *dfops);

/* klp-ccp: from fs/xfs/xfs_trace.h */
#if !defined(_TRACE_XFS_H) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_XFS_H */

#include <trace/define_trace.h>

/* klp-ccp: from fs/xfs/libxfs/xfs_bmap_btree.h */
#define XFS_BM_MAXLEVELS(mp,w)		((mp)->m_bm_maxlevels[(w)])

/* klp-ccp: from fs/xfs/libxfs/xfs_trans_space.h */
#define	XFS_EXTENTADD_SPACE_RES(mp,w)	(XFS_BM_MAXLEVELS(mp,w) - 1)

#define	XFS_DIOSTRAT_SPACE_RES(mp, v)	\
	(XFS_EXTENTADD_SPACE_RES(mp, XFS_DATA_FORK) + (v))

/* klp-ccp: from fs/xfs/libxfs/xfs_quota_defs.h */
#define XFS_QMOPT_RES_REGBLKS	0x0010000

/* klp-ccp: from fs/xfs/xfs_quota.h */
#ifdef CONFIG_XFS_QUOTA

static int (*klpe_xfs_trans_reserve_quota_nblks)(struct xfs_trans *,
		struct xfs_inode *, long, long, uint);

static int (*klpe_xfs_qm_dqattach_locked)(struct xfs_inode *, uint);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_XFS_QUOTA */

/* klp-ccp: from fs/xfs/xfs_reflink.h */
static int (*klpe_xfs_reflink_trim_around_shared)(struct xfs_inode *ip,
		struct xfs_bmbt_irec *irec, bool *shared, bool *trimmed);

int klpp_xfs_reflink_allocate_cow(struct xfs_inode *ip,
		struct xfs_bmbt_irec *imap, bool *shared, uint *lockmode);

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

		align = do_mod(offset_fsb, extsz);
		if (align)
			count_fsb += align;
		align = do_mod(count_fsb, extsz);
		if (align)
			count_fsb += extsz - align;
	}

	return count_fsb;
}

/* klp-ccp: from fs/xfs/xfs_reflink.c */
STATIC int
(*klpe_xfs_reflink_convert_cow_extent)(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	xfs_fileoff_t		offset_fsb,
	xfs_filblks_t		count_fsb,
	struct xfs_defer_ops	*dfops);

int
klpp_xfs_reflink_allocate_cow(
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	bool			*shared,
	uint			*lockmode)
{
	struct xfs_mount	*mp = ip->i_mount;
	xfs_fileoff_t		offset_fsb = imap->br_startoff;
	xfs_filblks_t		count_fsb = imap->br_blockcount;
	struct xfs_bmbt_irec	got;
	struct xfs_defer_ops	dfops;
	struct xfs_trans	*tp = NULL;
	xfs_fsblock_t		first_block;
	int			nimaps, error = 0;
	bool			trimmed;
	xfs_filblks_t		resaligned;
	xfs_extlen_t		resblks = 0;
	struct xfs_iext_cursor	icur;

retry:
	ASSERT(xfs_is_reflink_inode(ip));
	ASSERT(xfs_isilocked(ip, XFS_ILOCK_EXCL | XFS_ILOCK_SHARED));

	/*
	 * Even if the extent is not shared we might have a preallocation for
	 * it in the COW fork.  If so use it.
	 * The data fork mapping may have changed while we dropped the ILOCK
	 * (a racing O_DIRECT writer under IOLOCK_SHARED can complete a full
	 * CoW cycle including xfs_reflink_end_cow(), which remaps this offset
	 * and drops the refcount of the old shared block).  Re-read it so the
	 * shared-status recheck below and the caller's in-place iomap both
	 * operate on the current mapping rather than a stale physical block.
	 */
	nimaps = 1;
	error = (*klpe_xfs_bmapi_read)(ip, imap->br_startoff,
		imap->br_blockcount, imap, &nimaps, 0);
	if (error)
		goto out;

	/*
	 * Check for an overlapping extent again now that we dropped the ilock.
	 */
	if ((*klpe_xfs_iext_lookup_extent)(ip, ip->i_cowfp, offset_fsb, &icur, &got) &&
	    got.br_startoff <= offset_fsb) {
		*shared = true;

		/* If we have a real allocation in the COW fork we're done. */
		if (!isnullstartblock(got.br_startblock)) {
			(*klpe_xfs_trim_extent)(&got, offset_fsb, count_fsb);
			*imap = got;
			goto convert;
		}

		(*klpe_xfs_trim_extent)(imap, got.br_startoff, got.br_blockcount);
	} else {
		error = (*klpe_xfs_reflink_trim_around_shared)(ip, imap, shared, &trimmed);
		if (error || !*shared)
			goto out;
	}

	if (!tp) {
		resaligned = xfs_aligned_fsb_count(imap->br_startoff,
			imap->br_blockcount, (*klpe_xfs_get_cowextsz_hint)(ip));
		resblks = XFS_DIOSTRAT_SPACE_RES(mp, resaligned);

		(*klpe_xfs_iunlock)(ip, *lockmode);
		error = (*klpe_xfs_trans_alloc)(mp, &M_RES(mp)->tr_write, resblks, 0, 0, &tp);
		*lockmode = XFS_ILOCK_EXCL;
		(*klpe_xfs_ilock)(ip, *lockmode);

		if (error)
			return error;

		error = (*klpe_xfs_qm_dqattach_locked)(ip, 0);
		if (error)
			goto out;
		goto retry;
	}

	error = (*klpe_xfs_trans_reserve_quota_nblks)(tp, ip, resblks, 0,
			XFS_QMOPT_RES_REGBLKS);
	if (error)
		goto out;

	(*klpe_xfs_trans_ijoin)(tp, ip, 0);

	(*klpe_xfs_defer_init)(&dfops, &first_block);
	nimaps = 1;

	/* Allocate the entire reservation as unwritten blocks. */
	error = (*klpe_xfs_bmapi_write)(tp, ip, imap->br_startoff, imap->br_blockcount,
			XFS_BMAPI_COWFORK | XFS_BMAPI_PREALLOC, &first_block,
			resblks, imap, &nimaps, &dfops);
	if (error)
		goto out_bmap_cancel;

	/* Finish up. */
	error = (*klpe_xfs_defer_finish)(&tp, &dfops);
	if (error)
		goto out_bmap_cancel;

	error = (*klpe_xfs_trans_commit)(tp);
	if (error)
		return error;
convert:
	return (*klpe_xfs_reflink_convert_cow_extent)(ip, imap, offset_fsb, count_fsb,
			&dfops);
out_bmap_cancel:
	(*klpe_xfs_defer_cancel)(&dfops);
	(*klpe_xfs_trans_reserve_quota_nblks)(tp, ip, -((long)resblks), -(0), 0x0010000);
out:
	if (tp)
		(*klpe_xfs_trans_cancel)(tp);
	return error;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "xfs"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xfs_bmapi_read", (void *)&klpe_xfs_bmapi_read, "xfs" },
	{ "xfs_bmapi_write", (void *)&klpe_xfs_bmapi_write, "xfs" },
	{ "xfs_defer_cancel", (void *)&klpe_xfs_defer_cancel, "xfs" },
	{ "xfs_defer_finish", (void *)&klpe_xfs_defer_finish, "xfs" },
	{ "xfs_defer_init", (void *)&klpe_xfs_defer_init, "xfs" },
	{ "xfs_get_cowextsz_hint", (void *)&klpe_xfs_get_cowextsz_hint,
	  "xfs" },
	{ "xfs_iext_lookup_extent", (void *)&klpe_xfs_iext_lookup_extent,
	  "xfs" },
	{ "xfs_ilock", (void *)&klpe_xfs_ilock, "xfs" },
	{ "xfs_iunlock", (void *)&klpe_xfs_iunlock, "xfs" },
	{ "xfs_qm_dqattach_locked", (void *)&klpe_xfs_qm_dqattach_locked,
	  "xfs" },
	{ "xfs_reflink_convert_cow_extent",
	  (void *)&klpe_xfs_reflink_convert_cow_extent, "xfs" },
	{ "xfs_reflink_trim_around_shared",
	  (void *)&klpe_xfs_reflink_trim_around_shared, "xfs" },
	{ "xfs_trans_alloc", (void *)&klpe_xfs_trans_alloc, "xfs" },
	{ "xfs_trans_cancel", (void *)&klpe_xfs_trans_cancel, "xfs" },
	{ "xfs_trans_commit", (void *)&klpe_xfs_trans_commit, "xfs" },
	{ "xfs_trans_ijoin", (void *)&klpe_xfs_trans_ijoin, "xfs" },
	{ "xfs_trans_reserve_quota_nblks",
	  (void *)&klpe_xfs_trans_reserve_quota_nblks, "xfs" },
	{ "xfs_trim_extent", (void *)&klpe_xfs_trim_extent, "xfs" },
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

int livepatch_bsc1271543_init(void)
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

void livepatch_bsc1271543_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
