/*
 * livepatch_bsc1214123
 *
 * Fix for CVE-2023-4273, bsc#1214123
 *
 *  Upstream commit:
 *  d42334578eba ("exfat: check if filename entries exceeds max filename length")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  d8c4244726b6e607b175ae2e9980cbee40ce04b6
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b7e68de2789ddf95edbb89aa5bcc68485dcc7d21
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_EXFAT_FS)

#if !IS_MODULE(CONFIG_EXFAT_FS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from fs/exfat/dir.c */
#include <linux/compat.h>
#include <linux/bio.h>
#include <linux/buffer_head.h>
/* klp-ccp: from fs/exfat/exfat_raw.h */
#include <linux/types.h>

#define EXFAT_EOF_CLUSTER	0xFFFFFFFFu

#define ALLOC_FAT_CHAIN		0x01
#define ALLOC_NO_FAT_CHAIN	0x03

#define DENTRY_SIZE_BITS	5

#define MAX_EXFAT_DENTRIES	8388608

#define EXFAT_FILE_NAME_LEN		15

struct exfat_dentry {
	__u8 type;
	union {
		struct {
			__u8 num_ext;
			__le16 checksum;
			__le16 attr;
			__le16 reserved1;
			__le16 create_time;
			__le16 create_date;
			__le16 modify_time;
			__le16 modify_date;
			__le16 access_time;
			__le16 access_date;
			__u8 create_time_cs;
			__u8 modify_time_cs;
			__u8 create_tz;
			__u8 modify_tz;
			__u8 access_tz;
			__u8 reserved2[7];
		} __packed file; /* file directory entry */
		struct {
			__u8 flags;
			__u8 reserved1;
			__u8 name_len;
			__le16 name_hash;
			__le16 reserved2;
			__le64 valid_size;
			__le32 reserved3;
			__le32 start_clu;
			__le64 size;
		} __packed stream; /* stream extension directory entry */
		struct {
			__u8 flags;
			__le16 unicode_0_14[EXFAT_FILE_NAME_LEN];
		} __packed name; /* file name directory entry */
		struct {
			__u8 flags;
			__u8 reserved[18];
			__le32 start_clu;
			__le64 size;
		} __packed bitmap; /* allocation bitmap directory entry */
		struct {
			__u8 reserved1[3];
			__le32 checksum;
			__u8 reserved2[12];
			__le32 start_clu;
			__le64 size;
		} __packed upcase; /* up-case table directory entry */
	} __packed dentry;
} __packed;

/* klp-ccp: from fs/exfat/exfat_fs.h */
#include <linux/fs.h>
#include <linux/ratelimit.h>

enum exfat_error_mode {
	EXFAT_ERRORS_CONT,	/* ignore error and continue */
	EXFAT_ERRORS_PANIC,	/* panic on error */
	EXFAT_ERRORS_RO,	/* remount r/o on error */
};

#define EXFAT_HASH_BITS		8
#define EXFAT_HASH_SIZE		(1UL << EXFAT_HASH_BITS)

#define ES_ALL_ENTRIES		0

#define TYPE_UNUSED		0x0000
#define TYPE_DELETED		0x0001

#define TYPE_DIR		0x0104
#define TYPE_FILE		0x011F
#define TYPE_CRITICAL_SEC	0x0200
#define TYPE_STREAM		0x0201
#define TYPE_EXTEND		0x0202

#define TYPE_BENIGN_SEC		0x0800
#define TYPE_ALL		0x0FFF

#define MAX_NAME_LENGTH		255 /* max len of file name excluding NULL */

#define DIR_CACHE_SIZE		(256*sizeof(struct exfat_dentry)/512+1)

#define EXFAT_HINT_NONE		-1

#define EXFAT_B_TO_CLU(b, sbi)		((b) >> (sbi)->cluster_size_bits)

#define EXFAT_B_TO_DEN(b)		((b) >> DENTRY_SIZE_BITS)
#define EXFAT_DEN_TO_B(b)		((b) << DENTRY_SIZE_BITS)

struct exfat_dentry_namebuf {
	char *lfn;
	int lfnbuf_len; /* usually MAX_UNINAME_BUF_SIZE */
};

struct exfat_uni_name {
	/* +3 for null and for converting */
	unsigned short name[MAX_NAME_LENGTH + 3];
	u16 name_hash;
	unsigned char name_len;
};

struct exfat_chain {
	unsigned int dir;
	unsigned int size;
	unsigned char flags;
};

struct exfat_hint_femp {
	/* entry index of a directory */
	int eidx;
	/* count of continuous empty entry */
	int count;
	/* the cluster that first empty slot exists in */
	struct exfat_chain cur;
};

struct exfat_hint {
	unsigned int clu;
	union {
		unsigned int off; /* cluster offset */
		int eidx; /* entry index */
	};
};

struct exfat_entry_set_cache {
	struct super_block *sb;
	bool modified;
	unsigned int start_off;
	int num_bh;
	struct buffer_head *bh[DIR_CACHE_SIZE];
	unsigned int num_entries;
};

struct exfat_dir_entry {
	struct exfat_chain dir;
	int entry;
	unsigned int type;
	unsigned int start_clu;
	unsigned char flags;
	unsigned short attr;
	loff_t size;
	unsigned int num_subdirs;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 crtime;
	struct exfat_dentry_namebuf namebuf;
};

struct exfat_mount_options {
	kuid_t fs_uid;
	kgid_t fs_gid;
	unsigned short fs_fmask;
	unsigned short fs_dmask;
	/* permission for setting the [am]time */
	unsigned short allow_utime;
	/* charset for filename input/display */
	char *iocharset;
	/* on error: continue, panic, remount-ro */
	enum exfat_error_mode errors;
	unsigned utf8:1, /* Use of UTF-8 character set */
		 discard:1; /* Issue discard requests on deletions */
	int time_offset; /* Offset of timestamps from UTC (in minutes) */
};

struct exfat_sb_info {
	unsigned long long num_sectors; /* num of sectors in volume */
	unsigned int num_clusters; /* num of clusters in volume */
	unsigned int cluster_size; /* cluster size in bytes */
	unsigned int cluster_size_bits;
	unsigned int sect_per_clus; /* cluster size in sectors */
	unsigned int sect_per_clus_bits;
	unsigned long long FAT1_start_sector; /* FAT1 start sector */
	unsigned long long FAT2_start_sector; /* FAT2 start sector */
	unsigned long long data_start_sector; /* data area start sector */
	unsigned int num_FAT_sectors; /* num of FAT sectors */
	unsigned int root_dir; /* root dir cluster */
	unsigned int dentries_per_clu; /* num of dentries per cluster */
	unsigned int vol_flags; /* volume flags */
	unsigned int vol_flags_persistent; /* volume flags to retain */
	struct buffer_head *boot_bh; /* buffer_head of BOOT sector */

	unsigned int map_clu; /* allocation bitmap start cluster */
	unsigned int map_sectors; /* num of allocation bitmap sectors */
	struct buffer_head **vol_amap; /* allocation bitmap */

	unsigned short *vol_utbl; /* upcase table */

	unsigned int clu_srch_ptr; /* cluster search pointer */
	unsigned int used_clusters; /* number of used clusters */

	struct mutex s_lock; /* superblock lock */
	struct mutex bitmap_lock; /* bitmap lock */
	struct exfat_mount_options options;
	struct nls_table *nls_io; /* Charset used for input and display */
	struct ratelimit_state ratelimit;

	spinlock_t inode_hash_lock;
	struct hlist_head inode_hashtable[EXFAT_HASH_SIZE];

	struct rcu_head rcu;
};

struct exfat_inode_info {
	struct exfat_chain dir;
	int entry;
	unsigned int type;
	unsigned short attr;
	unsigned int start_clu;
	unsigned char flags;
	/*
	 * the copy of low 32bit of i_version to check
	 * the validation of hint_stat.
	 */
	unsigned int version;

	/* hint for cluster last accessed */
	struct exfat_hint hint_bmap;
	/* hint for entry index we try to lookup next time */
	struct exfat_hint hint_stat;
	/* hint for first empty entry */
	struct exfat_hint_femp hint_femp;

	spinlock_t cache_lru_lock;
	struct list_head cache_lru;
	int nr_caches;
	/* for avoiding the race between alloc and free */
	unsigned int cache_valid_id;

	/*
	 * NOTE: i_size_ondisk is 64bits, so must hold ->inode_lock to access.
	 * physically allocated size.
	 */
	loff_t i_size_ondisk;
	/* block-aligned i_size (used in cont_write_begin) */
	loff_t i_size_aligned;
	/* on-disk position of directory entry or 0 */
	loff_t i_pos;
	/* hash by i_location */
	struct hlist_node i_hash_fat;
	/* protect bmap against truncate */
	struct rw_semaphore truncate_lock;
	struct inode vfs_inode;
	/* File creation time */
	struct timespec64 i_crtime;
};

static inline struct exfat_sb_info *EXFAT_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct exfat_inode_info *EXFAT_I(struct inode *inode)
{
	return container_of(inode, struct exfat_inode_info, vfs_inode);
}

static int (*klpe_exfat_ent_get)(struct super_block *sb, unsigned int loc,
		unsigned int *content);

static unsigned int (*klpe_exfat_get_entry_type)(struct exfat_dentry *p_entry);

int klpp_exfat_find_dir_entry(struct super_block *sb, struct exfat_inode_info *ei,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname,
		int num_entries, unsigned int type, struct exfat_hint *hint_opt);

static struct exfat_dentry *(*klpe_exfat_get_dentry)(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, struct buffer_head **bh,
		sector_t *sector);
static struct exfat_dentry *(*klpe_exfat_get_dentry_cached)(struct exfat_entry_set_cache *es,
		int num);
static struct exfat_entry_set_cache *(*klpe_exfat_get_dentry_set)(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, unsigned int type);
static int (*klpe_exfat_free_dentry_set)(struct exfat_entry_set_cache *es, int sync);

static int (*klpe_exfat_uniname_ncmp)(struct super_block *sb, unsigned short *a,
		unsigned short *b, unsigned int len);
static int (*klpe_exfat_utf16_to_nls)(struct super_block *sb,
		struct exfat_uni_name *uniname, unsigned char *p_cstring,
		int len);

static void (*klpe_exfat_get_entry_time)(struct exfat_sb_info *sbi, struct timespec64 *ts,
		u8 tz, __le16 time, __le16 date, u8 time_cs);

static void (*klpe_exfat_chain_set)(struct exfat_chain *ec, unsigned int dir,
		unsigned int size, unsigned char flags);
static void (*klpe_exfat_chain_dup)(struct exfat_chain *dup, struct exfat_chain *ec);

/* klp-ccp: from fs/exfat/dir.c */
static int exfat_extract_uni_name(struct exfat_dentry *ep,
		unsigned short *uniname)
{
	int i, len = 0;

	for (i = 0; i < EXFAT_FILE_NAME_LEN; i++) {
		*uniname = le16_to_cpu(ep->dentry.name.unicode_0_14[i]);
		if (*uniname == 0x0)
			return len;
		uniname++;
		len++;
	}

	*uniname = 0x0;
	return len;

}

static void klpp_exfat_get_uniname_from_ext_entry(struct super_block *sb,
		struct exfat_chain *p_dir, int entry, unsigned short *uniname)
{
	int i;
	struct exfat_entry_set_cache *es;
	unsigned int uni_len = 0, len;

	es = (*klpe_exfat_get_dentry_set)(sb, p_dir, entry, ES_ALL_ENTRIES);
	if (!es)
		return;

	/*
	 * First entry  : file entry
	 * Second entry : stream-extension entry
	 * Third entry  : first file-name entry
	 * So, the index of first file-name dentry should start from 2.
	 */
	for (i = 2; i < es->num_entries; i++) {
		struct exfat_dentry *ep = (*klpe_exfat_get_dentry_cached)(es, i);

		/* end of name entry */
		if ((*klpe_exfat_get_entry_type)(ep) != TYPE_EXTEND)
			break;

		len = exfat_extract_uni_name(ep, uniname);
		uni_len += len;
		if (len != EXFAT_FILE_NAME_LEN || uni_len >= MAX_NAME_LENGTH)
			break;
		uniname += EXFAT_FILE_NAME_LEN;
	}

	(*klpe_exfat_free_dentry_set)(es, false);
}

int klpp_exfat_readdir(struct inode *inode, loff_t *cpos, struct exfat_dir_entry *dir_entry)
{
	int i, dentries_per_clu, dentries_per_clu_bits = 0, num_ext;
	unsigned int type, clu_offset, max_dentries;
	sector_t sector;
	struct exfat_chain dir, clu;
	struct exfat_uni_name uni_name;
	struct exfat_dentry *ep;
	struct super_block *sb = inode->i_sb;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);
	struct exfat_inode_info *ei = EXFAT_I(inode);
	unsigned int dentry = EXFAT_B_TO_DEN(*cpos) & 0xFFFFFFFF;
	struct buffer_head *bh;

	/* check if the given file ID is opened */
	if (ei->type != TYPE_DIR)
		return -EPERM;

	if (ei->entry == -1)
		(*klpe_exfat_chain_set)(&dir, sbi->root_dir, 0, ALLOC_FAT_CHAIN);
	else
		(*klpe_exfat_chain_set)(&dir, ei->start_clu,
			EXFAT_B_TO_CLU(i_size_read(inode), sbi), ei->flags);

	dentries_per_clu = sbi->dentries_per_clu;
	dentries_per_clu_bits = ilog2(dentries_per_clu);
	max_dentries = (unsigned int)min_t(u64, MAX_EXFAT_DENTRIES,
					   (u64)sbi->num_clusters << dentries_per_clu_bits);

	clu_offset = dentry >> dentries_per_clu_bits;
	(*klpe_exfat_chain_dup)(&clu, &dir);

	if (clu.flags == ALLOC_NO_FAT_CHAIN) {
		clu.dir += clu_offset;
		clu.size -= clu_offset;
	} else {
		/* hint_information */
		if (clu_offset > 0 && ei->hint_bmap.off != EXFAT_EOF_CLUSTER &&
		    ei->hint_bmap.off > 0 && clu_offset >= ei->hint_bmap.off) {
			clu_offset -= ei->hint_bmap.off;
			clu.dir = ei->hint_bmap.clu;
		}

		while (clu_offset > 0) {
			if ((*klpe_exfat_ent_get)(sb, *(&(clu.dir)), &(clu.dir)))
				return -EIO;

			clu_offset--;
		}
	}

	while (clu.dir != EXFAT_EOF_CLUSTER && dentry < max_dentries) {
		i = dentry & (dentries_per_clu - 1);

		for ( ; i < dentries_per_clu; i++, dentry++) {
			ep = (*klpe_exfat_get_dentry)(sb, &clu, i, &bh, &sector);
			if (!ep)
				return -EIO;

			type = (*klpe_exfat_get_entry_type)(ep);
			if (type == TYPE_UNUSED) {
				brelse(bh);
				break;
			}

			if (type != TYPE_FILE && type != TYPE_DIR) {
				brelse(bh);
				continue;
			}

			num_ext = ep->dentry.file.num_ext;
			dir_entry->attr = le16_to_cpu(ep->dentry.file.attr);
			(*klpe_exfat_get_entry_time)(sbi, &dir_entry->crtime,
					ep->dentry.file.create_tz,
					ep->dentry.file.create_time,
					ep->dentry.file.create_date,
					ep->dentry.file.create_time_cs);
			(*klpe_exfat_get_entry_time)(sbi, &dir_entry->mtime,
					ep->dentry.file.modify_tz,
					ep->dentry.file.modify_time,
					ep->dentry.file.modify_date,
					ep->dentry.file.modify_time_cs);
			(*klpe_exfat_get_entry_time)(sbi, &dir_entry->atime,
					ep->dentry.file.access_tz,
					ep->dentry.file.access_time,
					ep->dentry.file.access_date,
					0);

			*uni_name.name = 0x0;
			klpp_exfat_get_uniname_from_ext_entry(sb, &clu, i,
				uni_name.name);
			(*klpe_exfat_utf16_to_nls)(sb, &uni_name,
				dir_entry->namebuf.lfn,
				dir_entry->namebuf.lfnbuf_len);
			brelse(bh);

			ep = (*klpe_exfat_get_dentry)(sb, &clu, i + 1, &bh, NULL);
			if (!ep)
				return -EIO;
			dir_entry->size =
				le64_to_cpu(ep->dentry.stream.valid_size);
			dir_entry->entry = dentry;
			brelse(bh);

			ei->hint_bmap.off = dentry >> dentries_per_clu_bits;
			ei->hint_bmap.clu = clu.dir;

			*cpos = EXFAT_DEN_TO_B(dentry + 1 + num_ext);
			return 0;
		}

		if (clu.flags == ALLOC_NO_FAT_CHAIN) {
			if (--clu.size > 0)
				clu.dir++;
			else
				clu.dir = EXFAT_EOF_CLUSTER;
		} else {
			if ((*klpe_exfat_ent_get)(sb, *(&(clu.dir)), &(clu.dir)))
				return -EIO;
		}
	}

	dir_entry->namebuf.lfn[0] = '\0';
	*cpos = EXFAT_DEN_TO_B(dentry);
	return 0;
}

enum {
	DIRENT_STEP_FILE,
	DIRENT_STEP_STRM,
	DIRENT_STEP_NAME,
	DIRENT_STEP_SECD,
};

int klpp_exfat_find_dir_entry(struct super_block *sb, struct exfat_inode_info *ei,
		struct exfat_chain *p_dir, struct exfat_uni_name *p_uniname,
		int num_entries, unsigned int type, struct exfat_hint *hint_opt)
{
	int i, rewind = 0, dentry = 0, end_eidx = 0, num_ext = 0, len;
	int order, step, name_len = 0;
	int dentries_per_clu, num_empty = 0;
	unsigned int entry_type;
	unsigned short *uniname = NULL;
	struct exfat_chain clu;
	struct exfat_hint *hint_stat = &ei->hint_stat;
	struct exfat_hint_femp candi_empty;
	struct exfat_sb_info *sbi = EXFAT_SB(sb);

	dentries_per_clu = sbi->dentries_per_clu;

	(*klpe_exfat_chain_dup)(&clu, p_dir);

	if (hint_stat->eidx) {
		clu.dir = hint_stat->clu;
		dentry = hint_stat->eidx;
		end_eidx = dentry;
	}

	candi_empty.eidx = EXFAT_HINT_NONE;
rewind:
	order = 0;
	step = DIRENT_STEP_FILE;
	while (clu.dir != EXFAT_EOF_CLUSTER) {
		i = dentry & (dentries_per_clu - 1);
		for (; i < dentries_per_clu; i++, dentry++) {
			struct exfat_dentry *ep;
			struct buffer_head *bh;

			if (rewind && dentry == end_eidx)
				goto not_found;

			ep = (*klpe_exfat_get_dentry)(sb, &clu, i, &bh, NULL);
			if (!ep)
				return -EIO;

			entry_type = (*klpe_exfat_get_entry_type)(ep);

			if (entry_type == TYPE_UNUSED ||
			    entry_type == TYPE_DELETED) {
				step = DIRENT_STEP_FILE;

				num_empty++;
				if (candi_empty.eidx == EXFAT_HINT_NONE &&
						num_empty == 1) {
					(*klpe_exfat_chain_set)(&candi_empty.cur,
						clu.dir, clu.size, clu.flags);
				}

				if (candi_empty.eidx == EXFAT_HINT_NONE &&
						num_empty >= num_entries) {
					candi_empty.eidx =
						dentry - (num_empty - 1);
					WARN_ON(candi_empty.eidx < 0);
					candi_empty.count = num_empty;

					if (ei->hint_femp.eidx ==
							EXFAT_HINT_NONE ||
						candi_empty.eidx <=
							 ei->hint_femp.eidx)
						ei->hint_femp = candi_empty;
				}

				brelse(bh);
				if (entry_type == TYPE_UNUSED)
					goto not_found;
				continue;
			}

			num_empty = 0;
			candi_empty.eidx = EXFAT_HINT_NONE;

			if (entry_type == TYPE_FILE || entry_type == TYPE_DIR) {
				step = DIRENT_STEP_FILE;
				hint_opt->clu = clu.dir;
				hint_opt->eidx = i;
				if (type == TYPE_ALL || type == entry_type) {
					num_ext = ep->dentry.file.num_ext;
					step = DIRENT_STEP_STRM;
				}
				brelse(bh);
				continue;
			}

			if (entry_type == TYPE_STREAM) {
				u16 name_hash;

				if (step != DIRENT_STEP_STRM) {
					step = DIRENT_STEP_FILE;
					brelse(bh);
					continue;
				}
				step = DIRENT_STEP_FILE;
				name_hash = le16_to_cpu(
						ep->dentry.stream.name_hash);
				if (p_uniname->name_hash == name_hash &&
				    p_uniname->name_len ==
						ep->dentry.stream.name_len) {
					step = DIRENT_STEP_NAME;
					order = 1;
					name_len = 0;
				}
				brelse(bh);
				continue;
			}

			brelse(bh);
			if (entry_type == TYPE_EXTEND) {
				unsigned short entry_uniname[16], unichar;

				if (step != DIRENT_STEP_NAME ||
				    name_len >= MAX_NAME_LENGTH) {
					step = DIRENT_STEP_FILE;
					continue;
				}

				if (++order == 2)
					uniname = p_uniname->name;
				else
					uniname += EXFAT_FILE_NAME_LEN;

				len = exfat_extract_uni_name(ep, entry_uniname);
				name_len += len;

				unichar = *(uniname+len);
				*(uniname+len) = 0x0;

				if ((*klpe_exfat_uniname_ncmp)(sb, uniname,
					entry_uniname, len)) {
					step = DIRENT_STEP_FILE;
				} else if (p_uniname->name_len == name_len) {
					if (order == num_ext)
						goto found;
					step = DIRENT_STEP_SECD;
				}

				*(uniname+len) = unichar;
				continue;
			}

			if (entry_type &
					(TYPE_CRITICAL_SEC | TYPE_BENIGN_SEC)) {
				if (step == DIRENT_STEP_SECD) {
					if (++order == num_ext)
						goto found;
					continue;
				}
			}
			step = DIRENT_STEP_FILE;
		}

		if (clu.flags == ALLOC_NO_FAT_CHAIN) {
			if (--clu.size > 0)
				clu.dir++;
			else
				clu.dir = EXFAT_EOF_CLUSTER;
		} else {
			if ((*klpe_exfat_ent_get)(sb, *(&clu.dir), &clu.dir))
				return -EIO;
		}
	}

not_found:
	/*
	 * We started at not 0 index,so we should try to find target
	 * from 0 index to the index we started at.
	 */
	if (!rewind && end_eidx) {
		rewind = 1;
		dentry = 0;
		clu.dir = p_dir->dir;
		/* reset empty hint */
		num_empty = 0;
		candi_empty.eidx = EXFAT_HINT_NONE;
		goto rewind;
	}

	/* initialized hint_stat */
	hint_stat->clu = p_dir->dir;
	hint_stat->eidx = 0;
	return -ENOENT;

found:
	/* next dentry we'll find is out of this cluster */
	if (!((dentry + 1) & (dentries_per_clu - 1))) {
		int ret = 0;

		if (clu.flags == ALLOC_NO_FAT_CHAIN) {
			if (--clu.size > 0)
				clu.dir++;
			else
				clu.dir = EXFAT_EOF_CLUSTER;
		} else {
			ret = (*klpe_exfat_ent_get)(sb, *(&clu.dir), &clu.dir);
		}

		if (ret || clu.dir == EXFAT_EOF_CLUSTER) {
			/* just initialized hint_stat */
			hint_stat->clu = p_dir->dir;
			hint_stat->eidx = 0;
			return (dentry - num_ext);
		}
	}

	hint_stat->clu = clu.dir;
	hint_stat->eidx = dentry + 1;
	return dentry - num_ext;
}


#include "livepatch_bsc1214123.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "exfat"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "exfat_chain_dup", (void *)&klpe_exfat_chain_dup, "exfat" },
	{ "exfat_chain_set", (void *)&klpe_exfat_chain_set, "exfat" },
	{ "exfat_ent_get", (void *)&klpe_exfat_ent_get, "exfat" },
	{ "exfat_free_dentry_set", (void *)&klpe_exfat_free_dentry_set,
	  "exfat" },
	{ "exfat_get_dentry", (void *)&klpe_exfat_get_dentry, "exfat" },
	{ "exfat_get_dentry_cached", (void *)&klpe_exfat_get_dentry_cached,
	  "exfat" },
	{ "exfat_get_dentry_set", (void *)&klpe_exfat_get_dentry_set,
	  "exfat" },
	{ "exfat_get_entry_time", (void *)&klpe_exfat_get_entry_time,
	  "exfat" },
	{ "exfat_get_entry_type", (void *)&klpe_exfat_get_entry_type,
	  "exfat" },
	{ "exfat_uniname_ncmp", (void *)&klpe_exfat_uniname_ncmp, "exfat" },
	{ "exfat_utf16_to_nls", (void *)&klpe_exfat_utf16_to_nls, "exfat" },
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

int livepatch_bsc1214123_init(void)
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

void livepatch_bsc1214123_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_EXFAT_FS) */
