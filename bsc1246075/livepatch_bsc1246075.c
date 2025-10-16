/*
 * livepatch_bsc1246075
 *
 * Fix for CVE-2025-38206, bsc#1246075
 *
 *  Upstream commit:
 *  1f3d9724e16d ("exfat: fix double free in delayed_free")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  e34f20066e4b175b85f646015cc7d2a208629dc0
 *
 *  SLE15-SP6 commit:
 *  38c19501fe9c6dd853e5dbd198cfd7d075a6f28a
 *
 *  SLE MICRO-6-0 commit:
 *  38c19501fe9c6dd853e5dbd198cfd7d075a6f28a
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

/* klp-ccp: from fs/exfat/nls.c */
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include <asm/unaligned.h>

/* klp-ccp: from fs/exfat/exfat_raw.h */
#include <linux/types.h>

#define EXFAT_EOF_CLUSTER	0xFFFFFFFFu

#define EXFAT_RESERVED_CLUSTERS	2

#define ALLOC_FAT_CHAIN		0x01

#define CS_DEFAULT		2

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
		struct {
			__u8 flags;
			__u8 vendor_guid[16];
			__u8 vendor_defined[14];
		} __packed vendor_ext; /* vendor extension directory entry */
		struct {
			__u8 flags;
			__u8 vendor_guid[16];
			__u8 vendor_defined[2];
			__le32 start_clu;
			__le64 size;
		} __packed vendor_alloc; /* vendor allocation directory entry */
		struct {
			__u8 flags;
			__u8 custom_defined[18];
			__le32 start_clu;
			__le64 size;
		} __packed generic_secondary; /* generic secondary directory entry */
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

struct exfat_chain {
	unsigned int dir;
	unsigned int size;
	unsigned char flags;
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
		 sys_tz:1, /* Use local timezone */
		 discard:1, /* Issue discard requests on deletions */
		 keep_last_dots:1; /* Keep trailing periods in paths */
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

void klpp_exfat_free_upcase_table(struct exfat_sb_info *sbi)
{
	kvfree(sbi->vol_utbl);
	sbi->vol_utbl = NULL;
}

#include "livepatch_bsc1246075.h"

#include <linux/livepatch.h>
