/*
 * livepatch_bsc1226325
 *
 * Fix for CVE-2024-36964, bsc#1226325
 *
 *  Upstream commit:
 *  cd25e15e57e6 ("fs/9p: only translate RWX permissions for plain 9P2000")
 *
 *  SLE12-SP5 commit:
 *  c4e6c4f5e692977df885f3621bbaae4615872687
 *
 *  SLE15-SP2 and -SP3 commit:
 *  c4d4f4cfba7e24eeafff463045e0e50e68feb342
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b5d7488e51327f1c6d84e90cdc8b73f8c7f1a230
 *
 *  SLE15-SP6 commit:
 *  ebd0dc67ce13d594fe18a5e9d803bfb13b87e5d2
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

/* klp-ccp: from fs/9p/vfs_inode.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/slab.h>

/* klp-ccp: from include/linux/xattr.h */
#define _LINUX_XATTR_H

/* klp-ccp: from fs/9p/vfs_inode.c */
#include <net/9p/9p.h>

/* klp-ccp: from include/net/9p/client.h */
#define NET_9P_CLIENT_H

/* klp-ccp: from fs/9p/v9fs.h */
#include <linux/netfs.h>

enum p9_session_flags {
	V9FS_PROTO_2000U    = 0x01,
	V9FS_PROTO_2000L    = 0x02,
	V9FS_ACCESS_SINGLE  = 0x04,
	V9FS_ACCESS_USER    = 0x08,
	V9FS_ACCESS_CLIENT  = 0x10,
	V9FS_POSIX_ACL      = 0x20,
	V9FS_NO_XATTR       = 0x40,
	V9FS_IGNORE_QV      = 0x80, /* ignore qid.version for cache hints */
	V9FS_DIRECT_IO      = 0x100,
	V9FS_SYNC           = 0x200
};

struct v9fs_session_info {
	/* options */
	unsigned int flags;
	unsigned char nodev;
	unsigned short debug;
	unsigned int afid;
	unsigned int cache;
#ifdef CONFIG_9P_FSCACHE
	char *cachetag;
	struct fscache_volume *fscache;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	char *uname;		/* user name to mount as */
	char *aname;		/* name of remote hierarchy being mounted */
	unsigned int maxdata;	/* max data for client interface */
	kuid_t dfltuid;		/* default uid/muid for legacy support */
	kgid_t dfltgid;		/* default gid for legacy support */
	kuid_t uid;		/* if ACCESS_SINGLE, the uid that has access */
	struct p9_client *clnt;	/* 9p client */
	struct list_head slist; /* list of sessions registered with v9fs */
	struct rw_semaphore rename_sem;
	long session_lock_timeout; /* retry interval for blocking locks */
};

#define V9FS_INO_INVALID_ATTR 0x01

struct v9fs_inode {
	struct netfs_inode netfs; /* Netfslib context and vfs inode */
	struct p9_qid qid;
	unsigned int cache_validity;
	struct mutex v_mutex;
};

static inline struct v9fs_inode *V9FS_I(const struct inode *inode)
{
	return container_of(inode, struct v9fs_inode, netfs.inode);
}

static inline int v9fs_proto_dotu(struct v9fs_session_info *v9ses)
{
	return v9ses->flags & V9FS_PROTO_2000U;
}

/* klp-ccp: from fs/9p/v9fs_vfs.h */
#define V9FS_STAT2INODE_KEEP_ISIZE 1

static inline void v9fs_i_size_write(struct inode *inode, loff_t i_size)
{
	/*
	 * 32-bit need the lock, concurrent updates could break the
	 * sequences and make i_size_read() loop forever.
	 * 64-bit updates are atomic and can skip the locking.
	 */
	if (sizeof(i_size) > sizeof(long))
		spin_lock(&inode->i_lock);
	i_size_write(inode, i_size);
	if (sizeof(i_size) > sizeof(long))
		spin_unlock(&inode->i_lock);
}

/* klp-ccp: from fs/9p/fid.h */
#include <linux/list.h>
/* klp-ccp: from fs/9p/xattr.h */
#include <linux/xattr.h>
#include <net/9p/9p.h>
#include <net/9p/client.h>

/* klp-ccp: from fs/9p/vfs_inode.c */
static int p9mode2perm(struct v9fs_session_info *v9ses,
		       struct p9_wstat *stat)
{
	int res;
	int mode = stat->mode;

	res = mode & 0777; /* S_IRWXUGO */
	if (v9fs_proto_dotu(v9ses)) {
		if ((mode & P9_DMSETUID) == P9_DMSETUID)
			res |= S_ISUID;

		if ((mode & P9_DMSETGID) == P9_DMSETGID)
			res |= S_ISGID;

		if ((mode & P9_DMSETVTX) == P9_DMSETVTX)
			res |= S_ISVTX;
	}
	return res;
}

umode_t klpp_p9mode2unixmode(struct v9fs_session_info *v9ses,
			       struct p9_wstat *stat, dev_t *rdev)
{
	int res, r;
	u32 mode = stat->mode;

	*rdev = 0;
	res = p9mode2perm(v9ses, stat);

	if ((mode & P9_DMDIR) == P9_DMDIR)
		res |= S_IFDIR;
	else if ((mode & P9_DMSYMLINK) && (v9fs_proto_dotu(v9ses)))
		res |= S_IFLNK;
	else if ((mode & P9_DMSOCKET) && (v9fs_proto_dotu(v9ses))
		 && (v9ses->nodev == 0))
		res |= S_IFSOCK;
	else if ((mode & P9_DMNAMEDPIPE) && (v9fs_proto_dotu(v9ses))
		 && (v9ses->nodev == 0))
		res |= S_IFIFO;
	else if ((mode & P9_DMDEVICE) && (v9fs_proto_dotu(v9ses))
		 && (v9ses->nodev == 0)) {
		char type = 0;
		int major = -1, minor = -1;

		r = sscanf(stat->extension, "%c %i %i", &type, &major, &minor);
		if (r != 3) {
			p9_debug(P9_DEBUG_ERROR,
				 "invalid device string, umode will be bogus: %s\n",
				 stat->extension);
			return res;
		}
		switch (type) {
		case 'c':
			res |= S_IFCHR;
			break;
		case 'b':
			res |= S_IFBLK;
			break;
		default:
			p9_debug(P9_DEBUG_ERROR, "Unknown special type %c %s\n",
				 type, stat->extension);
		}
		*rdev = MKDEV(major, minor);
	} else
		res |= S_IFREG;

	return res;
}

void
klpp_v9fs_stat2inode(struct p9_wstat *stat, struct inode *inode,
		 struct super_block *sb, unsigned int flags)
{
	umode_t mode;
	struct v9fs_session_info *v9ses = sb->s_fs_info;
	struct v9fs_inode *v9inode = V9FS_I(inode);

	set_nlink(inode, 1);

	inode->i_atime.tv_sec = stat->atime;
	inode->i_mtime.tv_sec = stat->mtime;
	inode->i_ctime.tv_sec = stat->mtime;

	inode->i_uid = v9ses->dfltuid;
	inode->i_gid = v9ses->dfltgid;

	if (v9fs_proto_dotu(v9ses)) {
		inode->i_uid = stat->n_uid;
		inode->i_gid = stat->n_gid;
	}
	if ((S_ISREG(inode->i_mode)) || (S_ISDIR(inode->i_mode))) {
		if (v9fs_proto_dotu(v9ses)) {
			unsigned int i_nlink;
			/*
			 * Hadlink support got added later to the .u extension.
			 * So there can be a server out there that doesn't
			 * support this even with .u extension. That would
			 * just leave us with stat->extension being an empty
			 * string, though.
			 */
			/* HARDLINKCOUNT %u */
			if (sscanf(stat->extension,
				   " HARDLINKCOUNT %u", &i_nlink) == 1)
				set_nlink(inode, i_nlink);
		}
	}
	mode = p9mode2perm(v9ses, stat);
	mode |= inode->i_mode & ~S_IALLUGO;
	inode->i_mode = mode;

	if (!(flags & V9FS_STAT2INODE_KEEP_ISIZE))
		v9fs_i_size_write(inode, stat->length);
	/* not real number of blocks, but 512 byte ones ... */
	inode->i_blocks = (stat->length + 512 - 1) >> 9;
	v9inode->cache_validity &= ~V9FS_INO_INVALID_ATTR;
}

#include "livepatch_bsc1226325.h"
