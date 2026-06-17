/*
 * livepatch_bsc1263902
 *
 * Fix for CVE-2026-31694, bsc#1263902
 *
 *  Copyright (c) 2026 SUSE
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

#include <linux/fuse.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/wait.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/mutex.h>
#include <linux/rwsem.h>
#include <linux/rbtree.h>

#include <linux/workqueue.h>
#include <linux/kref.h>

#include <linux/refcount.h>
#include <linux/user_namespace.h>

struct fuse_inode {
	/** Inode data */
	struct inode inode;

	/** Unique ID, which identifies the inode between userspace
	 * and kernel */
	u64 nodeid;

	/** Number of lookups on this inode */
	u64 nlookup;

	/** The request used for sending the FORGET message */
	struct fuse_forget_link *forget;

	/** Time in jiffies until the file attributes are valid */
	u64 i_time;

	/* Which attributes are invalid */
	u32 inval_mask;

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	union {
		/* Write related fields (regular file only) */
		struct {
			/* Files usable in writepage.  Protected by fi->lock */
			struct list_head write_files;

			/* Writepages pending on truncate or fsync */
			struct list_head queued_writes;

			/* Number of sent writes, a negative bias
			 * (FUSE_NOWRITE) means more writes are blocked */
			int writectr;

			/* Waitq for writepage completion */
			wait_queue_head_t page_waitq;

			/* List of writepage requestst (pending or sent) */
			struct rb_root writepages;
		};

		/* readdir cache (directory only) */
		struct {
			/* true if fully cached */
			bool cached;

			/* size of cache */
			loff_t size;

			/* position at end of cache (position of next entry) */
			loff_t pos;

			/* version of the cache */
			u64 version;

			/* modification time of directory when cache was
			 * started */
			struct timespec64 mtime;

			/* iversion of directory when cache was started */
			u64 iversion;

			/* protects above fields */
			spinlock_t lock;
		} rdc;
	};

	/** Miscellaneous bits describing inode state */
	unsigned long state;

	/** Lock for serializing lookup and readdir for back compatibility*/
	struct mutex mutex;

	/** Lock to protect write related fields */
	spinlock_t lock;

#ifdef CONFIG_FUSE_DAX
	struct fuse_inode_dax *dax;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct fuse_submount_lookup *submount_lookup;
};

struct fuse_file {
	/** Fuse connection for this file */
	struct fuse_mount *fm;

	/* Argument space reserved for release */
	struct fuse_release_args *release_args;

	/** Kernel file handle guaranteed to be unique */
	u64 kh;

	/** File handle used by userspace */
	u64 fh;

	/** Node id of this file */
	u64 nodeid;

	/** Refcount */
	refcount_t count;

	/** FOPEN_* flags returned by open */
	u32 open_flags;

	/** Entry on inode's write_files list */
	struct list_head write_entry;

	/* Readdir related */
	struct {
		/*
		 * Protects below fields against (crazy) parallel readdir on
		 * same open file.  Uncontended in the normal case.
		 */
		struct mutex lock;

		/* Dir stream position */
		loff_t pos;

		/* Offset in cache */
		loff_t cache_off;

		/* Version of cache we are reading */
		u64 version;

	} readdir;

	/** RB node to be linked on fuse_conn->polled_files */
	struct rb_node polled_node;

	/** Wait queue head for poll */
	wait_queue_head_t poll_wait;

	/** Has flock been performed on this file? */
	bool flock:1;
};

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

/* klp-ccp: from fs/fuse/readdir.c */
#include <linux/pagemap.h>
#include <linux/highmem.h>

static void fuse_add_dirent_to_cache(struct file *file,
				     struct fuse_dirent *dirent, loff_t pos)
{
	struct fuse_inode *fi = get_fuse_inode(file_inode(file));
	size_t reclen = FUSE_DIRENT_SIZE(dirent);
	pgoff_t index;
	struct page *page;
	loff_t size;
	u64 version;
	unsigned int offset;
	void *addr;

	/* Dirent doesn't fit in readdir cache page?  Skip caching. */
	if (reclen > PAGE_SIZE)
		return;

	spin_lock(&fi->rdc.lock);
	/*
	 * Is cache already completed?  Or this entry does not go at the end of
	 * cache?
	 */
	if (fi->rdc.cached || pos != fi->rdc.pos) {
		spin_unlock(&fi->rdc.lock);
		return;
	}
	version = fi->rdc.version;
	size = fi->rdc.size;
	offset = size & ~PAGE_MASK;
	index = size >> PAGE_SHIFT;
	/* Dirent doesn't fit in current page?  Jump to next page. */
	if (offset + reclen > PAGE_SIZE) {
		index++;
		offset = 0;
	}
	spin_unlock(&fi->rdc.lock);

	if (offset) {
		page = find_lock_page(file->f_mapping, index);
	} else {
		page = find_or_create_page(file->f_mapping, index,
					   mapping_gfp_mask(file->f_mapping));
	}
	if (!page)
		return;

	spin_lock(&fi->rdc.lock);
	/* Raced with another readdir */
	if (fi->rdc.version != version || fi->rdc.size != size ||
	    WARN_ON(fi->rdc.pos != pos))
		goto unlock;

	addr = kmap_local_page(page);
	if (!offset) {
		clear_page(addr);
		SetPageUptodate(page);
	}
	memcpy(addr + offset, dirent, reclen);
	kunmap_local(addr);
	fi->rdc.size = (index << PAGE_SHIFT) + offset + reclen;
	fi->rdc.pos = dirent->off;
unlock:
	spin_unlock(&fi->rdc.lock);
	unlock_page(page);
	put_page(page);
}

bool klpp_fuse_emit(struct file *file, struct dir_context *ctx,
		      struct fuse_dirent *dirent)
{
	struct fuse_file *ff = file->private_data;

	if (ff->open_flags & FOPEN_CACHE_DIR)
		fuse_add_dirent_to_cache(file, dirent, ctx->pos);

	return dir_emit(ctx, dirent->name, dirent->namelen, dirent->ino,
			dirent->type);
}


#include "livepatch_bsc1263902.h"

