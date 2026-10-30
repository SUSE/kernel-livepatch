/*
 * livepatch_bsc1271837
 *
 * Fix for CVE-2026-53381, bsc#1271837
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


#include "livepatch_bsc1271837.h"


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
#include <linux/poll.h>
#include <linux/workqueue.h>
#include <linux/kref.h>
#include <linux/xattr.h>
#include <linux/pid_namespace.h>
#include <linux/refcount.h>
#include <linux/user_namespace.h>

#define FUSE_CTL_NUM_DENTRIES 5

struct fuse_forget_link {
	struct fuse_forget_one forget_one;
	struct fuse_forget_link *next;
};

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

struct fuse_in_arg {
	unsigned size;
	const void *value;
};

struct fuse_arg {
	unsigned size;
	void *value;
};

struct fuse_args {
	uint64_t nodeid;
	uint32_t opcode;
	uint8_t in_numargs;
	uint8_t out_numargs;
	uint8_t ext_idx;
	bool force:1;
	bool noreply:1;
	bool nocreds:1;
	bool in_pages:1;
	bool out_pages:1;
	bool user_pages:1;
	bool out_argvar:1;
	bool page_zeroing:1;
	bool page_replace:1;
	bool may_block:1;
	bool is_ext:1;
	struct fuse_in_arg in_args[3];
	struct fuse_arg out_args[2];
	void (*end)(struct fuse_mount *fm, struct fuse_args *args, int error);
};

struct fuse_iqueue {
	/** Connection established */
	unsigned connected;

	/** Lock protecting accesses to members of this structure */
	spinlock_t lock;

	/** Readers of the connection are waiting on this */
	wait_queue_head_t waitq;

	/** The next unique request id */
	u64 reqctr;

	/** The list of pending requests */
	struct list_head pending;

	/** Pending interrupts */
	struct list_head interrupts;

	/** Queue of pending forgets */
	struct fuse_forget_link forget_list_head;
	struct fuse_forget_link *forget_list_tail;

	/** Batching of FORGET requests (positive indicates FORGET batch) */
	int forget_batch;

	/** O_ASYNC requests */
	struct fasync_struct *fasync;

	/** Device-specific callbacks */
	const struct fuse_iqueue_ops *ops;

	/** Device-specific state */
	void *priv;
};

enum fuse_dax_mode {
	FUSE_DAX_INODE_DEFAULT,	/* default */
	FUSE_DAX_ALWAYS,	/* "-o dax=always" */
	FUSE_DAX_NEVER,		/* "-o dax=never" */
	FUSE_DAX_INODE_USER,	/* "-o dax=inode" */
};

struct fuse_conn {
	/** Lock protecting accessess to  members of this structure */
	spinlock_t lock;

	/** Refcount */
	refcount_t count;

	/** Number of fuse_dev's */
	atomic_t dev_count;

	struct rcu_head rcu;

	/** The user id for this mount */
	kuid_t user_id;

	/** The group id for this mount */
	kgid_t group_id;

	/** The pid namespace for this mount */
	struct pid_namespace *pid_ns;

	/** The user namespace for this mount */
	struct user_namespace *user_ns;

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Maximum number of pages that can be used in a single request */
	unsigned int max_pages;

	/** Constrain ->max_pages to this value during feature negotiation */
	unsigned int max_pages_limit;

	/** Input queue */
	struct fuse_iqueue iq;

	/** The next unique kernel file handle */
	atomic64_t khctr;

	/** rbtree of fuse_files waiting for poll events indexed by ph */
	struct rb_root polled_files;

	/** Maximum number of outstanding background requests */
	unsigned max_background;

	/** Number of background requests at which congestion starts */
	unsigned congestion_threshold;

	/** Number of requests currently in the background */
	unsigned num_background;

	/** Number of background requests currently queued for userspace */
	unsigned active_background;

	/** The list of background requests set aside for later queuing */
	struct list_head bg_queue;

	/** Protects: max_background, congestion_threshold, num_background,
	 * active_background, bg_queue, blocked */
	spinlock_t bg_lock;

	/** Flag indicating that INIT reply has been received. Allocating
	 * any fuse request will be suspended until the flag is set */
	int initialized;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** Connection aborted via sysfs */
	bool aborted;

	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readahead asynchronously?  Only set in INIT */
	unsigned async_read:1;

	/** Return an unique read error after abort.  Only set in INIT */
	unsigned abort_err:1;

	/** Do not send separate SETATTR request before open(O_TRUNC)  */
	unsigned atomic_o_trunc:1;

	/** Filesystem supports NFS exporting.  Only set in INIT */
	unsigned export_support:1;

	/** write-back cache policy (default is write-through) */
	unsigned writeback_cache:1;

	/** allow parallel lookups and readdir (default is serialized) */
	unsigned parallel_dirops:1;

	/** handle fs handles killing suid/sgid/cap on write/chown/trunc */
	unsigned handle_killpriv:1;

	/** cache READLINK responses in page cache */
	unsigned cache_symlinks:1;

	/* show legacy mount options */
	unsigned int legacy_opts_show:1;

	/*
	 * fs kills suid/sgid/cap on write/chown/trunc. suid is killed on
	 * write/trunc only if caller did not have CAP_FSETID.  sgid is killed
	 * on write/truncate only if caller did not have CAP_FSETID as well as
	 * file has group execute permission.
	 */
	unsigned handle_killpriv_v2:1;

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is open/release not implemented by fs? */
	unsigned no_open:1;

	/** Is opendir/releasedir not implemented by fs? */
	unsigned no_opendir:1;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

	/** Does file server support extended setxattr */
	unsigned setxattr_ext:1;

	/** Is getxattr not implemented by fs? */
	unsigned no_getxattr:1;

	/** Is listxattr not implemented by fs? */
	unsigned no_listxattr:1;

	/** Is removexattr not implemented by fs? */
	unsigned no_removexattr:1;

	/** Are posix file locking primitives not implemented by fs? */
	unsigned no_lock:1;

	/** Is access not implemented by fs? */
	unsigned no_access:1;

	/** Is create not implemented by fs? */
	unsigned no_create:1;

	/** Is interrupt not implemented by fs? */
	unsigned no_interrupt:1;

	/** Is bmap not implemented by fs? */
	unsigned no_bmap:1;

	/** Is poll not implemented by fs? */
	unsigned no_poll:1;

	/** Do multi-page cached writes */
	unsigned big_writes:1;

	/** Don't apply umask to creation modes */
	unsigned dont_mask:1;

	/** Are BSD file locking primitives not implemented by fs? */
	unsigned no_flock:1;

	/** Is fallocate not implemented by fs? */
	unsigned no_fallocate:1;

	/** Is rename with flags implemented by fs? */
	unsigned no_rename2:1;

	/** Use enhanced/automatic page cache invalidation. */
	unsigned auto_inval_data:1;

	/** Filesystem is fully responsible for page cache invalidation. */
	unsigned explicit_inval_data:1;

	/** Does the filesystem support readdirplus? */
	unsigned do_readdirplus:1;

	/** Does the filesystem want adaptive readdirplus? */
	unsigned readdirplus_auto:1;

	/** Does the filesystem support asynchronous direct-IO submission? */
	unsigned async_dio:1;

	/** Is lseek not implemented by fs? */
	unsigned no_lseek:1;

	/** Does the filesystem support posix acls? */
	unsigned posix_acl:1;

	/** Check permissions based on the file mode or not? */
	unsigned default_permissions:1;

	/** Allow other than the mounter user to access the filesystem ? */
	unsigned allow_other:1;

	/** Does the filesystem support copy_file_range? */
	unsigned no_copy_file_range:1;

	/* Send DESTROY request */
	unsigned int destroy:1;

	/* Delete dentries that have gone stale */
	unsigned int delete_stale:1;

	/** Do not create entry in fusectl fs */
	unsigned int no_control:1;

	/** Do not allow MNT_FORCE umount */
	unsigned int no_force_umount:1;

	/* Auto-mount submounts announced by the server */
	unsigned int auto_submounts:1;

	/* Propagate syncfs() to server */
	unsigned int sync_fs:1;

	/* Initialize security xattrs when creating a new inode */
	unsigned int init_security:1;

	/* Add supplementary group info when creating a new inode */
	unsigned int create_supp_group:1;

	/* Does the filesystem support per inode DAX? */
	unsigned int inode_dax:1;

	/* Is tmpfile not implemented by fs? */
	unsigned int no_tmpfile:1;

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/** Negotiated minor version */
	unsigned minor;

	/** Entry on the fuse_mount_list */
	struct list_head entry;

	/** Device ID from the root super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[FUSE_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Version counter for attribute changes */
	atomic64_t attr_version;

	/** Called on final put */
	void (*release)(struct fuse_conn *);

	/**
	 * Read/write semaphore to hold when accessing the sb of any
	 * fuse_mount belonging to this connection
	 */
	struct rw_semaphore killsb;

	/** List of device instances belonging to this connection */
	struct list_head devices;

#ifdef CONFIG_FUSE_DAX
	enum fuse_dax_mode dax_mode;

	/* Dax specific conn data, non-NULL if DAX is enabled */
	struct fuse_conn_dax *dax;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct list_head mounts;

	/* New writepages go into this bucket */
	struct fuse_sync_bucket __rcu *curr_bucket;
};

struct fuse_mount {
	/* Underlying (potentially shared) connection to the FUSE server */
	struct fuse_conn *fc;

	/*
	 * Super block for this connection (fc->killsb must be held when
	 * accessing this).
	 */
	struct super_block *sb;

	/* Entry on fc->mounts */
	struct list_head fc_entry;
	struct rcu_head rcu;
};

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id);
/* klp-ccp: from fs/fuse/file.c */
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/fs.h>
#include <linux/filelock.h>

struct fuse_release_args {
	struct fuse_args args;
	struct fuse_release_in inarg;
	struct inode *inode;
};

extern void fuse_file_put(struct fuse_file *ff, bool sync, bool isdir);

extern void fuse_prepare_release(struct fuse_inode *fi, struct fuse_file *ff,
				 unsigned int flags, int opcode);

void klpp_fuse_file_release(struct inode *inode, struct fuse_file *ff,
		       unsigned int open_flags, fl_owner_t id, bool isdir)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_release_args *ra = ff->release_args;
	int opcode = isdir ? FUSE_RELEASEDIR : FUSE_RELEASE;

	fuse_prepare_release(fi, ff, open_flags, opcode);

	if (ff->flock) {
		ra->inarg.release_flags |= FUSE_RELEASE_FLOCK_UNLOCK;
		ra->inarg.lock_owner = fuse_lock_owner_id(ff->fm->fc, id);
	}
	/* Hold inode until release is finished */
	ra->inode = igrab(inode);

	/*
	 * Normally this will send the RELEASE request, however if
	 * some asynchronous READ or WRITE requests are outstanding,
	 * the sending will be delayed.
	 *
	 * Make the release synchronous if this is a fuseblk mount,
	 * synchronous RELEASE is allowed (and desirable) in this case
	 * because the server can be trusted not to screw up.
	 *
	 * Exception is virtio-fs, which is not affected by the above (server is
	 * on host, cannot close open files in guest).  Virtio-fs needs sync
	 * release, because the num_waiting mechanism to wait for all requests
	 * before commencing with fs shutdown doesn't work if submounts are
	 * used.
	 */
	fuse_file_put(ff, ff->fm->fc->auto_submounts, isdir);
}

u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id);


#include <linux/livepatch.h>

extern typeof(fuse_file_put) fuse_file_put
	 KLP_RELOC_SYMBOL(fuse, fuse, fuse_file_put);
extern typeof(fuse_lock_owner_id) fuse_lock_owner_id
	 KLP_RELOC_SYMBOL(fuse, fuse, fuse_lock_owner_id);
extern typeof(fuse_prepare_release) fuse_prepare_release
	 KLP_RELOC_SYMBOL(fuse, fuse, fuse_prepare_release);
