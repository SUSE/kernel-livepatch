#ifndef _BSC1184952_COMMON_H
#define _BSC1184952_COMMON_H

int livepatch_bsc1184952_fuse_acl_init(void);
void livepatch_bsc1184952_fuse_acl_cleanup(void);

int livepatch_bsc1184952_fuse_dir_init(void);
void livepatch_bsc1184952_fuse_dir_cleanup(void);

int livepatch_bsc1184952_fuse_file_init(void);
void livepatch_bsc1184952_fuse_file_cleanup(void);

int livepatch_bsc1184952_fuse_inode_init(void);
void livepatch_bsc1184952_fuse_inode_cleanup(void);

int livepatch_bsc1184952_fuse_xattr_init(void);
void livepatch_bsc1184952_fuse_xattr_cleanup(void);


/* klp-ccp: from fs/fuse/fuse_i.h */
#include <linux/fuse.h>
#include <linux/fs.h>
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
#include <linux/xattr.h>
#include <linux/refcount.h>

#define FUSE_MAX_PAGES_PER_REQ 32

#define FUSE_NOWRITE INT_MIN

#define FUSE_NAME_MAX 1024

#define FUSE_CTL_NUM_DENTRIES 5

#define FUSE_REQ_INLINE_PAGES 1

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

	/** The sticky bit in inode->i_mode may have been removed, so
	    preserve the original mode */
	umode_t orig_i_mode;

	/** 64 bit inode number */
	u64 orig_ino;

	/** Version of last attribute change */
	u64 attr_version;

	/** Files usable in writepage.  Protected by fc->lock */
	struct list_head write_files;

	/** Writepages pending on truncate or fsync */
	struct list_head queued_writes;

	/** Number of sent writes, a negative bias (FUSE_NOWRITE)
	 * means more writes are blocked */
	int writectr;

	/** Waitq for writepage completion */
	wait_queue_head_t page_waitq;

	/** List of writepage requestst (pending or sent) */
	struct list_head writepages;

	/** Miscellaneous bits describing inode state */
	unsigned long state;

	/** Lock for serializing lookup and readdir for back compatibility*/
	struct mutex mutex;
};

enum {
	/** Advise readdirplus  */
	FUSE_I_ADVISE_RDPLUS,
	/** Initialized with readdirplus */
	FUSE_I_INIT_RDPLUS,
	/** An operation changing file size is in progress  */
	FUSE_I_SIZE_UNSTABLE,
	/*
	 * Fix CVE-2020-36322
	 *  +2 lines
	 */
	/* Bad inode */
	KLPP_FUSE_I_BAD,
};

struct fuse_file {
	/** Fuse connection for this file */
	struct fuse_conn *fc;

	/** Request reserved for flush and release */
	struct fuse_req *reserved_req;

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

struct fuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** True if the data for the last argument is in req->pages */
	unsigned argpages:1;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

struct fuse_arg {
	unsigned size;
	void *value;
};

struct fuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;

	/*
	 * The following bitfields are not changed during the request
	 * processing
	 */

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar:1;

	/** Last argument is a list of pages to copy data to */
	unsigned argpages:1;

	/** Zero partially or not copied pages */
	unsigned page_zeroing:1;

	/** Pages may be replaced with new ones */
	unsigned page_replace:1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_arg args[2];
};

struct fuse_page_desc {
	unsigned int length;
	unsigned int offset;
};

struct fuse_args {
	struct {
		struct {
			uint32_t opcode;
			uint64_t nodeid;
		} h;
		unsigned numargs;
		struct fuse_in_arg args[3];

	} in;
	struct {
		unsigned argvar:1;
		unsigned numargs;
		struct fuse_arg args[2];
	} out;
};

#define FUSE_ARGS(args) struct fuse_args args = {}

struct fuse_io_priv {
	struct kref refcnt;
	int async;
	spinlock_t lock;
	unsigned reqs;
	ssize_t bytes;
	size_t size;
	__u64 offset;
	bool write;
	int err;
	struct kiocb *iocb;
	struct file *file;
	struct completion *done;
	bool blocking;
};

#define FUSE_IO_PRIV_SYNC(f) \
{					\
	.refcnt = KREF_INIT(1),		\
	.async = 0,			\
	.file = f,			\
}

enum fuse_req_flag {
	FR_ISREPLY,
	FR_FORCE,
	FR_BACKGROUND,
	FR_WAITING,
	FR_ABORTED,
	FR_INTERRUPTED,
	FR_LOCKED,
	FR_PENDING,
	FR_SENT,
	FR_FINISHED,
	FR_PRIVATE,
};

struct fuse_req {
	/** This can be on either pending processing or io lists in
	    fuse_conn */
	struct list_head list;

	/** Entry on the interrupts list  */
	struct list_head intr_entry;

	/** refcount */
	refcount_t count;

	/** Unique ID for the interrupt request */
	u64 intr_unique;

	/* Request flags, updated with test/set/clear_bit() */
	unsigned long flags;

	/** The request input */
	struct fuse_in in;

	/** The request output */
	struct fuse_out out;

	/** Used to wake up the task waiting for completion of request*/
	wait_queue_head_t waitq;

	/** Data for asynchronous requests */
	union {
		struct {
			struct fuse_release_in in;
			struct inode *inode;
		} release;
		struct fuse_init_in init_in;
		struct fuse_init_out init_out;
		struct cuse_init_in cuse_init_in;
		struct {
			struct fuse_read_in in;
			u64 attr_ver;
		} read;
		struct {
			struct fuse_write_in in;
			struct fuse_write_out out;
			struct fuse_req *next;
		} write;
		struct fuse_notify_retrieve_in retrieve_in;
	} misc;

	/** page vector */
	struct page **pages;

	/** page-descriptor vector */
	struct fuse_page_desc *page_descs;

	/** size of the 'pages' array */
	unsigned max_pages;

	/** inline page vector */
	struct page *inline_pages[FUSE_REQ_INLINE_PAGES];

	/** inline page-descriptor vector */
	struct fuse_page_desc inline_page_descs[FUSE_REQ_INLINE_PAGES];

	/** number of pages in vector */
	unsigned num_pages;

	/** File used in the request (or NULL) */
	struct fuse_file *ff;

	/** Inode used in the request or NULL */
	struct inode *inode;

	/** AIO control block */
	struct fuse_io_priv *io;

	/** Link on fi->writepages */
	struct list_head writepages_entry;

	/** Request completion callback */
	void (*end)(struct fuse_conn *, struct fuse_req *);

	/** Request is stolen from fuse_file->reserved_req */
	struct file *stolen_file;
};

struct fuse_iqueue {
	/** Connection established */
	unsigned connected;

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

	/** Maximum read size */
	unsigned max_read;

	/** Maximum write size */
	unsigned max_write;

	/** Input queue */
	struct fuse_iqueue iq;

	/** The next unique kernel file handle */
	u64 khctr;

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

	/** Flag indicating that INIT reply has been received. Allocating
	 * any fuse request will be suspended until the flag is set */
	int initialized;

	/** Flag indicating if connection is blocked.  This will be
	    the case before the INIT reply is received, and if there
	    are too many outstading backgrounds requests */
	int blocked;

	/** waitq for blocked connection */
	wait_queue_head_t blocked_waitq;

	/** waitq for reserved requests */
	wait_queue_head_t reserved_req_waitq;

	/** Connection established, cleared on umount, connection
	    abort and device release */
	unsigned connected;

	/** Connection failed (version mismatch).  Cannot race with
	    setting other bitfields since it is only set once in INIT
	    reply, before any other request, and never cleared */
	unsigned conn_error:1;

	/** Connection successful.  Only set in INIT */
	unsigned conn_init:1;

	/** Do readpages asynchronously?  Only set in INIT */
	unsigned async_read:1;

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

	/*
	 * The following bitfields are only for optimization purposes
	 * and hence races in setting them will not cause malfunction
	 */

	/** Is open/release not implemented by fs? */
	unsigned no_open:1;

	/** Is fsync not implemented by fs? */
	unsigned no_fsync:1;

	/** Is fsyncdir not implemented by fs? */
	unsigned no_fsyncdir:1;

	/** Is flush not implemented by fs? */
	unsigned no_flush:1;

	/** Is setxattr not implemented by fs? */
	unsigned no_setxattr:1;

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

	/** The number of requests waiting for completion */
	atomic_t num_waiting;

	/** Negotiated minor version */
	unsigned minor;

	/** Entry on the fuse_conn_list */
	struct list_head entry;

	/** Device ID from super block */
	dev_t dev;

	/** Dentries in the control filesystem */
	struct dentry *ctl_dentry[FUSE_CTL_NUM_DENTRIES];

	/** number of dentries used in the above array */
	int ctl_ndents;

	/** Key for lock owner ID scrambling */
	u32 scramble_key[4];

	/** Reserved request for the DESTROY message */
	struct fuse_req *destroy_req;

	/** Version counter for attribute changes */
	u64 attr_version;

	/** Called on final put */
	void (*release)(struct fuse_conn *);

	/** Super block for this connection. */
	struct super_block *sb;

	/** Read/write semaphore to hold when accessing sb. */
	struct rw_semaphore killsb;

	/** List of device instances belonging to this connection */
	struct list_head devices;
};

static inline struct fuse_conn *get_fuse_conn_super(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct fuse_conn *get_fuse_conn(struct inode *inode)
{
	return get_fuse_conn_super(inode->i_sb);
}

static inline struct fuse_inode *get_fuse_inode(struct inode *inode)
{
	return container_of(inode, struct fuse_inode, inode);
}

static inline u64 get_node_id(struct inode *inode)
{
	return get_fuse_inode(inode)->nodeid;
}

/* New. */
static inline void klpp_fuse_make_bad(struct inode *inode)
{
	remove_inode_hash(inode);
	set_bit(KLPP_FUSE_I_BAD, &get_fuse_inode(inode)->state);
}

/* New. */
static inline bool klpp_fuse_is_bad(struct inode *inode)
{
      return unlikely(test_bit(KLPP_FUSE_I_BAD, &get_fuse_inode(inode)->state) ||
		      is_bad_inode(inode));
}

struct inode *klpp_fuse_iget(struct super_block *sb, u64 nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version);

#define FUSE_DIO_WRITE (1 << 0)

#endif
