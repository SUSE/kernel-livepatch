/*
 * livepatch_bsc1247499
 *
 * Fix for CVE-2025-38498, bsc#1247499
 *
 *  Upstream commit:
 *  12f147ddd6de ("do_change_type(): refuse to operate on unmounted/not ours mounts")
 *
 *  SLE12-SP5 commit:
 *  fc35a302be80d67451e7d56f2ec0ebea19e808b4
 *
 *  SLE15-SP3 commit:
 *  77d7bfc507e3ace4850481bb7a95d686e97b97bc
 *
 *  SLE15-SP4 and -SP5 commit:
 *  16fc04ae8647461fd00835face2a989cd1e5dc55
 *
 *  SLE15-SP6 commit:
 *  545afad23ad7fc3dffb37308edd16bfcce8017e8
 *
 *  SLE MICRO-6-0 commit:
 *  545afad23ad7fc3dffb37308edd16bfcce8017e8
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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


#define __KERNEL__ 1
#define CC_USING_FENTRY 1

/* klp-ccp: from fs/namespace.c */
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/capability.h>

#include <linux/user_namespace.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/idr.h>
#include <linux/init.h>		/* init_rootfs */

#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/proc_ns.h>
#include <linux/magic.h>

#include <linux/sched/task.h>

/* klp-ccp: from include/uapi/linux/mount.h */
#define MS_RDONLY	 1	/* Mount read-only */
#define MS_NOSUID	 2	/* Ignore suid and sgid bits */
#define MS_NODEV	 4	/* Disallow access to device special files */
#define MS_NOEXEC	 8	/* Disallow program execution */
#define MS_SYNCHRONOUS	16	/* Writes are synced at once */
#define MS_REMOUNT	32	/* Alter flags of a mounted FS */
#define MS_MANDLOCK	64	/* Allow mandatory locks on an FS */

#define MS_NOSYMFOLLOW	256	/* Do not follow symlinks */
#define MS_NOATIME	1024	/* Do not update access times. */
#define MS_NODIRATIME	2048	/* Do not update directory access times */
#define MS_BIND		4096
#define MS_MOVE		8192
#define MS_REC		16384

#define MS_SILENT	32768

#define MS_UNBINDABLE	(1<<17)	/* change to unbindable */
#define MS_PRIVATE	(1<<18)	/* change to private */
#define MS_SLAVE	(1<<19)	/* change to slave */
#define MS_SHARED	(1<<20)	/* change to shared */
#define MS_RELATIME	(1<<21)	/* Update atime relative to mtime/ctime. */

#define MS_I_VERSION	(1<<23) /* Update inode I_version field */
#define MS_STRICTATIME	(1<<24) /* Always perform atime updates */
#define MS_LAZYTIME	(1<<25) /* Update the on-disk [acm]times lazily */

#define MS_NOUSER	(1<<31)

#define MS_RMT_MASK	(MS_RDONLY|MS_SYNCHRONOUS|MS_MANDLOCK|MS_I_VERSION|\
			 MS_LAZYTIME)

#define MS_MGC_VAL 0xC0ED0000
#define MS_MGC_MSK 0xffff0000

/* klp-ccp: from fs/namespace.c */
#include <linux/fs_context.h>

#include <linux/mnt_idmapping.h>

/* klp-ccp: from fs/pnode.h */
#include <linux/list.h>
/* klp-ccp: from fs/mount.h */
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>

struct mnt_namespace {
	struct ns_common	ns;
	struct mount *	root;
	/*
	 * Traversal and modification of .list is protected by either
	 * - taking namespace_sem for write, OR
	 * - taking namespace_sem for read AND taking .ns_lock.
	 */
	struct list_head	list;
	spinlock_t		ns_lock;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
} __randomize_layout;

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
#error "klp-ccp: non-taken branch"
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
	struct mountpoint *mnt_mp;	/* where is it mounted */
	union {
		struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
} __randomize_layout;

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

extern seqlock_t mount_lock;

/* klp-ccp: from fs/pnode.h */
void change_mnt_propagation(struct mount *, int);

/* klp-ccp: from fs/internal.h */
extern int parse_monolithic_mount_data(struct fs_context *, void *);

extern bool may_mount(void);

extern int reconfigure_super(struct fs_context *);

extern bool mount_capable(struct fs_context *);

extern const struct dentry_operations ns_dentry_operations;

/* klp-ccp: from fs/namespace.c */
extern u64 event;

extern struct rw_semaphore namespace_sem;

extern __cacheline_aligned_in_smp seqlock_t mount_lock;

static inline void lock_mount_hash(void)
{
	write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
	write_sequnlock(&mount_lock);
}

bool __mnt_is_readonly(struct vfsmount *mnt);

extern typeof(__mnt_is_readonly) __mnt_is_readonly;

static unsigned int mnt_get_writers(struct mount *mnt)
{
#ifdef CONFIG_SMP
	unsigned int count = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		count += per_cpu_ptr(mnt->mnt_pcp, cpu)->mnt_writers;
	}

	return count;
#else
#error "klp-ccp: non-taken branch"
#endif
}

static inline int mnt_hold_writers(struct mount *mnt)
{
	mnt->mnt.mnt_flags |= MNT_WRITE_HOLD;
	/*
	 * After storing MNT_WRITE_HOLD, we'll read the counters. This store
	 * should be visible before we do.
	 */
	smp_mb();

	/*
	 * With writers on hold, if this value is zero, then there are
	 * definitely no active writers (although held writers may subsequently
	 * increment the count, they'll have to wait, and decrement it after
	 * seeing MNT_READONLY).
	 *
	 * It is OK to have counter incremented on one CPU and decremented on
	 * another: the sum will add up correctly. The danger would be when we
	 * sum up each counter, if we read a counter before it is incremented,
	 * but then read another CPU's count which it has been subsequently
	 * decremented from -- we would see more decrements than we should.
	 * MNT_WRITE_HOLD protects against this scenario, because
	 * mnt_want_write first increments count, then smp_mb, then spins on
	 * MNT_WRITE_HOLD, so it can't be decremented by another CPU while
	 * we're counting up here.
	 */
	if (mnt_get_writers(mnt) > 0)
		return -EBUSY;

	return 0;
}

static inline void mnt_unhold_writers(struct mount *mnt)
{
	/*
	 * MNT_READONLY must become visible before ~MNT_WRITE_HOLD, so writers
	 * that become unheld will see MNT_READONLY.
	 */
	smp_wmb();
	mnt->mnt.mnt_flags &= ~MNT_WRITE_HOLD;
}

static int mnt_make_readonly(struct mount *mnt)
{
	int ret;

	ret = mnt_hold_writers(mnt);
	if (!ret)
		mnt->mnt.mnt_flags |= MNT_READONLY;
	mnt_unhold_writers(mnt);
	return ret;
}

static inline int check_mnt(struct mount *mnt)
{
	return mnt->mnt_ns == current->nsproxy->mnt_ns;
}

static void touch_mnt_namespace(struct mnt_namespace *ns)
{
	if (ns) {
		ns->event = ++event;
		wake_up_interruptible(&ns->poll);
	}
}

static struct mount *next_mnt(struct mount *p, struct mount *root)
{
	struct list_head *next = p->mnt_mounts.next;
	if (next == &p->mnt_mounts) {
		while (1) {
			if (p == root)
				return NULL;
			next = p->mnt_child.next;
			if (next != &p->mnt_parent->mnt_mounts)
				break;
			p = p->mnt_parent;
		}
	}
	return list_entry(next, struct mount, mnt_child);
}

struct vfsmount *vfs_create_mount(struct fs_context *fc);

extern typeof(vfs_create_mount) vfs_create_mount;

void mntput(struct vfsmount *mnt);

extern typeof(mntput) mntput;

extern void namespace_unlock(void);

static inline void namespace_lock(void)
{
	down_write(&namespace_sem);
}

enum umount_tree_flags {
	UMOUNT_SYNC = 1,
	UMOUNT_PROPAGATE = 2,
	UMOUNT_CONNECTED = 4,
};

extern void umount_tree(struct mount *mnt, enum umount_tree_flags how);

bool may_mount(void);

extern void warn_mandlock(void);

static bool is_mnt_ns_file(struct dentry *dentry)
{
	/* Is this a proxy for a mount namespace? */
	return dentry->d_op == &ns_dentry_operations &&
	       dentry->d_fsdata == &mntns_operations;
}

static struct mnt_namespace *to_mnt_ns(struct ns_common *ns)
{
	return container_of(ns, struct mnt_namespace, ns);
}

static bool mnt_ns_loop(struct dentry *dentry)
{
	/* Could bind mounting the mount namespace inode cause a
	 * mount namespace loop?
	 */
	struct mnt_namespace *mnt_ns;
	if (!is_mnt_ns_file(dentry))
		return false;

	mnt_ns = to_mnt_ns(get_proc_ns(dentry->d_inode));
	return current->nsproxy->mnt_ns->seq >= mnt_ns->seq;
}

extern int invent_group_ids(struct mount *mnt, bool recurse);

extern struct mountpoint *lock_mount(struct path *path);

extern void unlock_mount(struct mountpoint *where);

extern int graft_tree(struct mount *mnt, struct mount *p, struct mountpoint *mp);

static int flags_to_propagation_type(int ms_flags)
{
	int type = ms_flags & ~(MS_REC | MS_SILENT);

	/* Fail if any non-propagation flags are set */
	if (type & ~(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		return 0;
	/* Only one propagation flag should be set */
	if (!is_power_of_2(type))
		return 0;
	return type;
}

static int do_change_type(struct path *path, int ms_flags)
{
	struct mount *m;
	struct mount *mnt = real_mount(path->mnt);
	int recurse = ms_flags & MS_REC;
	int type;
	int err = 0;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	type = flags_to_propagation_type(ms_flags);
	if (!type)
		return -EINVAL;

	namespace_lock();
	if (!check_mnt(mnt)) {
		err = -EINVAL;
		goto out_unlock;
	}
	if (type == MS_SHARED) {
		err = invent_group_ids(mnt, recurse);
		if (err)
			goto out_unlock;
	}

	lock_mount_hash();
	for (m = mnt; m; m = (recurse ? next_mnt(m, mnt) : NULL))
		change_mnt_propagation(m, type);
	unlock_mount_hash();

 out_unlock:
	namespace_unlock();
	return err;
}

extern struct mount *__do_loopback(struct path *old_path, int recurse);

static int do_loopback(struct path *path, const char *old_name,
				int recurse)
{
	struct path old_path;
	struct mount *mnt = NULL, *parent;
	struct mountpoint *mp;
	int err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
	if (err)
		return err;

	err = -EINVAL;
	if (mnt_ns_loop(old_path.dentry))
		goto out;

	mp = lock_mount(path);
	if (IS_ERR(mp)) {
		err = PTR_ERR(mp);
		goto out;
	}

	parent = real_mount(path->mnt);
	if (!check_mnt(parent))
		goto out2;

	mnt = __do_loopback(&old_path, recurse);
	if (IS_ERR(mnt)) {
		err = PTR_ERR(mnt);
		goto out2;
	}

	err = graft_tree(mnt, parent, mp);
	if (err) {
		lock_mount_hash();
		umount_tree(mnt, UMOUNT_SYNC);
		unlock_mount_hash();
	}
out2:
	unlock_mount(mp);
out:
	path_put(&old_path);
	return err;
}

static bool can_change_locked_flags(struct mount *mnt, unsigned int mnt_flags)
{
	unsigned int fl = mnt->mnt.mnt_flags;

	if ((fl & MNT_LOCK_READONLY) &&
	    !(mnt_flags & MNT_READONLY))
		return false;

	if ((fl & MNT_LOCK_NODEV) &&
	    !(mnt_flags & MNT_NODEV))
		return false;

	if ((fl & MNT_LOCK_NOSUID) &&
	    !(mnt_flags & MNT_NOSUID))
		return false;

	if ((fl & MNT_LOCK_NOEXEC) &&
	    !(mnt_flags & MNT_NOEXEC))
		return false;

	if ((fl & MNT_LOCK_ATIME) &&
	    ((fl & MNT_ATIME_MASK) != (mnt_flags & MNT_ATIME_MASK)))
		return false;

	return true;
}

static int change_mount_ro_state(struct mount *mnt, unsigned int mnt_flags)
{
	bool readonly_request = (mnt_flags & MNT_READONLY);

	if (readonly_request == __mnt_is_readonly(&mnt->mnt))
		return 0;

	if (readonly_request)
		return mnt_make_readonly(mnt);

	mnt->mnt.mnt_flags &= ~MNT_READONLY;
	return 0;
}

static void set_mount_attributes(struct mount *mnt, unsigned int mnt_flags)
{
	mnt_flags |= mnt->mnt.mnt_flags & ~MNT_USER_SETTABLE_MASK;
	mnt->mnt.mnt_flags = mnt_flags;
	touch_mnt_namespace(mnt->mnt_ns);
}

extern void mnt_warn_timestamp_expiry(struct path *mountpoint, struct vfsmount *mnt);

static int do_reconfigure_mnt(struct path *path, unsigned int mnt_flags)
{
	struct super_block *sb = path->mnt->mnt_sb;
	struct mount *mnt = real_mount(path->mnt);
	int ret;

	if (!check_mnt(mnt))
		return -EINVAL;

	if (path->dentry != mnt->mnt.mnt_root)
		return -EINVAL;

	if (!can_change_locked_flags(mnt, mnt_flags))
		return -EPERM;

	/*
	 * We're only checking whether the superblock is read-only not
	 * changing it, so only take down_read(&sb->s_umount).
	 */
	down_read(&sb->s_umount);
	lock_mount_hash();
	ret = change_mount_ro_state(mnt, mnt_flags);
	if (ret == 0)
		set_mount_attributes(mnt, mnt_flags);
	unlock_mount_hash();
	up_read(&sb->s_umount);

	mnt_warn_timestamp_expiry(path, &mnt->mnt);

	return ret;
}

static int do_remount(struct path *path, int ms_flags, int sb_flags,
		      int mnt_flags, void *data)
{
	int err;
	struct super_block *sb = path->mnt->mnt_sb;
	struct mount *mnt = real_mount(path->mnt);
	struct fs_context *fc;

	if (!check_mnt(mnt))
		return -EINVAL;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	if (!can_change_locked_flags(mnt, mnt_flags))
		return -EPERM;

	fc = fs_context_for_reconfigure(path->dentry, sb_flags, MS_RMT_MASK);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	/*
	 * Indicate to the filesystem that the remount request is coming
	 * from the legacy mount system call.
	 */
	fc->oldapi = true;

	err = parse_monolithic_mount_data(fc, data);
	if (!err) {
		down_write(&sb->s_umount);
		err = -EPERM;
		if (ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)) {
			err = reconfigure_super(fc);
			if (!err) {
				lock_mount_hash();
				set_mount_attributes(mnt, mnt_flags);
				unlock_mount_hash();
			}
		}
		up_write(&sb->s_umount);
	}

	mnt_warn_timestamp_expiry(path, &mnt->mnt);

	put_fs_context(fc);
	return err;
}

extern int do_move_mount(struct path *old_path, struct path *new_path);

static int do_move_mount_old(struct path *path, const char *old_name)
{
	struct path old_path;
	int err;

	if (!old_name || !*old_name)
		return -EINVAL;

	err = kern_path(old_name, LOOKUP_FOLLOW, &old_path);
	if (err)
		return err;

	err = do_move_mount(&old_path, path);
	path_put(&old_path);
	return err;
}

extern int do_add_mount(struct mount *newmnt, struct mountpoint *mp,
			const struct path *path, int mnt_flags);

extern bool mount_too_revealing(const struct super_block *sb, int *new_mnt_flags);

static int do_new_mount_fc(struct fs_context *fc, struct path *mountpoint,
			   unsigned int mnt_flags)
{
	struct vfsmount *mnt;
	struct mountpoint *mp;
	struct super_block *sb = fc->root->d_sb;
	int error;

	error = security_sb_kern_mount(sb);
	if (!error && mount_too_revealing(sb, &mnt_flags))
		error = -EPERM;

	if (unlikely(error)) {
		fc_drop_locked(fc);
		return error;
	}

	up_write(&sb->s_umount);

	mnt = vfs_create_mount(fc);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	mnt_warn_timestamp_expiry(mountpoint, mnt);

	mp = lock_mount(mountpoint);
	if (IS_ERR(mp)) {
		mntput(mnt);
		return PTR_ERR(mp);
	}
	error = do_add_mount(real_mount(mnt), mp, mountpoint, mnt_flags);
	unlock_mount(mp);
	if (error < 0)
		mntput(mnt);
	return error;
}

static int do_new_mount(struct path *path, const char *fstype, int sb_flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct fs_context *fc;
	const char *subtype = NULL;
	int err = 0;

	if (!fstype)
		return -EINVAL;

	type = get_fs_type(fstype);
	if (!type)
		return -ENODEV;

	if (type->fs_flags & FS_HAS_SUBTYPE) {
		subtype = strchr(fstype, '.');
		if (subtype) {
			subtype++;
			if (!*subtype) {
				put_filesystem(type);
				return -EINVAL;
			}
		}
	}

	fc = fs_context_for_mount(type, sb_flags);
	put_filesystem(type);
	if (IS_ERR(fc))
		return PTR_ERR(fc);

	/*
	 * Indicate to the filesystem that the mount request is coming
	 * from the legacy mount system call.
	 */
	fc->oldapi = true;

	if (subtype)
		err = vfs_parse_fs_string(fc, "subtype",
					  subtype, strlen(subtype));
	if (!err && name)
		err = vfs_parse_fs_string(fc, "source", name, strlen(name));
	if (!err)
		err = parse_monolithic_mount_data(fc, data);
	if (!err && !mount_capable(fc))
		err = -EPERM;
	if (!err)
		err = vfs_get_tree(fc);
	if (!err)
		err = do_new_mount_fc(fc, path, mnt_flags);

	put_fs_context(fc);
	return err;
}

int klpp_path_mount(const char *dev_name, struct path *path,
		const char *type_page, unsigned long flags, void *data_page)
{
	unsigned int mnt_flags = 0, sb_flags;
	int ret;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */
	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	if (flags & MS_NOUSER)
		return -EINVAL;

	ret = security_sb_mount(dev_name, path, type_page, flags, data_page);
	if (ret)
		return ret;
	if (!may_mount())
		return -EPERM;
	if (flags & SB_MANDLOCK)
		warn_mandlock();

	/* Default to relatime unless overriden */
	if (!(flags & MS_NOATIME))
		mnt_flags |= MNT_RELATIME;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
	if (flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;
	if (flags & MS_NOSYMFOLLOW)
		mnt_flags |= MNT_NOSYMFOLLOW;

	/* The default atime for remount is preservation */
	if ((flags & MS_REMOUNT) &&
	    ((flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME |
		       MS_STRICTATIME)) == 0)) {
		mnt_flags &= ~MNT_ATIME_MASK;
		mnt_flags |= path->mnt->mnt_flags & MNT_ATIME_MASK;
	}

	sb_flags = flags & (SB_RDONLY |
			    SB_SYNCHRONOUS |
			    SB_MANDLOCK |
			    SB_DIRSYNC |
			    SB_SILENT |
			    SB_POSIXACL |
			    SB_LAZYTIME |
			    SB_I_VERSION);

	if ((flags & (MS_REMOUNT | MS_BIND)) == (MS_REMOUNT | MS_BIND))
		return do_reconfigure_mnt(path, mnt_flags);
	if (flags & MS_REMOUNT)
		return do_remount(path, flags, sb_flags, mnt_flags, data_page);
	if (flags & MS_BIND)
		return do_loopback(path, dev_name, flags & MS_REC);
	if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		return do_change_type(path, flags);
	if (flags & MS_MOVE)
		return do_move_mount_old(path, dev_name);

	return do_new_mount(path, type_page, sb_flags, mnt_flags, dev_name,
			    data_page);
}

bool mount_too_revealing(const struct super_block *sb, int *new_mnt_flags);

extern const struct proc_ns_operations mntns_operations;


#include "livepatch_bsc1247499.h"

#include <linux/livepatch.h>

extern typeof(__do_loopback) __do_loopback
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __do_loopback);
extern typeof(change_mnt_propagation) change_mnt_propagation
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, change_mnt_propagation);
extern typeof(do_add_mount) do_add_mount
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_add_mount);
extern typeof(do_move_mount) do_move_mount
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_move_mount);
extern typeof(event) event KLP_RELOC_SYMBOL(vmlinux, vmlinux, event);
extern typeof(fc_drop_locked) fc_drop_locked
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fc_drop_locked);
extern typeof(graft_tree) graft_tree
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, graft_tree);
extern typeof(invent_group_ids) invent_group_ids
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, invent_group_ids);
extern typeof(lock_mount) lock_mount
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, lock_mount);
extern typeof(may_mount) may_mount KLP_RELOC_SYMBOL(vmlinux, vmlinux, may_mount);
extern typeof(mnt_warn_timestamp_expiry) mnt_warn_timestamp_expiry
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mnt_warn_timestamp_expiry);
extern typeof(mntns_operations) mntns_operations
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mntns_operations);
extern typeof(mount_capable) mount_capable
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mount_capable);
extern typeof(mount_lock) mount_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mount_lock);
extern typeof(mount_too_revealing) mount_too_revealing
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mount_too_revealing);
extern typeof(namespace_sem) namespace_sem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, namespace_sem);
extern typeof(namespace_unlock) namespace_unlock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, namespace_unlock);
extern typeof(ns_dentry_operations) ns_dentry_operations
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ns_dentry_operations);
extern typeof(parse_monolithic_mount_data) parse_monolithic_mount_data
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, parse_monolithic_mount_data);
extern typeof(put_filesystem) put_filesystem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, put_filesystem);
extern typeof(reconfigure_super) reconfigure_super
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, reconfigure_super);
extern typeof(security_sb_kern_mount) security_sb_kern_mount
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_sb_kern_mount);
extern typeof(security_sb_mount) security_sb_mount
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_sb_mount);
extern typeof(umount_tree) umount_tree
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, umount_tree);
extern typeof(unlock_mount) unlock_mount
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, unlock_mount);
extern typeof(warn_mandlock) warn_mandlock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, warn_mandlock);
