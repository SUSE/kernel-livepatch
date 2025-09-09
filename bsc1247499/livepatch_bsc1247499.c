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
#define RETPOLINE 1

/* klp-ccp: from fs/namespace.c */
#include <linux/syscalls.h>

/* klp-ccp: from include/linux/mm.h */
#ifdef __KERNEL__

/* klp-ccp: from include/linux/fs.h */
static void (*klpe_put_filesystem)(struct file_system_type *fs);

static bool (*klpe_is_empty_dir_inode)(struct inode *inode);

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from include/linux/mm.h */
#endif /* __KERNEL__ */

/* klp-ccp: from fs/namespace.c */
#include <linux/export.h>
#include <linux/capability.h>

#include <linux/user_namespace.h>
#include <linux/namei.h>

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_SECURITY

static int (*klpe_security_sb_remount)(struct super_block *sb, void *data);

static int (*klpe_security_sb_mount)(const char *dev_name, const struct path *path,
		      const char *type, unsigned long flags, void *data);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */

/* klp-ccp: from fs/namespace.c */
#include <linux/cred.h>
#include <linux/idr.h>
#include <linux/init.h>		/* init_rootfs */

#include <linux/uaccess.h>
#include <linux/proc_ns.h>

/* klp-ccp: from include/linux/proc_ns.h */
static const struct proc_ns_operations (*klpe_mntns_operations);

/* klp-ccp: from fs/namespace.c */
#include <linux/magic.h>

#include <linux/sched/task.h>

/* klp-ccp: from fs/pnode.h */
#include <linux/list.h>
/* klp-ccp: from fs/mount.h */
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	atomic_t		count;
	struct ns_common	ns;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
};

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
	struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
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
	struct fs_pin mnt_umount;
	struct dentry *mnt_ex_mountpoint;
};

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static seqlock_t (*klpe_mount_lock);

static inline void klpr_lock_mount_hash(void)
{
	write_seqlock(&(*klpe_mount_lock));
}

static inline void klpr_unlock_mount_hash(void)
{
	write_sequnlock(&(*klpe_mount_lock));
}

/* klp-ccp: from fs/pnode.h */
#define IS_MNT_SHARED(m) ((m)->mnt.mnt_flags & MNT_SHARED)

#define IS_MNT_UNBINDABLE(m) ((m)->mnt.mnt_flags & MNT_UNBINDABLE)

#define CL_COPY_MNT_NS_FILE	0x80

static void (*klpe_change_mnt_propagation)(struct mount *, int);

static struct mount *(*klpe_copy_tree)(struct mount *, struct dentry *, int);

/* klp-ccp: from fs/internal.h */
static int (*klpe_do_remount_sb)(struct super_block *, int, void *, int);

static const struct dentry_operations (*klpe_ns_dentry_operations);

/* klp-ccp: from fs/namespace.c */
static struct rw_semaphore (*klpe_namespace_sem);

int __mnt_is_readonly(struct vfsmount *mnt);

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

static int klpr_mnt_make_readonly(struct mount *mnt)
{
	int ret = 0;

	klpr_lock_mount_hash();
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
		ret = -EBUSY;
	else
		mnt->mnt.mnt_flags |= MNT_READONLY;
	/*
	 * MNT_READONLY must become visible before ~MNT_WRITE_HOLD, so writers
	 * that become unheld will see MNT_READONLY.
	 */
	smp_wmb();
	mnt->mnt.mnt_flags &= ~MNT_WRITE_HOLD;
	klpr_unlock_mount_hash();
	return ret;
}

static void klpr___mnt_unmake_readonly(struct mount *mnt)
{
	klpr_lock_mount_hash();
	mnt->mnt.mnt_flags &= ~MNT_READONLY;
	klpr_unlock_mount_hash();
}

static inline int check_mnt(struct mount *mnt)
{
	return mnt->mnt_ns == current->nsproxy->mnt_ns;
}

static void (*klpe_touch_mnt_namespace)(struct mnt_namespace *ns);

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

struct vfsmount *
vfs_kern_mount(struct file_system_type *type, int flags, const char *name, void *data);

extern typeof(vfs_kern_mount) vfs_kern_mount;

static struct mount *(*klpe_clone_mnt)(struct mount *old, struct dentry *root,
					int flag);

void mntput(struct vfsmount *mnt);

extern typeof(mntput) mntput;

static void (*klpe_namespace_unlock)(void);

static inline void klpr_namespace_lock(void)
{
	down_write(&(*klpe_namespace_sem));
}

enum umount_tree_flags {
	UMOUNT_SYNC = 1,
	UMOUNT_PROPAGATE = 2,
	UMOUNT_CONNECTED = 4,
};

static void (*klpe_umount_tree)(struct mount *mnt, enum umount_tree_flags how);

static inline bool may_mount(void)
{
	return ns_capable(current->nsproxy->mnt_ns->user_ns, CAP_SYS_ADMIN);
}

#ifdef	CONFIG_MANDATORY_FILE_LOCKING
#error "klp-ccp: non-taken branch"
#else
static inline bool may_mandlock(void)
{
	pr_warn("VFS: \"mand\" mount option not supported");
	return false;
}
#endif

static bool klpr_is_mnt_ns_file(struct dentry *dentry)
{
	/* Is this a proxy for a mount namespace? */
	return dentry->d_op == &(*klpe_ns_dentry_operations) &&
	       dentry->d_fsdata == &(*klpe_mntns_operations);
}

static struct mnt_namespace *(*klpe_to_mnt_ns)(struct ns_common *ns);

static bool klpr_mnt_ns_loop(struct dentry *dentry)
{
	/* Could bind mounting the mount namespace inode cause a
	 * mount namespace loop?
	 */
	struct mnt_namespace *mnt_ns;
	if (!klpr_is_mnt_ns_file(dentry))
		return false;

	mnt_ns = (*klpe_to_mnt_ns)(get_proc_ns(dentry->d_inode));
	return current->nsproxy->mnt_ns->seq >= mnt_ns->seq;
}

static bool (*klpe_has_locked_children)(struct mount *mnt, struct dentry *dentry);

static int (*klpe_invent_group_ids)(struct mount *mnt, bool recurse);

static int (*klpe_attach_recursive_mnt)(struct mount *source_mnt,
			struct mount *dest_mnt,
			struct mountpoint *dest_mp,
			struct path *parent_path);

static struct mountpoint *(*klpe_lock_mount)(struct path *path);

static void (*klpe_unlock_mount)(struct mountpoint *where);

static int (*klpe_graft_tree)(struct mount *mnt, struct mount *p, struct mountpoint *mp);

static int flags_to_propagation_type(int flags)
{
	int type = flags & ~(MS_REC | MS_SILENT);

	/* Fail if any non-propagation flags are set */
	if (type & ~(MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		return 0;
	/* Only one propagation flag should be set */
	if (!is_power_of_2(type))
		return 0;
	return type;
}

static int klpr_do_change_type(struct path *path, int flag)
{
	struct mount *m;
	struct mount *mnt = real_mount(path->mnt);
	int recurse = flag & MS_REC;
	int type;
	int err = 0;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	type = flags_to_propagation_type(flag);
	if (!type)
		return -EINVAL;

	klpr_namespace_lock();
	if (!check_mnt(mnt)) {
		err = -EINVAL;
		goto out_unlock;
	}
	if (type == MS_SHARED) {
		err = (*klpe_invent_group_ids)(mnt, recurse);
		if (err)
			goto out_unlock;
	}

	klpr_lock_mount_hash();
	for (m = mnt; m; m = (recurse ? next_mnt(m, mnt) : NULL))
		(*klpe_change_mnt_propagation)(m, type);
	klpr_unlock_mount_hash();

 out_unlock:
	(*klpe_namespace_unlock)();
	return err;
}

static int klpr_do_loopback(struct path *path, const char *old_name,
				int recurse)
{
	struct path old_path;
	struct mount *mnt = NULL, *old, *parent;
	struct mountpoint *mp;
	int err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &old_path);
	if (err)
		return err;

	err = -EINVAL;
	if (klpr_mnt_ns_loop(old_path.dentry))
		goto out; 

	mp = (*klpe_lock_mount)(path);
	err = PTR_ERR(mp);
	if (IS_ERR(mp))
		goto out;

	old = real_mount(old_path.mnt);
	parent = real_mount(path->mnt);

	err = -EINVAL;
	if (IS_MNT_UNBINDABLE(old))
		goto out2;

	if (!check_mnt(parent))
		goto out2;

	if (!check_mnt(old) && old_path.dentry->d_op != &(*klpe_ns_dentry_operations))
		goto out2;

	if (!recurse && (*klpe_has_locked_children)(old, old_path.dentry))
		goto out2;

	if (recurse)
		mnt = (*klpe_copy_tree)(old, old_path.dentry, CL_COPY_MNT_NS_FILE);
	else
		mnt = (*klpe_clone_mnt)(old, old_path.dentry, 0);

	if (IS_ERR(mnt)) {
		err = PTR_ERR(mnt);
		goto out2;
	}

	mnt->mnt.mnt_flags &= ~MNT_LOCKED;

	err = (*klpe_graft_tree)(mnt, parent, mp);
	if (err) {
		klpr_lock_mount_hash();
		(*klpe_umount_tree)(mnt, UMOUNT_SYNC);
		klpr_unlock_mount_hash();
	}
out2:
	(*klpe_unlock_mount)(mp);
out:
	path_put(&old_path);
	return err;
}

static int klpr_change_mount_flags(struct vfsmount *mnt, int ms_flags)
{
	int error = 0;
	int readonly_request = 0;

	if (ms_flags & MS_RDONLY)
		readonly_request = 1;
	if (readonly_request == __mnt_is_readonly(mnt))
		return 0;

	if (readonly_request)
		error = klpr_mnt_make_readonly(real_mount(mnt));
	else
		klpr___mnt_unmake_readonly(real_mount(mnt));
	return error;
}

static int klpr_do_remount(struct path *path, int flags, int mnt_flags,
		      void *data)
{
	int err;
	struct super_block *sb = path->mnt->mnt_sb;
	struct mount *mnt = real_mount(path->mnt);

	if (!check_mnt(mnt))
		return -EINVAL;

	if (path->dentry != path->mnt->mnt_root)
		return -EINVAL;

	/* Don't allow changing of locked mnt flags.
	 *
	 * No locks need to be held here while testing the various
	 * MNT_LOCK flags because those flags can never be cleared
	 * once they are set.
	 */
	if ((mnt->mnt.mnt_flags & MNT_LOCK_READONLY) &&
	    !(mnt_flags & MNT_READONLY)) {
		return -EPERM;
	}
	if ((mnt->mnt.mnt_flags & MNT_LOCK_NODEV) &&
	    !(mnt_flags & MNT_NODEV)) {
		return -EPERM;
	}
	if ((mnt->mnt.mnt_flags & MNT_LOCK_NOSUID) &&
	    !(mnt_flags & MNT_NOSUID)) {
		return -EPERM;
	}
	if ((mnt->mnt.mnt_flags & MNT_LOCK_NOEXEC) &&
	    !(mnt_flags & MNT_NOEXEC)) {
		return -EPERM;
	}
	if ((mnt->mnt.mnt_flags & MNT_LOCK_ATIME) &&
	    ((mnt->mnt.mnt_flags & MNT_ATIME_MASK) != (mnt_flags & MNT_ATIME_MASK))) {
		return -EPERM;
	}

	err = (*klpe_security_sb_remount)(sb, data);
	if (err)
		return err;

	down_write(&sb->s_umount);
	if (flags & MS_BIND)
		err = klpr_change_mount_flags(path->mnt, flags);
	else if (!capable(CAP_SYS_ADMIN))
		err = -EPERM;
	else
		err = (*klpe_do_remount_sb)(sb, flags, data, 0);
	if (!err) {
		klpr_lock_mount_hash();
		mnt_flags |= mnt->mnt.mnt_flags & ~MNT_USER_SETTABLE_MASK;
		mnt->mnt.mnt_flags = mnt_flags;
		(*klpe_touch_mnt_namespace)(mnt->mnt_ns);
		klpr_unlock_mount_hash();
	}
	up_write(&sb->s_umount);
	return err;
}

static inline int tree_contains_unbindable(struct mount *mnt)
{
	struct mount *p;
	for (p = mnt; p; p = next_mnt(p, mnt)) {
		if (IS_MNT_UNBINDABLE(p))
			return 1;
	}
	return 0;
}

static int klpr_do_move_mount(struct path *path, const char *old_name)
{
	struct path old_path, parent_path;
	struct mount *p;
	struct mount *old;
	struct mountpoint *mp;
	int err;
	if (!old_name || !*old_name)
		return -EINVAL;
	err = kern_path(old_name, LOOKUP_FOLLOW, &old_path);
	if (err)
		return err;

	mp = (*klpe_lock_mount)(path);
	err = PTR_ERR(mp);
	if (IS_ERR(mp))
		goto out;

	old = real_mount(old_path.mnt);
	p = real_mount(path->mnt);

	err = -EINVAL;
	if (!check_mnt(p) || !check_mnt(old))
		goto out1;

	if (old->mnt.mnt_flags & MNT_LOCKED)
		goto out1;

	err = -EINVAL;
	if (old_path.dentry != old_path.mnt->mnt_root)
		goto out1;

	if (!mnt_has_parent(old))
		goto out1;

	if (d_is_dir(path->dentry) !=
	      d_is_dir(old_path.dentry))
		goto out1;
	/*
	 * Don't move a mount residing in a shared parent.
	 */
	if (IS_MNT_SHARED(old->mnt_parent))
		goto out1;
	/*
	 * Don't move a mount tree containing unbindable mounts to a destination
	 * mount which is shared.
	 */
	if (IS_MNT_SHARED(p) && tree_contains_unbindable(old))
		goto out1;
	err = -ELOOP;
	for (; mnt_has_parent(p); p = p->mnt_parent)
		if (p == old)
			goto out1;

	err = (*klpe_attach_recursive_mnt)(old, real_mount(path->mnt), mp, &parent_path);
	if (err)
		goto out1;

	/* if the mount is moved, it should no longer be expire
	 * automatically */
	list_del_init(&old->mnt_expire);
out1:
	(*klpe_unlock_mount)(mp);
out:
	if (!err)
		path_put(&parent_path);
	path_put(&old_path);
	return err;
}

static struct vfsmount *fs_set_subtype(struct vfsmount *mnt, const char *fstype)
{
	int err;
	const char *subtype = strchr(fstype, '.');
	if (subtype) {
		subtype++;
		err = -EINVAL;
		if (!subtype[0])
			goto err;
	} else
		subtype = "";

	mnt->mnt_sb->s_subtype = kstrdup(subtype, GFP_KERNEL);
	err = -ENOMEM;
	if (!mnt->mnt_sb->s_subtype)
		goto err;
	return mnt;

 err:
	mntput(mnt);
	return ERR_PTR(err);
}

static int (*klpe_do_add_mount)(struct mount *newmnt, struct path *path, int mnt_flags);

static bool klpr_mount_too_revealing(struct vfsmount *mnt, int *new_mnt_flags);

static int klpr_do_new_mount(struct path *path, const char *fstype, int flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct vfsmount *mnt;
	int err;

	if (!fstype)
		return -EINVAL;

	type = get_fs_type(fstype);
	if (!type)
		return -ENODEV;

	mnt = vfs_kern_mount(type, flags, name, data);
	if (!IS_ERR(mnt) && (type->fs_flags & FS_HAS_SUBTYPE) &&
	    !mnt->mnt_sb->s_subtype)
		mnt = fs_set_subtype(mnt, fstype);

	(*klpe_put_filesystem)(type);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	if (klpr_mount_too_revealing(mnt, &mnt_flags)) {
		mntput(mnt);
		return -EPERM;
	}

	err = (*klpe_do_add_mount)(real_mount(mnt), path, mnt_flags);
	if (err)
		mntput(mnt);
	return err;
}

long klpp_do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int retval = 0;
	int mnt_flags = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */
	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	/* ... and get the mountpoint */
	retval = user_path(dir_name, &path);
	if (retval)
		return retval;

	retval = (*klpe_security_sb_mount)(dev_name, &path,
				   type_page, flags, data_page);
	if (!retval && !may_mount())
		retval = -EPERM;
	if (!retval && (flags & MS_MANDLOCK) && !may_mandlock())
		retval = -EPERM;
	if (retval)
		goto dput_out;

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

	/* The default atime for remount is preservation */
	if ((flags & MS_REMOUNT) &&
	    ((flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME |
		       MS_STRICTATIME)) == 0)) {
		mnt_flags &= ~MNT_ATIME_MASK;
		mnt_flags |= path.mnt->mnt_flags & MNT_ATIME_MASK;
	}

	flags &= ~(MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_ACTIVE | MS_BORN |
		   MS_NOATIME | MS_NODIRATIME | MS_RELATIME| MS_KERNMOUNT |
		   MS_STRICTATIME | MS_NOREMOTELOCK | MS_SUBMOUNT);

	if (flags & MS_REMOUNT)
		retval = klpr_do_remount(&path, flags & ~MS_REMOUNT, mnt_flags,
				    data_page);
	else if (flags & MS_BIND)
		retval = klpr_do_loopback(&path, dev_name, flags & MS_REC);
	else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		retval = klpr_do_change_type(&path, flags);
	else if (flags & MS_MOVE)
		retval = klpr_do_move_mount(&path, dev_name);
	else
		retval = klpr_do_new_mount(&path, type_page, flags, mnt_flags,
				      dev_name, data_page);
dput_out:
	path_put(&path);
	return retval;
}

static bool klpr_mnt_already_visible(struct mnt_namespace *ns, struct vfsmount *new,
				int *new_mnt_flags)
{
	int new_flags = *new_mnt_flags;
	struct mount *mnt;
	bool visible = false;

	down_read(&(*klpe_namespace_sem));
	list_for_each_entry(mnt, &ns->list, mnt_list) {
		struct mount *child;
		int mnt_flags;

		if (mnt->mnt.mnt_sb->s_type != new->mnt_sb->s_type)
			continue;

		/* This mount is not fully visible if it's root directory
		 * is not the root directory of the filesystem.
		 */
		if (mnt->mnt.mnt_root != mnt->mnt.mnt_sb->s_root)
			continue;

		/* A local view of the mount flags */
		mnt_flags = mnt->mnt.mnt_flags;

		/* Don't miss readonly hidden in the superblock flags */
		if (mnt->mnt.mnt_sb->s_flags & MS_RDONLY)
			mnt_flags |= MNT_LOCK_READONLY;

		/* Verify the mount flags are equal to or more permissive
		 * than the proposed new mount.
		 */
		if ((mnt_flags & MNT_LOCK_READONLY) &&
		    !(new_flags & MNT_READONLY))
			continue;
		if ((mnt_flags & MNT_LOCK_ATIME) &&
		    ((mnt_flags & MNT_ATIME_MASK) != (new_flags & MNT_ATIME_MASK)))
			continue;

		/* This mount is not fully visible if there are any
		 * locked child mounts that cover anything except for
		 * empty directories.
		 */
		list_for_each_entry(child, &mnt->mnt_mounts, mnt_child) {
			struct inode *inode = child->mnt_mountpoint->d_inode;
			/* Only worry about locked mounts */
			if (!(child->mnt.mnt_flags & MNT_LOCKED))
				continue;
			/* Is the directory permanetly empty? */
			if (!(*klpe_is_empty_dir_inode)(inode))
				goto next;
		}
		/* Preserve the locked attributes */
		*new_mnt_flags |= mnt_flags & (MNT_LOCK_READONLY | \
					       MNT_LOCK_ATIME);
		visible = true;
		goto found;
	next:	;
	}
found:
	up_read(&(*klpe_namespace_sem));
	return visible;
}

static bool klpr_mount_too_revealing(struct vfsmount *mnt, int *new_mnt_flags)
{
	const unsigned long required_iflags = SB_I_NOEXEC | SB_I_NODEV;
	struct mnt_namespace *ns = current->nsproxy->mnt_ns;
	unsigned long s_iflags;

	if (ns->user_ns == &init_user_ns)
		return false;

	/* Can this filesystem be too revealing? */
	s_iflags = mnt->mnt_sb->s_iflags;
	if (!(s_iflags & SB_I_USERNS_VISIBLE))
		return false;

	if ((s_iflags & required_iflags) != required_iflags) {
		WARN_ONCE(1, "Expected s_iflags to contain 0x%lx\n",
			  required_iflags);
		return true;
	}

	return !klpr_mnt_already_visible(ns, mnt, new_mnt_flags);
}


#include "livepatch_bsc1247499.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "attach_recursive_mnt", (void *)&klpe_attach_recursive_mnt },
	{ "change_mnt_propagation", (void *)&klpe_change_mnt_propagation },
	{ "clone_mnt", (void *)&klpe_clone_mnt },
	{ "copy_tree", (void *)&klpe_copy_tree },
	{ "do_add_mount", (void *)&klpe_do_add_mount },
	{ "do_remount_sb", (void *)&klpe_do_remount_sb },
	{ "graft_tree", (void *)&klpe_graft_tree },
	{ "has_locked_children", (void *)&klpe_has_locked_children },
	{ "invent_group_ids", (void *)&klpe_invent_group_ids },
	{ "is_empty_dir_inode", (void *)&klpe_is_empty_dir_inode },
	{ "lock_mount", (void *)&klpe_lock_mount },
	{ "mntns_operations", (void *)&klpe_mntns_operations },
	{ "mount_lock", (void *)&klpe_mount_lock },
	{ "namespace_sem", (void *)&klpe_namespace_sem },
	{ "namespace_unlock", (void *)&klpe_namespace_unlock },
	{ "ns_dentry_operations", (void *)&klpe_ns_dentry_operations },
	{ "put_filesystem", (void *)&klpe_put_filesystem },
	{ "security_sb_mount", (void *)&klpe_security_sb_mount },
	{ "security_sb_remount", (void *)&klpe_security_sb_remount },
	{ "to_mnt_ns", (void *)&klpe_to_mnt_ns },
	{ "touch_mnt_namespace", (void *)&klpe_touch_mnt_namespace },
	{ "umount_tree", (void *)&klpe_umount_tree },
	{ "unlock_mount", (void *)&klpe_unlock_mount },
};

int livepatch_bsc1247499_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

