/*
 * livepatch_bsc1248673
 *
 * Fix for CVE-2025-38499, bsc#1248673
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


/* klp-ccp: from fs/namespace.c */
#include <linux/syscalls.h>

/* klp-ccp: from fs/namespace.c */
#include <linux/export.h>
#include <linux/capability.h>

#include <linux/user_namespace.h>

#include <linux/security.h>
#include <linux/cred.h>
#include <linux/idr.h>
#include <linux/init.h>		/* init_rootfs */

#include <linux/file.h>
#include <linux/uaccess.h>

#include <linux/magic.h>

#include <linux/sched/task.h>

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

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

/* klp-ccp: from fs/pnode.h */
#define IS_MNT_UNBINDABLE(m) ((m)->mnt.mnt_flags & MNT_UNBINDABLE)

#define CL_PRIVATE 		0x10

/* klp-ccp: from fs/namespace.c */
extern struct rw_semaphore namespace_sem;

static inline int check_mnt(struct mount *mnt)
{
	return mnt->mnt_ns == current->nsproxy->mnt_ns;
}

extern struct mount *clone_mnt(struct mount *old, struct dentry *root,
					int flag);

extern bool has_locked_children(struct mount *mnt, struct dentry *dentry);

struct vfsmount *klpp_clone_private_mount(const struct path *path)
{
	struct mount *old_mnt = real_mount(path->mnt);
	struct mount *new_mnt;

	down_read(&namespace_sem);
	if (IS_MNT_UNBINDABLE(old_mnt))
		goto invalid;

	if (!check_mnt(old_mnt))
		goto invalid;

	if (!ns_capable(old_mnt->mnt_ns->user_ns, CAP_SYS_ADMIN))
		goto perm;

	if (has_locked_children(old_mnt, path->dentry))
		goto invalid;

	new_mnt = clone_mnt(old_mnt, path->dentry, CL_PRIVATE);
	up_read(&namespace_sem);

	if (IS_ERR(new_mnt))
		return ERR_CAST(new_mnt);

	/* Longterm mount to be removed by kern_unmount*() */
	new_mnt->mnt_ns = MNT_NS_INTERNAL;

	return &new_mnt->mnt;

invalid:
	up_read(&namespace_sem);
	return ERR_PTR(-EINVAL);

perm:
	up_read(&namespace_sem);
	return ERR_PTR(-EPERM);
}

typeof(klpp_clone_private_mount) klpp_clone_private_mount;


#include "livepatch_bsc1248673.h"

#include <linux/livepatch.h>

extern typeof(clone_mnt) clone_mnt KLP_RELOC_SYMBOL(vmlinux, vmlinux, clone_mnt);
extern typeof(has_locked_children) has_locked_children
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, has_locked_children);
extern typeof(namespace_sem) namespace_sem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, namespace_sem);
