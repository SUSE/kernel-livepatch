/*
 * bsc1267388_fs_notify_fsnotify
 *
 * Fix for CVE-2026-46150, bsc#1267388
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


#include "livepatch_bsc1267388.h"


/* klp-ccp: from fs/notify/fsnotify.c */
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/srcu.h>
#include <linux/fsnotify_backend.h>

/* klp-ccp: from include/linux/fsnotify_backend.h */
#ifdef __KERNEL__

#ifdef CONFIG_FSNOTIFY

int klpp_fsnotify(struct inode *to_tell, __u32 mask, const void *data, int data_is,
		    const unsigned char *name, u32 cookie);

struct fsnotify_mark *klpr_fsnotify_next_mark(struct fsnotify_mark *mark);

#else
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_FSNOTIFY */

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif	/* __KERNEL __ */

/* klp-ccp: from fs/notify/fsnotify.h */
#include <linux/list.h>
#include <linux/fsnotify.h>
#include <linux/srcu.h>
#include <linux/types.h>
/* klp-ccp: from fs/mount.h */
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

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

/* klp-ccp: from fs/notify/fsnotify.h */
struct fsnotify_iter_info {
	struct fsnotify_mark *inode_mark;
	struct fsnotify_mark *vfsmount_mark;
	int srcu_idx;
	unsigned int report_type;
};

static struct srcu_struct (*klpe_fsnotify_mark_srcu);

static int (*klpe_fsnotify_compare_groups)(struct fsnotify_group *a,
				   struct fsnotify_group *b);

/* klp-ccp: from fs/notify/fsnotify.c */
static int send_to_group(struct inode *to_tell,
			 struct fsnotify_mark *inode_mark,
			 struct fsnotify_mark *vfsmount_mark,
			 __u32 mask, const void *data,
			 int data_is, u32 cookie,
			 const unsigned char *file_name,
			 struct fsnotify_iter_info *iter_info)
{
	struct fsnotify_group *group = NULL;
	__u32 inode_test_mask = 0;
	__u32 vfsmount_test_mask = 0;

	if (unlikely(!inode_mark && !vfsmount_mark)) {
		BUG();
		return 0;
	}

	/* clear ignored on inode modification */
	if (mask & FS_MODIFY) {
		if (inode_mark &&
		    !(inode_mark->flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY))
			inode_mark->ignored_mask = 0;
		if (vfsmount_mark &&
		    !(vfsmount_mark->flags & FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY))
			vfsmount_mark->ignored_mask = 0;
	}

	/* does the inode mark tell us to do something? */
	if (inode_mark) {
		group = inode_mark->group;
		inode_test_mask = (mask & ~FS_EVENT_ON_CHILD);
		inode_test_mask &= inode_mark->mask;
		inode_test_mask &= ~inode_mark->ignored_mask;
	}

	/* does the vfsmount_mark tell us to do something? */
	if (vfsmount_mark) {
		vfsmount_test_mask = (mask & ~FS_EVENT_ON_CHILD);
		group = vfsmount_mark->group;
		vfsmount_test_mask &= vfsmount_mark->mask;
		vfsmount_test_mask &= ~vfsmount_mark->ignored_mask;
		if (inode_mark)
			vfsmount_test_mask &= ~inode_mark->ignored_mask;
	}

	pr_debug("%s: group=%p to_tell=%p mask=%x inode_mark=%p"
		 " inode_test_mask=%x vfsmount_mark=%p vfsmount_test_mask=%x"
		 " data=%p data_is=%d cookie=%d\n",
		 __func__, group, to_tell, mask, inode_mark,
		 inode_test_mask, vfsmount_mark, vfsmount_test_mask, data,
		 data_is, cookie);

	if (!inode_test_mask && !vfsmount_test_mask)
		return 0;

	return group->ops->handle_event(group, to_tell, inode_mark,
					vfsmount_mark, mask, data, data_is,
					file_name, cookie, iter_info);
}

struct fsnotify_mark *klpr_fsnotify_next_mark(struct fsnotify_mark *mark)
{
	struct hlist_node *node = NULL;

	if (mark)
		node = srcu_dereference(mark->obj_list.next,
					&fsnotify_mark_srcu);
	return hlist_entry_safe(node, struct fsnotify_mark, obj_list);
}

int klpp_fsnotify(struct inode *to_tell, __u32 mask, const void *data, int data_is,
	     const unsigned char *file_name, u32 cookie)
{
	struct hlist_node *inode_node = NULL, *vfsmount_node = NULL;
	struct fsnotify_mark *inode_mark, *vfsmount_mark;
	struct fsnotify_mark_connector *inode_conn, *vfsmount_conn;
	struct fsnotify_iter_info iter_info;
	struct mount *mnt;
	int ret = 0;
	/* global tests shouldn't care about events on child only the specific event */
	__u32 test_mask = (mask & ~FS_EVENT_ON_CHILD);

	if (data_is == FSNOTIFY_EVENT_PATH)
		mnt = real_mount(((const struct path *)data)->mnt);
	else
		mnt = NULL;

	/*
	 * Optimization: srcu_read_lock() has a memory barrier which can
	 * be expensive.  It protects walking the *_fsnotify_marks lists.
	 * However, if we do not walk the lists, we do not have to do
	 * SRCU because we have no references to any objects and do not
	 * need SRCU to keep them "alive".
	 */
	if (!to_tell->i_fsnotify_marks &&
	    (!mnt || !mnt->mnt_fsnotify_marks))
		return 0;
	/*
	 * if this is a modify event we may need to clear the ignored masks
	 * otherwise return if neither the inode nor the vfsmount care about
	 * this type of event.
	 */
	if (!(mask & FS_MODIFY) &&
	    !(test_mask & to_tell->i_fsnotify_mask) &&
	    !(mnt && test_mask & mnt->mnt_fsnotify_mask))
		return 0;

	iter_info.srcu_idx = srcu_read_lock(&(*klpe_fsnotify_mark_srcu));

	inode_conn = srcu_dereference(to_tell->i_fsnotify_marks,
				      &fsnotify_mark_srcu);
	if (inode_conn)
		inode_node = srcu_dereference(inode_conn->list.first,
					      &fsnotify_mark_srcu);

	/* An event "on child" is not intended for a mount mark */
	if (mnt && !(mask & FS_EVENT_ON_CHILD)) {
		inode_conn = srcu_dereference(to_tell->i_fsnotify_marks,
					      &fsnotify_mark_srcu);
		if (inode_conn)
			inode_node = srcu_dereference(inode_conn->list.first,
						      &fsnotify_mark_srcu);
		vfsmount_conn = srcu_dereference(mnt->mnt_fsnotify_marks,
					         &fsnotify_mark_srcu);
		if (vfsmount_conn)
			vfsmount_node = srcu_dereference(
						vfsmount_conn->list.first,
						&fsnotify_mark_srcu);
	}

	iter_info.inode_mark =
		hlist_entry_safe(srcu_dereference(inode_node, &fsnotify_mark_srcu),
				 struct fsnotify_mark, obj_list);

	iter_info.vfsmount_mark =
		hlist_entry_safe(srcu_dereference(vfsmount_node, &fsnotify_mark_srcu),
			         struct fsnotify_mark, obj_list);
	/*
	 * We need to merge inode & vfsmount mark lists so that inode mark
	 * ignore masks are properly reflected for mount mark notifications.
	 * That's why this traversal is so complicated...
	 */
	while (iter_info.inode_mark || iter_info.vfsmount_mark) {
		inode_mark = iter_info.inode_mark;
		vfsmount_mark = iter_info.vfsmount_mark;
		if (inode_mark && vfsmount_mark) {
			int cmp = (*klpe_fsnotify_compare_groups)(inode_mark->group,
							  vfsmount_mark->group);
			if (cmp > 0)
				inode_mark = NULL;
			else if (cmp < 0)
				vfsmount_mark = NULL;
		}
		iter_info.report_type = 0;
		if (inode_mark)
			iter_info.report_type |= FSNOTIFY_OBJ_TYPE_INODE;
		if (vfsmount_mark)
			iter_info.report_type |= FSNOTIFY_OBJ_TYPE_VFSMOUNT;

		ret = send_to_group(to_tell, inode_mark, vfsmount_mark, mask,
				    data, data_is, cookie, file_name,
				    &iter_info);

		if (ret && (mask & ALL_FSNOTIFY_PERM_EVENTS))
			goto out;

		if (inode_mark)
			iter_info.inode_mark = klpr_fsnotify_next_mark(inode_mark);
		if (vfsmount_mark)
			iter_info.vfsmount_mark =
					klpr_fsnotify_next_mark(vfsmount_mark);
	}
	ret = 0;
out:
	srcu_read_unlock(&(*klpe_fsnotify_mark_srcu), iter_info.srcu_idx);

	return ret;
}

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fsnotify_compare_groups", (void *)&klpe_fsnotify_compare_groups },
	{ "fsnotify_mark_srcu", (void *)&klpe_fsnotify_mark_srcu },
};

int bsc1267388_fs_notify_fsnotify_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

