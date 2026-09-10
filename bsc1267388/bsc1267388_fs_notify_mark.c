/*
 * bsc1267388_fs_notify_mark
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


/* klp-ccp: from fs/notify/mark.c */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/ratelimit.h>
#include <linux/atomic.h>
#include <linux/fsnotify_backend.h>

/* klp-ccp: from include/linux/fsnotify_backend.h */
#ifdef __KERNEL__

#ifdef CONFIG_FSNOTIFY

bool klpp_fsnotify_prepare_user_wait(struct fsnotify_iter_info *iter_info);

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

/* klp-ccp: from fs/notify/fsnotify.h */
extern struct srcu_struct fsnotify_mark_srcu;

/* klp-ccp: from fs/notify/mark.c */
extern struct srcu_struct fsnotify_mark_srcu;

void fsnotify_put_mark(struct fsnotify_mark *mark);

extern typeof(fsnotify_put_mark) fsnotify_put_mark;

static bool klpp_fsnotify_get_mark_safe(struct fsnotify_mark *mark)
{
	if (refcount_inc_not_zero(&mark->refcnt)) {
		spin_lock(&mark->lock);
		if (mark->flags & FSNOTIFY_MARK_FLAG_ATTACHED) {
			/* mark is attached, group is still alive then */
			atomic_inc(&mark->group->user_waits);
			spin_unlock(&mark->lock);
			return true;
		}
		spin_unlock(&mark->lock);
		fsnotify_put_mark(mark);
	}
	return false;
}

static void fsnotify_put_mark_wake(struct fsnotify_mark *mark)
{
	if (mark) {
		struct fsnotify_group *group = mark->group;

		fsnotify_put_mark(mark);
		/*
		 * We abuse notification_waitq on group shutdown for waiting for
		 * all marks pinned when waiting for userspace.
		 */
		if (atomic_dec_and_test(&group->user_waits) && group->shutdown)
			wake_up(&group->notification_waitq);
	}
}

bool klpp_fsnotify_prepare_user_wait(struct fsnotify_iter_info *iter_info)
	__releases(&fsnotify_mark_srcu)
{
	int type;

	fsnotify_foreach_iter_type(type) {
		struct fsnotify_mark *mark = iter_info->marks[type];

		/* This can fail if mark is being removed */
		while (mark && !klpp_fsnotify_get_mark_safe(mark)) {
			if (mark->group == iter_info->current_group) {
				__release(&fsnotify_mark_srcu);
				goto fail;
			}
			/* This is a mark in an unrelated group, skip */
			mark = klpr_fsnotify_next_mark(mark);
			iter_info->marks[type] = mark;
		}
	}

	/*
	 * Now that all marks are pinned by refcount in the inode / vfsmount / etc
	 * lists, we can drop SRCU lock, and safely resume the list iteration
	 * once userspace returns.
	 */
	srcu_read_unlock(&fsnotify_mark_srcu, iter_info->srcu_idx);

	return true;

fail:
	for (type--; type >= 0; type--)
		fsnotify_put_mark_wake(iter_info->marks[type]);
	return false;
}


#include <linux/livepatch.h>

extern typeof(fsnotify_mark_srcu) fsnotify_mark_srcu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fsnotify_mark_srcu);
