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
struct fsnotify_iter_info {
	struct fsnotify_mark *inode_mark;
	struct fsnotify_mark *vfsmount_mark;
	int srcu_idx;
	unsigned int report_type;
};

static struct srcu_struct (*klpe_fsnotify_mark_srcu);

/* klp-ccp: from fs/notify/mark.c */
static bool (*klpe_fsnotify_get_mark_safe)(struct fsnotify_mark *mark);

static void (*klpe_fsnotify_put_mark_wake)(struct fsnotify_mark *mark);

static bool klpr_fsnotify_get_mark_iter_ref(struct fsnotify_mark **markp, bool report)
{
	while (*markp && !(*klpe_fsnotify_get_mark_safe)(*markp)) {
		if (report)
			return false;
		/* Skip mark in unrelated group */
		*markp = klpr_fsnotify_next_mark(*markp);
	}
	return true;
}

bool klpp_fsnotify_prepare_user_wait(struct fsnotify_iter_info *iter_info)
{
	/* This can fail if mark is being removed */
	if (!klpr_fsnotify_get_mark_iter_ref(&iter_info->inode_mark,
			iter_info->report_type & FSNOTIFY_OBJ_TYPE_INODE))
		return false;
	if (!klpr_fsnotify_get_mark_iter_ref(&iter_info->vfsmount_mark,
			iter_info->report_type & FSNOTIFY_OBJ_TYPE_VFSMOUNT)) {
		(*klpe_fsnotify_put_mark_wake)(iter_info->inode_mark);
		return false;
	}

	/*
	 * Now that both marks are pinned by refcount in the inode / vfsmount
	 * lists, we can drop SRCU lock, and safely resume the list iteration
	 * once userspace returns.
	 */
	srcu_read_unlock(&(*klpe_fsnotify_mark_srcu), iter_info->srcu_idx);

	return true;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fsnotify_get_mark_safe", (void *)&klpe_fsnotify_get_mark_safe },
	{ "fsnotify_mark_srcu", (void *)&klpe_fsnotify_mark_srcu },
	{ "fsnotify_put_mark_wake", (void *)&klpe_fsnotify_put_mark_wake },
};

int bsc1267388_fs_notify_mark_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

