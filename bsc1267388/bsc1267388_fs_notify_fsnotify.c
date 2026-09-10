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

/* klp-ccp: from fs/notify/fsnotify.h */
extern struct srcu_struct fsnotify_mark_srcu;

/* klp-ccp: from fs/notify/fsnotify.c */
struct fsnotify_mark *klpr_fsnotify_next_mark(struct fsnotify_mark *mark)
{
	struct hlist_node *node = NULL;

	if (mark)
		node = srcu_dereference(mark->obj_list.next,
					&fsnotify_mark_srcu);

	return hlist_entry_safe(node, struct fsnotify_mark, obj_list);
}

#include <linux/livepatch.h>

extern typeof(fsnotify_mark_srcu) fsnotify_mark_srcu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fsnotify_mark_srcu);
