/*
 * livepatch_bsc1263177
 *
 * Fix for CVE-2026-31586, bsc#1263177
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1263177.h"


/* klp-ccp: from mm/backing-dev.c */
#include <linux/blkdev.h>
#include <linux/wait.h>
#include <linux/rbtree.h>
#include <linux/kthread.h>
#include <linux/backing-dev.h>
#include <linux/blk-cgroup.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/writeback.h>
#include <linux/device.h>
#include <trace/events/writeback.h>

#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#else
#error "klp-ccp: non-taken branch"
#endif

extern void wb_shutdown(struct bdi_writeback *wb);

extern void wb_exit(struct bdi_writeback *wb);

#ifdef CONFIG_CGROUP_WRITEBACK

#include <linux/memcontrol.h>

extern spinlock_t cgwb_lock;

extern void cgwb_free_rcu(struct rcu_head *rcu_head);

void klpp_cgwb_release_workfn(struct work_struct *work)
{
	struct bdi_writeback *wb = container_of(work, struct bdi_writeback,
						release_work);
	struct backing_dev_info *bdi = wb->bdi;

	mutex_lock(&wb->bdi->cgwb_release_mutex);
	wb_shutdown(wb);

	css_put(wb->memcg_css);

	/* triggers blkg destruction if no online users left */
	blkcg_unpin_online(wb->blkcg_css);

	css_put(wb->blkcg_css);
	mutex_unlock(&wb->bdi->cgwb_release_mutex);

	fprop_local_destroy_percpu(&wb->memcg_completions);

	spin_lock_irq(&cgwb_lock);
	list_del(&wb->offline_node);
	spin_unlock_irq(&cgwb_lock);

	wb_exit(wb);
	bdi_put(bdi);
	WARN_ON_ONCE(!list_empty(&wb->b_attached));
	call_rcu(&wb->rcu, cgwb_free_rcu);
}

#else	/* CONFIG_CGROUP_WRITEBACK */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_CGROUP_WRITEBACK */

void bdi_put(struct backing_dev_info *bdi);

extern typeof(bdi_put) bdi_put;


#include <linux/livepatch.h>

extern typeof(blkcg_unpin_online) blkcg_unpin_online
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, blkcg_unpin_online);
extern typeof(cgwb_free_rcu) cgwb_free_rcu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgwb_free_rcu);
extern typeof(cgwb_lock) cgwb_lock KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgwb_lock);
extern typeof(fprop_local_destroy_percpu) fprop_local_destroy_percpu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fprop_local_destroy_percpu);
extern typeof(wb_exit) wb_exit KLP_RELOC_SYMBOL(vmlinux, vmlinux, wb_exit);
extern typeof(wb_shutdown) wb_shutdown
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, wb_shutdown);
