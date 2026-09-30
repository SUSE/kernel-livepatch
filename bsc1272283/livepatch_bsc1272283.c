/*
 * livepatch_bsc1272283
 *
 * Fix for CVE-2026-63802, bsc#1272283
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


#include "livepatch_bsc1272283.h"


/* klp-ccp: from block/blk-cgroup.c */
#include <linux/ioprio.h>
#include <linux/kdev_t.h>
#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/err.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/ctype.h>
#include <linux/resume_user_mode.h>
#include <linux/psi.h>
#include <linux/part_stat.h>
/* klp-ccp: from block/blk.h */
#include <linux/blk-crypto.h>
#include <linux/memblock.h>	/* for max_pfn/max_low_pfn */
#include <xen/xen.h>
/* klp-ccp: from block/blk-crypto-internal.h */
#include <linux/bio.h>
#include <linux/blk-mq.h>
/* klp-ccp: from block/blk-cgroup.h */
#include <linux/blk-cgroup.h>
#include <linux/cgroup.h>
#include <linux/kthread.h>
#include <linux/blk-mq.h>
#include <linux/llist.h>

#ifdef CONFIG_BLK_CGROUP

enum blkg_iostat_type {
	BLKG_IOSTAT_READ,
	BLKG_IOSTAT_WRITE,
	BLKG_IOSTAT_DISCARD,

	BLKG_IOSTAT_NR,
};

struct blkg_iostat {
	u64				bytes[BLKG_IOSTAT_NR];
	u64				ios[BLKG_IOSTAT_NR];
};

struct blkg_iostat_set {
	struct u64_stats_sync		sync;
	struct blkcg_gq		       *blkg;
	struct llist_node		lnode;
	int				lqueued;	/* queued in llist */
	struct blkg_iostat		cur;
	struct blkg_iostat		last;
};

struct blkcg_gq {
	/* Pointer to the associated request_queue */
	struct request_queue		*q;
	struct list_head		q_node;
	struct hlist_node		blkcg_node;
	struct blkcg			*blkcg;

	/* all non-root blkcg_gq's are guaranteed to have access to parent */
	struct blkcg_gq			*parent;

	/* reference count */
	struct percpu_ref		refcnt;

	/* is this blkg online? protected by both blkcg and q locks */
	bool				online;

	struct blkg_iostat_set __percpu	*iostat_cpu;
	struct blkg_iostat_set		iostat;

	struct blkg_policy_data		*pd[BLKCG_MAX_POLS];
#ifdef CONFIG_BLK_CGROUP_PUNT_BIO
	spinlock_t			async_bio_lock;
	struct bio_list			async_bios;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	union {
		struct work_struct	async_bio_work;
		struct work_struct	free_work;
	};

	atomic_t			use_delay;
	atomic64_t			delay_nsec;
	atomic64_t			delay_start;
	u64				last_delay;
	int				last_use;

	struct rcu_head			rcu_head;
};

struct blkcg {
	struct cgroup_subsys_state	css;
	spinlock_t			lock;
	refcount_t			online_pin;

	struct radix_tree_root		blkg_tree;
	struct blkcg_gq	__rcu		*blkg_hint;
	struct hlist_head		blkg_list;

	struct blkcg_policy_data	*cpd[BLKCG_MAX_POLS];

	struct list_head		all_blkcgs_node;

	/*
	 * List of updated percpu blkg_iostat_set's since the last flush.
	 */
	struct llist_head __percpu	*lhead;

#ifdef CONFIG_BLK_CGROUP_FC_APPID
	char                            fc_app_id[FC_APPID_LEN];
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_CGROUP_WRITEBACK
	struct list_head		cgwb_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

#else	/* CONFIG_BLK_CGROUP */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_BLK_CGROUP */

/* klp-ccp: from block/blk-ioprio.h */
#include <linux/kconfig.h>

/* klp-ccp: from block/blk-cgroup.c */
static void __blkcg_rstat_flush(struct blkcg *blkcg, int cpu);

extern raw_spinlock_t blkg_stat_lock;

extern void blkg_free_workfn(struct work_struct *work);

static void blkg_free(struct blkcg_gq *blkg)
{
	if (!blkg)
		return;

	/*
	 * Both ->pd_free_fn() and request queue's release handler may
	 * sleep, so free us by scheduling one work func
	 */
	INIT_WORK(&blkg->free_work, blkg_free_workfn);
	schedule_work(&blkg->free_work);
}

void klpp___blkg_release(struct rcu_head *rcu)
{
	struct blkcg_gq *blkg = container_of(rcu, struct blkcg_gq, rcu_head);

#ifdef CONFIG_BLK_CGROUP_PUNT_BIO
	WARN_ON(!bio_list_empty(&blkg->async_bios));
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	css_put(&blkg->blkcg->css);
	blkg_free(blkg);
}

void klpp_blkg_release(struct percpu_ref *ref)
{
	struct blkcg_gq *blkg = container_of(ref, struct blkcg_gq, refcnt);
	struct blkcg *blkcg = blkg->blkcg;
	int cpu;

	/*
	 * Flush all the non-empty percpu lockless lists before releasing
	 * us, given these stat belongs to us.
	 *
	 * blkg_stat_lock is for serializing blkg stat update
	 */
	for_each_possible_cpu(cpu)
		__blkcg_rstat_flush(blkcg, cpu);

	call_rcu(&blkg->rcu_head, klpp___blkg_release);
}

static void blkg_iostat_set(struct blkg_iostat *dst, struct blkg_iostat *src)
{
	int i;

	for (i = 0; i < BLKG_IOSTAT_NR; i++) {
		dst->bytes[i] = src->bytes[i];
		dst->ios[i] = src->ios[i];
	}
}

extern void blkcg_iostat_update(struct blkcg_gq *blkg, struct blkg_iostat *cur,
				struct blkg_iostat *last);

static void __blkcg_rstat_flush(struct blkcg *blkcg, int cpu)
{
	struct llist_head *lhead = per_cpu_ptr(blkcg->lhead, cpu);
	struct llist_node *lnode;
	struct blkg_iostat_set *bisc, *next_bisc;
	unsigned long flags;

	rcu_read_lock();

	lnode = llist_del_all(lhead);
	if (!lnode)
		goto out;

	/*
	 * For covering concurrent parent blkg update from blkg_release().
	 *
	 * When flushing from cgroup, cgroup_rstat_lock is always held, so
	 * this lock won't cause contention most of time.
	 */
	raw_spin_lock_irqsave(&blkg_stat_lock, flags);

	/*
	 * Iterate only the iostat_cpu's queued in the lockless list.
	 */
	llist_for_each_entry_safe(bisc, next_bisc, lnode, lnode) {
		struct blkcg_gq *blkg = bisc->blkg;
		struct blkcg_gq *parent = blkg->parent;
		struct blkg_iostat cur;
		unsigned int seq;

		/*
		 * Order assignment of `next_bisc` from `bisc->lnode.next` in
		 * llist_for_each_entry_safe and clearing `bisc->lqueued` for
		 * avoiding to assign `next_bisc` with new next pointer added
		 * in blk_cgroup_bio_start() in case of re-ordering.
		 *
		 * The pair barrier is implied in llist_add() in blk_cgroup_bio_start().
		 */
		smp_mb();

		WRITE_ONCE(bisc->lqueued, false);
		if (bisc == &blkg->iostat)
			goto propagate_up; /* propagate up to parent only */

		/* fetch the current per-cpu values */
		do {
			seq = u64_stats_fetch_begin(&bisc->sync);
			blkg_iostat_set(&cur, &bisc->cur);
		} while (u64_stats_fetch_retry(&bisc->sync, seq));

		blkcg_iostat_update(blkg, &cur, &bisc->last);

propagate_up:
		/* propagate global delta to parent (unless that's root) */
		if (parent && parent->parent) {
			blkcg_iostat_update(parent, &blkg->iostat.cur,
					    &blkg->iostat.last);
			/*
			 * Queue parent->iostat to its blkcg's lockless
			 * list to propagate up to the grandparent if the
			 * iostat hasn't been queued yet.
			 */
			if (!parent->iostat.lqueued) {
				struct llist_head *plhead;

				plhead = per_cpu_ptr(parent->blkcg->lhead, cpu);
				llist_add(&parent->iostat.lnode, plhead);
				parent->iostat.lqueued = true;
			}
		}
	}
	raw_spin_unlock_irqrestore(&blkg_stat_lock, flags);
out:
	rcu_read_unlock();
}


#include <linux/livepatch.h>

extern typeof(blkcg_iostat_update) blkcg_iostat_update
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, blkcg_iostat_update);
extern typeof(blkg_free_workfn) blkg_free_workfn
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, blkg_free_workfn);
extern typeof(blkg_stat_lock) blkg_stat_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, blkg_stat_lock);
