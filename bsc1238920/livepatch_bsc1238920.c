/*
 * livepatch_bsc1238920
 *
 * Fix for CVE-2022-49465, bsc#1238920
 *
 *  Upstream commit:
 *  5a011f889b48 ("blk-throttle: Set BIO_THROTTLED when bio has been throttled")
 *
 *  SLE12-SP5 commit:
 *  885f88f17e45cd4e0954c5733db4a5fd45b7027e
 *
 *  SLE15-SP3 commit:
 *  0dcd6fb6cbf2f77523a0e23d676f57a7c7bccfc5
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b13c6e53b7b7ac497e52c3aef31116cacf797768
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
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


/* klp-ccp: from block/blk-throttle.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/blktrace_api.h>
#include <linux/blk-cgroup.h>

/* klp-ccp: from include/linux/blk-cgroup.h */
#ifdef CONFIG_BLK_CGROUP
#else	/* CONFIG_BLK_CGROUP */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_BLK_CGROUP */

/* klp-ccp: from block/blk.h */
#include <linux/idr.h>
/* klp-ccp: from block/blk-stat.h */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/ktime.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>

/* klp-ccp: from block/blk-throttle.c */
static struct blkcg_policy (*klpe_blkcg_policy_throtl);

struct throtl_qnode {
	struct list_head	node;		/* service_queue->queued[] */
	struct bio_list		bios;		/* queued bios */
	struct throtl_grp	*tg;		/* tg this qnode belongs to */
};

struct throtl_service_queue {
	struct throtl_service_queue *parent_sq;	/* the parent service_queue */

	/*
	 * Bios queued directly to this service_queue or dispatched from
	 * children throtl_grp's.
	 */
	struct list_head	queued[2];	/* throtl_qnode [READ/WRITE] */
	unsigned int		nr_queued[2];	/* number of queued bios */

	/*
	 * RB tree of active children throtl_grp's, which are sorted by
	 * their ->disptime.
	 */
	struct rb_root		pending_tree;	/* RB tree of active tgs */
	struct rb_node		*first_pending;	/* first node in the tree */
	unsigned int		nr_pending;	/* # queued in the tree */
	unsigned long		first_pending_disptime;	/* disptime of the first tg */
	struct timer_list	pending_timer;	/* fires on first_pending_disptime */
};

enum tg_state_flags {
	THROTL_TG_PENDING	= 1 << 0,	/* on parent's pending tree */
	THROTL_TG_WAS_EMPTY	= 1 << 1,	/* bio_lists[] became non-empty */
};

enum {
	LIMIT_LOW,
	LIMIT_MAX,
	LIMIT_CNT,
};

struct throtl_grp {
	/* must be the first member */
	struct blkg_policy_data pd;

	/* active throtl group service_queue member */
	struct rb_node rb_node;

	/* throtl_data this group belongs to */
	struct throtl_data *td;

	/* this group's service queue */
	struct throtl_service_queue service_queue;

	/*
	 * qnode_on_self is used when bios are directly queued to this
	 * throtl_grp so that local bios compete fairly with bios
	 * dispatched from children.  qnode_on_parent is used when bios are
	 * dispatched from this throtl_grp into its parent and will compete
	 * with the sibling qnode_on_parents and the parent's
	 * qnode_on_self.
	 */
	struct throtl_qnode qnode_on_self[2];
	struct throtl_qnode qnode_on_parent[2];

	/*
	 * Dispatch time in jiffies. This is the estimated time when group
	 * will unthrottle and is ready to dispatch more bio. It is used as
	 * key to sort active groups in service tree.
	 */
	unsigned long disptime;

	unsigned int flags;

	/* are there any throtl rules between this group and td? */
	bool has_rules[2];

	/* internally used bytes per second rate limits */
	uint64_t bps[2][LIMIT_CNT];
	/* user configured bps limits */
	uint64_t bps_conf[2][LIMIT_CNT];

	/* internally used IOPS limits */
	unsigned int iops[2][LIMIT_CNT];
	/* user configured IOPS limits */
	unsigned int iops_conf[2][LIMIT_CNT];

	/* Number of bytes disptached in current slice */
	uint64_t bytes_disp[2];
	/* Number of bio's dispatched in current slice */
	unsigned int io_disp[2];

	unsigned long last_low_overflow_time[2];

	uint64_t last_bytes_disp[2];
	unsigned int last_io_disp[2];

	unsigned long last_check_time;

	unsigned long latency_target; /* us */
	unsigned long latency_target_conf; /* us */
	/* When did we start a new slice */
	unsigned long slice_start[2];
	unsigned long slice_end[2];

	unsigned long last_finish_time; /* ns / 1024 */
	unsigned long checked_last_finish_time; /* ns / 1024 */
	unsigned long avg_idletime; /* ns / 1024 */
	unsigned long idletime_threshold; /* us */
	unsigned long idletime_threshold_conf; /* us */

	unsigned int bio_cnt; /* total bios */
	unsigned int bad_bio_cnt; /* bios exceeding latency threshold */
	unsigned long bio_cnt_reset_time;
};

#define LATENCY_BUCKET_SIZE 9

struct latency_bucket {
	unsigned long total_latency; /* ns / 1024 */
	int samples;
};

struct avg_latency_bucket {
	unsigned long latency; /* ns / 1024 */
	bool valid;
};

struct throtl_data
{
	/* service tree for active throtl groups */
	struct throtl_service_queue service_queue;

	struct request_queue *queue;

	/* Total Number of queued bios on READ and WRITE lists */
	unsigned int nr_queued[2];

	unsigned int throtl_slice;

	/* Work for dispatching throttled bios */
	struct work_struct dispatch_work;
	unsigned int limit_index;
	bool limit_valid[LIMIT_CNT];

	unsigned long low_upgrade_time;
	unsigned long low_downgrade_time;

	unsigned int scale;

	struct latency_bucket tmp_buckets[2][LATENCY_BUCKET_SIZE];
	struct avg_latency_bucket avg_buckets[2][LATENCY_BUCKET_SIZE];
	struct latency_bucket __percpu *latency_buckets[2];
	unsigned long last_calculate_time;
	unsigned long filtered_latency;

	bool track_bio_latency;
};

static inline struct throtl_grp *pd_to_tg(struct blkg_policy_data *pd)
{
	return pd ? container_of(pd, struct throtl_grp, pd) : NULL;
}

static inline struct throtl_grp *klpr_blkg_to_tg(struct blkcg_gq *blkg)
{
	return pd_to_tg(blkg_to_pd(blkg, &(*klpe_blkcg_policy_throtl)));
}

static inline struct blkcg_gq *tg_to_blkg(struct throtl_grp *tg)
{
	return pd_to_blkg(&tg->pd);
}

static struct throtl_grp *sq_to_tg(struct throtl_service_queue *sq)
{
	if (sq && sq->parent_sq)
		return container_of(sq, struct throtl_grp, service_queue);
	else
		return NULL;
}

static struct throtl_data *sq_to_td(struct throtl_service_queue *sq)
{
	struct throtl_grp *tg = sq_to_tg(sq);

	if (tg)
		return tg->td;
	else
		return container_of(sq, struct throtl_data, service_queue);
}

static uint64_t (*klpe_tg_bps_limit)(struct throtl_grp *tg, int rw);

static unsigned int (*klpe_tg_iops_limit)(struct throtl_grp *tg, int rw);

#define throtl_log(sq, fmt, args...)	do {				\
	struct throtl_grp *__tg = sq_to_tg((sq));			\
	struct throtl_data *__td = sq_to_td((sq));			\
									\
	(void)__td;							\
	if (likely(!blk_trace_note_message_enabled(__td->queue)))	\
		break;							\
	if ((__tg)) {							\
		blk_add_cgroup_trace_msg(__td->queue,			\
			tg_to_blkg(__tg)->blkcg, "throtl " fmt, ##args);\
	} else {							\
		blk_add_trace_msg(__td->queue, "throtl " fmt, ##args);	\
	}								\
} while (0)

static void (*klpe_throtl_upgrade_state)(struct throtl_data *td);

static bool (*klpe_throtl_schedule_next_dispatch)(struct throtl_service_queue *sq,
					  bool force);

static inline void throtl_set_slice_end(struct throtl_grp *tg, bool rw,
					unsigned long jiffy_end)
{
	tg->slice_end[rw] = roundup(jiffy_end, tg->td->throtl_slice);
}

static bool throtl_slice_used(struct throtl_grp *tg, bool rw)
{
	if (time_in_range(jiffies, tg->slice_start[rw], tg->slice_end[rw]))
		return false;

	return true;
}

static inline void klpr_throtl_trim_slice(struct throtl_grp *tg, bool rw)
{
	unsigned long nr_slices, time_elapsed, io_trim;
	u64 bytes_trim, tmp;

	BUG_ON(time_before(tg->slice_end[rw], tg->slice_start[rw]));

	/*
	 * If bps are unlimited (-1), then time slice don't get
	 * renewed. Don't try to trim the slice if slice is used. A new
	 * slice will start when appropriate.
	 */
	if (throtl_slice_used(tg, rw))
		return;

	/*
	 * A bio has been dispatched. Also adjust slice_end. It might happen
	 * that initially cgroup limit was very low resulting in high
	 * slice_end, but later limit was bumped up and bio was dispached
	 * sooner, then we need to reduce slice_end. A high bogus slice_end
	 * is bad because it does not allow new slice to start.
	 */

	throtl_set_slice_end(tg, rw, jiffies + tg->td->throtl_slice);

	time_elapsed = jiffies - tg->slice_start[rw];

	nr_slices = time_elapsed / tg->td->throtl_slice;

	if (!nr_slices)
		return;
	tmp = (*klpe_tg_bps_limit)(tg, rw) * tg->td->throtl_slice * nr_slices;
	do_div(tmp, HZ);
	bytes_trim = tmp;

	io_trim = ((*klpe_tg_iops_limit)(tg, rw) * tg->td->throtl_slice * nr_slices) /
		HZ;

	if (!bytes_trim && !io_trim)
		return;

	if (tg->bytes_disp[rw] >= bytes_trim)
		tg->bytes_disp[rw] -= bytes_trim;
	else
		tg->bytes_disp[rw] = 0;

	if (tg->io_disp[rw] >= io_trim)
		tg->io_disp[rw] -= io_trim;
	else
		tg->io_disp[rw] = 0;

	tg->slice_start[rw] += nr_slices * tg->td->throtl_slice;

	throtl_log(&tg->service_queue,
		   "[%c] trim slice nr=%lu bytes=%llu io=%lu start=%lu end=%lu jiffies=%lu",
		   rw == READ ? 'R' : 'W', nr_slices, bytes_trim, io_trim,
		   tg->slice_start[rw], tg->slice_end[rw], jiffies);
}

static bool (*klpe_tg_may_dispatch)(struct throtl_grp *tg, struct bio *bio,
			    unsigned long *wait);

static void (*klpe_throtl_charge_bio)(struct throtl_grp *tg, struct bio *bio);

static void (*klpe_throtl_add_bio_tg)(struct bio *bio, struct throtl_qnode *qn,
			      struct throtl_grp *tg);

static void (*klpe_tg_update_disptime)(struct throtl_grp *tg);

static bool (*klpe_throtl_can_upgrade)(struct throtl_data *td,
	struct throtl_grp *this_tg);

static struct blkcg_policy (*klpe_blkcg_policy_throtl);

static unsigned long __tg_last_low_overflow_time(struct throtl_grp *tg)
{
	unsigned long rtime = jiffies, wtime = jiffies;

	if (tg->bps[READ][LIMIT_LOW] || tg->iops[READ][LIMIT_LOW])
		rtime = tg->last_low_overflow_time[READ];
	if (tg->bps[WRITE][LIMIT_LOW] || tg->iops[WRITE][LIMIT_LOW])
		wtime = tg->last_low_overflow_time[WRITE];
	return min(rtime, wtime);
}

static unsigned long (*klpe_tg_last_low_overflow_time)(struct throtl_grp *tg);

static bool (*klpe_throtl_tg_is_idle)(struct throtl_grp *tg);

static bool (*klpe_throtl_can_upgrade)(struct throtl_data *td,
	struct throtl_grp *this_tg);

static void klpr_throtl_upgrade_check(struct throtl_grp *tg)
{
	unsigned long now = jiffies;

	if (tg->td->limit_index != LIMIT_LOW)
		return;

	if (time_after(tg->last_check_time + tg->td->throtl_slice, now))
		return;

	tg->last_check_time = now;

	if (!time_after_eq(now,
	     __tg_last_low_overflow_time(tg) + tg->td->throtl_slice))
		return;

	if ((*klpe_throtl_can_upgrade)(tg->td, NULL))
		(*klpe_throtl_upgrade_state)(tg->td);
}

static void (*klpe_throtl_upgrade_state)(struct throtl_data *td);

static void throtl_downgrade_state(struct throtl_data *td, int new)
{
	td->scale /= 2;

	throtl_log(&td->service_queue, "downgrade, scale %d", td->scale);
	if (td->scale) {
		td->low_upgrade_time = jiffies - td->scale * td->throtl_slice;
		return;
	}

	td->limit_index = new;
	td->low_downgrade_time = jiffies;
}

static bool klpr_throtl_tg_can_downgrade(struct throtl_grp *tg)
{
	struct throtl_data *td = tg->td;
	unsigned long now = jiffies;

	/*
	 * If cgroup is below low limit, consider downgrade and throttle other
	 * cgroups
	 */
	if (time_after_eq(now, td->low_upgrade_time + td->throtl_slice) &&
	    time_after_eq(now, (*klpe_tg_last_low_overflow_time)(tg) +
					td->throtl_slice) &&
	    (!(*klpe_throtl_tg_is_idle)(tg) ||
	     !list_empty(&tg_to_blkg(tg)->blkcg->css.children)))
		return true;
	return false;
}

static bool klpr_throtl_hierarchy_can_downgrade(struct throtl_grp *tg)
{
	while (true) {
		if (!klpr_throtl_tg_can_downgrade(tg))
			return false;
		tg = sq_to_tg(tg->service_queue.parent_sq);
		if (!tg || !tg_to_blkg(tg)->parent)
			break;
	}
	return true;
}

static void klpr_throtl_downgrade_check(struct throtl_grp *tg)
{
	uint64_t bps;
	unsigned int iops;
	unsigned long elapsed_time;
	unsigned long now = jiffies;

	if (tg->td->limit_index != LIMIT_MAX ||
	    !tg->td->limit_valid[LIMIT_LOW])
		return;
	if (!list_empty(&tg_to_blkg(tg)->blkcg->css.children))
		return;
	if (time_after(tg->last_check_time + tg->td->throtl_slice, now))
		return;

	elapsed_time = now - tg->last_check_time;
	tg->last_check_time = now;

	if (time_before(now, (*klpe_tg_last_low_overflow_time)(tg) +
			tg->td->throtl_slice))
		return;

	if (tg->bps[READ][LIMIT_LOW]) {
		bps = tg->last_bytes_disp[READ] * HZ;
		do_div(bps, elapsed_time);
		if (bps >= tg->bps[READ][LIMIT_LOW])
			tg->last_low_overflow_time[READ] = now;
	}

	if (tg->bps[WRITE][LIMIT_LOW]) {
		bps = tg->last_bytes_disp[WRITE] * HZ;
		do_div(bps, elapsed_time);
		if (bps >= tg->bps[WRITE][LIMIT_LOW])
			tg->last_low_overflow_time[WRITE] = now;
	}

	if (tg->iops[READ][LIMIT_LOW]) {
		iops = tg->last_io_disp[READ] * HZ / elapsed_time;
		if (iops >= tg->iops[READ][LIMIT_LOW])
			tg->last_low_overflow_time[READ] = now;
	}

	if (tg->iops[WRITE][LIMIT_LOW]) {
		iops = tg->last_io_disp[WRITE] * HZ / elapsed_time;
		if (iops >= tg->iops[WRITE][LIMIT_LOW])
			tg->last_low_overflow_time[WRITE] = now;
	}

	/*
	 * If cgroup is below low limit, consider downgrade and throttle other
	 * cgroups
	 */
	if (klpr_throtl_hierarchy_can_downgrade(tg))
		throtl_downgrade_state(tg->td, LIMIT_LOW);

	tg->last_bytes_disp[READ] = 0;
	tg->last_bytes_disp[WRITE] = 0;
	tg->last_io_disp[READ] = 0;
	tg->last_io_disp[WRITE] = 0;
}

static void blk_throtl_update_idletime(struct throtl_grp *tg)
{
	unsigned long now = ktime_get_ns() >> 10;
	unsigned long last_finish_time = tg->last_finish_time;

	if (now <= last_finish_time || last_finish_time == 0 ||
	    last_finish_time == tg->checked_last_finish_time)
		return;

	tg->avg_idletime = (tg->avg_idletime * 7 + now - last_finish_time) >> 3;
	tg->checked_last_finish_time = last_finish_time;
}

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
#error "klp-ccp: non-taken branch"
#else
static inline void throtl_update_latency_buckets(struct throtl_data *td)
{
}
#endif

static void blk_throtl_assoc_bio(struct throtl_grp *tg, struct bio *bio)
{
#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
#error "klp-ccp: non-taken branch"
#endif
}

bool klpp_blk_throtl_bio(struct request_queue *q, struct blkcg_gq *blkg,
		    struct bio *bio)
{
	struct throtl_qnode *qn = NULL;
	struct throtl_grp *tg = klpr_blkg_to_tg(blkg ?: q->root_blkg);
	struct throtl_service_queue *sq;
	bool rw = bio_data_dir(bio);
	bool throttled = false;
	struct throtl_data *td = tg->td;

	WARN_ON_ONCE(!rcu_read_lock_held());

	/* see throtl_charge_bio() */
	if (bio_flagged(bio, BIO_THROTTLED) || !tg->has_rules[rw])
		return throttled;

	spin_lock_irq(q->queue_lock);

	throtl_update_latency_buckets(td);

	if (unlikely(blk_queue_bypass(q)))
		goto out_unlock;

	blk_throtl_assoc_bio(tg, bio);
	blk_throtl_update_idletime(tg);

	sq = &tg->service_queue;

again:
	while (true) {
		if (tg->last_low_overflow_time[rw] == 0)
			tg->last_low_overflow_time[rw] = jiffies;
		klpr_throtl_downgrade_check(tg);
		klpr_throtl_upgrade_check(tg);
		/* throtl is FIFO - if bios are already queued, should queue */
		if (sq->nr_queued[rw])
			break;

		/* if above limits, break to queue */
		if (!(*klpe_tg_may_dispatch)(tg, bio, NULL)) {
			tg->last_low_overflow_time[rw] = jiffies;
			if ((*klpe_throtl_can_upgrade)(td, tg)) {
				(*klpe_throtl_upgrade_state)(td);
				goto again;
			}
			break;
		}

		/* within limits, let's charge and dispatch directly */
		(*klpe_throtl_charge_bio)(tg, bio);

		/*
		 * We need to trim slice even when bios are not being queued
		 * otherwise it might happen that a bio is not queued for
		 * a long time and slice keeps on extending and trim is not
		 * called for a long time. Now if limits are reduced suddenly
		 * we take into account all the IO dispatched so far at new
		 * low rate and * newly queued IO gets a really long dispatch
		 * time.
		 *
		 * So keep on trimming slice even if bio is not queued.
		 */
		klpr_throtl_trim_slice(tg, rw);

		/*
		 * @bio passed through this layer without being throttled.
		 * Climb up the ladder.  If we''re already at the top, it
		 * can be executed directly.
		 */
		qn = &tg->qnode_on_parent[rw];
		sq = sq->parent_sq;
		tg = sq_to_tg(sq);
		if (!tg)
			goto out_unlock;
	}

	/* out-of-limit, queue to @tg */
	throtl_log(sq, "[%c] bio. bdisp=%llu sz=%u bps=%llu iodisp=%u iops=%u queued=%d/%d",
		   rw == READ ? 'R' : 'W',
		   tg->bytes_disp[rw], bio->bi_iter.bi_size,
		   (*klpe_tg_bps_limit)(tg, rw),
		   tg->io_disp[rw], (*klpe_tg_iops_limit)(tg, rw),
		   sq->nr_queued[READ], sq->nr_queued[WRITE]);

	tg->last_low_overflow_time[rw] = jiffies;

	td->nr_queued[rw]++;
	(*klpe_throtl_add_bio_tg)(bio, qn, tg);
	throttled = true;

	/*
	 * Update @tg's dispatch time and force schedule dispatch if @tg
	 * was empty before @bio.  The forced scheduling isn't likely to
	 * cause undue delay as @bio is likely to be dispatched directly if
	 * its @tg's disptime is not in the future.
	 */
	if (tg->flags & THROTL_TG_WAS_EMPTY) {
		(*klpe_tg_update_disptime)(tg);
		(*klpe_throtl_schedule_next_dispatch)(tg->service_queue.parent_sq, true);
	}

out_unlock:
	bio_set_flag(bio, BIO_THROTTLED);

#ifdef CONFIG_BLK_DEV_THROTTLING_LOW
#error "klp-ccp: non-taken branch"
#endif
	spin_unlock_irq(q->queue_lock);

	return throttled;
}


#include "livepatch_bsc1238920.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "blkcg_policy_throtl", (void *)&klpe_blkcg_policy_throtl },
	{ "tg_bps_limit", (void *)&klpe_tg_bps_limit },
	{ "tg_iops_limit", (void *)&klpe_tg_iops_limit },
	{ "tg_last_low_overflow_time",
	  (void *)&klpe_tg_last_low_overflow_time },
	{ "tg_may_dispatch", (void *)&klpe_tg_may_dispatch },
	{ "tg_update_disptime", (void *)&klpe_tg_update_disptime },
	{ "throtl_add_bio_tg", (void *)&klpe_throtl_add_bio_tg },
	{ "throtl_can_upgrade", (void *)&klpe_throtl_can_upgrade },
	{ "throtl_charge_bio", (void *)&klpe_throtl_charge_bio },
	{ "throtl_schedule_next_dispatch",
	  (void *)&klpe_throtl_schedule_next_dispatch },
	{ "throtl_tg_is_idle", (void *)&klpe_throtl_tg_is_idle },
	{ "throtl_upgrade_state", (void *)&klpe_throtl_upgrade_state },
};

int livepatch_bsc1238920_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

