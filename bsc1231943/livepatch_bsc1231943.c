/*
 * livepatch_bsc1231943
 *
 * Fix for CVE-2024-47706, bsc#1231943
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from block/bfq-iosched.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/cgroup.h>
#include <linux/elevator.h>
#include <linux/ktime.h>
#include <linux/rbtree.h>
#include <linux/ioprio.h>

/* klp-ccp: from block/blk.h */
#include <linux/idr.h>

/* klp-ccp: from block/blk-stat.h */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/ktime.h>
#include <linux/rcupdate.h>
#include <linux/timer.h>

/* klp-ccp: from block/bfq-iosched.h */
#include <linux/blktrace_api.h>
#include <linux/hrtimer.h>
#include <linux/blk-cgroup.h>

struct bfq_entity {
	/* service_tree member */
	struct rb_node rb_node;

	/*
	 * Flag, true if the entity is on a tree (either the active or
	 * the idle one of its service_tree) or is in service.
	 */
	bool on_st;

	/* B-WF2Q+ start and finish timestamps [sectors/weight] */
	u64 start, finish;

	/* tree the entity is enqueued into; %NULL if not on a tree */
	struct rb_root *tree;

	/*
	 * minimum start time of the (active) subtree rooted at this
	 * entity; used for O(log N) lookups into active trees
	 */
	u64 min_start;

	/* amount of service received during the last service slot */
	int service;

	/* budget, used also to calculate F_i: F_i = S_i + @budget / @weight */
	int budget;

	/* weight of the queue */
	int weight;
	/* next weight if a change is in progress */
	int new_weight;

	/* original weight, used to implement weight boosting */
	int orig_weight;

	/* parent entity, for hierarchical scheduling */
	struct bfq_entity *parent;

	/*
	 * For non-leaf nodes in the hierarchy, the associated
	 * scheduler queue, %NULL on leaf nodes.
	 */
	struct bfq_sched_data *my_sched_data;
	/* the scheduler queue this entity belongs to */
	struct bfq_sched_data *sched_data;

	/* flag, set to request a weight, ioprio or ioprio_class change  */
	int prio_changed;

	/* flag, set if the entity is counted in groups_with_pending_reqs */
	bool in_groups_with_pending_reqs;
};

struct bfq_ttime {
	/* completion time of the last request */
	u64 last_end_request;

	/* total process thinktime */
	u64 ttime_total;
	/* number of thinktime samples */
	unsigned long ttime_samples;
	/* average process thinktime */
	u64 ttime_mean;
};

struct bfq_queue {
	/* reference counter */
	int ref;
	/* parent bfq_data */
	struct bfq_data *bfqd;

	/* current ioprio and ioprio class */
	unsigned short ioprio, ioprio_class;
	/* next ioprio and ioprio class if a change is in progress */
	unsigned short new_ioprio, new_ioprio_class;

	/*
	 * Shared bfq_queue if queue is cooperating with one or more
	 * other queues.
	 */
	struct bfq_queue *new_bfqq;
	/* request-position tree member (see bfq_group's @rq_pos_tree) */
	struct rb_node pos_node;
	/* request-position tree root (see bfq_group's @rq_pos_tree) */
	struct rb_root *pos_root;

	/* sorted list of pending requests */
	struct rb_root sort_list;
	/* if fifo isn't expired, next request to serve */
	struct request *next_rq;
	/* number of sync and async requests queued */
	int queued[2];
	/* number of requests currently allocated */
	int allocated;
	/* number of pending metadata requests */
	int meta_pending;
	/* fifo list of requests in sort_list */
	struct list_head fifo;

	/* entity representing this queue in the scheduler */
	struct bfq_entity entity;

	/* pointer to the weight counter associated with this entity */
	struct bfq_weight_counter *weight_counter;

	/* maximum budget allowed from the feedback mechanism */
	int max_budget;
	/* budget expiration (in jiffies) */
	unsigned long budget_timeout;

	/* number of requests on the dispatch list or inside driver */
	int dispatched;

	/* status flags */
	unsigned long flags;

	/* node for active/idle bfqq list inside parent bfqd */
	struct list_head bfqq_list;

	/* associated @bfq_ttime struct */
	struct bfq_ttime ttime;

	/* bit vector: a 1 for each seeky requests in history */
	u32 seek_history;

	/* node for the device's burst list */
	struct hlist_node burst_list_node;

	/* position of the last request enqueued */
	sector_t last_request_pos;

	/* Number of consecutive pairs of request completion and
	 * arrival, such that the queue becomes idle after the
	 * completion, but the next request arrives within an idle
	 * time slice; used only if the queue's IO_bound flag has been
	 * cleared.
	 */
	unsigned int requests_within_timer;

	/* pid of the process owning the queue, used for logging purposes */
	pid_t pid;

	/*
	 * Pointer to the bfq_io_cq owning the bfq_queue, set to %NULL
	 * if the queue is shared.
	 */
	struct bfq_io_cq *bic;

	/* current maximum weight-raising time for this queue */
	unsigned long wr_cur_max_time;
	/*
	 * Minimum time instant such that, only if a new request is
	 * enqueued after this time instant in an idle @bfq_queue with
	 * no outstanding requests, then the task associated with the
	 * queue it is deemed as soft real-time (see the comments on
	 * the function bfq_bfqq_softrt_next_start())
	 */
	unsigned long soft_rt_next_start;
	/*
	 * Start time of the current weight-raising period if
	 * the @bfq-queue is being weight-raised, otherwise
	 * finish time of the last weight-raising period.
	 */
	unsigned long last_wr_start_finish;
	/* factor by which the weight of this queue is multiplied */
	unsigned int wr_coeff;
	/*
	 * Time of the last transition of the @bfq_queue from idle to
	 * backlogged.
	 */
	unsigned long last_idle_bklogged;
	/*
	 * Cumulative service received from the @bfq_queue since the
	 * last transition from idle to backlogged.
	 */
	unsigned long service_from_backlogged;
	/*
	 * Cumulative service received from the @bfq_queue since its
	 * last transition to weight-raised state.
	 */
	unsigned long service_from_wr;

	/*
	 * Value of wr start time when switching to soft rt
	 */
	unsigned long wr_start_at_switch_to_srt;

	unsigned long split_time; /* time of last split */

	unsigned long first_IO_time; /* time of first I/O for this queue */

	/* max service rate measured so far */
	u32 max_service_rate;
	/*
	 * Ratio between the service received by bfqq while it is in
	 * service, and the cumulative service (of requests of other
	 * queues) that may be injected while bfqq is empty but still
	 * in service. To increase precision, the coefficient is
	 * measured in tenths of unit. Here are some example of (1)
	 * ratios, (2) resulting percentages of service injected
	 * w.r.t. to the total service dispatched while bfqq is in
	 * service, and (3) corresponding values of the coefficient:
	 * 1 (50%) -> 10
	 * 2 (33%) -> 20
	 * 10 (9%) -> 100
	 * 9.9 (9%) -> 99
	 * 1.5 (40%) -> 15
	 * 0.5 (66%) -> 5
	 * 0.1 (90%) -> 1
	 *
	 * So, if the coefficient is lower than 10, then
	 * injected service is more than bfqq service.
	 */
	unsigned int inject_coeff;
	/* amount of service injected in current service slot */
	unsigned int injected_service;
};

struct bfq_io_cq {
	/* associated io_cq structure */
	struct io_cq icq; /* must be the first member */
	/* array of two process queues, the sync and the async */
	struct bfq_queue *bfqq[2];
	/* per (request_queue, blkcg) ioprio */
	int ioprio;
#ifdef CONFIG_BFQ_GROUP_IOSCHED
	uint64_t blkcg_serial_nr; /* the current blkcg serial */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	bool saved_has_short_ttime;
	/*
	 * Same purpose as the previous two fields for the I/O bound
	 * classification of a queue.
	 */
	bool saved_IO_bound;

	/*
	 * Same purpose as the previous fields for the value of the
	 * field keeping the queue's belonging to a large burst
	 */
	bool saved_in_large_burst;
	/*
	 * True if the queue belonged to a burst list before its merge
	 * with another cooperating queue.
	 */
	bool was_in_burst_list;

	/*
	 * Similar to previous fields: save wr information.
	 */
	unsigned long saved_wr_coeff;
	unsigned long saved_last_wr_start_finish;
	unsigned long saved_wr_start_at_switch_to_srt;
	unsigned int saved_wr_cur_max_time;
	struct bfq_ttime saved_ttime;
};

struct bfq_data {
	/* device request queue */
	struct request_queue *queue;
	/* dispatch queue */
	struct list_head dispatch;

	/* root bfq_group for the device */
	struct bfq_group *root_group;

	/*
	 * rbtree of weight counters of @bfq_queues, sorted by
	 * weight. Used to keep track of whether all @bfq_queues have
	 * the same weight. The tree contains one counter for each
	 * distinct weight associated to some active and not
	 * weight-raised @bfq_queue (see the comments to the functions
	 * bfq_weights_tree_[add|remove] for further details).
	 */
	struct rb_root queue_weights_tree;

	/*
	 * Number of groups with at least one descendant process that
	 * has at least one request waiting for completion. Note that
	 * this accounts for also requests already dispatched, but not
	 * yet completed. Therefore this number of groups may differ
	 * (be larger) than the number of active groups, as a group is
	 * considered active only if its corresponding entity has
	 * descendant queues with at least one request queued. This
	 * number is used to decide whether a scenario is symmetric.
	 * For a detailed explanation see comments on the computation
	 * of the variable asymmetric_scenario in the function
	 * bfq_better_to_idle().
	 *
	 * However, it is hard to compute this number exactly, for
	 * groups with multiple descendant processes. Consider a group
	 * that is inactive, i.e., that has no descendant process with
	 * pending I/O inside BFQ queues. Then suppose that
	 * num_groups_with_pending_reqs is still accounting for this
	 * group, because the group has descendant processes with some
	 * I/O request still in flight. num_groups_with_pending_reqs
	 * should be decremented when the in-flight request of the
	 * last descendant process is finally completed (assuming that
	 * nothing else has changed for the group in the meantime, in
	 * terms of composition of the group and active/inactive state of child
	 * groups and processes). To accomplish this, an additional
	 * pending-request counter must be added to entities, and must
	 * be updated correctly. To avoid this additional field and operations,
	 * we resort to the following tradeoff between simplicity and
	 * accuracy: for an inactive group that is still counted in
	 * num_groups_with_pending_reqs, we decrement
	 * num_groups_with_pending_reqs when the first descendant
	 * process of the group remains with no request waiting for
	 * completion.
	 *
	 * Even this simpler decrement strategy requires a little
	 * carefulness: to avoid multiple decrements, we flag a group,
	 * more precisely an entity representing a group, as still
	 * counted in num_groups_with_pending_reqs when it becomes
	 * inactive. Then, when the first descendant queue of the
	 * entity remains with no request waiting for completion,
	 * num_groups_with_pending_reqs is decremented, and this flag
	 * is reset. After this flag is reset for the entity,
	 * num_groups_with_pending_reqs won't be decremented any
	 * longer in case a new descendant queue of the entity remains
	 * with no request waiting for completion.
	 */
	unsigned int num_groups_with_pending_reqs;

	/*
	 * Number of bfq_queues containing requests (including the
	 * queue in service, even if it is idling).
	 */
	int busy_queues;
	/* number of weight-raised busy @bfq_queues */
	int wr_busy_queues;
	/* number of queued requests */
	int queued;
	/* number of requests dispatched and waiting for completion */
	int rq_in_driver;

	/*
	 * Maximum number of requests in driver in the last
	 * @hw_tag_samples completed requests.
	 */
	int max_rq_in_driver;
	/* number of samples used to calculate hw_tag */
	int hw_tag_samples;
	/* flag set to one if the driver is showing a queueing behavior */
	int hw_tag;

	/* number of budgets assigned */
	int budgets_assigned;

	/*
	 * Timer set when idling (waiting) for the next request from
	 * the queue in service.
	 */
	struct hrtimer idle_slice_timer;

	/* bfq_queue in service */
	struct bfq_queue *in_service_queue;

	/* on-disk position of the last served request */
	sector_t last_position;

	/* time of last request completion (ns) */
	u64 last_completion;

	/* time of first rq dispatch in current observation interval (ns) */
	u64 first_dispatch;
	/* time of last rq dispatch in current observation interval (ns) */
	u64 last_dispatch;

	/* beginning of the last budget */
	ktime_t last_budget_start;
	/* beginning of the last idle slice */
	ktime_t last_idling_start;

	/* number of samples in current observation interval */
	int peak_rate_samples;
	/* num of samples of seq dispatches in current observation interval */
	u32 sequential_samples;
	/* total num of sectors transferred in current observation interval */
	u64 tot_sectors_dispatched;
	/* max rq size seen during current observation interval (sectors) */
	u32 last_rq_max_size;
	/* time elapsed from first dispatch in current observ. interval (us) */
	u64 delta_from_first;
	/*
	 * Current estimate of the device peak rate, measured in
	 * [(sectors/usec) / 2^BFQ_RATE_SHIFT]. The left-shift by
	 * BFQ_RATE_SHIFT is performed to increase precision in
	 * fixed-point calculations.
	 */
	u32 peak_rate;

	/* maximum budget allotted to a bfq_queue before rescheduling */
	int bfq_max_budget;

	/* list of all the bfq_queues active on the device */
	struct list_head active_list;
	/* list of all the bfq_queues idle on the device */
	struct list_head idle_list;

	/*
	 * Timeout for async/sync requests; when it fires, requests
	 * are served in fifo order.
	 */
	u64 bfq_fifo_expire[2];
	/* weight of backward seeks wrt forward ones */
	unsigned int bfq_back_penalty;
	/* maximum allowed backward seek */
	unsigned int bfq_back_max;
	/* maximum idling time */
	u32 bfq_slice_idle;

	/* user-configured max budget value (0 for auto-tuning) */
	int bfq_user_max_budget;
	/*
	 * Timeout for bfq_queues to consume their budget; used to
	 * prevent seeky queues from imposing long latencies to
	 * sequential or quasi-sequential ones (this also implies that
	 * seeky queues cannot receive guarantees in the service
	 * domain; after a timeout they are charged for the time they
	 * have been in service, to preserve fairness among them, but
	 * without service-domain guarantees).
	 */
	unsigned int bfq_timeout;

	/*
	 * Number of consecutive requests that must be issued within
	 * the idle time slice to set again idling to a queue which
	 * was marked as non-I/O-bound (see the definition of the
	 * IO_bound flag for further details).
	 */
	unsigned int bfq_requests_within_timer;

	/*
	 * Force device idling whenever needed to provide accurate
	 * service guarantees, without caring about throughput
	 * issues. CAVEAT: this may even increase latencies, in case
	 * of useless idling for processes that did stop doing I/O.
	 */
	bool strict_guarantees;

	/*
	 * Last time at which a queue entered the current burst of
	 * queues being activated shortly after each other; for more
	 * details about this and the following parameters related to
	 * a burst of activations, see the comments on the function
	 * bfq_handle_burst.
	 */
	unsigned long last_ins_in_burst;
	/*
	 * Reference time interval used to decide whether a queue has
	 * been activated shortly after @last_ins_in_burst.
	 */
	unsigned long bfq_burst_interval;
	/* number of queues in the current burst of queue activations */
	int burst_size;

	/* common parent entity for the queues in the burst */
	struct bfq_entity *burst_parent_entity;
	/* Maximum burst size above which the current queue-activation
	 * burst is deemed as 'large'.
	 */
	unsigned long bfq_large_burst_thresh;
	/* true if a large queue-activation burst is in progress */
	bool large_burst;
	/*
	 * Head of the burst list (as for the above fields, more
	 * details in the comments on the function bfq_handle_burst).
	 */
	struct hlist_head burst_list;

	/* if set to true, low-latency heuristics are enabled */
	bool low_latency;
	/*
	 * Maximum factor by which the weight of a weight-raised queue
	 * is multiplied.
	 */
	unsigned int bfq_wr_coeff;
	/* maximum duration of a weight-raising period (jiffies) */
	unsigned int bfq_wr_max_time;

	/* Maximum weight-raising duration for soft real-time processes */
	unsigned int bfq_wr_rt_max_time;
	/*
	 * Minimum idle period after which weight-raising may be
	 * reactivated for a queue (in jiffies).
	 */
	unsigned int bfq_wr_min_idle_time;
	/*
	 * Minimum period between request arrivals after which
	 * weight-raising may be reactivated for an already busy async
	 * queue (in jiffies).
	 */
	unsigned long bfq_wr_min_inter_arr_async;

	/* Max service-rate for a soft real-time queue, in sectors/sec */
	unsigned int bfq_wr_max_softrt_rate;
	/*
	 * Cached value of the product ref_rate*ref_wr_duration, used
	 * for computing the maximum duration of weight raising
	 * automatically.
	 */
	u64 rate_dur_prod;

	/* fallback dummy bfqq for extreme OOM conditions */
	struct bfq_queue oom_bfqq;

	spinlock_t lock;

	/*
	 * bic associated with the task issuing current bio for
	 * merging. This and the next field are used as a support to
	 * be able to perform the bic lookup, needed by bio-merge
	 * functions, before the scheduler lock is taken, and thus
	 * avoid taking the request-queue lock while the scheduler
	 * lock is being held.
	 */
	struct bfq_io_cq *bio_bic;
	/* bfqq associated with the task issuing current bio for merging */
	struct bfq_queue *bio_bfqq;

	/*
	 * Depth limits used in bfq_limit_depth (see comments on the
	 * function)
	 */
	unsigned int word_depths[2][2];
};

static int (*klpe_bfq_bfqq_just_created)(const struct bfq_queue *bfqq);

static int (*klpe_bfq_bfqq_busy)(const struct bfq_queue *bfqq);

static void (*klpe_bfq_mark_bfqq_has_short_ttime)(struct bfq_queue *bfqq);

static void (*klpe_bfq_clear_bfqq_has_short_ttime)(struct bfq_queue *bfqq);

static int (*klpe_bfq_bfqq_sync)(const struct bfq_queue *bfqq);

static void (*klpe_bfq_mark_bfqq_IO_bound)(struct bfq_queue *bfqq);

static void (*klpe_bfq_clear_bfqq_IO_bound)(struct bfq_queue *bfqq);

static void (*klpe_bfq_mark_bfqq_in_large_burst)(struct bfq_queue *bfqq);

static void (*klpe_bfq_clear_bfqq_in_large_burst)(struct bfq_queue *bfqq);

static int (*klpe_bfq_bfqq_in_large_burst)(const struct bfq_queue *bfqq);

static void (*klpe_bfq_clear_bfqq_coop)(struct bfq_queue *bfqq);

static int (*klpe_bfq_bfqq_coop)(const struct bfq_queue *bfqq);

static void (*klpe_bfq_clear_bfqq_split_coop)(struct bfq_queue *bfqq);

static int (*klpe_bfq_bfqq_split_coop)(const struct bfq_queue *bfqq);

static struct bfq_queue *(*klpe_bic_to_bfqq)(struct bfq_io_cq *bic, bool is_sync);
static void (*klpe_bic_set_bfqq)(struct bfq_io_cq *bic, struct bfq_queue *bfqq, bool is_sync);
static struct bfq_data *(*klpe_bic_to_bfqd)(struct bfq_io_cq *bic);

static void (*klpe_bfq_put_queue)(struct bfq_queue *bfqq);

static void (*klpe_bfq_bic_update_cgroup)(struct bfq_io_cq *bic, struct bio *bio);

static struct blkcg_gq *(*klpe_bfqg_to_blkg)(struct bfq_group *bfqg);
static struct bfq_group *(*klpe_bfqq_group)(struct bfq_queue *bfqq);

static unsigned short (*klpe_bfq_ioprio_to_weight)(int ioprio);

#define klpr_bfq_log_bfqq(bfqd, bfqq, fmt, args...)	do {			\
	blk_add_cgroup_trace_msg((bfqd)->queue,				\
			(*klpe_bfqg_to_blkg)((*klpe_bfqq_group)(bfqq))->blkcg,		\
			"bfq%d%c " fmt, (bfqq)->pid,			\
			(*klpe_bfq_bfqq_sync)((bfqq)) ? 'S' : 'A', ##args);	\
} while (0)

/* klp-ccp: from block/blk-wbt.h */
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/wait.h>
#include <linux/timer.h>
#include <linux/ktime.h>

/* klp-ccp: from block/bfq-iosched.c */
static struct bfq_io_cq *icq_to_bic(struct io_cq *icq)
{
	/* bic->icq is the first member, %NULL will convert to %NULL */
	return container_of(icq, struct bfq_io_cq, icq);
}

static unsigned int bfq_wr_duration(struct bfq_data *bfqd)
{
	u64 dur;

	if (bfqd->bfq_wr_max_time > 0)
		return bfqd->bfq_wr_max_time;

	dur = bfqd->rate_dur_prod;
	do_div(dur, bfqd->peak_rate);

	/*
	 * Limit duration between 3 and 25 seconds. The upper limit
	 * has been conservatively set after the following worst case:
	 * on a QEMU/KVM virtual machine
	 * - running in a slow PC
	 * - with a virtual disk stacked on a slow low-end 5400rpm HDD
	 * - serving a heavy I/O workload, such as the sequential reading
	 *   of several files
	 * mplayer took 23 seconds to start, if constantly weight-raised.
	 *
	 * As for higher values than that accomodating the above bad
	 * scenario, tests show that higher values would often yield
	 * the opposite of the desired result, i.e., would worsen
	 * responsiveness by allowing non-interactive applications to
	 * preserve weight raising for too long.
	 *
	 * On the other end, lower values than 3 seconds make it
	 * difficult for most interactive tasks to complete their jobs
	 * before weight-raising finishes.
	 */
	return clamp_val(dur, msecs_to_jiffies(3000), msecs_to_jiffies(25000));
}

static void switch_back_to_interactive_wr(struct bfq_queue *bfqq,
					  struct bfq_data *bfqd)
{
	bfqq->wr_coeff = bfqd->bfq_wr_coeff;
	bfqq->wr_cur_max_time = bfq_wr_duration(bfqd);
	bfqq->last_wr_start_finish = bfqq->wr_start_at_switch_to_srt;
}

static void
klpr_bfq_bfqq_resume_state(struct bfq_queue *bfqq, struct bfq_data *bfqd,
		      struct bfq_io_cq *bic, bool bfq_already_existing)
{
	unsigned int old_wr_coeff = bfqq->wr_coeff;
	bool busy = bfq_already_existing && (*klpe_bfq_bfqq_busy)(bfqq);

	if (bic->saved_has_short_ttime)
		(*klpe_bfq_mark_bfqq_has_short_ttime)(bfqq);
	else
		(*klpe_bfq_clear_bfqq_has_short_ttime)(bfqq);

	if (bic->saved_IO_bound)
		(*klpe_bfq_mark_bfqq_IO_bound)(bfqq);
	else
		(*klpe_bfq_clear_bfqq_IO_bound)(bfqq);

	bfqq->ttime = bic->saved_ttime;
	bfqq->wr_coeff = bic->saved_wr_coeff;
	bfqq->wr_start_at_switch_to_srt = bic->saved_wr_start_at_switch_to_srt;
	bfqq->last_wr_start_finish = bic->saved_last_wr_start_finish;
	bfqq->wr_cur_max_time = bic->saved_wr_cur_max_time;

	if (bfqq->wr_coeff > 1 && ((*klpe_bfq_bfqq_in_large_burst)(bfqq) ||
	    time_is_before_jiffies(bfqq->last_wr_start_finish +
				   bfqq->wr_cur_max_time))) {
		if (bfqq->wr_cur_max_time == bfqd->bfq_wr_rt_max_time &&
		    !(*klpe_bfq_bfqq_in_large_burst)(bfqq) &&
		    time_is_after_eq_jiffies(bfqq->wr_start_at_switch_to_srt +
					     bfq_wr_duration(bfqd))) {
			switch_back_to_interactive_wr(bfqq, bfqd);
		} else {
			bfqq->wr_coeff = 1;
			klpr_bfq_log_bfqq(bfqq->bfqd, bfqq,
				     "resume state: switching off wr");
		}
	}

	/* make sure weight will be updated, however we got here */
	bfqq->entity.prio_changed = 1;

	if (likely(!busy))
		return;

	if (old_wr_coeff == 1 && bfqq->wr_coeff > 1)
		bfqd->wr_busy_queues++;
	else if (old_wr_coeff > 1 && bfqq->wr_coeff == 1)
		bfqd->wr_busy_queues--;
}

static int bfqq_process_refs(struct bfq_queue *bfqq)
{
	return bfqq->ref - bfqq->allocated - bfqq->entity.on_st;
}

static void bfq_reset_burst_list(struct bfq_data *bfqd, struct bfq_queue *bfqq)
{
	struct bfq_queue *item;
	struct hlist_node *n;

	hlist_for_each_entry_safe(item, n, &bfqd->burst_list, burst_list_node)
		hlist_del_init(&item->burst_list_node);
	hlist_add_head(&bfqq->burst_list_node, &bfqd->burst_list);
	bfqd->burst_size = 1;
	bfqd->burst_parent_entity = bfqq->entity.parent;
}

static void klpr_bfq_add_to_burst(struct bfq_data *bfqd, struct bfq_queue *bfqq)
{
	/* Increment burst size to take into account also bfqq */
	bfqd->burst_size++;

	if (bfqd->burst_size == bfqd->bfq_large_burst_thresh) {
		struct bfq_queue *pos, *bfqq_item;
		struct hlist_node *n;

		/*
		 * Enough queues have been activated shortly after each
		 * other to consider this burst as large.
		 */
		bfqd->large_burst = true;

		/*
		 * We can now mark all queues in the burst list as
		 * belonging to a large burst.
		 */
		hlist_for_each_entry(bfqq_item, &bfqd->burst_list,
				     burst_list_node)
			(*klpe_bfq_mark_bfqq_in_large_burst)(bfqq_item);
		(*klpe_bfq_mark_bfqq_in_large_burst)(bfqq);

		/*
		 * From now on, and until the current burst finishes, any
		 * new queue being activated shortly after the last queue
		 * was inserted in the burst can be immediately marked as
		 * belonging to a large burst. So the burst list is not
		 * needed any more. Remove it.
		 */
		hlist_for_each_entry_safe(pos, n, &bfqd->burst_list,
					  burst_list_node)
			hlist_del_init(&pos->burst_list_node);
	} else /*
		* Burst not yet large: add bfqq to the burst list. Do
		* not increment the ref counter for bfqq, because bfqq
		* is removed from the burst list before freeing bfqq
		* in put_queue.
		*/
		hlist_add_head(&bfqq->burst_list_node, &bfqd->burst_list);
}

static void klpr_bfq_handle_burst(struct bfq_data *bfqd, struct bfq_queue *bfqq)
{
	/*
	 * If bfqq is already in the burst list or is part of a large
	 * burst, or finally has just been split, then there is
	 * nothing else to do.
	 */
	if (!hlist_unhashed(&bfqq->burst_list_node) ||
	    (*klpe_bfq_bfqq_in_large_burst)(bfqq) ||
	    time_is_after_eq_jiffies(bfqq->split_time +
				     msecs_to_jiffies(10)))
		return;

	/*
	 * If bfqq's creation happens late enough, or bfqq belongs to
	 * a different group than the burst group, then the current
	 * burst is finished, and related data structures must be
	 * reset.
	 *
	 * In this respect, consider the special case where bfqq is
	 * the very first queue created after BFQ is selected for this
	 * device. In this case, last_ins_in_burst and
	 * burst_parent_entity are not yet significant when we get
	 * here. But it is easy to verify that, whether or not the
	 * following condition is true, bfqq will end up being
	 * inserted into the burst list. In particular the list will
	 * happen to contain only bfqq. And this is exactly what has
	 * to happen, as bfqq may be the first queue of the first
	 * burst.
	 */
	if (time_is_before_jiffies(bfqd->last_ins_in_burst +
	    bfqd->bfq_burst_interval) ||
	    bfqq->entity.parent != bfqd->burst_parent_entity) {
		bfqd->large_burst = false;
		bfq_reset_burst_list(bfqd, bfqq);
		goto end;
	}

	/*
	 * If we get here, then bfqq is being activated shortly after the
	 * last queue. So, if the current burst is also large, we can mark
	 * bfqq as belonging to this large burst immediately.
	 */
	if (bfqd->large_burst) {
		(*klpe_bfq_mark_bfqq_in_large_burst)(bfqq);
		goto end;
	}

	/*
	 * If we get here, then a large-burst state has not yet been
	 * reached, but bfqq is being activated shortly after the last
	 * queue. Then we add bfqq to the burst.
	 */
	klpr_bfq_add_to_burst(bfqd, bfqq);
end:
	/*
	 * At this point, bfqq either has been added to the current
	 * burst or has caused the current burst to terminate and a
	 * possible new burst to start. In particular, in the second
	 * case, bfqq has become the first queue in the possible new
	 * burst.  In both cases last_ins_in_burst needs to be moved
	 * forward.
	 */
	bfqd->last_ins_in_burst = jiffies;
}

static void (*klpe_bfq_put_cooperator)(struct bfq_queue *bfqq);

static void
klpr_bfq_set_next_ioprio_data(struct bfq_queue *bfqq, struct bfq_io_cq *bic)
{
	struct task_struct *tsk = current;
	int ioprio_class;
	struct bfq_data *bfqd = bfqq->bfqd;

	if (!bfqd)
		return;

	ioprio_class = IOPRIO_PRIO_CLASS(bic->ioprio);
	switch (ioprio_class) {
	default:
		dev_err(bfqq->bfqd->queue->backing_dev_info->dev,
			"bfq: bad prio class %d\n", ioprio_class);
		/* fall through */
	case IOPRIO_CLASS_NONE:
		/*
		 * No prio set, inherit CPU scheduling settings.
		 */
		bfqq->new_ioprio = task_nice_ioprio(tsk);
		bfqq->new_ioprio_class = task_nice_ioclass(tsk);
		break;
	case IOPRIO_CLASS_RT:
		bfqq->new_ioprio = IOPRIO_PRIO_DATA(bic->ioprio);
		bfqq->new_ioprio_class = IOPRIO_CLASS_RT;
		break;
	case IOPRIO_CLASS_BE:
		bfqq->new_ioprio = IOPRIO_PRIO_DATA(bic->ioprio);
		bfqq->new_ioprio_class = IOPRIO_CLASS_BE;
		break;
	case IOPRIO_CLASS_IDLE:
		bfqq->new_ioprio_class = IOPRIO_CLASS_IDLE;
		bfqq->new_ioprio = 7;
		break;
	}

	if (bfqq->new_ioprio >= IOPRIO_BE_NR) {
		pr_crit("bfq_set_next_ioprio_data: new_ioprio %d\n",
			bfqq->new_ioprio);
		bfqq->new_ioprio = IOPRIO_BE_NR - 1;
	}

	bfqq->entity.new_weight = (*klpe_bfq_ioprio_to_weight)(bfqq->new_ioprio);
	bfqq->entity.prio_changed = 1;
}

static struct bfq_queue *(*klpe_bfq_get_queue)(struct bfq_data *bfqd,
				       struct bio *bio, bool is_sync,
				       struct bfq_io_cq *bic);

static void klpr_bfq_check_ioprio_change(struct bfq_io_cq *bic, struct bio *bio)
{
	struct bfq_data *bfqd = (*klpe_bic_to_bfqd)(bic);
	struct bfq_queue *bfqq;
	int ioprio = bic->icq.ioc->ioprio;

	/*
	 * This condition may trigger on a newly created bic, be sure to
	 * drop the lock before returning.
	 */
	if (unlikely(!bfqd) || likely(bic->ioprio == ioprio))
		return;

	bic->ioprio = ioprio;

	bfqq = (*klpe_bic_to_bfqq)(bic, false);
	if (bfqq) {
		/* release process reference on this queue */
		(*klpe_bfq_put_queue)(bfqq);
		bfqq = (*klpe_bfq_get_queue)(bfqd, bio, BLK_RW_ASYNC, bic);
		(*klpe_bic_set_bfqq)(bic, bfqq, false);
	}

	bfqq = (*klpe_bic_to_bfqq)(bic, true);
	if (bfqq)
		klpr_bfq_set_next_ioprio_data(bfqq, bic);
}

static struct bfq_queue *(*klpe_bfq_get_queue)(struct bfq_data *bfqd,
				       struct bio *bio, bool is_sync,
				       struct bfq_io_cq *bic);

static struct bfq_queue *
klpr_bfq_split_bfqq(struct bfq_io_cq *bic, struct bfq_queue *bfqq)
{
	klpr_bfq_log_bfqq(bfqq->bfqd, bfqq, "splitting queue");

	if (bfqq_process_refs(bfqq) == 1) {
		bfqq->pid = current->pid;
		(*klpe_bfq_clear_bfqq_coop)(bfqq);
		(*klpe_bfq_clear_bfqq_split_coop)(bfqq);
		return bfqq;
	}

	(*klpe_bic_set_bfqq)(bic, NULL, 1);

	(*klpe_bfq_put_cooperator)(bfqq);

	(*klpe_bfq_put_queue)(bfqq);
	return NULL;
}

static struct bfq_queue *klpr_bfq_get_bfqq_handle_split(struct bfq_data *bfqd,
						   struct bfq_io_cq *bic,
						   struct bio *bio,
						   bool split, bool is_sync,
						   bool *new_queue)
{
	struct bfq_queue *bfqq = (*klpe_bic_to_bfqq)(bic, is_sync);

	if (likely(bfqq && bfqq != &bfqd->oom_bfqq))
		return bfqq;

	if (new_queue)
		*new_queue = true;

	if (bfqq)
		(*klpe_bfq_put_queue)(bfqq);
	bfqq = (*klpe_bfq_get_queue)(bfqd, bio, is_sync, bic);

	(*klpe_bic_set_bfqq)(bic, bfqq, is_sync);
	if (split && is_sync) {
		if ((bic->was_in_burst_list && bfqd->large_burst) ||
		    bic->saved_in_large_burst)
			(*klpe_bfq_mark_bfqq_in_large_burst)(bfqq);
		else {
			(*klpe_bfq_clear_bfqq_in_large_burst)(bfqq);
			if (bic->was_in_burst_list)
				/*
				 * If bfqq was in the current
				 * burst list before being
				 * merged, then we have to add
				 * it back. And we do not need
				 * to increase burst_size, as
				 * we did not decrement
				 * burst_size when we removed
				 * bfqq from the burst list as
				 * a consequence of a merge
				 * (see comments in
				 * bfq_put_queue). In this
				 * respect, it would be rather
				 * costly to know whether the
				 * current burst list is still
				 * the same burst list from
				 * which bfqq was removed on
				 * the merge. To avoid this
				 * cost, if bfqq was in a
				 * burst list, then we add
				 * bfqq to the current burst
				 * list without any further
				 * check. This can cause
				 * inappropriate insertions,
				 * but rarely enough to not
				 * harm the detection of large
				 * bursts significantly.
				 */
				hlist_add_head(&bfqq->burst_list_node,
					       &bfqd->burst_list);
		}
		bfqq->split_time = jiffies;
	}

	return bfqq;
}

struct bfq_queue *klpp_bfq_init_rq(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct bio *bio = rq->bio;
	struct bfq_data *bfqd = q->elevator->elevator_data;
	struct bfq_io_cq *bic;
	const int is_sync = rq_is_sync(rq);
	struct bfq_queue *bfqq;
	bool new_queue = false;
	bool bfqq_already_existing = false, split = false;

	if (unlikely(!rq->elv.icq))
		return NULL;

	/*
	 * Assuming that elv.priv[1] is set only if everything is set
	 * for this rq. This holds true, because this function is
	 * invoked only for insertion or merging, and, after such
	 * events, a request cannot be manipulated any longer before
	 * being removed from bfq.
	 */
	if (rq->elv.priv[1])
		return rq->elv.priv[1];

	bic = icq_to_bic(rq->elv.icq);

	klpr_bfq_check_ioprio_change(bic, bio);

	(*klpe_bfq_bic_update_cgroup)(bic, bio);

	bfqq = klpr_bfq_get_bfqq_handle_split(bfqd, bic, bio, false, is_sync,
					 &new_queue);

	if (likely(!new_queue)) {
		/* If the queue was seeky for too long, break it apart. */
		if ((*klpe_bfq_bfqq_coop)(bfqq) && (*klpe_bfq_bfqq_split_coop)(bfqq)) {
			klpr_bfq_log_bfqq(bfqd, bfqq, "breaking apart bfqq");

			/* Update bic before losing reference to bfqq */
			if ((*klpe_bfq_bfqq_in_large_burst)(bfqq))
				bic->saved_in_large_burst = true;

			bfqq = klpr_bfq_split_bfqq(bic, bfqq);
			split = true;

			if (!bfqq)
				bfqq = klpr_bfq_get_bfqq_handle_split(bfqd, bic, bio,
								 true, is_sync,
								 NULL);
			else
				bfqq_already_existing = true;
		}
	}

	bfqq->allocated++;
	bfqq->ref++;
	klpr_bfq_log_bfqq(bfqd, bfqq, "get_request %p: bfqq %p, %d",
		     rq, bfqq, bfqq->ref);

	rq->elv.priv[0] = bic;
	rq->elv.priv[1] = bfqq;

	/*
	 * If a bfq_queue has only one process reference, it is owned
	 * by only this bic: we can then set bfqq->bic = bic. in
	 * addition, if the queue has also just been split, we have to
	 * resume its state.
	 */
	if (likely(bfqq != &bfqd->oom_bfqq) && !bfqq->new_bfqq &&
	    bfqq_process_refs(bfqq) == 1) {
		bfqq->bic = bic;
		if (split) {
			/*
			 * The queue has just been split from a shared
			 * queue: restore the idle window and the
			 * possible weight raising period.
			 */
			klpr_bfq_bfqq_resume_state(bfqq, bfqd, bic,
					      bfqq_already_existing);
		}
	}

	if (unlikely((*klpe_bfq_bfqq_just_created)(bfqq)))
		klpr_bfq_handle_burst(bfqd, bfqq);

	return bfqq;
}


#include "livepatch_bsc1231943.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bfq_bfqq_busy", (void *)&klpe_bfq_bfqq_busy },
	{ "bfq_bfqq_coop", (void *)&klpe_bfq_bfqq_coop },
	{ "bfq_bfqq_in_large_burst", (void *)&klpe_bfq_bfqq_in_large_burst },
	{ "bfq_bfqq_just_created", (void *)&klpe_bfq_bfqq_just_created },
	{ "bfq_bfqq_split_coop", (void *)&klpe_bfq_bfqq_split_coop },
	{ "bfq_bfqq_sync", (void *)&klpe_bfq_bfqq_sync },
	{ "bfq_bic_update_cgroup", (void *)&klpe_bfq_bic_update_cgroup },
	{ "bfq_clear_bfqq_IO_bound", (void *)&klpe_bfq_clear_bfqq_IO_bound },
	{ "bfq_clear_bfqq_coop", (void *)&klpe_bfq_clear_bfqq_coop },
	{ "bfq_clear_bfqq_has_short_ttime",
	  (void *)&klpe_bfq_clear_bfqq_has_short_ttime },
	{ "bfq_clear_bfqq_in_large_burst",
	  (void *)&klpe_bfq_clear_bfqq_in_large_burst },
	{ "bfq_clear_bfqq_split_coop",
	  (void *)&klpe_bfq_clear_bfqq_split_coop },
	{ "bfq_get_queue", (void *)&klpe_bfq_get_queue },
	{ "bfq_ioprio_to_weight", (void *)&klpe_bfq_ioprio_to_weight },
	{ "bfq_mark_bfqq_IO_bound", (void *)&klpe_bfq_mark_bfqq_IO_bound },
	{ "bfq_mark_bfqq_has_short_ttime",
	  (void *)&klpe_bfq_mark_bfqq_has_short_ttime },
	{ "bfq_mark_bfqq_in_large_burst",
	  (void *)&klpe_bfq_mark_bfqq_in_large_burst },
	{ "bfq_put_cooperator", (void *)&klpe_bfq_put_cooperator },
	{ "bfq_put_queue", (void *)&klpe_bfq_put_queue },
	{ "bfqg_to_blkg", (void *)&klpe_bfqg_to_blkg },
	{ "bfqq_group", (void *)&klpe_bfqq_group },
	{ "bic_set_bfqq", (void *)&klpe_bic_set_bfqq },
	{ "bic_to_bfqd", (void *)&klpe_bic_to_bfqd },
	{ "bic_to_bfqq", (void *)&klpe_bic_to_bfqq },
};

int livepatch_bsc1231943_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
