/*
 * livepatch_bsc1241331
 *
 * Fix for CVE-2022-49179, bsc#1241331
 *
 *  Upstream commit:
 *  8410f7097773 ("block, bfq: don't move oom_bfqq")
 *
 *  SLE12-SP5 commit:
 *  08606deaf4dfd97f351a73dc756a075aabaa5484
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  817b56469979ad583a128a29adf5eae085a46d00
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.com>
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

/* klp-ccp: from block/bfq-cgroup.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/cgroup.h>
#include <linux/elevator.h>
#include <linux/ktime.h>
#include <linux/rbtree.h>
#include <linux/ioprio.h>

/* klp-ccp: from block/bfq-iosched.h */
#include <linux/hrtimer.h>
#include <linux/blk-cgroup.h>

#define BFQ_IOPRIO_CLASSES	3

struct bfq_service_tree {
	/* tree for active entities (i.e., those backlogged) */
	struct rb_root active;
	/* tree for idle entities (i.e., not backlogged, with V < F_i)*/
	struct rb_root idle;

	/* idle entity with minimum F_i */
	struct bfq_entity *first_idle;
	/* idle entity with maximum F_i */
	struct bfq_entity *last_idle;

	/* scheduler virtual time */
	u64 vtime;
	/* scheduler weight sum; active and idle entities contribute to it */
	unsigned long wsum;
};

struct bfq_sched_data {
	/* entity in service */
	struct bfq_entity *in_service_entity;
	/* head-of-line entity (see comments above) */
	struct bfq_entity *next_in_service;
	/* array of service trees, one per ioprio_class */
	struct bfq_service_tree service_tree[BFQ_IOPRIO_CLASSES];
	/* last time CLASS_IDLE was served */
	unsigned long bfq_class_idle_last_service;

};

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

static int (*klpe_bfq_bfqq_busy)(const struct bfq_queue *bfqq);

enum bfqq_expiration {
	BFQQE_TOO_IDLE = 0,		/*
					 * queue has been idling for
					 * too long
					 */
	BFQQE_BUDGET_TIMEOUT,	/* budget took too long to be used */
	BFQQE_BUDGET_EXHAUSTED,	/* budget consumed */
	BFQQE_NO_MORE_REQUESTS,	/* the queue has no more requests */
	BFQQE_PREEMPTED		/* preemption in progress */
};

struct bfqg_stats {
#if defined(CONFIG_BFQ_GROUP_IOSCHED) && defined(CONFIG_DEBUG_BLK_CGROUP)
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_BFQ_GROUP_IOSCHED && CONFIG_DEBUG_BLK_CGROUP */
};

#ifdef CONFIG_BFQ_GROUP_IOSCHED

struct bfq_group {
	/* must be the first member */
	struct blkg_policy_data pd;

	/* cached path for this blkg (see comments in bfq_bic_update_cgroup) */
	char blkg_path[128];

	/* reference counter (see comments in bfq_bic_update_cgroup) */
	int ref;

	struct bfq_entity entity;
	struct bfq_sched_data sched_data;

	void *bfqd;

	struct bfq_queue *async_bfqq[2][IOPRIO_BE_NR];
	struct bfq_queue *async_idle_bfqq;

	struct bfq_entity *my_entity;

	int active_entities;

	struct rb_root rq_pos_tree;

	struct bfqg_stats stats;
};

#else
#error "klp-ccp: non-taken branch"
#endif

static void (*klpe_bfq_pos_tree_add_move)(struct bfq_data *bfqd, struct bfq_queue *bfqq);

static void (*klpe_bfq_bfqq_expire)(struct bfq_data *bfqd, struct bfq_queue *bfqq,
		     bool compensate, enum bfqq_expiration reason);

static void (*klpe_bfq_schedule_dispatch)(struct bfq_data *bfqd);

static void (*klpe_bfqg_and_blkg_put)(struct bfq_group *bfqg);

static struct bfq_service_tree *(*klpe_bfq_entity_service_tree)(struct bfq_entity *entity);

static void (*klpe_bfq_put_idle_entity)(struct bfq_service_tree *st,
			 struct bfq_entity *entity);

static void (*klpe_bfq_deactivate_bfqq)(struct bfq_data *bfqd, struct bfq_queue *bfqq,
			 bool ins_into_idle_tree, bool expiration);
static void (*klpe_bfq_activate_bfqq)(struct bfq_data *bfqd, struct bfq_queue *bfqq);

#ifdef CONFIG_BFQ_GROUP_IOSCHED
static struct bfq_group *(*klpe_bfqq_group)(struct bfq_queue *bfqq);

#else /* CONFIG_BFQ_GROUP_IOSCHED */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_BFQ_GROUP_IOSCHED */

/* klp-ccp: from block/bfq-cgroup.c */
#ifdef CONFIG_BFQ_GROUP_IOSCHED

static struct blkcg_gq *(*klpe_bfqg_to_blkg)(struct bfq_group *bfqg);

static void bfqg_get(struct bfq_group *bfqg)
{
	bfqg->ref++;
}

static void klpr_bfqg_and_blkg_get(struct bfq_group *bfqg)
{
	/* see comments in bfq_bic_update_cgroup for why refcounting bfqg */
	bfqg_get(bfqg);

	blkg_get((*klpe_bfqg_to_blkg)(bfqg));
}

void klpp_bfq_bfqq_move(struct bfq_data *bfqd, struct bfq_queue *bfqq,
		   struct bfq_group *bfqg)
{
	struct bfq_entity *entity = &bfqq->entity;

	/*
	 * oom_bfqq is not allowed to move, oom_bfqq will hold ref to root_group
	 * until elevator exit.
	 */
	if (bfqq == &bfqd->oom_bfqq)
		return;

	/* If bfqq is empty, then bfq_bfqq_expire also invokes
	 * bfq_del_bfqq_busy, thereby removing bfqq and its entity
	 * from data structures related to current group. Otherwise we
	 * need to remove bfqq explicitly with bfq_deactivate_bfqq, as
	 * we do below.
	 */
	if (bfqq == bfqd->in_service_queue)
		(*klpe_bfq_bfqq_expire)(bfqd, bfqd->in_service_queue,
				false, BFQQE_PREEMPTED);

	if ((*klpe_bfq_bfqq_busy)(bfqq))
		(*klpe_bfq_deactivate_bfqq)(bfqd, bfqq, false, false);
	else if (entity->on_st)
		(*klpe_bfq_put_idle_entity)((*klpe_bfq_entity_service_tree)(entity), entity);
	(*klpe_bfqg_and_blkg_put)((*klpe_bfqq_group)(bfqq));

	entity->parent = bfqg->my_entity;
	entity->sched_data = &bfqg->sched_data;
	/* pin down bfqg and its associated blkg  */
	klpr_bfqg_and_blkg_get(bfqg);

	if ((*klpe_bfq_bfqq_busy)(bfqq)) {
		(*klpe_bfq_pos_tree_add_move)(bfqd, bfqq);
		(*klpe_bfq_activate_bfqq)(bfqd, bfqq);
	}

	if (!bfqd->in_service_queue && !bfqd->rq_in_driver)
		(*klpe_bfq_schedule_dispatch)(bfqd);
}

#else	/* CONFIG_BFQ_GROUP_IOSCHED */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_BFQ_GROUP_IOSCHED */


#include "livepatch_bsc1241331.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bfq_activate_bfqq", (void *)&klpe_bfq_activate_bfqq },
	{ "bfq_bfqq_busy", (void *)&klpe_bfq_bfqq_busy },
	{ "bfq_bfqq_expire", (void *)&klpe_bfq_bfqq_expire },
	{ "bfq_deactivate_bfqq", (void *)&klpe_bfq_deactivate_bfqq },
	{ "bfq_entity_service_tree", (void *)&klpe_bfq_entity_service_tree },
	{ "bfq_pos_tree_add_move", (void *)&klpe_bfq_pos_tree_add_move },
	{ "bfq_put_idle_entity", (void *)&klpe_bfq_put_idle_entity },
	{ "bfq_schedule_dispatch", (void *)&klpe_bfq_schedule_dispatch },
	{ "bfqg_and_blkg_put", (void *)&klpe_bfqg_and_blkg_put },
	{ "bfqg_to_blkg", (void *)&klpe_bfqg_to_blkg },
	{ "bfqq_group", (void *)&klpe_bfqq_group },
};

int livepatch_bsc1241331_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

