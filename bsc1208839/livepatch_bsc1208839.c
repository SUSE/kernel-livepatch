/*
 * livepatch_bsc1208839
 *
 * Fix for CVE-2023-1077, bsc#1208839
 *
 *  Upstream commit:
 *  7c4a5b89a0b5 ("sched/rt: pick_next_rt_entity(): check list_entry")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  6b28935b995268411d66e37d3a189d180938bec6
 *
 *  SLE15-SP2 and -SP3 commit:
 *  a8f82d0a678dffb0999c7cac200e82c1c6e23f8d
 *
 *  SLE15-SP4 and -SP5 commit:
 *  f5b50ae93e30541783e63f82687b869401d24f83
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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



/* klp-ccp: from kernel/sched/sched.h */
#include <linux/sched.h>

/* klp-ccp: from include/linux/plist.h */
static void (*klpe_plist_del)(struct plist_node *node, struct plist_head *head);

/* klp-ccp: from kernel/sched/sched.h */
#include <linux/sched/topology.h>

/* klp-ccp: from kernel/sched/sched.h */
#include <linux/sched/signal.h>

#include <linux/gfp.h>

/* klp-ccp: from kernel/sched/sched.h */
#include <linux/sched/task.h>
#include <linux/kernel_stat.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>

/* klp-ccp: from kernel/sched/sched.h */
#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#endif

/* klp-ccp: from kernel/sched/cpupri.h */
#include <linux/sched.h>
/* klp-ccp: from kernel/sched/cpudeadline.h */
#include <linux/sched.h>
#include <linux/sched/deadline.h>

/* klp-ccp: from kernel/sched/sched.h */
#define SCHED_WARN_ON(x)	WARN_ONCE(x, #x)

#define TASK_ON_RQ_QUEUED	1

struct rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};

struct cfs_rq {
	struct load_weight load;
	unsigned long runnable_weight;
	unsigned int nr_running, h_nr_running;

	u64 exec_clock;
	u64 min_vruntime;
#ifndef CONFIG_64BIT
#error "klp-ccp: non-taken branch"
#endif
	struct rb_root_cached tasks_timeline;

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity *curr, *next, *last, *skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int nr_spread_over;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SMP
	struct sched_avg avg;
#ifndef CONFIG_64BIT
#error "klp-ccp: non-taken branch"
#endif
	struct {
		raw_spinlock_t	lock ____cacheline_aligned;
		int		nr;
		unsigned long	load_avg;
		unsigned long	util_avg;
		unsigned long	runnable_sum;
	} removed;

#ifdef CONFIG_FAIR_GROUP_SCHED
	unsigned long tg_load_avg_contrib;
	long propagate;
	long prop_runnable_sum;

	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_FAIR_GROUP_SCHED */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq *rq;	/* cpu runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
	 * list is used during load balance.
	 */
	int on_list;
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;	/* group that "owns" this runqueue */

#ifdef CONFIG_CFS_BANDWIDTH
	int runtime_enabled;
#ifndef __GENKSYMS__
	int expires_seq;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u64 runtime_expires;
	s64 runtime_remaining;

	u64 throttled_clock, throttled_clock_task;
	u64 throttled_clock_task_time;
	int throttled, throttle_count;
	struct list_head throttled_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_CFS_BANDWIDTH */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int next; /* next highest */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	} highest_prio;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_SMP
	unsigned long rt_nr_migratory;
	unsigned long rt_nr_total;
	int overloaded;
	struct plist_head pushable_tasks;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */
	int rt_queued;

	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned long rt_nr_boosted;

	struct rq *rq;
	struct task_group *tg;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root_cached root;

	unsigned long dl_nr_running;

#ifdef CONFIG_SMP
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;

	unsigned long dl_nr_migratory;
	int overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root_cached pushable_dl_tasks_root;
#else
#error "klp-ccp: non-taken branch"
#endif
};

struct rq {
	/* runqueue lock: */
	raw_spinlock_t lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
	unsigned int nr_running;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
	unsigned int numa_migrate_on;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	
#define CPU_LOAD_IDX_MAX 5
unsigned long cpu_load[CPU_LOAD_IDX_MAX];
#ifdef CONFIG_NO_HZ_COMMON
#ifdef CONFIG_SMP
	unsigned long last_load_update_tick;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */
	unsigned long nohz_flags;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NO_HZ_COMMON */
#ifdef CONFIG_NO_HZ_FULL
	unsigned long last_sched_tick;
#endif
	struct load_weight load;
	unsigned long nr_load_updates;
	u64 nr_switches;

	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct list_head leaf_cfs_rq_list;
	struct list_head *tmp_alone_branch;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_FAIR_GROUP_SCHED */
	unsigned long nr_uninterruptible;

	struct task_struct *curr, *idle, *stop;
	unsigned long next_balance;
	struct mm_struct *prev_mm;

	unsigned int clock_update_flags;
	u64 clock;
	u64 clock_task;

	atomic_t nr_iowait;

#ifdef CONFIG_SMP
	struct root_domain *rd;
	struct sched_domain *sd;

	unsigned long cpu_capacity;
	unsigned long cpu_capacity_orig;

	struct callback_head *balance_callback;

	unsigned char idle_balance;
	/* For active balancing */
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	/* cpu of this runqueue: */
	int cpu;
	int online;

	struct list_head cfs_tasks;

	u64 rt_avg;
	u64 age_stamp;
	u64 idle_stamp;
	u64 avg_idle;

	/* This is used to determine avg_idle's max value */
	u64 max_idle_balance_cost;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
#error "klp-ccp: non-taken branch"
#endif
#ifdef CONFIG_PARAVIRT
	u64 prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
#error "klp-ccp: non-taken branch"
#endif
	unsigned long calc_load_update;
	long calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	int hrtick_csd_pending;
	call_single_data_t hrtick_csd;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct hrtimer hrtick_timer;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SCHEDSTATS
	struct sched_info rq_sched_info;
	unsigned long long rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int yld_count;

	/* schedule() stats */
	unsigned int sched_count;
	unsigned int sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int ttwu_count;
	unsigned int ttwu_local;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SMP
	struct llist_head wake_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_CPU_IDLE
	struct cpuidle_state *idle_state;
#endif
};

#define RQCF_ACT_SKIP	0x02
#define RQCF_UPDATED	0x04

static inline void assert_clock_updated(struct rq *rq)
{
	/*
	 * The only reason for not seeing a clock update since the
	 * last rq_pin_lock() is if we're currently skipping updates.
	 */
	SCHED_WARN_ON(rq->clock_update_flags < RQCF_ACT_SKIP);
}

static inline u64 rq_clock_task(struct rq *rq)
{
	lockdep_assert_held(&rq->lock);
	assert_clock_updated(rq);

	return rq->clock_task;
}

struct rq_flags {
	unsigned long flags;
	struct pin_cookie cookie;
#ifdef CONFIG_SCHED_DEBUG
	unsigned int clock_update_flags;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

static inline void rq_unpin_lock(struct rq *rq, struct rq_flags *rf)
{
#ifdef CONFIG_SCHED_DEBUG
	if (rq->clock_update_flags > RQCF_ACT_SKIP)
		rf->clock_update_flags = RQCF_UPDATED;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	lockdep_unpin_lock(&rq->lock, rf->cookie);
}

static inline void rq_repin_lock(struct rq *rq, struct rq_flags *rf)
{
	lockdep_repin_lock(&rq->lock, rf->cookie);

#ifdef CONFIG_SCHED_DEBUG
	rq->clock_update_flags |= rf->clock_update_flags;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
}

#ifdef CONFIG_SMP

static inline void
queue_balance_callback(struct rq *rq,
		       struct callback_head *head,
		       void (*func)(struct rq *rq))
{
	lockdep_assert_held(&rq->lock);

	if (unlikely(head->next))
		return;

	head->func = (void (*)(struct callback_head *))func;
	head->next = rq->balance_callback;
	rq->balance_callback = head;
}

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SMP */

#ifdef CONFIG_SCHED_DEBUG
# include <linux/static_key.h>

#else
#error "klp-ccp: non-taken branch"
#endif

static inline int task_on_rq_queued(struct task_struct *p)
{
	return p->on_rq == TASK_ON_RQ_QUEUED;
}

#define RETRY_TASK		((void *)-1UL)

struct sched_class {
	const struct sched_class *next;

	void (*enqueue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*dequeue_task) (struct rq *rq, struct task_struct *p, int flags);
	void (*yield_task) (struct rq *rq);
	bool (*yield_to_task) (struct rq *rq, struct task_struct *p, bool preempt);

	void (*check_preempt_curr) (struct rq *rq, struct task_struct *p, int flags);

	/*
	 * It is the responsibility of the pick_next_task() method that will
	 * return the next task to call put_prev_task() on the @prev task or
	 * something equivalent.
	 *
	 * May return RETRY_TASK when it finds a higher prio class has runnable
	 * tasks.
	 */
	struct task_struct * (*pick_next_task) (struct rq *rq,
						struct task_struct *prev,
						struct rq_flags *rf);
	void (*put_prev_task) (struct rq *rq, struct task_struct *p);

#ifdef CONFIG_SMP
	int  (*select_task_rq)(struct task_struct *p, int task_cpu, int sd_flag, int flags);
	void (*migrate_task_rq)(struct task_struct *p, int new_cpu);

	void (*task_woken) (struct rq *this_rq, struct task_struct *task);

	void (*set_cpus_allowed)(struct task_struct *p,
				 const struct cpumask *newmask);

	void (*rq_online)(struct rq *rq);
	void (*rq_offline)(struct rq *rq);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	void (*set_curr_task) (struct rq *rq);
	void (*task_tick) (struct rq *rq, struct task_struct *p, int queued);
	void (*task_fork) (struct task_struct *p);
	void (*task_dead) (struct task_struct *p);

	/*
	 * The switched_from() call is allowed to drop rq->lock, therefore we
	 * cannot assume the switched_from/switched_to pair is serliazed by
	 * rq->lock. They are however serialized by p->pi_lock.
	 */
	void (*switched_from) (struct rq *this_rq, struct task_struct *task);
	void (*switched_to) (struct rq *this_rq, struct task_struct *task);
	void (*prio_changed) (struct rq *this_rq, struct task_struct *task,
			     int oldprio);

	unsigned int (*get_rr_interval) (struct rq *rq,
					 struct task_struct *task);

	void (*update_curr) (struct rq *rq);

#ifdef CONFIG_FAIR_GROUP_SCHED
	void (*task_change_group) (struct task_struct *p, int type);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

static inline void put_prev_task(struct rq *rq, struct task_struct *prev)
{
	prev->sched_class->put_prev_task(rq, prev);
}

static const struct sched_class (*klpe_rt_sched_class);

/* klp-ccp: from kernel/sched/rt.c */
#include <linux/slab.h>
#include <linux/irq_work.h>

#ifdef CONFIG_RT_GROUP_SCHED

#define rt_entity_is_task(rt_se) (!(rt_se)->my_q)

static inline struct task_struct *rt_task_of(struct sched_rt_entity *rt_se)
{
#ifdef CONFIG_SCHED_DEBUG
	WARN_ON_ONCE(!rt_entity_is_task(rt_se));
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return container_of(rt_se, struct task_struct, rt);
}

#else /* CONFIG_RT_GROUP_SCHED */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_RT_GROUP_SCHED */

#ifdef CONFIG_SMP

static void (*klpe_pull_rt_task)(struct rq *this_rq);

static inline bool need_pull_rt_task(struct rq *rq, struct task_struct *prev)
{
	/* Try to pull RT tasks here if we lower this rq's prio */
	return rq->rt.highest_prio.curr > prev->prio;
}

static inline int has_pushable_tasks(struct rq *rq)
{
	return !plist_head_empty(&rq->rt.pushable_tasks);
}

static struct callback_head __percpu (*klpe_rt_push_head);

static void (*klpe_push_rt_tasks)(struct rq *);

static inline void klpr_queue_push_tasks(struct rq *rq)
{
	if (!has_pushable_tasks(rq))
		return;

	queue_balance_callback(rq, &per_cpu((*klpe_rt_push_head), rq->cpu), (*klpe_push_rt_tasks));
}

static void klpr_dequeue_pushable_task(struct rq *rq, struct task_struct *p)
{
	(*klpe_plist_del)(&p->pushable_tasks, &rq->rt.pushable_tasks);

	/* Update the new highest prio pushable task */
	if (has_pushable_tasks(rq)) {
		p = plist_first_entry(&rq->rt.pushable_tasks,
				      struct task_struct, pushable_tasks);
		rq->rt.highest_prio.next = p->prio;
	} else
		rq->rt.highest_prio.next = MAX_RT_PRIO;
}

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SMP */

#ifdef CONFIG_RT_GROUP_SCHED

static inline struct rt_rq *group_rt_rq(struct sched_rt_entity *rt_se)
{
	return rt_se->my_q;
}

#else /* !CONFIG_RT_GROUP_SCHED */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_RT_GROUP_SCHED */

static void (*klpe_update_curr_rt)(struct rq *rq);

static struct sched_rt_entity *klpp_pick_next_rt_entity(struct rq *rq,
						   struct rt_rq *rt_rq)
{
	struct rt_prio_array *array = &rt_rq->active;
	struct sched_rt_entity *next = NULL;
	struct list_head *queue;
	int idx;

	idx = sched_find_first_bit(array->bitmap);
	BUG_ON(idx >= MAX_RT_PRIO);

	queue = array->queue + idx;
#ifdef CONFIG_SCHED_DEBUG
	if (WARN_ON_ONCE(list_empty(queue)))
		return NULL;
#endif
	next = list_entry(queue->next, struct sched_rt_entity, run_list);

	return next;
}

static struct task_struct *klpp__pick_next_task_rt(struct rq *rq)
{
	struct sched_rt_entity *rt_se;
	struct task_struct *p;
	struct rt_rq *rt_rq  = &rq->rt;

	do {
		rt_se = klpp_pick_next_rt_entity(rq, rt_rq);
		if (unlikely(!rt_se))
			return NULL;
		rt_rq = group_rt_rq(rt_se);
	} while (rt_rq);

	p = rt_task_of(rt_se);
	p->se.exec_start = rq_clock_task(rq);

	return p;
}

struct task_struct *
klpp_pick_next_task_rt(struct rq *rq, struct task_struct *prev, struct rq_flags *rf)
{
	struct task_struct *p;
	struct rt_rq *rt_rq = &rq->rt;

	if (need_pull_rt_task(rq, prev)) {
		/*
		 * This is OK, because current is on_cpu, which avoids it being
		 * picked for load-balance and preemption/IRQs are still
		 * disabled avoiding further scheduler activity on it and we're
		 * being very careful to re-start the picking loop.
		 */
		rq_unpin_lock(rq, rf);
		(*klpe_pull_rt_task)(rq);
		rq_repin_lock(rq, rf);
		/*
		 * pull_rt_task() can drop (and re-acquire) rq->lock; this
		 * means a dl or stop task can slip in, in which case we need
		 * to re-start task selection.
		 */
		if (unlikely((rq->stop && task_on_rq_queued(rq->stop)) ||
			     rq->dl.dl_nr_running))
			return RETRY_TASK;
	}

	/*
	 * We may dequeue prev's rt_rq in put_prev_task().
	 * So, we update time before rt_nr_running check.
	 */
	if (prev->sched_class == &(*klpe_rt_sched_class))
		(*klpe_update_curr_rt)(rq);

	if (!rt_rq->rt_queued)
		return NULL;

	put_prev_task(rq, prev);

	p = klpp__pick_next_task_rt(rq);

	/* The running task is never eligible for pushing */
	klpr_dequeue_pushable_task(rq, p);

	klpr_queue_push_tasks(rq);

	return p;
}



#include "livepatch_bsc1208839.h"
#include <linux/kernel.h>
#include "../kallsyms_relocs.h"


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "plist_del", (void *)&klpe_plist_del },
	{ "pull_rt_task", (void *)&klpe_pull_rt_task },
	{ "push_rt_tasks", (void *)&klpe_push_rt_tasks },
	{ "rt_push_head", (void *)&klpe_rt_push_head },
	{ "rt_sched_class", (void *)&klpe_rt_sched_class },
	{ "update_curr_rt", (void *)&klpe_update_curr_rt },
};


int livepatch_bsc1208839_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

