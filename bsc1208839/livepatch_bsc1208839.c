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
#include <linux/sched/coredump.h>
#include <linux/sched/cputime.h>
#include <linux/sched/isolation.h>
#include <linux/sched/jobctl.h>
#include <linux/sched/prio.h>
#include <linux/sched/rt.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/user.h>
#include <linux/bitops.h>
#include <linux/compat.h>
#include <linux/energy_model.h>
#include <linux/ratelimit.h>
#include <linux/stop_machine.h>
#include <linux/swait.h>

#ifdef CONFIG_PARAVIRT
# include <asm/paravirt.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define SCHED_WARN_ON(x)   WARN_ONCE(x, #x)

struct rt_prio_array {
	DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
	struct list_head queue[MAX_RT_PRIO];
};

#ifdef CONFIG_CGROUP_SCHED

#include <linux/cgroup.h>
#include <linux/psi.h>

#else /* CONFIG_CGROUP_SCHED */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_CGROUP_SCHED */

struct cfs_rq {
	struct load_weight	load;
	unsigned int		nr_running;
	unsigned int		h_nr_running;      /* SCHED_{NORMAL,BATCH,IDLE} */
	unsigned int		idle_nr_running;   /* SCHED_IDLE */
	unsigned int		idle_h_nr_running; /* SCHED_IDLE */

	u64			exec_clock;
	u64			min_vruntime;
#ifdef CONFIG_SCHED_CORE
	unsigned int		forceidle_seq;
	u64			min_vruntime_fi;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifndef CONFIG_64BIT
#error "klp-ccp: non-taken branch"
#endif
	struct rb_root_cached	tasks_timeline;

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity	*curr;
	struct sched_entity	*next;
	struct sched_entity	*last;
	struct sched_entity	*skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int		nr_spread_over;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SMP
	struct sched_avg	avg;
#ifndef CONFIG_64BIT
#error "klp-ccp: non-taken branch"
#endif
	struct {
		raw_spinlock_t	lock ____cacheline_aligned;
		int		nr;
		unsigned long	load_avg;
		unsigned long	util_avg;
		unsigned long	runnable_avg;
	} removed;

#ifdef CONFIG_FAIR_GROUP_SCHED
	unsigned long		tg_load_avg_contrib;
	long			propagate;
	long			prop_runnable_sum;

	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long		h_load;
	u64			last_h_load_update;
	struct sched_entity	*h_load_next;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_FAIR_GROUP_SCHED */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq		*rq;	/* CPU runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a CPU.
	 * This list is used during load balance.
	 */
	int			on_list;
	struct list_head	leaf_cfs_rq_list;
	struct task_group	*tg;	/* group that "owns" this runqueue */

	/* Locally cached copy of our task_group's idle value */
	int			idle;

#ifdef CONFIG_CFS_BANDWIDTH
	int			runtime_enabled;
	s64			runtime_remaining;

	u64			throttled_pelt_idle;
#ifndef CONFIG_64BIT
#error "klp-ccp: non-taken branch"
#endif
	u64			throttled_clock;
	u64			throttled_clock_pelt;
	u64			throttled_clock_pelt_time;
	int			throttled;
	int			throttle_count;
	struct list_head	throttled_list;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_CFS_BANDWIDTH */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

struct rt_rq {
	struct rt_prio_array	active;
	unsigned int		rt_nr_running;
	unsigned int		rr_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int		curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int		next; /* next highest */
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	} highest_prio;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_SMP
	unsigned int		rt_nr_migratory;
	unsigned int		rt_nr_total;
	int			overloaded;
	struct plist_head	pushable_tasks;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */
	int			rt_queued;

	int			rt_throttled;
	u64			rt_time;
	u64			rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t		rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
#error "klp-ccp: non-taken branch"
#endif
};

struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root_cached	root;

	unsigned int		dl_nr_running;

#ifdef CONFIG_SMP
	struct {
		u64		curr;
		u64		next;
	} earliest_dl;

	unsigned int		dl_nr_migratory;
	int			overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root_cached	pushable_dl_tasks_root;
#else
#error "klp-ccp: non-taken branch"
#endif
	u64			running_bw;

	/*
	 * Utilization of the tasks "assigned" to this runqueue (including
	 * the tasks that are in runqueue and the tasks that executed on this
	 * CPU and blocked). Increased when a task moves to this runqueue, and
	 * decreased when the task moves away (migrates, changes scheduling
	 * policy, or terminates).
	 * This is needed to compute the "inactive utilization" for the
	 * runqueue (inactive utilization = this_bw - running_bw).
	 */
	u64			this_bw;
	u64			extra_bw;

	/*
	 * Inverse of the fraction of CPU utilization that can be reclaimed
	 * by the GRUB algorithm.
	 */
	u64			bw_ratio;
};

struct rq {
	/* runqueue lock: */
	raw_spinlock_t		__lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
	unsigned int		nr_running;
#ifdef CONFIG_NUMA_BALANCING
#error "klp-ccp: non-taken branch"
#endif
#ifdef CONFIG_NO_HZ_COMMON
#ifdef CONFIG_SMP
	unsigned long		last_blocked_load_update_tick;
	unsigned int		has_blocked_load;
	call_single_data_t	nohz_csd;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */
	unsigned int		nohz_tick_stopped;
	atomic_t		nohz_flags;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_NO_HZ_COMMON */

#ifdef CONFIG_SMP
	unsigned int		ttwu_pending;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u64			nr_switches;

#ifdef CONFIG_UCLAMP_TASK
#error "klp-ccp: non-taken branch"
#endif
	struct cfs_rq		cfs;
	struct rt_rq		rt;
	struct dl_rq		dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct list_head	leaf_cfs_rq_list;
	struct list_head	*tmp_alone_branch;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_FAIR_GROUP_SCHED */
	unsigned int		nr_uninterruptible;

	struct task_struct __rcu	*curr;
	struct task_struct	*idle;
	struct task_struct	*stop;
	unsigned long		next_balance;
	struct mm_struct	*prev_mm;

	unsigned int		clock_update_flags;
	u64			clock;
	/* Ensure that all clocks are in the same cache line */
	u64			clock_task ____cacheline_aligned;
	u64			clock_pelt;
	unsigned long		lost_idle_time;
	u64			clock_pelt_idle;
	u64			clock_idle;
#ifndef CONFIG_64BIT
#error "klp-ccp: non-taken branch"
#endif
	atomic_t		nr_iowait;

#ifdef CONFIG_SCHED_DEBUG
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_MEMBARRIER
	int membarrier_state;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SMP
	struct root_domain		*rd;
	struct sched_domain __rcu	*sd;

	unsigned long		cpu_capacity;
	unsigned long		cpu_capacity_orig;

	struct callback_head	*balance_callback;

	unsigned char		nohz_idle_balance;
	unsigned char		idle_balance;

	unsigned long		misfit_task_load;

	/* For active balancing */
	int			active_balance;
	int			push_cpu;
	struct cpu_stop_work	active_balance_work;

	/* CPU of this runqueue: */
	int			cpu;
	int			online;

	struct list_head cfs_tasks;

	struct sched_avg	avg_rt;
	struct sched_avg	avg_dl;
#ifdef CONFIG_HAVE_SCHED_AVG_IRQ
#error "klp-ccp: non-taken branch"
#endif
#ifdef CONFIG_SCHED_THERMAL_PRESSURE
#error "klp-ccp: non-taken branch"
#endif
	u64			idle_stamp;
	u64			avg_idle;

	unsigned long		wake_stamp;
	u64			wake_avg_idle;

	/* This is used to determine avg_idle's max value */
	u64			max_idle_balance_cost;

#ifdef CONFIG_HOTPLUG_CPU
	struct rcuwait		hotplug_wait;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SMP */

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
#error "klp-ccp: non-taken branch"
#endif
#ifdef CONFIG_PARAVIRT
	u64			prev_steal_time;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
#error "klp-ccp: non-taken branch"
#endif
	unsigned long		calc_load_update;
	long			calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	call_single_data_t	hrtick_csd;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct hrtimer		hrtick_timer;
	ktime_t 		hrtick_time;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SCHEDSTATS
	struct sched_info	rq_sched_info;
	unsigned long long	rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int		yld_count;

	/* schedule() stats */
	unsigned int		sched_count;
	unsigned int		sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int		ttwu_count;
	unsigned int		ttwu_local;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_CPU_IDLE
	struct cpuidle_state	*idle_state;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_SMP
	unsigned int		nr_pinned;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	unsigned int		push_busy;
	struct cpu_stop_work	push_work;

#ifdef CONFIG_SCHED_CORE
	struct rq		*core;
	struct task_struct	*core_pick;
	unsigned int		core_enabled;
	unsigned int		core_sched_seq;
	struct rb_root		core_tree;

	/* shared state -- careful with sched_core_cpu_deactivate() */
	unsigned int		core_task_seq;
	unsigned int		core_pick_seq;
	unsigned long		core_cookie;
	unsigned int		core_forceidle_count;
	unsigned int		core_forceidle_seq;
	unsigned int		core_forceidle_occupation;
	u64			core_forceidle_start;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

#ifdef CONFIG_SCHED_DEBUG
# include <linux/static_key.h>

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/sched/rt.c */
#ifdef CONFIG_RT_GROUP_SCHED
#error "klp-ccp: non-taken branch"
#else /* CONFIG_RT_GROUP_SCHED */

static inline struct task_struct *rt_task_of(struct sched_rt_entity *rt_se)
{
	return container_of(rt_se, struct task_struct, rt);
}

#endif /* CONFIG_RT_GROUP_SCHED */

#ifdef CONFIG_RT_GROUP_SCHED
#error "klp-ccp: non-taken branch"
#else /* !CONFIG_RT_GROUP_SCHED */

static inline struct rt_rq *group_rt_rq(struct sched_rt_entity *rt_se)
{
	return NULL;
}

#endif /* CONFIG_RT_GROUP_SCHED */

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
	if (SCHED_WARN_ON(list_empty(queue)))
		return NULL;
	next = list_entry(queue->next, struct sched_rt_entity, run_list);

	return next;
}

struct task_struct *klpp__pick_next_task_rt(struct rq *rq)
{
	struct sched_rt_entity *rt_se;
	struct rt_rq *rt_rq  = &rq->rt;

	do {
		rt_se = klpp_pick_next_rt_entity(rq, rt_rq);
		if (unlikely(!rt_se))
			return NULL;
		rt_rq = group_rt_rq(rt_se);
	} while (rt_rq);

	return rt_task_of(rt_se);
}


#include "livepatch_bsc1208839.h"
