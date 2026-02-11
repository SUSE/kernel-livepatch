/*
 * livepatch_bsc1249205
 *
 * Fix for CVE-2025-38352, bsc#1249205
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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



#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1

/* klp-ccp: from kernel/time/posix-cpu-timers.c */
#include <linux/sched/signal.h>
#include <linux/sched/clock.h>

/* klp-ccp: from include/linux/signal.h */
static int (*klpe_print_fatal_signals);

static int (*klpe___group_send_sig_info)(int, struct siginfo *, struct task_struct *);

/* klp-ccp: from include/linux/sched/signal.h */
static struct sighand_struct *(*klpe___lock_task_sighand)(struct task_struct *tsk,
							unsigned long *flags);

static inline struct sighand_struct *klpr_lock_task_sighand(struct task_struct *tsk,
						       unsigned long *flags)
{
	struct sighand_struct *ret;

	ret = (*klpe___lock_task_sighand)(tsk, flags);
	(void)__cond_lock(&tsk->sighand->siglock, ret);
	return ret;
}

/* klp-ccp: from kernel/time/posix-cpu-timers.c */
#include <linux/sched/cputime.h>

/* klp-ccp: from include/linux/sched/cputime.h */
static void (*klpe_thread_group_cputimer)(struct task_struct *tsk, struct task_cputime *times);

/* klp-ccp: from kernel/time/posix-cpu-timers.c */
#include <linux/posix-timers.h>

/* klp-ccp: from include/linux/posix-timers.h */
void klpp_run_posix_cpu_timers(struct task_struct *task);

/* klp-ccp: from kernel/time/posix-cpu-timers.c */
#include <linux/errno.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/kernel_stat.h>
#include <trace/events/timer.h>
#include <linux/tick.h>
#include <linux/workqueue.h>


#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN

static u64 vtime_delta(struct vtime *vtime)
{
	unsigned long long clock;

	clock = sched_clock();
	if (clock < vtime->starttime)
		return 0;

	return clock - vtime->starttime;
}

void klpr_task_cputime(struct task_struct *t, u64 *utime, u64 *stime)
{
	struct vtime *vtime = &t->vtime;
	unsigned int seq;
	u64 delta;

	if (!vtime_accounting_enabled()) {
		*utime = t->utime;
		*stime = t->stime;
		return;
	}

	do {
		seq = read_seqcount_begin(&vtime->seqcount);

		*utime = t->utime;
		*stime = t->stime;

		/* Task is sleeping, nothing to add */
		if (vtime->state == VTIME_INACTIVE || is_idle_task(t))
			continue;

		delta = vtime_delta(vtime);

		/*
		 * Task runs either in user or kernel space, add pending nohz time to
		 * the right place.
		 */
		if (vtime->state == VTIME_USER || t->flags & PF_VCPU)
			*utime += vtime->utime + delta;
		else if (vtime->state == VTIME_SYS)
			*stime += vtime->stime + delta;
	} while (read_seqcount_retry(&vtime->seqcount, seq));
}

#else

static inline void klpr_task_cputime(struct task_struct *t,
				u64 *utime, u64 *stime)
{
	*utime = t->utime;
	*stime = t->stime;
}

#endif

static inline int task_cputime_zero(const struct task_cputime *cputime)
{
	if (!cputime->utime && !cputime->stime && !cputime->sum_exec_runtime)
		return 1;
	return 0;
}

static inline u64 prof_ticks(struct task_struct *p)
{
	u64 utime, stime;

	klpr_task_cputime(p, &utime, &stime);

	return utime + stime;
}
static inline u64 virt_ticks(struct task_struct *p)
{
	u64 utime, stime;

	klpr_task_cputime(p, &utime, &stime);

	return utime;
}

static inline void sample_cputime_atomic(struct task_cputime *times,
					 struct task_cputime_atomic *atomic_times)
{
	times->utime = atomic64_read(&atomic_times->utime);
	times->stime = atomic64_read(&atomic_times->stime);
	times->sum_exec_runtime = atomic64_read(&atomic_times->sum_exec_runtime);
}
static void (*klpe_cpu_timer_fire)(struct k_itimer *timer);

static unsigned long long
(*klpe_check_timers_list)(struct list_head *timers,
		  struct list_head *firing,
		  unsigned long long curr);


#ifdef CONFIG_NO_HZ_FULL

static bool (*klpe_tick_nohz_full_running);

static inline bool klpr_tick_nohz_full_enabled(void)
{
	if (!context_tracking_is_enabled())
		return false;

	return (*klpe_tick_nohz_full_running);
}

static void (*klpe_tick_nohz_dep_clear_task)(struct task_struct *tsk,
				     enum tick_dep_bits bit);

static inline void klpr_tick_dep_clear_task(struct task_struct *tsk,
				       enum tick_dep_bits bit)
{
	if (klpr_tick_nohz_full_enabled())
		(*klpe_tick_nohz_dep_clear_task)(tsk, bit);
}

static void (*klpe_tick_nohz_dep_clear_signal)(struct signal_struct *signal,
				       enum tick_dep_bits bit);

static inline void klpr_tick_dep_clear_signal(struct signal_struct *signal,
					 enum tick_dep_bits bit)
{
	if (klpr_tick_nohz_full_enabled())
		(*klpe_tick_nohz_dep_clear_signal)(signal, bit);
}
#else

static inline void klpr_tick_dep_clear_task(struct task_struct *tsk,
				       enum tick_dep_bits bit) { }

static inline void klpr_tick_dep_clear_signal(struct signal_struct *signal,
					 enum tick_dep_bits bit) { }

#endif

static void klpr_check_thread_timers(struct task_struct *tsk,
				struct list_head *firing)
{
	struct list_head *timers = tsk->cpu_timers;
	struct signal_struct *const sig = tsk->signal;
	struct task_cputime *tsk_expires = &tsk->cputime_expires;
	u64 expires;
	unsigned long soft;

	/*
	 * If cputime_expires is zero, then there are no active
	 * per thread CPU timers.
	 */
	if (task_cputime_zero(&tsk->cputime_expires))
		return;

	expires = (*klpe_check_timers_list)(timers, firing, prof_ticks(tsk));
	tsk_expires->prof_exp = expires;

	expires = (*klpe_check_timers_list)(++timers, firing, virt_ticks(tsk));
	tsk_expires->virt_exp = expires;

	tsk_expires->sched_exp = (*klpe_check_timers_list)(++timers, firing,
						   tsk->se.sum_exec_runtime);

	/*
	 * Check for the special case thread timers.
	 */
	soft = READ_ONCE(sig->rlim[RLIMIT_RTTIME].rlim_cur);
	if (soft != RLIM_INFINITY) {
		unsigned long hard =
			READ_ONCE(sig->rlim[RLIMIT_RTTIME].rlim_max);

		if (hard != RLIM_INFINITY &&
		    tsk->rt.timeout > DIV_ROUND_UP(hard, USEC_PER_SEC/HZ)) {
			/*
			 * At the hard limit, we just die.
			 * No need to calculate anything else now.
			 */
			if ((*klpe_print_fatal_signals)) {
				pr_info("CPU Watchdog Timeout (hard): %s[%d]\n",
					tsk->comm, task_pid_nr(tsk));
			}
			(*klpe___group_send_sig_info)(SIGKILL, SEND_SIG_PRIV, tsk);
			return;
		}
		if (tsk->rt.timeout > DIV_ROUND_UP(soft, USEC_PER_SEC/HZ)) {
			/*
			 * At the soft limit, send a SIGXCPU every second.
			 */
			if (soft < hard) {
				soft += USEC_PER_SEC;
				sig->rlim[RLIMIT_RTTIME].rlim_cur = soft;
			}
			if ((*klpe_print_fatal_signals)) {
				pr_info("RT Watchdog Timeout (soft): %s[%d]\n",
					tsk->comm, task_pid_nr(tsk));
			}
			(*klpe___group_send_sig_info)(SIGXCPU, SEND_SIG_PRIV, tsk);
		}
	}
	if (task_cputime_zero(tsk_expires))
		klpr_tick_dep_clear_task(tsk, TICK_DEP_BIT_POSIX_TIMER);
}

static inline void stop_process_timers(struct signal_struct *sig)
{
	struct thread_group_cputimer *cputimer = &sig->cputimer;

	/* Turn off cputimer->running. This is done without locking. */
	WRITE_ONCE(cputimer->running, false);
	klpr_tick_dep_clear_signal(sig, TICK_DEP_BIT_POSIX_TIMER);
}

static void (*klpe_check_cpu_itimer)(struct task_struct *tsk, struct cpu_itimer *it,
			     u64 *expires, u64 cur_time, int signo);

static void klpr_check_process_timers(struct task_struct *tsk,
				 struct list_head *firing)
{
	struct signal_struct *const sig = tsk->signal;
	u64 utime, ptime, virt_expires, prof_expires;
	u64 sum_sched_runtime, sched_expires;
	struct list_head *timers = sig->cpu_timers;
	struct task_cputime cputime;
	unsigned long soft;

	/*
	 * If cputimer is not running, then there are no active
	 * process wide timers (POSIX 1.b, itimers, RLIMIT_CPU).
	 */
	if (!READ_ONCE(tsk->signal->cputimer.running))
		return;

        /*
	 * Signify that a thread is checking for process timers.
	 * Write access to this field is protected by the sighand lock.
	 */
	sig->cputimer.checking_timer = true;

	/*
	 * Collect the current process totals.
	 */
	(*klpe_thread_group_cputimer)(tsk, &cputime);
	utime = cputime.utime;
	ptime = utime + cputime.stime;
	sum_sched_runtime = cputime.sum_exec_runtime;

	prof_expires = (*klpe_check_timers_list)(timers, firing, ptime);
	virt_expires = (*klpe_check_timers_list)(++timers, firing, utime);
	sched_expires = (*klpe_check_timers_list)(++timers, firing, sum_sched_runtime);

	/*
	 * Check for the special case process timers.
	 */
	(*klpe_check_cpu_itimer)(tsk, &sig->it[CPUCLOCK_PROF], &prof_expires, ptime,
			 SIGPROF);
	(*klpe_check_cpu_itimer)(tsk, &sig->it[CPUCLOCK_VIRT], &virt_expires, utime,
			 SIGVTALRM);
	soft = READ_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur);
	if (soft != RLIM_INFINITY) {
		unsigned long psecs = div_u64(ptime, NSEC_PER_SEC);
		unsigned long hard =
			READ_ONCE(sig->rlim[RLIMIT_CPU].rlim_max);
		u64 x;
		if (psecs >= hard) {
			/*
			 * At the hard limit, we just die.
			 * No need to calculate anything else now.
			 */
			if ((*klpe_print_fatal_signals)) {
				pr_info("RT Watchdog Timeout (hard): %s[%d]\n",
					tsk->comm, task_pid_nr(tsk));
			}
			(*klpe___group_send_sig_info)(SIGKILL, SEND_SIG_PRIV, tsk);
			return;
		}
		if (psecs >= soft) {
			/*
			 * At the soft limit, send a SIGXCPU every second.
			 */
			if ((*klpe_print_fatal_signals)) {
				pr_info("CPU Watchdog Timeout (soft): %s[%d]\n",
					tsk->comm, task_pid_nr(tsk));
			}
			(*klpe___group_send_sig_info)(SIGXCPU, SEND_SIG_PRIV, tsk);
			if (soft < hard) {
				soft++;
				sig->rlim[RLIMIT_CPU].rlim_cur = soft;
			}
		}
		x = soft * NSEC_PER_SEC;
		if (!prof_expires || x < prof_expires)
			prof_expires = x;
	}

	sig->cputime_expires.prof_exp = prof_expires;
	sig->cputime_expires.virt_exp = virt_expires;
	sig->cputime_expires.sched_exp = sched_expires;
	if (task_cputime_zero(&sig->cputime_expires))
		stop_process_timers(sig);

	sig->cputimer.checking_timer = false;
}

static inline int task_cputime_expired(const struct task_cputime *sample,
					const struct task_cputime *expires)
{
	if (expires->utime && sample->utime >= expires->utime)
		return 1;
	if (expires->stime && sample->utime + sample->stime >= expires->stime)
		return 1;
	if (expires->sum_exec_runtime != 0 &&
	    sample->sum_exec_runtime >= expires->sum_exec_runtime)
		return 1;
	return 0;
}

static inline int fastpath_timer_check(struct task_struct *tsk)
{
	struct signal_struct *sig;

	if (!task_cputime_zero(&tsk->cputime_expires)) {
		struct task_cputime task_sample;

		klpr_task_cputime(tsk, &task_sample.utime, &task_sample.stime);
		task_sample.sum_exec_runtime = tsk->se.sum_exec_runtime;
		if (task_cputime_expired(&task_sample, &tsk->cputime_expires))
			return 1;
	}

	sig = tsk->signal;
	/*
	 * Check if thread group timers expired when the cputimer is
	 * running and no other thread in the group is already checking
	 * for thread group cputimers. These fields are read without the
	 * sighand lock. However, this is fine because this is meant to
	 * be a fastpath heuristic to determine whether we should try to
	 * acquire the sighand lock to check/handle timers.
	 *
	 * In the worst case scenario, if 'running' or 'checking_timer' gets
	 * set but the current thread doesn't see the change yet, we'll wait
	 * until the next thread in the group gets a scheduler interrupt to
	 * handle the timer. This isn't an issue in practice because these
	 * types of delays with signals actually getting sent are expected.
	 */
	if (READ_ONCE(sig->cputimer.running) &&
	    !READ_ONCE(sig->cputimer.checking_timer)) {
		struct task_cputime group_sample;

		sample_cputime_atomic(&group_sample, &sig->cputimer.cputime_atomic);

		if (task_cputime_expired(&group_sample, &sig->cputime_expires))
			return 1;
	}

	return 0;
}

void klpp_run_posix_cpu_timers(struct task_struct *tsk)
{
	LIST_HEAD(firing);
	struct k_itimer *timer, *next;
	unsigned long flags;

	lockdep_assert_irqs_disabled();

	/*
	 * Ensure that release_task(tsk) can't happen while
	 * handle_posix_cpu_timers() is running. Otherwise, a concurrent
	 * posix_cpu_timer_del() may fail to lock_task_sighand(tsk) and
	 * miss timer->it.cpu.firing != 0.
	 */
	if (tsk->exit_state)
		return;

	/*
	 * The fast path checks that there are no expired thread or thread
	 * group timers.  If that's so, just return.
	 */
	if (!fastpath_timer_check(tsk))
		return;

	if (!klpr_lock_task_sighand(tsk, &flags))
		return;
	/*
	 * Here we take off tsk->signal->cpu_timers[N] and
	 * tsk->cpu_timers[N] all the timers that are firing, and
	 * put them on the firing list.
	 */
	klpr_check_thread_timers(tsk, &firing);

	klpr_check_process_timers(tsk, &firing);

	/*
	 * We must release these locks before taking any timer's lock.
	 * There is a potential race with timer deletion here, as the
	 * siglock now protects our private firing list.  We have set
	 * the firing flag in each timer, so that a deletion attempt
	 * that gets the timer lock before we do will give it up and
	 * spin until we've taken care of that timer below.
	 */
	unlock_task_sighand(tsk, &flags);

	/*
	 * Now that all the timers on our list have the firing flag,
	 * no one will touch their list entries but us.  We'll take
	 * each timer's lock before clearing its firing flag, so no
	 * timer call will interfere.
	 */
	list_for_each_entry_safe(timer, next, &firing, it.cpu.entry) {
		int cpu_firing;

		spin_lock(&timer->it_lock);
		list_del_init(&timer->it.cpu.entry);
		cpu_firing = timer->it.cpu.firing;
		timer->it.cpu.firing = 0;
		/*
		 * The firing flag is -1 if we collided with a reset
		 * of the timer, which already reported this
		 * almost-firing as an overrun.  So don't generate an event.
		 */
		if (likely(cpu_firing >= 0))
			(*klpe_cpu_timer_fire)(timer);
		spin_unlock(&timer->it_lock);
	}
}


#include "livepatch_bsc1249205.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__group_send_sig_info", (void *)&klpe___group_send_sig_info },
	{ "__lock_task_sighand", (void *)&klpe___lock_task_sighand },
	{ "check_cpu_itimer", (void *)&klpe_check_cpu_itimer },
	{ "check_timers_list", (void *)&klpe_check_timers_list },
	{ "cpu_timer_fire", (void *)&klpe_cpu_timer_fire },
	{ "print_fatal_signals", (void *)&klpe_print_fatal_signals },
	{ "thread_group_cputimer", (void *)&klpe_thread_group_cputimer },
#ifdef CONFIG_NO_HZ_FULL
	{ "tick_nohz_dep_clear_task", (void *)&klpe_tick_nohz_dep_clear_task },
	{ "tick_nohz_dep_clear_signal", (void *)&klpe_tick_nohz_dep_clear_signal },
	{ "tick_nohz_full_running", (void *)&klpe_tick_nohz_full_running },
#endif
};

int livepatch_bsc1249205_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

