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



/* klp-ccp: from kernel/time/posix-cpu-timers.c */
#include <linux/sched/signal.h>

/* klp-ccp: from include/linux/posix-timers.h */
void klpp_run_posix_cpu_timers(void);

/* klp-ccp: from kernel/time/posix-cpu-timers.c */
#include <linux/sched/cputime.h>
#include <linux/posix-timers.h>
#include <linux/errno.h>
#include <linux/math64.h>
#include <linux/uaccess.h>
#include <linux/kernel_stat.h>
#include <trace/events/timer.h>
#include <linux/tick.h>
#include <linux/workqueue.h>
#include <linux/compat.h>
#include <linux/sched/deadline.h>
#include <linux/task_work.h>

static inline bool expiry_cache_is_inactive(const struct posix_cputimers *pct)
{
	return !(~pct->bases[CPUCLOCK_PROF].nextevt |
		 ~pct->bases[CPUCLOCK_VIRT].nextevt |
		 ~pct->bases[CPUCLOCK_SCHED].nextevt);
}

static inline void store_samples(u64 *samples, u64 stime, u64 utime, u64 rtime)
{
	samples[CPUCLOCK_PROF] = stime + utime;
	samples[CPUCLOCK_VIRT] = utime;
	samples[CPUCLOCK_SCHED] = rtime;
}

static void task_sample_cputime(struct task_struct *p, u64 *samples)
{
	u64 stime, utime;

	task_cputime(p, &utime, &stime);
	store_samples(samples, stime, utime, p->se.sum_exec_runtime);
}

static void proc_sample_cputime_atomic(struct task_cputime_atomic *at,
				       u64 *samples)
{
	u64 stime, utime, rtime;

	utime = atomic64_read(&at->utime);
	stime = atomic64_read(&at->stime);
	rtime = atomic64_read(&at->sum_exec_runtime);
	store_samples(samples, stime, utime, rtime);
}

static inline bool
task_cputimers_expired(const u64 *samples, struct posix_cputimers *pct)
{
	int i;

	for (i = 0; i < CPUCLOCK_MAX; i++) {
		if (samples[i] >= pct->bases[i].nextevt)
			return true;
	}
	return false;
}

static inline bool fastpath_timer_check(struct task_struct *tsk)
{
	struct posix_cputimers *pct = &tsk->posix_cputimers;
	struct signal_struct *sig;

	if (!expiry_cache_is_inactive(pct)) {
		u64 samples[CPUCLOCK_MAX];

		task_sample_cputime(tsk, samples);
		if (task_cputimers_expired(samples, pct))
			return true;
	}

	sig = tsk->signal;
	pct = &sig->posix_cputimers;
	/*
	 * Check if thread group timers expired when timers are active and
	 * no other thread in the group is already handling expiry for
	 * thread group cputimers. These fields are read without the
	 * sighand lock. However, this is fine because this is meant to be
	 * a fastpath heuristic to determine whether we should try to
	 * acquire the sighand lock to handle timer expiry.
	 *
	 * In the worst case scenario, if concurrently timers_active is set
	 * or expiry_active is cleared, but the current thread doesn't see
	 * the change yet, the timer checks are delayed until the next
	 * thread in the group gets a scheduler interrupt to handle the
	 * timer. This isn't an issue in practice because these types of
	 * delays with signals actually getting sent are expected.
	 */
	if (READ_ONCE(pct->timers_active) && !READ_ONCE(pct->expiry_active)) {
		u64 samples[CPUCLOCK_MAX];

		proc_sample_cputime_atomic(&sig->cputimer.cputime_atomic,
					   samples);

		if (task_cputimers_expired(samples, pct))
			return true;
	}

	if (dl_task(tsk) && tsk->dl.dl_overrun)
		return true;

	return false;
}

#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK

static inline bool posix_cpu_timers_work_scheduled(struct task_struct *tsk)
{
	return tsk->posix_cputimers_work.scheduled;
}

static inline void __run_posix_cpu_timers(struct task_struct *tsk)
{
	if (WARN_ON_ONCE(tsk->posix_cputimers_work.scheduled))
		return;

	/* Schedule task work to actually expire the timers */
	tsk->posix_cputimers_work.scheduled = true;
	task_work_add(tsk, &tsk->posix_cputimers_work.work, TWA_RESUME);
}

#else /* CONFIG_POSIX_CPU_TIMERS_TASK_WORK */

static inline bool posix_cpu_timers_work_scheduled(struct task_struct *tsk)
{
	return false;
}

void collect_posix_cputimers(struct posix_cputimers *pct, u64 *samples,
				    struct list_head *firing);

static bool check_rlimit(u64 time, u64 limit, int signo, bool rt, bool hard)
{
	if (time < limit)
		return false;

	if (print_fatal_signals) {
		pr_info("%s Watchdog Timeout (%s): %s[%d]\n",
			rt ? "RT" : "CPU", hard ? "hard" : "soft",
			current->comm, task_pid_nr(current));
	}
	send_signal_locked(signo, SEND_SIG_PRIV, current, PIDTYPE_TGID);
	return true;
}

static inline void check_dl_overrun(struct task_struct *tsk)
{
	if (tsk->dl.dl_overrun) {
		tsk->dl.dl_overrun = 0;
		send_signal_locked(SIGXCPU, SEND_SIG_PRIV, tsk, PIDTYPE_TGID);
	}
}


#ifdef CONFIG_NO_HZ_FULL

void tick_nohz_dep_clear_task(struct task_struct *tsk,
				     enum tick_dep_bits bit);

static inline void klpr_tick_dep_clear_task(struct task_struct *tsk,
				       enum tick_dep_bits bit)
{
	if (tick_nohz_full_enabled())
		tick_nohz_dep_clear_task(tsk, bit);
}
#else
static inline void klpr_tick_dep_clear_task(struct task_struct *tsk,
				       enum tick_dep_bits bit) { }
#endif

static void check_thread_timers(struct task_struct *tsk,
				struct list_head *firing)
{
	struct posix_cputimers *pct = &tsk->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];
	unsigned long soft;

	if (dl_task(tsk))
		check_dl_overrun(tsk);

	if (expiry_cache_is_inactive(pct))
		return;

	task_sample_cputime(tsk, samples);
	collect_posix_cputimers(pct, samples, firing);

	/*
	 * Check for the special case thread timers.
	 */
	soft = task_rlimit(tsk, RLIMIT_RTTIME);
	if (soft != RLIM_INFINITY) {
		/* Task RT timeout is accounted in jiffies. RTTIME is usec */
		unsigned long rttime = tsk->rt.timeout * (USEC_PER_SEC / HZ);
		unsigned long hard = task_rlimit_max(tsk, RLIMIT_RTTIME);

		/* At the hard limit, send SIGKILL. No further action. */
		if (hard != RLIM_INFINITY &&
		    check_rlimit(rttime, hard, SIGKILL, true, true))
			return;

		/* At the soft limit, send a SIGXCPU every second */
		if (check_rlimit(rttime, soft, SIGXCPU, true, false)) {
			soft += USEC_PER_SEC;
			tsk->signal->rlim[RLIMIT_RTTIME].rlim_cur = soft;
		}
	}

	if (expiry_cache_is_inactive(pct))
		klpr_tick_dep_clear_task(tsk, TICK_DEP_BIT_POSIX_TIMER);
}


static inline void stop_process_timers(struct signal_struct *sig)
{
	struct posix_cputimers *pct = &sig->posix_cputimers;

	/* Turn off the active flag. This is done without locking. */
	WRITE_ONCE(pct->timers_active, false);
	tick_dep_clear_signal(sig, TICK_DEP_BIT_POSIX_TIMER);
}


void check_cpu_itimer(struct task_struct *tsk, struct cpu_itimer *it,
			     u64 *expires, u64 cur_time, int signo);

static void check_process_timers(struct task_struct *tsk,
				 struct list_head *firing)
{
	struct signal_struct *const sig = tsk->signal;
	struct posix_cputimers *pct = &sig->posix_cputimers;
	u64 samples[CPUCLOCK_MAX];
	unsigned long soft;

	/*
	 * If there are no active process wide timers (POSIX 1.b, itimers,
	 * RLIMIT_CPU) nothing to check. Also skip the process wide timer
	 * processing when there is already another task handling them.
	 */
	if (!READ_ONCE(pct->timers_active) || pct->expiry_active)
		return;

	/*
	 * Signify that a thread is checking for process timers.
	 * Write access to this field is protected by the sighand lock.
	 */
	pct->expiry_active = true;

	/*
	 * Collect the current process totals. Group accounting is active
	 * so the sample can be taken directly.
	 */
	proc_sample_cputime_atomic(&sig->cputimer.cputime_atomic, samples);
	collect_posix_cputimers(pct, samples, firing);

	/*
	 * Check for the special case process timers.
	 */
	check_cpu_itimer(tsk, &sig->it[CPUCLOCK_PROF],
			 &pct->bases[CPUCLOCK_PROF].nextevt,
			 samples[CPUCLOCK_PROF], SIGPROF);
	check_cpu_itimer(tsk, &sig->it[CPUCLOCK_VIRT],
			 &pct->bases[CPUCLOCK_VIRT].nextevt,
			 samples[CPUCLOCK_VIRT], SIGVTALRM);

	soft = task_rlimit(tsk, RLIMIT_CPU);
	if (soft != RLIM_INFINITY) {
		/* RLIMIT_CPU is in seconds. Samples are nanoseconds */
		unsigned long hard = task_rlimit_max(tsk, RLIMIT_CPU);
		u64 ptime = samples[CPUCLOCK_PROF];
		u64 softns = (u64)soft * NSEC_PER_SEC;
		u64 hardns = (u64)hard * NSEC_PER_SEC;

		/* At the hard limit, send SIGKILL. No further action. */
		if (hard != RLIM_INFINITY &&
		    check_rlimit(ptime, hardns, SIGKILL, false, true))
			return;

		/* At the soft limit, send a SIGXCPU every second */
		if (check_rlimit(ptime, softns, SIGXCPU, false, false)) {
			sig->rlim[RLIMIT_CPU].rlim_cur = soft + 1;
			softns += NSEC_PER_SEC;
		}

		/* Update the expiry cache */
		if (softns < pct->bases[CPUCLOCK_PROF].nextevt)
			pct->bases[CPUCLOCK_PROF].nextevt = softns;
	}

	if (expiry_cache_is_inactive(pct))
		stop_process_timers(sig);

	pct->expiry_active = false;
}

static inline bool posix_cpu_timers_enable_work(struct task_struct *tsk,
						unsigned long start)
{
	return true;
}

void cpu_timer_fire(struct k_itimer *timer);

static void handle_posix_cpu_timers(struct task_struct *tsk)
{
	struct k_itimer *timer, *next;
	unsigned long flags, start;
	LIST_HEAD(firing);

	if (!lock_task_sighand(tsk, &flags))
		return;

	do {
		/*
		 * On RT locking sighand lock does not disable interrupts,
		 * so this needs to be careful vs. ticks. Store the current
		 * jiffies value.
		 */
		start = READ_ONCE(jiffies);
		barrier();

		/*
		 * Here we take off tsk->signal->cpu_timers[N] and
		 * tsk->cpu_timers[N] all the timers that are firing, and
		 * put them on the firing list.
		 */
		check_thread_timers(tsk, &firing);

		check_process_timers(tsk, &firing);

		/*
		 * The above timer checks have updated the expiry cache and
		 * because nothing can have queued or modified timers after
		 * sighand lock was taken above it is guaranteed to be
		 * consistent. So the next timer interrupt fastpath check
		 * will find valid data.
		 *
		 * If timer expiry runs in the timer interrupt context then
		 * the loop is not relevant as timers will be directly
		 * expired in interrupt context. The stub function below
		 * returns always true which allows the compiler to
		 * optimize the loop out.
		 *
		 * If timer expiry is deferred to task work context then
		 * the following rules apply:
		 *
		 * - On !RT kernels no tick can have happened on this CPU
		 *   after sighand lock was acquired because interrupts are
		 *   disabled. So reenabling task work before dropping
		 *   sighand lock and reenabling interrupts is race free.
		 *
		 * - On RT kernels ticks might have happened but the tick
		 *   work ignored posix CPU timer handling because the
		 *   CPUTIMERS_WORK_SCHEDULED bit is set. Reenabling work
		 *   must be done very carefully including a check whether
		 *   ticks have happened since the start of the timer
		 *   expiry checks. posix_cpu_timers_enable_work() takes
		 *   care of that and eventually lets the expiry checks
		 *   run again.
		 */
	} while (!posix_cpu_timers_enable_work(tsk, start));

	/*
	 * We must release sighand lock before taking any timer's lock.
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
	list_for_each_entry_safe(timer, next, &firing, it.cpu.elist) {
		int cpu_firing;

		/*
		 * spin_lock() is sufficient here even independent of the
		 * expiry context. If expiry happens in hard interrupt
		 * context it's obvious. For task work context it's safe
		 * because all other operations on timer::it_lock happen in
		 * task context (syscall or exit).
		 */
		spin_lock(&timer->it_lock);
		list_del_init(&timer->it.cpu.elist);
		cpu_firing = timer->it.cpu.firing;
		timer->it.cpu.firing = 0;
		/*
		 * The firing flag is -1 if we collided with a reset
		 * of the timer, which already reported this
		 * almost-firing as an overrun.  So don't generate an event.
		 */
		if (likely(cpu_firing >= 0))
			cpu_timer_fire(timer);
		/* See posix_cpu_timer_wait_running() */
		rcu_assign_pointer(timer->it.cpu.handling, NULL);
		spin_unlock(&timer->it_lock);
	}
}


static inline void __run_posix_cpu_timers(struct task_struct *tsk)
{
	lockdep_posixtimer_enter();
	handle_posix_cpu_timers(tsk);
	lockdep_posixtimer_exit();
}

#endif /* CONFIG_POSIX_CPU_TIMERS_TASK_WORK */

void klpp_run_posix_cpu_timers(void)
{
	struct task_struct *tsk = current;

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
	 * If the actual expiry is deferred to task work context and the
	 * work is already scheduled there is no point to do anything here.
	 */
	if (posix_cpu_timers_work_scheduled(tsk))
		return;

	/*
	 * The fast path checks that there are no expired thread or thread
	 * group timers.  If that's so, just return.
	 */
	if (!fastpath_timer_check(tsk))
		return;

	__run_posix_cpu_timers(tsk);
}


#include "livepatch_bsc1249205.h"

#include <linux/livepatch.h>

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
extern typeof(task_cputime) task_cputime
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, task_cputime);
#endif
#ifdef CONFIG_POSIX_CPU_TIMERS_TASK_WORK
extern typeof(task_work_add) task_work_add
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, task_work_add);
#else
extern typeof(check_cpu_itimer) check_cpu_itimer
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, check_cpu_itimer);
extern typeof(collect_posix_cputimers) collect_posix_cputimers
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, collect_posix_cputimers);
extern typeof(cpu_timer_fire) cpu_timer_fire
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, cpu_timer_fire);
extern typeof(send_signal_locked) send_signal_locked
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, send_signal_locked);
extern typeof(print_fatal_signals) print_fatal_signals
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, print_fatal_signals);
extern typeof(__lock_task_sighand) __lock_task_sighand
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, __lock_task_sighand);
#ifdef CONFIG_NO_HZ_FULL
extern typeof(tick_nohz_dep_clear_task) tick_nohz_dep_clear_task
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, tick_nohz_dep_clear_task);
extern typeof(tick_nohz_dep_clear_signal) tick_nohz_dep_clear_signal
	KLP_RELOC_SYMBOL(vmlinux, vmlinux, tick_nohz_dep_clear_signal);
#endif
#endif
