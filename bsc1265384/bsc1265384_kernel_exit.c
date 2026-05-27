/*
 * bsc1265384_kernel_exit
 *
 * Fix for CVE-2026-46333, bsc#1265384
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


#include "livepatch_bsc1265384.h"


#define CC_USING_FENTRY 1
/* klp-ccp: from kernel/exit.c */
#include <linux/mm.h>

/* klp-ccp: from include/linux/mmzone.h */
#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

/* klp-ccp: from arch/x86/include/asm/percpu.h */
#ifdef __ASSEMBLY__
#error "klp-ccp: non-taken branch"
#else /* ...!ASSEMBLY */

/* klp-ccp: from include/linux/kernel.h */
void klpp_do_exit(long error_code) __noreturn;

/* klp-ccp: from arch/x86/include/asm/percpu.h */
#endif /* !__ASSEMBLY__ */

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from include/linux/mmzone.h */
#endif /* !__GENERATING_BOUNDS_H */

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* !__ASSEMBLY__ */

/* klp-ccp: from kernel/exit.c */
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>
#include <linux/sched/stat.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>
#include <linux/iocontext.h>
#include <linux/key.h>
#include <linux/cpu.h>
#include <linux/acct.h>
#include <linux/tsacct_kern.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/freezer.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/mempolicy.h>
#include <linux/taskstats_kern.h>
#include <linux/delayacct.h>
#include <linux/cgroup.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/pipe_fs_i.h>
#include <linux/audit.h> /* for audit_free() */
#include <linux/resource.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/blkdev.h>
#include <linux/task_work.h>
#include <linux/fs_struct.h>
#include <linux/init_task.h>
#include <linux/perf_event.h>
#include <trace/events/sched.h>
#include <linux/hw_breakpoint.h>
#include <linux/oom.h>
#include <linux/writeback.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/kmsan.h>
#include <linux/random.h>
#include <linux/rcuwait.h>
#include <linux/compat.h>
#include <linux/io_uring.h>
#include <linux/kprobes.h>
#include <linux/rethook.h>
#include <linux/sysfs.h>
#include <linux/user_events.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/mmu_context.h>

void release_task(struct task_struct *p);

extern void
kill_orphaned_pgrp(struct task_struct *tsk, struct task_struct *parent);

#include "../klp_trace.h"

KLPR_TRACE_EVENT(vmlinux,
             sched_process_exit,
             TP_PROTO(struct task_struct *p),
             TP_ARGS(p));

static void coredump_task_exit(struct task_struct *tsk)
{
	struct core_state *core_state;

	/*
	 * Serialize with any possible pending coredump.
	 * We must hold siglock around checking core_state
	 * and setting PF_POSTCOREDUMP.  The core-inducing thread
	 * will increment ->nr_threads for each thread in the
	 * group without PF_POSTCOREDUMP set.
	 */
	spin_lock_irq(&tsk->sighand->siglock);
	tsk->flags |= PF_POSTCOREDUMP;
	core_state = tsk->signal->core_state;
	spin_unlock_irq(&tsk->sighand->siglock);

	/* The vhost_worker does not particpate in coredumps */
	if (core_state &&
	    ((tsk->flags & (PF_IO_WORKER | PF_USER_WORKER)) != PF_USER_WORKER)) {
		struct core_thread self;

		self.task = current;
		if (self.task->flags & PF_SIGNALED)
			self.next = xchg(&core_state->dumper.next, &self);
		else
			self.task = NULL;
		/*
		 * Implies mb(), the result of xchg() must be visible
		 * to core_state->dumper.
		 */
		if (atomic_dec_and_test(&core_state->nr_threads))
			complete(&core_state->startup);

		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE|TASK_FREEZABLE);
			if (!self.task) /* see coredump_finish() */
				break;
			schedule();
		}
		__set_current_state(TASK_RUNNING);
	}
}

#ifdef CONFIG_MEMCG

void mm_update_next_owner(struct mm_struct *mm);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_MEMCG */

#if defined(CONFIG_X86)

extern typeof(enter_lazy_tlb) klpr_enter_lazy_tlb
         KLP_RELOC_SYMBOL(vmlinux, vmlinux, enter_lazy_tlb);

#else

static inline void klpr_enter_lazy_tlb(struct mm_struct *mm,
                        struct task_struct *tsk)
{
}

#endif

static void klpp_exit_mm(void)
{
	struct mm_struct *mm = current->mm;

	exit_mm_release(current, mm);
	if (!mm)
		return;
	sync_mm_rss(mm);
	mmap_read_lock(mm);
	mmgrab_lazy_tlb(mm);
	BUG_ON(mm != current->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(current);
	/*
	 * When a thread stops operating on an address space, the loop
	 * in membarrier_private_expedited() may not observe that
	 * tsk->mm, and the loop in membarrier_global_expedited() may
	 * not observe a MEMBARRIER_STATE_GLOBAL_EXPEDITED
	 * rq->membarrier_state, so those would not issue an IPI.
	 * Membarrier requires a memory barrier after accessing
	 * user-space memory, before clearing tsk->mm or the
	 * rq->membarrier_state.
	 */
	smp_mb__after_spinlock();
	local_irq_disable();
        KLP_SET_USER_DUMPABLE(current, get_dumpable(mm) == SUID_DUMP_USER);
	KLP_SET_USER_DUMPABLE(current, 1);
	current->mm = NULL;
	membarrier_update_current_mm(NULL);
	klpr_enter_lazy_tlb(mm, current);
	local_irq_enable();
	task_unlock(current);
	mmap_read_unlock(mm);
	mm_update_next_owner(mm);
	mmput(mm);
	if (test_thread_flag(TIF_MEMDIE))
		exit_oom_victim();
}

static struct task_struct *find_alive_thread(struct task_struct *p)
{
	struct task_struct *t;

	for_each_thread(p, t) {
		if (!(t->flags & PF_EXITING))
			return t;
	}
	return NULL;
}

static struct task_struct *find_child_reaper(struct task_struct *father,
						struct list_head *dead)
	__releases(&tasklist_lock)
	__acquires(&tasklist_lock)
{
	struct pid_namespace *pid_ns = task_active_pid_ns(father);
	struct task_struct *reaper = pid_ns->child_reaper;
	struct task_struct *p, *n;

	if (likely(reaper != father))
		return reaper;

	reaper = find_alive_thread(father);
	if (reaper) {
		pid_ns->child_reaper = reaper;
		return reaper;
	}

	write_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}

	zap_pid_ns_processes(pid_ns);
	write_lock_irq(&tasklist_lock);

	return father;
}

static struct task_struct *find_new_reaper(struct task_struct *father,
					   struct task_struct *child_reaper)
{
	struct task_struct *thread, *reaper;

	thread = find_alive_thread(father);
	if (thread)
		return thread;

	if (father->signal->has_child_subreaper) {
		unsigned int ns_level = task_pid(father)->level;
		/*
		 * Find the first ->is_child_subreaper ancestor in our pid_ns.
		 * We can't check reaper != child_reaper to ensure we do not
		 * cross the namespaces, the exiting parent could be injected
		 * by setns() + fork().
		 * We check pid->level, this is slightly more efficient than
		 * task_active_pid_ns(reaper) != task_active_pid_ns(father).
		 */
		for (reaper = father->real_parent;
		     task_pid(reaper)->level == ns_level;
		     reaper = reaper->real_parent) {
			if (reaper == &init_task)
				break;
			if (!reaper->signal->is_child_subreaper)
				continue;
			thread = find_alive_thread(reaper);
			if (thread)
				return thread;
		}
	}

	return child_reaper;
}

static void reparent_leader(struct task_struct *father, struct task_struct *p,
				struct list_head *dead)
{
	if (unlikely(p->exit_state == EXIT_DEAD))
		return;

	/* We don't want people slaying init. */
	p->exit_signal = SIGCHLD;

	/* If it has exited notify the new parent about this child's death. */
	if (!p->ptrace &&
	    p->exit_state == EXIT_ZOMBIE && thread_group_empty(p)) {
		if (do_notify_parent(p, p->exit_signal)) {
			p->exit_state = EXIT_DEAD;
			list_add(&p->ptrace_entry, dead);
		}
	}

	kill_orphaned_pgrp(p, father);
}

static void forget_original_parent(struct task_struct *father,
					struct list_head *dead)
{
	struct task_struct *p, *t, *reaper;

	if (unlikely(!list_empty(&father->ptraced)))
		exit_ptrace(father, dead);

	/* Can drop and reacquire tasklist_lock */
	reaper = find_child_reaper(father, dead);
	if (list_empty(&father->children))
		return;

	reaper = find_new_reaper(father, reaper);
	list_for_each_entry(p, &father->children, sibling) {
		for_each_thread(p, t) {
			RCU_INIT_POINTER(t->real_parent, reaper);
			BUG_ON((!t->ptrace) != (rcu_access_pointer(t->parent) == father));
			if (likely(!t->ptrace))
				t->parent = t->real_parent;
			if (t->pdeath_signal)
				group_send_sig_info(t->pdeath_signal,
						    SEND_SIG_NOINFO, t,
						    PIDTYPE_TGID);
		}
		/*
		 * If this is a threaded reparent there is no need to
		 * notify anyone anything has happened.
		 */
		if (!same_thread_group(reaper, father))
			reparent_leader(father, p, dead);
	}
	list_splice_tail_init(&father->children, &reaper->children);
}

static void exit_notify(struct task_struct *tsk, int group_dead)
{
	bool autoreap;
	struct task_struct *p, *n;
	LIST_HEAD(dead);

	write_lock_irq(&tasklist_lock);
	forget_original_parent(tsk, &dead);

	if (group_dead)
		kill_orphaned_pgrp(tsk->group_leader, NULL);

	tsk->exit_state = EXIT_ZOMBIE;
	if (unlikely(tsk->ptrace)) {
		int sig = thread_group_leader(tsk) &&
				thread_group_empty(tsk) &&
				!ptrace_reparented(tsk) ?
			tsk->exit_signal : SIGCHLD;
		autoreap = do_notify_parent(tsk, sig);
	} else if (thread_group_leader(tsk)) {
		autoreap = thread_group_empty(tsk) &&
			do_notify_parent(tsk, tsk->exit_signal);
	} else {
		autoreap = true;
	}

	if (autoreap) {
		tsk->exit_state = EXIT_DEAD;
		list_add(&tsk->ptrace_entry, &dead);
	}

	/* mt-exec, de_thread() is waiting for group leader */
	if (unlikely(tsk->signal->notify_count < 0))
		wake_up_process(tsk->signal->group_exec_task);
	write_unlock_irq(&tasklist_lock);

	list_for_each_entry_safe(p, n, &dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		release_task(p);
	}
}

#ifdef CONFIG_DEBUG_STACK_USAGE
#error "klp-ccp: non-taken branch"
#else
static inline void check_stack_usage(void) {}
#endif

static void synchronize_group_exit(struct task_struct *tsk, long code)
{
	struct sighand_struct *sighand = tsk->sighand;
	struct signal_struct *signal = tsk->signal;

	spin_lock_irq(&sighand->siglock);
	signal->quick_threads--;
	if ((signal->quick_threads == 0) &&
	    !(signal->flags & SIGNAL_GROUP_EXIT)) {
		signal->flags = SIGNAL_GROUP_EXIT;
		signal->group_exit_code = code;
		signal->group_stop_count = 0;
	}
	spin_unlock_irq(&sighand->siglock);
}

#if defined(CONFIG_X86)

extern typeof(flush_ptrace_hw_breakpoint) klpr_flush_ptrace_hw_breakpoint
         KLP_RELOC_SYMBOL(vmlinux, vmlinux, flush_ptrace_hw_breakpoint);
extern typeof(exit_thread) klpr_exit_thread
         KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_thread);

#elif defined(CONFIG_S390)

static inline void klpr_flush_ptrace_hw_breakpoint(struct task_struct *tsk)        { }
static inline void klpr_exit_thread(struct task_struct *tsk) { }

#elif defined(CONFIG_PPC)

extern typeof(unregister_hw_breakpoint) unregister_hw_breakpoint
         KLP_RELOC_SYMBOL(vmlinux, vmlinux, unregister_hw_breakpoint);

void klpr_flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
        int i;
        struct thread_struct *t = &tsk->thread;

        for (i = 0; i < nr_wp_slots(); i++) {
                unregister_hw_breakpoint(t->ptrace_bps[i]);
                t->ptrace_bps[i] = NULL;
        }
}

static inline void klpr_exit_thread(struct task_struct *tsk) { }

#endif

void __noreturn klpp_do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;

	WARN_ON(irqs_disabled());

	synchronize_group_exit(tsk, code);

	WARN_ON(tsk->plug);

	kcov_task_exit(tsk);
	kmsan_task_exit(tsk);

	coredump_task_exit(tsk);
	ptrace_event(PTRACE_EVENT_EXIT, code);
	user_events_exit(tsk);

	validate_creds_for_do_exit(tsk);

	io_uring_files_cancel();
	exit_signals(tsk);  /* sets PF_EXITING */

	/* sync mm's RSS info before statistics gathering */
	if (tsk->mm)
		sync_mm_rss(tsk->mm);
	acct_update_integrals(tsk);
	group_dead = atomic_dec_and_test(&tsk->signal->live);
	if (group_dead) {
		/*
		 * If the last thread of global init has exited, panic
		 * immediately to get a useable coredump.
		 */
		if (unlikely(is_global_init(tsk)))
			panic("Attempted to kill init! exitcode=0x%08x\n",
				tsk->signal->group_exit_code ?: (int)code);

#ifdef CONFIG_POSIX_TIMERS
		hrtimer_cancel(&tsk->signal->real_timer);
		exit_itimers(tsk);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (tsk->mm)
			setmax_mm_hiwater_rss(&tsk->signal->maxrss, tsk->mm);
	}
	acct_collect(code, group_dead);
	if (group_dead)
		tty_audit_exit();
	audit_free(tsk);

	tsk->exit_code = code;
	taskstats_exit(tsk, group_dead);

	klpp_exit_mm();

	if (group_dead)
		acct_process();
	klpr_trace_sched_process_exit(tsk);

	exit_sem(tsk);
	exit_shm(tsk);
	exit_files(tsk);
	exit_fs(tsk);
	if (group_dead)
		disassociate_ctty(1);
	exit_task_namespaces(tsk);
	exit_task_work(tsk);
	klpr_exit_thread(tsk);

	/*
	 * Flush inherited counters to the parent - before the parent
	 * gets woken up by child-exit notifications.
	 *
	 * because of cgroup mode, must be called before cgroup_exit()
	 */
	perf_event_exit_task(tsk);

	sched_autogroup_exit_task(tsk);
	cgroup_exit(tsk);

	/*
	 * FIXME: do that only when needed, using sched_exit tracepoint
	 */
	klpr_flush_ptrace_hw_breakpoint(tsk);

	exit_tasks_rcu_start();
	exit_notify(tsk, group_dead);
	proc_exit_connector(tsk);
	mpol_put_task_policy(tsk);
#ifdef CONFIG_FUTEX
	if (unlikely(current->pi_state_cache))
		kfree(current->pi_state_cache);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	debug_check_no_locks_held();

	if (tsk->io_context)
		exit_io_context(tsk);

	if (tsk->splice_pipe)
		free_pipe_info(tsk->splice_pipe);

	if (tsk->task_frag.page)
		put_page(tsk->task_frag.page);

	validate_creds_for_do_exit(tsk);
	exit_task_stack_account(tsk);

	check_stack_usage();
	preempt_disable();
	if (tsk->nr_dirtied)
		__this_cpu_add(dirty_throttle_leaks, tsk->nr_dirtied);
	exit_rcu();
	exit_tasks_rcu_finish();

	lockdep_free_task(tsk);
	do_task_dead();
}


#include <linux/livepatch.h>

extern typeof(__audit_free) __audit_free
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __audit_free);
extern typeof(__io_uring_cancel) __io_uring_cancel
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __io_uring_cancel);
extern typeof(acct_collect) acct_collect
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, acct_collect);
extern typeof(acct_process) acct_process
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, acct_process);
extern typeof(acct_update_integrals) acct_update_integrals
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, acct_update_integrals);
extern typeof(cgroup_exit) cgroup_exit
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgroup_exit);
extern typeof(ct_irq_enter_irqson) ct_irq_enter_irqson
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ct_irq_enter_irqson);
extern typeof(ct_irq_exit_irqson) ct_irq_exit_irqson
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ct_irq_exit_irqson);
extern typeof(dirty_throttle_leaks) dirty_throttle_leaks
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, dirty_throttle_leaks);
extern typeof(disassociate_ctty) disassociate_ctty
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, disassociate_ctty);
extern typeof(do_notify_parent) do_notify_parent
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_notify_parent);
extern typeof(do_task_dead) do_task_dead
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_task_dead);
extern typeof(exit_files) exit_files
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_files);
extern typeof(exit_fs) exit_fs KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_fs);
extern typeof(exit_io_context) exit_io_context
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_io_context);
extern typeof(exit_itimers) exit_itimers
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_itimers);
extern typeof(exit_mm_release) exit_mm_release
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_mm_release);
extern typeof(exit_oom_victim) exit_oom_victim
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_oom_victim);
extern typeof(exit_ptrace) exit_ptrace
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_ptrace);
extern typeof(exit_rcu) exit_rcu KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_rcu);
extern typeof(exit_sem) exit_sem KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_sem);
extern typeof(exit_shm) exit_shm KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_shm);
extern typeof(exit_signals) exit_signals
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_signals);
extern typeof(exit_task_namespaces) exit_task_namespaces
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_task_namespaces);
extern typeof(exit_task_stack_account) exit_task_stack_account
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_task_stack_account);
extern typeof(exit_tasks_rcu_finish) exit_tasks_rcu_finish
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_tasks_rcu_finish);
extern typeof(exit_tasks_rcu_start) exit_tasks_rcu_start
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_tasks_rcu_start);
extern typeof(free_pipe_info) free_pipe_info
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, free_pipe_info);
extern typeof(group_send_sig_info) group_send_sig_info
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, group_send_sig_info);
extern typeof(kill_orphaned_pgrp) kill_orphaned_pgrp
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, kill_orphaned_pgrp);
extern typeof(membarrier_update_current_mm) membarrier_update_current_mm
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, membarrier_update_current_mm);
extern typeof(mm_update_next_owner) mm_update_next_owner
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mm_update_next_owner);
extern typeof(mpol_put_task_policy) mpol_put_task_policy
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mpol_put_task_policy);
extern typeof(perf_event_exit_task) perf_event_exit_task
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, perf_event_exit_task);
extern typeof(proc_exit_connector) proc_exit_connector
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, proc_exit_connector);
extern typeof(ptrace_notify) ptrace_notify
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ptrace_notify);
extern typeof(release_task) release_task
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, release_task);
extern typeof(task_work_run) task_work_run
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, task_work_run);
extern typeof(tasklist_lock) tasklist_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tasklist_lock);
extern typeof(taskstats_exit) taskstats_exit
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, taskstats_exit);
extern typeof(tty_audit_exit) tty_audit_exit
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tty_audit_exit);
extern typeof(zap_pid_ns_processes) zap_pid_ns_processes
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, zap_pid_ns_processes);
