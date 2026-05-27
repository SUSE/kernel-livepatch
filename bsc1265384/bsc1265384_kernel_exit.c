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

/* klp-ccp: from kernel/exit.c */
#include <linux/mm.h>

/* klp-ccp: from include/linux/mmzone.h */
#ifndef __ASSEMBLY__
#ifndef __GENERATING_BOUNDS_H

/* klp-ccp: from include/linux/rcupdate.h */
#ifdef CONFIG_TASKS_RCU

static struct srcu_struct (*klpe_tasks_rcu_exit_srcu);

#else /* #ifdef CONFIG_TASKS_RCU */
#error "klp-ccp: non-taken branch"
#endif /* #else #ifdef CONFIG_TASKS_RCU */

#if defined(CONFIG_TREE_RCU) || defined(CONFIG_PREEMPT_RCU)

/* klp-ccp: from include/linux/rcutree.h */
static void (*klpe_exit_rcu)(void);

/* klp-ccp: from include/linux/rcupdate.h */
#elif defined(CONFIG_TINY_RCU)
#error "klp-ccp: non-taken branch"
#else
#error "klp-ccp: non-taken branch"
#endif

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from include/linux/mmzone.h */
#endif /* !__GENERATING_BOUNDS.H */

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* !__ASSEMBLY__ */

/* klp-ccp: from include/linux/mm.h */
#if defined(SPLIT_RSS_COUNTING)
static void (*klpe_sync_mm_rss)(struct mm_struct *mm);
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/exit.c */
#include <linux/slab.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/mm.h>

/* klp-ccp: from include/linux/sem.h */
#ifdef CONFIG_SYSVIPC

static void (*klpe_exit_sem)(struct task_struct *tsk);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/linux/shm.h */
#ifdef CONFIG_SYSVIPC

static void (*klpe_exit_shm)(struct task_struct *task);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/linux/sched/mm.h */
static void (*klpe_mm_release)(struct task_struct *, struct mm_struct *);

#ifdef CONFIG_MEMCG
static void (*klpe_mm_update_next_owner)(struct mm_struct *mm);
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MEMCG */

/* klp-ccp: from kernel/exit.c */
#include <linux/sched/stat.h>
#include <linux/sched/task.h>

/* klp-ccp: from include/linux/sched/task.h */
static rwlock_t (*klpe_tasklist_lock);

static void __noreturn (*klpe_do_task_dead)(void);

static void (*klpe_release_task)(struct task_struct * p);

static void (*klpe_exit_files)(struct task_struct *);
static void (*klpe_exit_itimers)(struct signal_struct *);

/* klp-ccp: from kernel/exit.c */
#include <linux/sched/task_stack.h>
#include <linux/sched/cputime.h>

/* klp-ccp: from include/linux/signal.h */
static int (*klpe_group_send_sig_info)(int sig, struct siginfo *info, struct task_struct *p);

static void (*klpe_exit_signals)(struct task_struct *tsk);

/* klp-ccp: from include/linux/sched/signal.h */
static __must_check bool (*klpe_do_notify_parent)(struct task_struct *, int);

/* klp-ccp: from kernel/exit.c */
#include <linux/interrupt.h>

/* klp-ccp: from arch/x86/include/asm/hw_irq.h */
#ifndef __ASSEMBLY__

/* klp-ccp: from include/linux/profile.h */
#ifdef CONFIG_PROFILING

static void (*klpe_profile_task_exit)(struct task_struct * task);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PROFILING */

#else
#error "klp-ccp: a preceeding branch should have been taken"
/* klp-ccp: from arch/x86/include/asm/hw_irq.h */
#endif /* !ASSEMBLY_ */

/* klp-ccp: from kernel/exit.c */
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/personality.h>
#include <linux/tty.h>

/* klp-ccp: from include/linux/tty.h */
#ifdef CONFIG_TTY

static void (*klpe_disassociate_ctty)(int priv);

#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_AUDIT

static void (*klpe_tty_audit_exit)(void);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/exit.c */
#include <linux/iocontext.h>

/* klp-ccp: from include/linux/iocontext.h */
#ifdef CONFIG_BLOCK

static void (*klpe_exit_io_context)(struct task_struct *task);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/exit.c */
#include <linux/key.h>
#include <linux/cpu.h>
#include <linux/acct.h>

/* klp-ccp: from include/linux/acct.h */
#ifdef CONFIG_BSD_PROCESS_ACCT

static void (*klpe_acct_collect)(long exitcode, int group_dead);
static void (*klpe_acct_process)(void);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/exit.c */
#include <linux/tsacct_kern.h>

/* klp-ccp: from include/linux/tsacct_kern.h */
#ifdef CONFIG_TASK_XACCT

static void (*klpe_acct_update_integrals)(struct task_struct *tsk);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TASK_XACCT */

/* klp-ccp: from kernel/exit.c */
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/freezer.h>
#include <linux/binfmts.h>
#include <linux/nsproxy.h>

/* klp-ccp: from include/linux/nsproxy.h */
static void (*klpe_exit_task_namespaces)(struct task_struct *tsk);

/* klp-ccp: from kernel/exit.c */
#include <linux/pid_namespace.h>

/* klp-ccp: from include/linux/pid_namespace.h */
#ifdef CONFIG_PID_NS

static void (*klpe_zap_pid_ns_processes)(struct pid_namespace *pid_ns);

#else /* !CONFIG_PID_NS */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PID_NS */

/* klp-ccp: from kernel/exit.c */
#include <linux/ptrace.h>

/* klp-ccp: from include/linux/ptrace.h */
static void (*klpe_ptrace_notify)(int exit_code);

static void (*klpe_exit_ptrace)(struct task_struct *tracer, struct list_head *dead);

static inline void klpr_ptrace_event(int event, unsigned long message)
{
	if (unlikely(ptrace_event_enabled(current, event))) {
		current->ptrace_message = message;
		(*klpe_ptrace_notify)((event << 8) | SIGTRAP);
	} else if (event == PTRACE_EVENT_EXEC) {
		/* legacy EXEC report via SIGTRAP */
		if ((current->ptrace & (PT_PTRACED|PT_SEIZED)) == PT_PTRACED)
			send_sig(SIGTRAP, current, 0);
	}
}

/* klp-ccp: from kernel/exit.c */
#include <linux/profile.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>

/* klp-ccp: from include/linux/cgroup.h */
#ifdef CONFIG_CGROUPS

static void (*klpe_cgroup_exit)(struct task_struct *p);

#else /* !CONFIG_CGROUPS */
#error "klp-ccp: non-taken branch"
#endif /* !CONFIG_CGROUPS */

/* klp-ccp: from kernel/exit.c */
#include <linux/mempolicy.h>

/* klp-ccp: from include/linux/writeback.h */
static int __percpu (*klpe_dirty_throttle_leaks);

/* klp-ccp: from include/linux/mempolicy.h */
#ifdef CONFIG_NUMA

static void (*klpe_mpol_put_task_policy)(struct task_struct *);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_NUMA */

/* klp-ccp: from kernel/exit.c */
#include <linux/taskstats_kern.h>

/* klp-ccp: from include/linux/taskstats_kern.h */
#ifdef CONFIG_TASKSTATS

static void (*klpe_taskstats_exit)(struct task_struct *, int group_dead);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TASKSTATS */

/* klp-ccp: from kernel/exit.c */
#include <linux/delayacct.h>
#include <linux/cgroup.h>
#include <linux/syscalls.h>

/* klp-ccp: from include/linux/perf_event.h */
#ifdef CONFIG_PERF_EVENTS

static void (*klpe_perf_event_exit_task)(struct task_struct *child);

#else /* !CONFIG_PERF_EVENTS: */
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/exit.c */
#include <linux/signal.h>
#include <linux/posix-timers.h>
#include <linux/cn_proc.h>

/* klp-ccp: from include/linux/cn_proc.h */
#ifdef CONFIG_PROC_EVENTS

static void (*klpe_proc_exit_connector)(struct task_struct *task);
#else
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_PROC_EVENTS */

/* klp-ccp: from kernel/exit.c */
#include <linux/mutex.h>
#include <linux/futex.h>
#include <linux/pipe_fs_i.h>

/* klp-ccp: from include/linux/pipe_fs_i.h */
static void (*klpe_free_pipe_info)(struct pipe_inode_info *);

/* klp-ccp: from kernel/exit.c */
#include <linux/audit.h> /* for audit_free() */

/* klp-ccp: from include/linux/audit.h */
#ifdef CONFIG_AUDITSYSCALL

static void (*klpe___audit_free)(struct task_struct *task);

static inline void klpr_audit_free(struct task_struct *task)
{
	if (unlikely(task->audit_context))
		(*klpe___audit_free)(task);
}

#else /* CONFIG_AUDITSYSCALL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_AUDITSYSCALL */

/* klp-ccp: from kernel/exit.c */
#include <linux/resource.h>
#include <linux/blkdev.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/tracehook.h>

/* klp-ccp: from include/linux/task_work.h */
static void (*klpe_task_work_run)(void);

static inline void klpr_exit_task_work(struct task_struct *task)
{
	(*klpe_task_work_run)();
}

/* klp-ccp: from kernel/exit.c */
#include <linux/fs_struct.h>

/* klp-ccp: from include/linux/fs_struct.h */
static void (*klpe_exit_fs)(struct task_struct *);

/* klp-ccp: from kernel/exit.c */
#include <linux/userfaultfd_k.h>
#include <linux/init_task.h>
#include <linux/perf_event.h>
#include <trace/events/sched.h>

#include "../klp_trace.h"
KLPR_TRACE_EVENT(sched_process_exit,
             TP_PROTO(struct task_struct *p),
             TP_ARGS(p));

/* klp-ccp: from kernel/exit.c */
#include <linux/hw_breakpoint.h>
#include <linux/oom.h>

/* klp-ccp: from include/linux/oom.h */
static void (*klpe_exit_oom_victim)(void);

/* klp-ccp: from kernel/exit.c */
#include <linux/writeback.h>
#include <linux/shm.h>
#include <linux/kcov.h>
#include <linux/random.h>
#include <linux/rcuwait.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
static void
(*klpe_kill_orphaned_pgrp)(struct task_struct *tsk, struct task_struct *parent);

#ifdef CONFIG_MEMCG
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_MEMCG */

#if defined(CONFIG_X86)
static void (*klpe_enter_lazy_tlb)(struct mm_struct *mm,
                                  struct task_struct *tsk);

#define klpr_enter_lazy_tlb        (*klpe_enter_lazy_tlb)

#elif defined(CONFIG_S390)

#define klpr_enter_lazy_tlb(mm,tsk)        do { } while (0)

#elif defined(CONFIG_PPC)

static inline void klpr_enter_lazy_tlb(struct mm_struct *mm,
                                  struct task_struct *tsk)
{
        /* 64-bit Book3E keeps track of current PGD in the PACA */
#ifdef CONFIG_PPC_BOOK3E_64
        get_paca()->pgd = NULL;
#endif
}

#endif

static void klpp_exit_mm(void)
{
	struct mm_struct *mm = current->mm;
	struct core_state *core_state;

	(*klpe_mm_release)(current, mm);
	if (!mm)
		return;
	(*klpe_sync_mm_rss)(mm);
	/*
	 * Serialize with any possible pending coredump.
	 * We must hold mmap_sem around checking core_state
	 * and clearing tsk->mm.  The core-inducing thread
	 * will increment ->nr_threads for each thread in the
	 * group with ->mm != NULL.
	 */
	down_read(&mm->mmap_sem);
	core_state = mm->core_state;
	if (core_state) {
		struct core_thread self;

		up_read(&mm->mmap_sem);

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
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!self.task) /* see coredump_finish() */
				break;
			freezable_schedule();
		}
		__set_current_state(TASK_RUNNING);
		down_read(&mm->mmap_sem);
	}
	mmgrab(mm);
	BUG_ON(mm != current->active_mm);
	/* more a memory barrier than a real lock */
	task_lock(current);
	KLP_SET_USER_DUMPABLE(current, get_dumpable(mm) == SUID_DUMP_USER);
	KLP_SET_USER_DUMPABLE_VALID(current, 1);
	current->mm = NULL;
	up_read(&mm->mmap_sem);
	klpr_enter_lazy_tlb(mm, current);
	task_unlock(current);
	(*klpe_mm_update_next_owner)(mm);
	mmput(mm);
	if (test_thread_flag(TIF_MEMDIE))
		(*klpe_exit_oom_victim)();
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

static struct task_struct *klpr_find_child_reaper(struct task_struct *father,
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

	write_unlock_irq(&(*klpe_tasklist_lock));

	list_for_each_entry_safe(p, n, dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		(*klpe_release_task)(p);
	}

	(*klpe_zap_pid_ns_processes)(pid_ns);
	write_lock_irq(&(*klpe_tasklist_lock));

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

static void klpr_reparent_leader(struct task_struct *father, struct task_struct *p,
				struct list_head *dead)
{
	if (unlikely(p->exit_state == EXIT_DEAD))
		return;

	/* We don't want people slaying init. */
	p->exit_signal = SIGCHLD;

	/* If it has exited notify the new parent about this child's death. */
	if (!p->ptrace &&
	    p->exit_state == EXIT_ZOMBIE && thread_group_empty(p)) {
		if ((*klpe_do_notify_parent)(p, p->exit_signal)) {
			p->exit_state = EXIT_DEAD;
			list_add(&p->ptrace_entry, dead);
		}
	}

	(*klpe_kill_orphaned_pgrp)(p, father);
}

static void klpr_forget_original_parent(struct task_struct *father,
					struct list_head *dead)
{
	struct task_struct *p, *t, *reaper;

	if (unlikely(!list_empty(&father->ptraced)))
		(*klpe_exit_ptrace)(father, dead);

	/* Can drop and reacquire tasklist_lock */
	reaper = klpr_find_child_reaper(father, dead);
	if (list_empty(&father->children))
		return;

	reaper = find_new_reaper(father, reaper);
	list_for_each_entry(p, &father->children, sibling) {
		for_each_thread(p, t) {
			t->real_parent = reaper;
			BUG_ON((!t->ptrace) != (t->parent == father));
			if (likely(!t->ptrace))
				t->parent = t->real_parent;
			if (t->pdeath_signal)
				(*klpe_group_send_sig_info)(t->pdeath_signal,
						    SEND_SIG_NOINFO, t);
		}
		/*
		 * If this is a threaded reparent there is no need to
		 * notify anyone anything has happened.
		 */
		if (!same_thread_group(reaper, father))
			klpr_reparent_leader(father, p, dead);
	}
	list_splice_tail_init(&father->children, &reaper->children);
}

static void klpr_exit_notify(struct task_struct *tsk, int group_dead)
{
	bool autoreap;
	struct task_struct *p, *n;
	LIST_HEAD(dead);

	write_lock_irq(&(*klpe_tasklist_lock));
	klpr_forget_original_parent(tsk, &dead);

	if (group_dead)
		(*klpe_kill_orphaned_pgrp)(tsk->group_leader, NULL);

	if (unlikely(tsk->ptrace)) {
		int sig = thread_group_leader(tsk) &&
				thread_group_empty(tsk) &&
				!ptrace_reparented(tsk) ?
			tsk->exit_signal : SIGCHLD;
		autoreap = (*klpe_do_notify_parent)(tsk, sig);
	} else if (thread_group_leader(tsk)) {
		autoreap = thread_group_empty(tsk) &&
			(*klpe_do_notify_parent)(tsk, tsk->exit_signal);
	} else {
		autoreap = true;
	}

	tsk->exit_state = autoreap ? EXIT_DEAD : EXIT_ZOMBIE;
	if (tsk->exit_state == EXIT_DEAD)
		list_add(&tsk->ptrace_entry, &dead);

	/* mt-exec, de_thread() is waiting for group leader */
	if (unlikely(tsk->signal->notify_count < 0))
		wake_up_process(tsk->signal->group_exit_task);
	write_unlock_irq(&(*klpe_tasklist_lock));

	list_for_each_entry_safe(p, n, &dead, ptrace_entry) {
		list_del_init(&p->ptrace_entry);
		(*klpe_release_task)(p);
	}
}

#ifdef CONFIG_DEBUG_STACK_USAGE
#error "klp-ccp: non-taken branch"
#else
static inline void check_stack_usage(void) {}
#endif

#if defined(CONFIG_X86)
static void (*klpe_exit_thread)(struct task_struct *tsk);
#define klpr_exit_thread (*klpe_exit_thread)

static void (*klpe_flush_ptrace_hw_breakpoint)(struct task_struct *tsk);
#define klpr_flush_ptrace_hw_breakpoint (*klpe_flush_ptrace_hw_breakpoint)

#elif defined(CONFIG_S390)

static inline void klpr_flush_ptrace_hw_breakpoint(struct task_struct *tsk)        { }
static inline void klpr_exit_thread(struct task_struct *tsk) { }

#elif defined(CONFIG_PPC)

static void (*klpe_unregister_hw_breakpoint)(struct perf_event *bp);
void klpr_flush_ptrace_hw_breakpoint(struct task_struct *tsk)
{
        struct thread_struct *t = &tsk->thread;

        (*klpe_unregister_hw_breakpoint)(t->ptrace_bps[0]);
        t->ptrace_bps[0] = NULL;
}

static inline void klpr_exit_thread(struct task_struct *tsk) { }

#endif

void __noreturn klpp_do_exit(long code)
{
	struct task_struct *tsk = current;
	int group_dead;
	TASKS_RCU(int tasks_rcu_i);

	(*klpe_profile_task_exit)(tsk);
	kcov_task_exit(tsk);

	WARN_ON(blk_needs_flush_plug(tsk));

	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	/*
	 * If do_exit is called because this processes oopsed, it's possible
	 * that get_fs() was left as KERNEL_DS, so reset it to USER_DS before
	 * continuing. Amongst other possible reasons, this is to prevent
	 * mm_release()->clear_child_tid() from writing to a user-controlled
	 * kernel address.
	 */
	set_fs(USER_DS);

	klpr_ptrace_event(PTRACE_EVENT_EXIT, code);

	validate_creds_for_do_exit(tsk);

	/*
	 * We're taking recursive faults here in do_exit. Safest is to just
	 * leave this task alone and wait for reboot.
	 */
	if (unlikely(tsk->flags & PF_EXITING)) {
		pr_alert("Fixing recursive fault but reboot is needed!\n");
		/*
		 * We can do this unlocked here. The futex code uses
		 * this flag just to verify whether the pi state
		 * cleanup has been done or not. In the worst case it
		 * loops once more. We pretend that the cleanup was
		 * done as there is no way to return. Either the
		 * OWNER_DIED bit is set by now or we push the blocked
		 * task into the wait for ever nirwana as well.
		 */
		tsk->flags |= PF_EXITPIDONE;
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule();
	}

	(*klpe_exit_signals)(tsk);  /* sets PF_EXITING */
	/*
	 * Ensure that all new tsk->pi_lock acquisitions must observe
	 * PF_EXITING. Serializes against futex.c:attach_to_pi_owner().
	 */
	smp_mb();
	/*
	 * Ensure that we must observe the pi_state in exit_mm() ->
	 * mm_release() -> exit_pi_state_list().
	 */
	raw_spin_unlock_wait(&tsk->pi_lock);

	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, task_pid_nr(current),
			preempt_count());
		preempt_count_set(PREEMPT_ENABLED);
	}

	/* sync mm's RSS info before statistics gathering */
	if (tsk->mm)
		(*klpe_sync_mm_rss)(tsk->mm);
	(*klpe_acct_update_integrals)(tsk);
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
		(*klpe_exit_itimers)(tsk->signal);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
		if (tsk->mm)
			setmax_mm_hiwater_rss(&tsk->signal->maxrss, tsk->mm);
	}
	(*klpe_acct_collect)(code, group_dead);
	if (group_dead)
		(*klpe_tty_audit_exit)();
	klpr_audit_free(tsk);

	tsk->exit_code = code;
	(*klpe_taskstats_exit)(tsk, group_dead);

	/*
	 * Since sampling can touch ->mm, make sure to stop everything before we
	 * tear it down.
	 *
	 * Also flushes inherited counters to the parent - before the parent
	 * gets woken up by child-exit notifications.
	 */
	(*klpe_perf_event_exit_task)(tsk);

	klpp_exit_mm();

	if (group_dead)
		(*klpe_acct_process)();
	klpr_trace_sched_process_exit(tsk);

	(*klpe_exit_sem)(tsk);
	(*klpe_exit_shm)(tsk);
	(*klpe_exit_files)(tsk);
	(*klpe_exit_fs)(tsk);
	if (group_dead)
		(*klpe_disassociate_ctty)(1);
	(*klpe_exit_task_namespaces)(tsk);
	klpr_exit_task_work(tsk);
	klpr_exit_thread(tsk);

	sched_autogroup_exit_task(tsk);
	(*klpe_cgroup_exit)(tsk);

	/*
	 * FIXME: do that only when needed, using sched_exit tracepoint
	 */
	klpr_flush_ptrace_hw_breakpoint(tsk);

	TASKS_RCU(preempt_disable());
	TASKS_RCU(tasks_rcu_i = __srcu_read_lock(&(*klpe_tasks_rcu_exit_srcu)));
	TASKS_RCU(preempt_enable());
	klpr_exit_notify(tsk, group_dead);
	(*klpe_proc_exit_connector)(tsk);
	(*klpe_mpol_put_task_policy)(tsk);
#ifdef CONFIG_FUTEX
	if (unlikely(current->pi_state_cache))
		kfree(current->pi_state_cache);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	debug_check_no_locks_held();
	/*
	 * We can do this unlocked here. The futex code uses this flag
	 * just to verify whether the pi state cleanup has been done
	 * or not. In the worst case it loops once more.
	 */
	tsk->flags |= PF_EXITPIDONE;

	if (tsk->io_context)
		(*klpe_exit_io_context)(tsk);

	if (tsk->splice_pipe)
		(*klpe_free_pipe_info)(tsk->splice_pipe);

	if (tsk->task_frag.page)
		put_page(tsk->task_frag.page);

	validate_creds_for_do_exit(tsk);

	check_stack_usage();
	preempt_disable();
	if (tsk->nr_dirtied)
		__this_cpu_add((*klpe_dirty_throttle_leaks), tsk->nr_dirtied);
	(*klpe_exit_rcu)();
	TASKS_RCU(__srcu_read_unlock(&(*klpe_tasks_rcu_exit_srcu), tasks_rcu_i));

	(*klpe_do_task_dead)();
}

typeof(klpp_do_exit) klpp_do_exit;


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
#if defined(CONFIG_X86)
        { "enter_lazy_tlb", (void *)&klpe_enter_lazy_tlb },
        { "flush_ptrace_hw_breakpoint", (void *)&klpe_flush_ptrace_hw_breakpoint },
        { "exit_thread", (void *)&klpe_exit_thread },
#elif defined(CONFIG_PPC)
        { "unregister_hw_breakpoint", (void *)&klpe_unregister_hw_breakpoint },
#endif
	{ "__audit_free", (void *)&klpe___audit_free },
	{ "__tracepoint_sched_process_exit",
	  (void *)&klpe___tracepoint_sched_process_exit },
	{ "acct_collect", (void *)&klpe_acct_collect },
	{ "acct_process", (void *)&klpe_acct_process },
	{ "acct_update_integrals", (void *)&klpe_acct_update_integrals },
	{ "cgroup_exit", (void *)&klpe_cgroup_exit },
	{ "dirty_throttle_leaks", (void *)&klpe_dirty_throttle_leaks },
	{ "disassociate_ctty", (void *)&klpe_disassociate_ctty },
	{ "do_notify_parent", (void *)&klpe_do_notify_parent },
	{ "do_task_dead", (void *)&klpe_do_task_dead },
	{ "exit_files", (void *)&klpe_exit_files },
	{ "exit_fs", (void *)&klpe_exit_fs },
	{ "exit_io_context", (void *)&klpe_exit_io_context },
	{ "exit_itimers", (void *)&klpe_exit_itimers },
	{ "exit_oom_victim", (void *)&klpe_exit_oom_victim },
	{ "exit_ptrace", (void *)&klpe_exit_ptrace },
	{ "exit_rcu", (void *)&klpe_exit_rcu },
	{ "exit_sem", (void *)&klpe_exit_sem },
	{ "exit_shm", (void *)&klpe_exit_shm },
	{ "exit_signals", (void *)&klpe_exit_signals },
	{ "exit_task_namespaces", (void *)&klpe_exit_task_namespaces },
	{ "free_pipe_info", (void *)&klpe_free_pipe_info },
	{ "group_send_sig_info", (void *)&klpe_group_send_sig_info },
	{ "kill_orphaned_pgrp", (void *)&klpe_kill_orphaned_pgrp },
	{ "mm_release", (void *)&klpe_mm_release },
	{ "mm_update_next_owner", (void *)&klpe_mm_update_next_owner },
	{ "mpol_put_task_policy", (void *)&klpe_mpol_put_task_policy },
	{ "perf_event_exit_task", (void *)&klpe_perf_event_exit_task },
	{ "proc_exit_connector", (void *)&klpe_proc_exit_connector },
	{ "profile_task_exit", (void *)&klpe_profile_task_exit },
	{ "ptrace_notify", (void *)&klpe_ptrace_notify },
	{ "release_task", (void *)&klpe_release_task },
	{ "sync_mm_rss", (void *)&klpe_sync_mm_rss },
	{ "task_work_run", (void *)&klpe_task_work_run },
	{ "tasklist_lock", (void *)&klpe_tasklist_lock },
	{ "tasks_rcu_exit_srcu", (void *)&klpe_tasks_rcu_exit_srcu },
	{ "taskstats_exit", (void *)&klpe_taskstats_exit },
	{ "tty_audit_exit", (void *)&klpe_tty_audit_exit },
	{ "zap_pid_ns_processes", (void *)&klpe_zap_pid_ns_processes },
};

int bsc1265384_kernel_exit_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

