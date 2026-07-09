/*
 * livepatch_bsc1267723
 *
 * Fix for CVE-2026-46173, bsc#1267723
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


#include "livepatch_bsc1267723.h"


#define CC_USING_FENTRY 1
/* klp-ccp: from kernel/exit.c */
#include <linux/mm.h>

/* klp-ccp: from include/linux/sched/task.h */
void __noreturn klpp_make_task_dead(int signr);

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

extern unsigned int oops_limit;

extern atomic_t oops_count;

void __noreturn do_exit(long code);

void __noreturn klpp_make_task_dead(int signr)
{
	/*
	 * Take the task off the cpu after something catastrophic has
	 * happened.
	 *
	 * We can get here from a kernel oops, sometimes with preemption off.
	 * Start by checking for critical errors.
	 * Then fix up important state like USER_DS and preemption.
	 * Then do everything else.
	 */
	struct task_struct *tsk = current;
	unsigned int limit;

	if (unlikely(in_interrupt()))
		panic("Aiee, killing interrupt handler!");
	if (unlikely(!tsk->pid))
		panic("Attempted to kill the idle task!");

	if (unlikely(irqs_disabled())) {
		pr_info("note: %s[%d] exited with irqs disabled\n",
			current->comm, task_pid_nr(current));
		local_irq_enable();
	}
	if (unlikely(in_atomic())) {
		pr_info("note: %s[%d] exited with preempt_count %d\n",
			current->comm, task_pid_nr(current),
			preempt_count());
		preempt_count_set(PREEMPT_ENABLED);
	}

	/*
	 * Every time the system oopses, if the oops happens while a reference
	 * to an object was held, the reference leaks.
	 * If the oops doesn't also leak memory, repeated oopsing can cause
	 * reference counters to wrap around (if they're not using refcount_t).
	 * This means that repeated oopsing can make unexploitable-looking bugs
	 * exploitable through repeated oopsing.
	 * To make sure this can't happen, place an upper bound on how often the
	 * kernel may oops without panic().
	 */
	limit = READ_ONCE(oops_limit);
	if (atomic_inc_return(&oops_count) >= limit && limit)
		panic("Oopsed too often (kernel.oops_limit is %d)", limit);

	/*
	 * We're taking recursive faults here in make_task_dead. Safest is to just
	 * leave this task alone and wait for reboot.
	 */
	if (unlikely(tsk->flags & PF_EXITING)) {
		pr_alert("Fixing recursive fault but reboot is needed!\n");
		futex_exit_recursive(tsk);
		tsk->exit_state = EXIT_DEAD;
		refcount_inc(&tsk->rcu_users);
		preempt_disable();
		do_task_dead();
	}

	do_exit(signr);
}


#include <linux/livepatch.h>

extern typeof(do_exit) do_exit KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_exit);
extern typeof(do_task_dead) do_task_dead
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_task_dead);
extern typeof(futex_exit_recursive) futex_exit_recursive
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, futex_exit_recursive);
extern typeof(oops_count) oops_count
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, oops_count);
extern typeof(oops_limit) oops_limit
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, oops_limit);
