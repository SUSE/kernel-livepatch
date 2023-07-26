/*
 * bsc1210987_fs_exec
 *
 * Fix for CVE-2023-2235, bsc#1210987
 *
 *  Copyright (c) 2023 SUSE
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

/* klp-ccp: from fs/exec.c */
#include <linux/kernel_read_file.h>
/* klp-ccp: from fs/exec.c */
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>

/* klp-ccp: from include/linux/pid.h */
static void (*klpe_exchange_tids)(struct task_struct *task, struct task_struct *old);
static void (*klpe_transfer_pid)(struct task_struct *old, struct task_struct *new,
			 enum pid_type);

/* klp-ccp: from include/linux/signal.h */
static struct kmem_cache *(*klpe_sighand_cachep);

/* klp-ccp: from include/linux/posix-timers.h */
static void (*klpe_posix_cpu_timers_exit)(struct task_struct *task);

/* klp-ccp: from include/linux/sched.h */
static void (*klpe___set_task_comm)(struct task_struct *tsk, const char *from, bool exec);

/* klp-ccp: from include/linux/sched/task.h */
static rwlock_t (*klpe_tasklist_lock);

static void (*klpe_release_task)(struct task_struct * p);

static void (*klpe_flush_thread)(void);

static void (*klpe_exit_itimers)(struct task_struct *);

/* klp-ccp: from include/linux/cred.h */
static int (*klpe_set_cred_ucounts)(struct cred *);

/* klp-ccp: from include/linux/sched/signal.h */
static void (*klpe_flush_signal_handlers)(struct task_struct *, int force_default);

static void (*klpe___wake_up_parent)(struct task_struct *p, struct task_struct *parent);

static int (*klpe_zap_other_threads)(struct task_struct *p);

static void (*klpe___cleanup_sighand)(struct sighand_struct *);
static void (*klpe_flush_itimer_signals)(void);

/* klp-ccp: from include/linux/mount.h */
static bool (*klpe_mnt_may_suid)(struct vfsmount *mnt);

/* klp-ccp: from include/linux/fdtable.h */
static int (*klpe_unshare_files)(void);

static void (*klpe_do_close_on_exec)(struct files_struct *);

/* klp-ccp: from fs/exec.c */
#include <linux/mm.h>

/* klp-ccp: from include/linux/sched/coredump.h */
static void (*klpe_set_dumpable)(struct mm_struct *mm, int value);

/* klp-ccp: from include/linux/mm.h */
static void (*klpe_mm_trace_rss_stat)(struct mm_struct *mm, int member, long count);

static inline void klpr_add_mm_counter(struct mm_struct *mm, int member, long value)
{
	long count = atomic_long_add_return(value, &mm->rss_stat.count[member]);

	(*klpe_mm_trace_rss_stat)(mm, member, count);
}

#if defined(SPLIT_RSS_COUNTING)
static void (*klpe_sync_mm_rss)(struct mm_struct *mm);
#else
#error "klp-ccp: non-taken branch"
#endif

static void (*klpe_set_mm_exe_file)(struct mm_struct *mm, struct file *new_exe_file);

/* klp-ccp: from fs/exec.c */
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>

/* klp-ccp: from include/linux/cgroup-defs.h */
#ifdef CONFIG_CGROUPS

#include <linux/percpu-rwsem.h>

static struct percpu_rw_semaphore (*klpe_cgroup_threadgroup_rwsem);

static inline void klpr_cgroup_threadgroup_change_begin(struct task_struct *tsk)
{
	percpu_down_read(&(*klpe_cgroup_threadgroup_rwsem));
}

static inline void klpr_cgroup_threadgroup_change_end(struct task_struct *tsk)
{
	percpu_up_read(&(*klpe_cgroup_threadgroup_rwsem));
}

#else	/* CONFIG_CGROUPS */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_CGROUPS */

/* klp-ccp: from fs/exec.c */
#include <linux/binfmts.h>

/* klp-ccp: from fs/exec.c */
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>

/* klp-ccp: from include/linux/sched/mm.h */
static void (*klpe_exec_mm_release)(struct task_struct *, struct mm_struct *);

#ifdef CONFIG_MEMCG
static void (*klpe_mm_update_next_owner)(struct mm_struct *mm);
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MEMCG */

#ifdef CONFIG_MEMBARRIER

static void (*klpe_membarrier_exec_mmap)(struct mm_struct *mm);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from fs/exec.c */
#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/pagemap.h>
#ifdef CONFIG_SECURITY

static int (*klpe_security_bprm_creds_from_file)(struct linux_binprm *bprm, struct file *file);

static void (*klpe_security_bprm_committing_creds)(struct linux_binprm *bprm);
static void (*klpe_security_bprm_committed_creds)(struct linux_binprm *bprm);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */

/* klp-ccp: from include/linux/perf_event.h */
#ifdef CONFIG_PERF_EVENTS

static void (*klpe_perf_event_exit_task)(struct task_struct *child);

#else /* !CONFIG_PERF_EVENTS: */
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from fs/exec.c */
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>

static int (*klpe_suid_dumpable);

/* klp-ccp: from fs/exec.c */
#include <linux/pid_namespace.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/security.h>
#include <linux/kmod.h>
#include <linux/compat.h>

/* klp-ccp: from include/linux/io_uring.h */
#if defined(CONFIG_IO_URING)

static void (*klpe___io_uring_cancel)(bool cancel_all);

static inline void klpr_io_uring_task_cancel(void)
{
	if (current->io_uring)
		(*klpe___io_uring_cancel)(true);
}

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from fs/exec.c */
#include <linux/syscall_user_dispatch.h>
#include <linux/uaccess.h>

#if defined(CONFIG_X86_64)

/* klp-ccp: from arch/x86/include/asm/mmu_context.h */
static void (*klpe_switch_mm)(struct mm_struct *prev, struct mm_struct *next,
		      struct task_struct *tsk);

#define klpr_activate_mm(prev, next)			\
do {						\
	paravirt_activate_mm((prev), (next));	\
	(*klpe_switch_mm)((prev), (next), NULL);	\
} while (0);

#elif defined(CONFIG_PPC64)

/* klp-ccp: from arch/powerpc/include/asm/mmu_context.h */
static void (*klpe_switch_mm_irqs_off)(struct mm_struct *prev, struct mm_struct *next,
					struct task_struct *tsk);

static inline void klpr_activate_mm(struct mm_struct *prev, struct mm_struct *next)
{
	(*klpe_switch_mm_irqs_off)(prev, next, current);
}

#elif defined(CONFIG_S390)

/* klp-ccp: from include/linux/mm_types.h */
static struct mm_struct (*klpe_init_mm);

/* klp-ccp: from arch/s390/include/asm/pgtable.h */
static unsigned long (*klpe_s390_invalid_asce);

/* klp-ccp: from arch/s390/include/asm/mmu_context.h */
#include <asm/ctl_reg.h>

static inline void klpr_switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
				      struct task_struct *tsk)
{
	int cpu = smp_processor_id();

	if (next == &(*klpe_init_mm))
		S390_lowcore.user_asce = (*klpe_s390_invalid_asce);
	else
		S390_lowcore.user_asce = next->context.asce;
	cpumask_set_cpu(cpu, &next->context.cpu_attach_mask);
	/* Clear previous user-ASCE from CR7 */
	__ctl_load((*klpe_s390_invalid_asce), 7, 7);
	if (prev != next)
		cpumask_clear_cpu(cpu, &prev->context.cpu_attach_mask);
}

static inline void klpr_switch_mm(struct mm_struct *prev, struct mm_struct *next,
			     struct task_struct *tsk)
{
	unsigned long flags;

	local_irq_save(flags);
	klpr_switch_mm_irqs_off(prev, next, tsk);
	local_irq_restore(flags);
}

static inline void klpr_activate_mm(struct mm_struct *prev, struct mm_struct *next)
{
	klpr_switch_mm(prev, next, current);
	cpumask_set_cpu(smp_processor_id(), mm_cpumask(next));
	__ctl_load(S390_lowcore.user_asce, 7, 7);
}

#else
#error "support for architecture not implemented"
#endif

/* klp-ccp: from fs/exec.c */
static int klpr_bprm_creds_from_file(struct linux_binprm *bprm);

#ifdef CONFIG_MMU

static void klpr_acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	klpr_add_mm_counter(mm, MM_ANONPAGES, diff);
}

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MMU */

static int klpr_exec_mmap(struct mm_struct *mm)
{
	struct task_struct *tsk;
	struct mm_struct *old_mm, *active_mm;
	int ret;

	/* Notify parent that we're no longer interested in the old VM */
	tsk = current;
	old_mm = current->mm;
	(*klpe_exec_mm_release)(tsk, old_mm);
	if (old_mm)
		(*klpe_sync_mm_rss)(old_mm);

	ret = down_write_killable(&tsk->signal->exec_update_lock);
	if (ret)
		return ret;

	if (old_mm) {
		/*
		 * Make sure that if there is a core dump in progress
		 * for the old mm, we get out and die instead of going
		 * through with the exec.  We must hold mmap_lock around
		 * checking core_state and changing tsk->mm.
		 */
		mmap_read_lock(old_mm);
		if (unlikely(old_mm->core_state)) {
			mmap_read_unlock(old_mm);
			up_write(&tsk->signal->exec_update_lock);
			return -EINTR;
		}
	}

	task_lock(tsk);
	(*klpe_membarrier_exec_mmap)(mm);

	local_irq_disable();
	active_mm = tsk->active_mm;
	tsk->active_mm = mm;
	tsk->mm = mm;
	/*
	 * This prevents preemption while active_mm is being loaded and
	 * it and mm are being updated, which could cause problems for
	 * lazy tlb mm refcounting when these are updated by context
	 * switches. Not all architectures can handle irqs off over
	 * activate_mm yet.
	 */
	if (!IS_ENABLED(CONFIG_ARCH_WANT_IRQS_OFF_ACTIVATE_MM))
		local_irq_enable();
	klpr_activate_mm(active_mm, mm);
	if (IS_ENABLED(CONFIG_ARCH_WANT_IRQS_OFF_ACTIVATE_MM))
		local_irq_enable();
	tsk->mm->vmacache_seqnum = 0;
	vmacache_flush(tsk);
	task_unlock(tsk);
	if (old_mm) {
		mmap_read_unlock(old_mm);
		BUG_ON(active_mm != old_mm);
		setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
		(*klpe_mm_update_next_owner)(old_mm);
		mmput(old_mm);
		return 0;
	}
	mmdrop(active_mm);
	return 0;
}

static int klpr_de_thread(struct task_struct *tsk)
{
	struct signal_struct *sig = tsk->signal;
	struct sighand_struct *oldsighand = tsk->sighand;
	spinlock_t *lock = &oldsighand->siglock;

	if (thread_group_empty(tsk))
		goto no_thread_group;

	/*
	 * Kill all other threads in the thread group.
	 */
	spin_lock_irq(lock);
	if (signal_group_exit(sig)) {
		/*
		 * Another group action in progress, just
		 * return so that the signal is processed.
		 */
		spin_unlock_irq(lock);
		return -EAGAIN;
	}

	sig->group_exit_task = tsk;
	sig->notify_count = (*klpe_zap_other_threads)(tsk);
	if (!thread_group_leader(tsk))
		sig->notify_count--;

	while (sig->notify_count) {
		__set_current_state(TASK_KILLABLE);
		spin_unlock_irq(lock);
		schedule();
		if (__fatal_signal_pending(tsk))
			goto killed;
		spin_lock_irq(lock);
	}
	spin_unlock_irq(lock);

	/*
	 * At this point all other threads have exited, all we have to
	 * do is to wait for the thread group leader to become inactive,
	 * and to assume its PID:
	 */
	if (!thread_group_leader(tsk)) {
		struct task_struct *leader = tsk->group_leader;

		for (;;) {
			klpr_cgroup_threadgroup_change_begin(tsk);
			write_lock_irq(&(*klpe_tasklist_lock));
			/*
			 * Do this under tasklist_lock to ensure that
			 * exit_notify() can't miss ->group_exit_task
			 */
			sig->notify_count = -1;
			if (likely(leader->exit_state))
				break;
			__set_current_state(TASK_KILLABLE);
			write_unlock_irq(&(*klpe_tasklist_lock));
			klpr_cgroup_threadgroup_change_end(tsk);
			schedule();
			if (__fatal_signal_pending(tsk))
				goto killed;
		}

		/*
		 * The only record we have of the real-time age of a
		 * process, regardless of execs it's done, is start_time.
		 * All the past CPU time is accumulated in signal_struct
		 * from sister threads now dead.  But in this non-leader
		 * exec, nothing survives from the original leader thread,
		 * whose birth marks the true age of this process now.
		 * When we take on its identity by switching to its PID, we
		 * also take its birthdate (always earlier than our own).
		 */
		tsk->start_time = leader->start_time;
		tsk->start_boottime = leader->start_boottime;

		BUG_ON(!same_thread_group(leader, tsk));
		/*
		 * An exec() starts a new thread group with the
		 * TGID of the previous thread group. Rehash the
		 * two threads with a switched PID, and release
		 * the former thread group leader:
		 */

		/* Become a process group leader with the old leader's pid.
		 * The old leader becomes a thread of the this thread group.
		 */
		(*klpe_exchange_tids)(tsk, leader);
		(*klpe_transfer_pid)(leader, tsk, PIDTYPE_TGID);
		(*klpe_transfer_pid)(leader, tsk, PIDTYPE_PGID);
		(*klpe_transfer_pid)(leader, tsk, PIDTYPE_SID);

		list_replace_rcu(&leader->tasks, &tsk->tasks);
		list_replace_init(&leader->sibling, &tsk->sibling);

		tsk->group_leader = tsk;
		leader->group_leader = tsk;

		tsk->exit_signal = SIGCHLD;
		leader->exit_signal = -1;

		BUG_ON(leader->exit_state != EXIT_ZOMBIE);
		leader->exit_state = EXIT_DEAD;

		/*
		 * We are going to release_task()->ptrace_unlink() silently,
		 * the tracer can sleep in do_wait(). EXIT_DEAD guarantees
		 * the tracer wont't block again waiting for this thread.
		 */
		if (unlikely(leader->ptrace))
			(*klpe___wake_up_parent)(leader, leader->parent);
		write_unlock_irq(&(*klpe_tasklist_lock));
		klpr_cgroup_threadgroup_change_end(tsk);

		(*klpe_release_task)(leader);
	}

	sig->group_exit_task = NULL;
	sig->notify_count = 0;

no_thread_group:
	/* we have changed execution domain */
	tsk->exit_signal = SIGCHLD;

	BUG_ON(!thread_group_leader(tsk));
	return 0;

killed:
	/* protects against exit_notify() and __exit_signal() */
	read_lock(&(*klpe_tasklist_lock));
	sig->group_exit_task = NULL;
	sig->notify_count = 0;
	read_unlock(&(*klpe_tasklist_lock));
	return -EAGAIN;
}

static int klpr_unshare_sighand(struct task_struct *me)
{
	struct sighand_struct *oldsighand = me->sighand;

	if (refcount_read(&oldsighand->count) != 1) {
		struct sighand_struct *newsighand;
		/*
		 * This ->sighand is shared with the CLONE_SIGHAND
		 * but not CLONE_THREAD task, switch to the new one.
		 */
		newsighand = kmem_cache_alloc((*klpe_sighand_cachep), GFP_KERNEL);
		if (!newsighand)
			return -ENOMEM;

		refcount_set(&newsighand->count, 1);
		memcpy(newsighand->action, oldsighand->action,
		       sizeof(newsighand->action));

		write_lock_irq(&(*klpe_tasklist_lock));
		spin_lock(&oldsighand->siglock);
		rcu_assign_pointer(me->sighand, newsighand);
		spin_unlock(&oldsighand->siglock);
		write_unlock_irq(&(*klpe_tasklist_lock));

		(*klpe___cleanup_sighand)(oldsighand);
	}
	return 0;
}

#include "livepatch_bsc1210987.h"

int klpp_begin_new_exec(struct linux_binprm * bprm)
{
	struct task_struct *me = current;
	int retval;

	/* Once we are committed compute the creds */
	retval = klpr_bprm_creds_from_file(bprm);
	if (retval)
		return retval;

	/*
	 * Ensure all future errors are fatal.
	 */
	bprm->point_of_no_return = true;

	/*
	 * Make this the only thread in the thread group.
	 */
	retval = klpr_de_thread(me);
	if (retval)
		goto out;

	/*
	 * Cancel any io_uring activity across execve
	 */
	klpr_io_uring_task_cancel();

	/* Ensure the files table is not shared. */
	retval = (*klpe_unshare_files)();
	if (retval)
		goto out;

	/*
	 * Must be called _before_ exec_mmap() as bprm->mm is
	 * not visibile until then. This also enables the update
	 * to be lockless.
	 */
	(*klpe_set_mm_exe_file)(bprm->mm, bprm->file);

	/* If the binary is not readable then enforce mm->dumpable=0 */
	would_dump(bprm, bprm->file);
	if (bprm->have_execfd)
		would_dump(bprm, bprm->executable);

	/*
	 * Release all of the old mmap stuff
	 */
	klpr_acct_arg_size(bprm, 0);
	retval = klpr_exec_mmap(bprm->mm);
	if (retval)
		goto out;

	bprm->mm = NULL;

#ifdef CONFIG_POSIX_TIMERS
	spin_lock_irq(&me->sighand->siglock);
	(*klpe_posix_cpu_timers_exit)(me);
	spin_unlock_irq(&me->sighand->siglock);
	(*klpe_exit_itimers)(me);
	(*klpe_flush_itimer_signals)();
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	retval = klpr_unshare_sighand(me);
	if (retval)
		goto out_unlock;

	/*
	 * Ensure that the uaccess routines can actually operate on userspace
	 * pointers:
	 */
	force_uaccess_begin();

	me->flags &= ~(PF_RANDOMIZE | PF_FORKNOEXEC | PF_KTHREAD |
					PF_NOFREEZE | PF_NO_SETAFFINITY);
	(*klpe_flush_thread)();
	me->personality &= ~bprm->per_clear;

	clear_syscall_work_syscall_user_dispatch(me);

	/*
	 * We have to apply CLOEXEC before we change whether the process is
	 * dumpable (in setup_new_exec) to avoid a race with a process in userspace
	 * trying to access the should-be-closed file descriptors of a process
	 * undergoing exec(2).
	 */
	(*klpe_do_close_on_exec)(me->files);

	if (bprm->secureexec) {
		/* Make sure parent cannot signal privileged process. */
		me->pdeath_signal = 0;

		/*
		 * For secureexec, reset the stack limit to sane default to
		 * avoid bad behavior from the prior rlimits. This has to
		 * happen before arch_pick_mmap_layout(), which examines
		 * RLIMIT_STACK, but after the point of no return to avoid
		 * needing to clean up the change on failure.
		 */
		if (bprm->rlim_stack.rlim_cur > _STK_LIM)
			bprm->rlim_stack.rlim_cur = _STK_LIM;
	}

	me->sas_ss_sp = me->sas_ss_size = 0;

	/*
	 * Figure out dumpability. Note that this checking only of current
	 * is wrong, but userspace depends on it. This should be testing
	 * bprm->secureexec instead.
	 */
	if (bprm->interp_flags & BINPRM_FLAGS_ENFORCE_NONDUMP ||
	    !(uid_eq(current_euid(), current_uid()) &&
	      gid_eq(current_egid(), current_gid())))
		(*klpe_set_dumpable)(current->mm, (*klpe_suid_dumpable));
	else
		(*klpe_set_dumpable)(current->mm, SUID_DUMP_USER);

	klpp_perf_event_exec();
	(*klpe___set_task_comm)(me, kbasename(bprm->filename), true);

	/* An exec changes our domain. We are no longer part of the thread
	   group */
	WRITE_ONCE(me->self_exec_id, me->self_exec_id + 1);
	(*klpe_flush_signal_handlers)(me, 0);

	retval = (*klpe_set_cred_ucounts)(bprm->cred);
	if (retval < 0)
		goto out_unlock;

	/*
	 * install the new credentials for this executable
	 */
	(*klpe_security_bprm_committing_creds)(bprm);

	commit_creds(bprm->cred);
	bprm->cred = NULL;

	/*
	 * Disable monitoring for regular users
	 * when executing setuid binaries. Must
	 * wait until new credentials are committed
	 * by commit_creds() above
	 */
	if (get_dumpable(me->mm) != SUID_DUMP_USER)
		(*klpe_perf_event_exit_task)(me);
	/*
	 * cred_guard_mutex must be held at least to this point to prevent
	 * ptrace_attach() from altering our determination of the task's
	 * credentials; any time after this it may be unlocked.
	 */
	(*klpe_security_bprm_committed_creds)(bprm);

	/* Pass the opened binary to the interpreter. */
	if (bprm->have_execfd) {
		retval = get_unused_fd_flags(0);
		if (retval < 0)
			goto out_unlock;
		fd_install(retval, bprm->executable);
		bprm->executable = NULL;
		bprm->execfd = retval;
	}
	return 0;

out_unlock:
	up_write(&me->signal->exec_update_lock);
out:
	return retval;
}

void would_dump(struct linux_binprm *bprm, struct file *file);

static void klpr_bprm_fill_uid(struct linux_binprm *bprm, struct file *file)
{
	/* Handle suid and sgid on files */
	struct user_namespace *mnt_userns;
	struct inode *inode;
	unsigned int mode;
	kuid_t uid;
	kgid_t gid;

	if (!(*klpe_mnt_may_suid)(file->f_path.mnt))
		return;

	if (task_no_new_privs(current))
		return;

	inode = file->f_path.dentry->d_inode;
	mode = READ_ONCE(inode->i_mode);
	if (!(mode & (S_ISUID|S_ISGID)))
		return;

	mnt_userns = file_mnt_user_ns(file);

	/* Be careful if suid/sgid is set */
	inode_lock(inode);

	/* reload atomically mode/uid/gid now that lock held */
	mode = inode->i_mode;
	uid = i_uid_into_mnt(mnt_userns, inode);
	gid = i_gid_into_mnt(mnt_userns, inode);
	inode_unlock(inode);

	/* We ignore suid/sgid if there are no mappings for them in the ns */
	if (!kuid_has_mapping(bprm->cred->user_ns, uid) ||
		 !kgid_has_mapping(bprm->cred->user_ns, gid))
		return;

	if (mode & S_ISUID) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->euid = uid;
	}

	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->egid = gid;
	}
}

static int klpr_bprm_creds_from_file(struct linux_binprm *bprm)
{
	/* Compute creds based on which file? */
	struct file *file = bprm->execfd_creds ? bprm->executable : bprm->file;

	klpr_bprm_fill_uid(bprm, file);
	return (*klpe_security_bprm_creds_from_file)(bprm, file);
}



#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__cleanup_sighand", (void *)&klpe___cleanup_sighand },
	{ "__io_uring_cancel", (void *)&klpe___io_uring_cancel },
	{ "__set_task_comm", (void *)&klpe___set_task_comm },
	{ "__wake_up_parent", (void *)&klpe___wake_up_parent },
	{ "cgroup_threadgroup_rwsem", (void *)&klpe_cgroup_threadgroup_rwsem },
	{ "do_close_on_exec", (void *)&klpe_do_close_on_exec },
	{ "exchange_tids", (void *)&klpe_exchange_tids },
	{ "exec_mm_release", (void *)&klpe_exec_mm_release },
	{ "exit_itimers", (void *)&klpe_exit_itimers },
	{ "flush_itimer_signals", (void *)&klpe_flush_itimer_signals },
	{ "flush_signal_handlers", (void *)&klpe_flush_signal_handlers },
	{ "flush_thread", (void *)&klpe_flush_thread },
	{ "membarrier_exec_mmap", (void *)&klpe_membarrier_exec_mmap },
	{ "mm_trace_rss_stat", (void *)&klpe_mm_trace_rss_stat },
	{ "mm_update_next_owner", (void *)&klpe_mm_update_next_owner },
	{ "mnt_may_suid", (void *)&klpe_mnt_may_suid },
	{ "perf_event_exit_task", (void *)&klpe_perf_event_exit_task },
	{ "posix_cpu_timers_exit", (void *)&klpe_posix_cpu_timers_exit },
	{ "release_task", (void *)&klpe_release_task },
	{ "security_bprm_committed_creds",
	  (void *)&klpe_security_bprm_committed_creds },
	{ "security_bprm_committing_creds",
	  (void *)&klpe_security_bprm_committing_creds },
	{ "security_bprm_creds_from_file",
	  (void *)&klpe_security_bprm_creds_from_file },
	{ "set_cred_ucounts", (void *)&klpe_set_cred_ucounts },
	{ "set_dumpable", (void *)&klpe_set_dumpable },
	{ "set_mm_exe_file", (void *)&klpe_set_mm_exe_file },
	{ "sighand_cachep", (void *)&klpe_sighand_cachep },
	{ "suid_dumpable", (void *)&klpe_suid_dumpable },
#if defined(CONFIG_X86_64)
	{ "switch_mm", (void *)&klpe_switch_mm },
#elif defined(CONFIG_PPC64)
	{ "switch_mm_irqs_off", (void *)&klpe_switch_mm_irqs_off },
#elif defined(CONFIG_S390)
	{ "init_mm", (void *)&klpe_init_mm },
	{ "s390_invalid_asce", (void *)&klpe_s390_invalid_asce },
#endif
	{ "sync_mm_rss", (void *)&klpe_sync_mm_rss },
	{ "tasklist_lock", (void *)&klpe_tasklist_lock },
	{ "transfer_pid", (void *)&klpe_transfer_pid },
	{ "unshare_files", (void *)&klpe_unshare_files },
	{ "zap_other_threads", (void *)&klpe_zap_other_threads },
};

int bsc1210987_fs_exec_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
