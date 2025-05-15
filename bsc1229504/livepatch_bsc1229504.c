/*
 * livepatch_bsc1229504
 *
 * Fix for CVE-2024-43882, bsc#1229504
 *
 *  Upstream commit:
 *  f50733b45d86 ("exec: Fix ToCToU between perm check and set-uid/gid usage")
 *
 *  SLE12-SP5 commit:
 *  236a83a2cf3e63feb330395fe7e94a0b27870ac0
 *
 *  SLE15-SP3 commit:
 *  ce6fb0c780628c336745ccb286ff418a4ed2c281
 *
 *  SLE15-SP4 and -SP5 commit:
 *  83a7456632866f91bb766a5d6914bb9025c71caa
 *
 *  SLE15-SP6 commit:
 *  7a21b9de3359142bdd8c9587ff4f063d5cd2ef2b
 *
 *  SLE MICRO-6-0 commit:
 *  7a21b9de3359142bdd8c9587ff4f063d5cd2ef2b
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from fs/exec.c */
#include <linux/kernel_read_file.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>

#include <linux/sched/task.h>
#include <linux/pagemap.h>
#include <linux/perf_event.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>

/* klp-ccp: from include/linux/binfmts.h */
int klpp_begin_new_exec(struct linux_binprm * bprm);

/* klp-ccp: from fs/exec.c */
#include <linux/pid_namespace.h>
#include <linux/module.h>

#include <linux/mount.h>
#include <linux/security.h>
#include <linux/syscalls.h>

#include <linux/kmod.h>

#include <linux/compat.h>

#include <linux/io_uring.h>
#include <linux/syscall_user_dispatch.h>

#include <linux/uaccess.h>
#include <asm/mmu_context.h>

static int klpr_bprm_creds_from_file(struct linux_binprm *bprm);

extern int suid_dumpable;

#ifdef CONFIG_MMU

static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_MMU */

static int exec_mmap(struct mm_struct *mm)
{
	struct task_struct *tsk;
	struct mm_struct *old_mm, *active_mm;
	int ret;

	/* Notify parent that we're no longer interested in the old VM */
	tsk = current;
	old_mm = current->mm;
	exec_mm_release(tsk, old_mm);
	if (old_mm)
		sync_mm_rss(old_mm);

	ret = down_write_killable(&tsk->signal->exec_update_lock);
	if (ret)
		return ret;

	if (old_mm) {
		/*
		 * If there is a pending fatal signal perhaps a signal
		 * whose default action is to create a coredump get
		 * out and die instead of going through with the exec.
		 */
		ret = mmap_read_lock_killable(old_mm);
		if (ret) {
			up_write(&tsk->signal->exec_update_lock);
			return ret;
		}
	}

	task_lock(tsk);
	membarrier_exec_mmap(mm);

	local_irq_disable();
	active_mm = tsk->active_mm;
	tsk->active_mm = mm;
	tsk->mm = mm;
	mm_init_cid(mm);
	/*
	 * This prevents preemption while active_mm is being loaded and
	 * it and mm are being updated, which could cause problems for
	 * lazy tlb mm refcounting when these are updated by context
	 * switches. Not all architectures can handle irqs off over
	 * activate_mm yet.
	 */
	if (!IS_ENABLED(CONFIG_ARCH_WANT_IRQS_OFF_ACTIVATE_MM))
		local_irq_enable();
	activate_mm(active_mm, mm);
	if (IS_ENABLED(CONFIG_ARCH_WANT_IRQS_OFF_ACTIVATE_MM))
		local_irq_enable();
	lru_gen_add_mm(mm);
	task_unlock(tsk);
	lru_gen_use_mm(mm);
	if (old_mm) {
		mmap_read_unlock(old_mm);
		BUG_ON(active_mm != old_mm);
		setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
		mm_update_next_owner(old_mm);
		mmput(old_mm);
		return 0;
	}
	mmdrop_lazy_tlb(active_mm);
	return 0;
}

static int de_thread(struct task_struct *tsk)
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
	if ((sig->flags & SIGNAL_GROUP_EXIT) || sig->group_exec_task) {
		/*
		 * Another group action in progress, just
		 * return so that the signal is processed.
		 */
		spin_unlock_irq(lock);
		return -EAGAIN;
	}

	sig->group_exec_task = tsk;
	sig->notify_count = zap_other_threads(tsk);
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
			cgroup_threadgroup_change_begin(tsk);
			write_lock_irq(&tasklist_lock);
			/*
			 * Do this under tasklist_lock to ensure that
			 * exit_notify() can't miss ->group_exec_task
			 */
			sig->notify_count = -1;
			if (likely(leader->exit_state))
				break;
			__set_current_state(TASK_KILLABLE);
			write_unlock_irq(&tasklist_lock);
			cgroup_threadgroup_change_end(tsk);
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
		exchange_tids(tsk, leader);
		transfer_pid(leader, tsk, PIDTYPE_TGID);
		transfer_pid(leader, tsk, PIDTYPE_PGID);
		transfer_pid(leader, tsk, PIDTYPE_SID);

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
		 * the tracer won't block again waiting for this thread.
		 */
		if (unlikely(leader->ptrace))
			__wake_up_parent(leader, leader->parent);
		write_unlock_irq(&tasklist_lock);
		cgroup_threadgroup_change_end(tsk);

		release_task(leader);
	}

	sig->group_exec_task = NULL;
	sig->notify_count = 0;

no_thread_group:
	/* we have changed execution domain */
	tsk->exit_signal = SIGCHLD;

	BUG_ON(!thread_group_leader(tsk));
	return 0;

killed:
	/* protects against exit_notify() and __exit_signal() */
	read_lock(&tasklist_lock);
	sig->group_exec_task = NULL;
	sig->notify_count = 0;
	read_unlock(&tasklist_lock);
	return -EAGAIN;
}

static int unshare_sighand(struct task_struct *me)
{
	struct sighand_struct *oldsighand = me->sighand;

	if (refcount_read(&oldsighand->count) != 1) {
		struct sighand_struct *newsighand;
		/*
		 * This ->sighand is shared with the CLONE_SIGHAND
		 * but not CLONE_THREAD task, switch to the new one.
		 */
		newsighand = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
		if (!newsighand)
			return -ENOMEM;

		refcount_set(&newsighand->count, 1);

		write_lock_irq(&tasklist_lock);
		spin_lock(&oldsighand->siglock);
		memcpy(newsighand->action, oldsighand->action,
		       sizeof(newsighand->action));
		rcu_assign_pointer(me->sighand, newsighand);
		spin_unlock(&oldsighand->siglock);
		write_unlock_irq(&tasklist_lock);

		__cleanup_sighand(oldsighand);
	}
	return 0;
}

void __set_task_comm(struct task_struct *tsk, const char *buf, bool exec);

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
	retval = de_thread(me);
	if (retval)
		goto out;

	/*
	 * Cancel any io_uring activity across execve
	 */
	io_uring_task_cancel();

	/* Ensure the files table is not shared. */
	retval = unshare_files();
	if (retval)
		goto out;

	/*
	 * Must be called _before_ exec_mmap() as bprm->mm is
	 * not visible until then. This also enables the update
	 * to be lockless.
	 */
	retval = set_mm_exe_file(bprm->mm, bprm->file);
	if (retval)
		goto out;

	/* If the binary is not readable then enforce mm->dumpable=0 */
	would_dump(bprm, bprm->file);
	if (bprm->have_execfd)
		would_dump(bprm, bprm->executable);

	/*
	 * Release all of the old mmap stuff
	 */
	acct_arg_size(bprm, 0);
	retval = exec_mmap(bprm->mm);
	if (retval)
		goto out;

	bprm->mm = NULL;

	retval = exec_task_namespaces();
	if (retval)
		goto out_unlock;

#ifdef CONFIG_POSIX_TIMERS
	spin_lock_irq(&me->sighand->siglock);
	posix_cpu_timers_exit(me);
	spin_unlock_irq(&me->sighand->siglock);
	exit_itimers(me);
	flush_itimer_signals();
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	retval = unshare_sighand(me);
	if (retval)
		goto out_unlock;

	me->flags &= ~(PF_RANDOMIZE | PF_FORKNOEXEC |
					PF_NOFREEZE | PF_NO_SETAFFINITY);
	flush_thread();
	me->personality &= ~bprm->per_clear;

	clear_syscall_work_syscall_user_dispatch(me);

	/*
	 * We have to apply CLOEXEC before we change whether the process is
	 * dumpable (in setup_new_exec) to avoid a race with a process in userspace
	 * trying to access the should-be-closed file descriptors of a process
	 * undergoing exec(2).
	 */
	do_close_on_exec(me->files);

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
		set_dumpable(current->mm, suid_dumpable);
	else
		set_dumpable(current->mm, SUID_DUMP_USER);

	perf_event_exec();
	__set_task_comm(me, kbasename(bprm->filename), true);

	/* An exec changes our domain. We are no longer part of the thread
	   group */
	WRITE_ONCE(me->self_exec_id, me->self_exec_id + 1);
	flush_signal_handlers(me, 0);

	retval = set_cred_ucounts(bprm->cred);
	if (retval < 0)
		goto out_unlock;

	/*
	 * install the new credentials for this executable
	 */
	security_bprm_committing_creds(bprm);

	commit_creds(bprm->cred);
	bprm->cred = NULL;

	/*
	 * Disable monitoring for regular users
	 * when executing setuid binaries. Must
	 * wait until new credentials are committed
	 * by commit_creds() above
	 */
	if (get_dumpable(me->mm) != SUID_DUMP_USER)
		perf_event_exit_task(me);
	/*
	 * cred_guard_mutex must be held at least to this point to prevent
	 * ptrace_attach() from altering our determination of the task's
	 * credentials; any time after this it may be unlocked.
	 */
	security_bprm_committed_creds(bprm);

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
	if (!bprm->cred)
		mutex_unlock(&me->signal->cred_guard_mutex);

out:
	return retval;
}

typeof(klpp_begin_new_exec) klpp_begin_new_exec;

void would_dump(struct linux_binprm *bprm, struct file *file);

extern typeof(would_dump) would_dump;

static void klpp_bprm_fill_uid(struct linux_binprm *bprm, struct file *file)
{
	/* Handle suid and sgid on files */
	struct mnt_idmap *idmap;
	struct inode *inode = file_inode(file);
	unsigned int mode;
	vfsuid_t vfsuid;
	vfsgid_t vfsgid;
	int err;

	if (!mnt_may_suid(file->f_path.mnt))
		return;

	if (task_no_new_privs(current))
		return;

	mode = READ_ONCE(inode->i_mode);
	if (!(mode & (S_ISUID|S_ISGID)))
		return;

	idmap = file_mnt_idmap(file);

	/* Be careful if suid/sgid is set */
	inode_lock(inode);

	/* Atomically reload and check mode/uid/gid now that lock held. */
	mode = inode->i_mode;
	vfsuid = i_uid_into_vfsuid(idmap, inode);
	vfsgid = i_gid_into_vfsgid(idmap, inode);
	err = inode_permission(idmap, inode, MAY_EXEC);
	inode_unlock(inode);

	/* Did the exec bit vanish out from under us? Give up. */
	if (err)
		return;

	/* We ignore suid/sgid if there are no mappings for them in the ns */
	if (!vfsuid_has_mapping(bprm->cred->user_ns, vfsuid) ||
	    !vfsgid_has_mapping(bprm->cred->user_ns, vfsgid))
		return;

	if (mode & S_ISUID) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->euid = vfsuid_into_kuid(vfsuid);
	}

	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->egid = vfsgid_into_kgid(vfsgid);
	}
}

static int klpr_bprm_creds_from_file(struct linux_binprm *bprm)
{
	/* Compute creds based on which file? */
	struct file *file = bprm->execfd_creds ? bprm->executable : bprm->file;

	klpp_bprm_fill_uid(bprm, file);
	return security_bprm_creds_from_file(bprm, file);
}

void set_dumpable(struct mm_struct *mm, int value);


#include "livepatch_bsc1229504.h"

#include <linux/livepatch.h>

#if defined(CONFIG_X86)

extern typeof(switch_mm) switch_mm
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, switch_mm);

#elif defined(CONFIG_PPC)

extern typeof(switch_mm_irqs_off) switch_mm_irqs_off
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, switch_mm_irqs_off);

#elif defined(CONFIG_S390)

extern typeof(s390_invalid_asce) s390_invalid_asce
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, s390_invalid_asce);
extern typeof(init_mm) init_mm
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, init_mm);

#else
#error "non taken branch"
#endif

extern typeof(__cleanup_sighand) __cleanup_sighand
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __cleanup_sighand);
extern typeof(__io_uring_cancel) __io_uring_cancel
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __io_uring_cancel);
extern typeof(__set_task_comm) __set_task_comm
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __set_task_comm);
extern typeof(__wake_up_parent) __wake_up_parent
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, __wake_up_parent);
extern typeof(cgroup_threadgroup_rwsem) cgroup_threadgroup_rwsem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, cgroup_threadgroup_rwsem);
extern typeof(do_close_on_exec) do_close_on_exec
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, do_close_on_exec);
extern typeof(exchange_tids) exchange_tids
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exchange_tids);
extern typeof(exec_mm_release) exec_mm_release
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exec_mm_release);
extern typeof(exec_task_namespaces) exec_task_namespaces
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exec_task_namespaces);
extern typeof(exit_itimers) exit_itimers
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, exit_itimers);
extern typeof(flush_itimer_signals) flush_itimer_signals
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, flush_itimer_signals);
extern typeof(flush_signal_handlers) flush_signal_handlers
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, flush_signal_handlers);
extern typeof(flush_thread) flush_thread
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, flush_thread);
extern typeof(lru_gen_add_mm) lru_gen_add_mm
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, lru_gen_add_mm);
extern typeof(membarrier_exec_mmap) membarrier_exec_mmap
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, membarrier_exec_mmap);
extern typeof(mm_trace_rss_stat) mm_trace_rss_stat
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mm_trace_rss_stat);
extern typeof(mm_update_next_owner) mm_update_next_owner
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mm_update_next_owner);
extern typeof(mnt_may_suid) mnt_may_suid
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mnt_may_suid);
extern typeof(perf_event_exec) perf_event_exec
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, perf_event_exec);
extern typeof(perf_event_exit_task) perf_event_exit_task
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, perf_event_exit_task);
extern typeof(posix_cpu_timers_exit) posix_cpu_timers_exit
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, posix_cpu_timers_exit);
extern typeof(release_task) release_task
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, release_task);
extern typeof(security_bprm_committed_creds) security_bprm_committed_creds
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_bprm_committed_creds);
extern typeof(security_bprm_committing_creds) security_bprm_committing_creds
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_bprm_committing_creds);
extern typeof(security_bprm_creds_from_file) security_bprm_creds_from_file
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, security_bprm_creds_from_file);
extern typeof(set_cred_ucounts) set_cred_ucounts
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, set_cred_ucounts);
extern typeof(set_dumpable) set_dumpable
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, set_dumpable);
extern typeof(set_mm_exe_file) set_mm_exe_file
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, set_mm_exe_file);
extern typeof(sighand_cachep) sighand_cachep
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sighand_cachep);
extern typeof(suid_dumpable) suid_dumpable
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, suid_dumpable);
extern typeof(tasklist_lock) tasklist_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, tasklist_lock);
extern typeof(transfer_pid) transfer_pid
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, transfer_pid);
extern typeof(unshare_files) unshare_files
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, unshare_files);
extern typeof(zap_other_threads) zap_other_threads
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, zap_other_threads);
