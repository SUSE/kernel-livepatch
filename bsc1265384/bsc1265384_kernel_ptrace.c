/*
 * bsc1265384_kernel_ptrace
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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
#define CC_USING_FENTRY 1

/* klp-ccp: from kernel/ptrace.c */
#include <linux/capability.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ptrace.h>
#include <linux/security.h>

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_SECURITY

static int (*klpe_security_ptrace_access_check)(struct task_struct *child, unsigned int mode);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */

/* klp-ccp: from kernel/ptrace.c */
#include <linux/signal.h>
#include <linux/uio.h>
#include <linux/audit.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/regset.h>
#include <linux/hw_breakpoint.h>
#include <linux/cn_proc.h>
#include <linux/compat.h>
#include <linux/sched/signal.h>

static bool ptrace_has_cap(struct user_namespace *ns, unsigned int mode)
{
	if (mode & PTRACE_MODE_NOAUDIT)
		return ns_capable_noaudit(ns, CAP_SYS_PTRACE);
	return ns_capable(ns, CAP_SYS_PTRACE);
}

static bool task_still_dumpable(struct task_struct *task, unsigned int mode)
{
	struct mm_struct *mm = task->mm;
	if (mm) {
		if (get_dumpable(mm) == SUID_DUMP_USER)
			return true;
		return ptrace_has_cap(mm->user_ns, mode);
	}

	if (KLP_USER_DUMPABLE_VALID(task)) {
		if (KLP_USER_DUMPABLE(task))
			return true;
		return ptrace_has_cap(&init_user_ns, mode);
	}

	if (task->flags & PF_KTHREAD)
		return ptrace_has_cap(&init_user_ns, mode);

	return true;   /* pre-patch in-flight user exiter */
}

int klpp___ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	const struct cred *cred = current_cred(), *tcred;
	kuid_t caller_uid;
	kgid_t caller_gid;

	if (!(mode & PTRACE_MODE_FSCREDS) == !(mode & PTRACE_MODE_REALCREDS)) {
		WARN(1, "denying ptrace access check without PTRACE_MODE_*CREDS\n");
		return -EPERM;
	}

	/* May we inspect the given task?
	 * This check is used both for attaching with ptrace
	 * and for allowing access to sensitive information in /proc.
	 *
	 * ptrace_attach denies several cases that /proc allows
	 * because setting up the necessary parent/child relationship
	 * or halting the specified task is impossible.
	 */

	/* Don't let security modules deny introspection */
	if (same_thread_group(task, current))
		return 0;
	rcu_read_lock();
	if (mode & PTRACE_MODE_FSCREDS) {
		caller_uid = cred->fsuid;
		caller_gid = cred->fsgid;
	} else {
		/*
		 * Using the euid would make more sense here, but something
		 * in userland might rely on the old behavior, and this
		 * shouldn't be a security problem since
		 * PTRACE_MODE_REALCREDS implies that the caller explicitly
		 * used a syscall that requests access to another process
		 * (and not a filesystem syscall to procfs).
		 */
		caller_uid = cred->uid;
		caller_gid = cred->gid;
	}
	tcred = __task_cred(task);
	if (uid_eq(caller_uid, tcred->euid) &&
	    uid_eq(caller_uid, tcred->suid) &&
	    uid_eq(caller_uid, tcred->uid)  &&
	    gid_eq(caller_gid, tcred->egid) &&
	    gid_eq(caller_gid, tcred->sgid) &&
	    gid_eq(caller_gid, tcred->gid))
		goto ok;
	if (ptrace_has_cap(tcred->user_ns, mode))
		goto ok;
	rcu_read_unlock();
	return -EPERM;
ok:
	rcu_read_unlock();
	/*
	 * If a task drops privileges and becomes nondumpable (through a syscall
	 * like setresuid()) while we are trying to access it, we must ensure
	 * that the dumpability is read after the credentials; otherwise,
	 * we may be able to attach to a task that we shouldn't be able to
	 * attach to (as if the task had dropped privileges without becoming
	 * nondumpable).
	 * Pairs with a write barrier in commit_creds().
	 */
	smp_rmb();
        if (!task_still_dumpable(task, mode))
                return -EPERM;

	return (*klpe_security_ptrace_access_check)(task, mode);
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "security_ptrace_access_check",
	  (void *)&klpe_security_ptrace_access_check },
};

int bsc1265384_kernel_ptrace_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

