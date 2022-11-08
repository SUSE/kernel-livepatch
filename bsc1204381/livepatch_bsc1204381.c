/*
 * livepatch_bsc1204381
 *
 * Fix for bsc#1204381
 *
 *  Upstream commit:
 *  dcd46d897adb ("exec: Force single empty string when argv is empty")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  4ee3bddf6bfe70d01f64ba87c08ed67a312b92f1
 *
 *  SLE15-SP2 and -SP3 commit:
 *  dffa04e1f4ac951749521cdd317ea4def7e13599
 *
 *  SLE15-SP4 commit:
 *  256509dd34346035da0e108eb0e3f004752fc224
 *
 *
 *  Copyright (c) 2022 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#include <linux/tracepoint.h>

/* from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name);		\
	static inline void klpr_trace_##name(proto)			\
	{								\
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name),	\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond), 0);		\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\

#define KLPR_DECLARE_TRACE(name, proto, args)				\
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),	\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define KLPR_DEFINE_EVENT(template, name, proto, args)			\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

#define KLPR_TRACE_EVENT(name, proto, args)			\
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))



/* klp-ccp: from fs/exec.c */
#include <linux/slab.h>
#include <linux/fdtable.h>

/* klp-ccp: from include/linux/fs.h */
static struct filename *(*klpe_getname_flags)(const char __user *, int, int *);
static struct filename *(*klpe_getname)(const char __user *);

static void (*klpe_putname)(struct filename *name);

/* klp-ccp: from include/linux/fdtable.h */
static void (*klpe_put_files_struct)(struct files_struct *fs);
static void (*klpe_reset_files_struct)(struct files_struct *);
static int (*klpe_unshare_files)(struct files_struct **);

/* klp-ccp: from fs/exec.c */
#include <linux/mm.h>

/* klp-ccp: from include/linux/mm.h */
static struct kmem_cache *(*klpe_vm_area_cachep);

static int (*klpe_insert_vm_struct)(struct mm_struct *, struct vm_area_struct *);

/* klp-ccp: from fs/exec.c */
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/sched/mm.h>

/* klp-ccp: from include/linux/sched/mm.h */
static struct mm_struct * (*klpe_mm_alloc)(void);

/* klp-ccp: from fs/exec.c */
#include <linux/sched/coredump.h>
#include <linux/sched/signal.h>

/* klp-ccp: from include/linux/sched/task.h */
static void (*klpe_sched_exec)(void);

/* klp-ccp: from include/linux/sched/numa_balancing.h */
#ifdef CONFIG_NUMA_BALANCING

static void (*klpe_task_numa_free)(struct task_struct *p, bool final);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from fs/exec.c */
#include <linux/sched/task.h>
#include <linux/perf_event.h>

/* klp-ccp: from include/linux/ptrace.h */
static void (*klpe_ptrace_notify)(int exit_code);

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

/* klp-ccp: from fs/exec.c */
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>

/* klp-ccp: from include/linux/binfmts.h */
int klpp_remove_arg_zero(struct linux_binprm *);

int klpp_copy_strings_kernel(int argc, const char *const *argv,
			       struct linux_binprm *bprm);
static int (*klpe_prepare_bprm_creds)(struct linux_binprm *bprm);

int klpp_do_execve(struct filename *,
		     const char __user * const __user *,
		     const char __user * const __user *);
static int klpp_do_execveat(int, struct filename *,
		       const char __user * const __user *,
		       const char __user * const __user *,
		       int);

/* klp-ccp: from fs/exec.c */
#include <linux/pid_namespace.h>
#include <uapi/linux/elf-em.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/compat.h>

/* klp-ccp: from include/linux/tsacct_kern.h */
#ifdef CONFIG_TASK_XACCT

static void (*klpe_acct_update_integrals)(struct task_struct *tsk);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_TASK_XACCT */

/* klp-ccp: from include/linux/cn_proc.h */
#ifdef CONFIG_PROC_EVENTS

static void (*klpe_proc_exec_connector)(struct task_struct *task);

#else
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_PROC_EVENTS */

/* klp-ccp: from fs/exec.c */
#include <linux/audit.h>

/* klp-ccp: from include/linux/audit.h */
#ifdef CONFIG_AUDITSYSCALL

static void (*klpe___audit_bprm)(struct linux_binprm *bprm);

static inline void klpr_audit_bprm(struct linux_binprm *bprm)
{
	if (unlikely(!audit_dummy_context()))
		(*klpe___audit_bprm)(bprm);
}

#else /* CONFIG_AUDITSYSCALL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_AUDITSYSCALL */

/* klp-ccp: from fs/exec.c */
#include <linux/kmod.h>
#include <linux/fs_struct.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <asm/mmu_context.h>

/* klp-ccp: from include/trace/events/sched.h */
KLPR_TRACE_EVENT(sched_process_exec,

	TP_PROTO(struct task_struct *p, pid_t old_pid,
		 struct linux_binprm *bprm),

	TP_ARGS(p, old_pid, bprm)
);

/* klp-ccp: from fs/exec.c */
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

static struct page *klpp_get_arg_page(struct linux_binprm *bprm, unsigned long pos,
		int write)
{
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;

#ifdef CONFIG_STACK_GROWSUP
#error "klp-ccp: non-taken branch"
#endif
	if (write)
		gup_flags |= FOLL_WRITE;

	/*
	 * We are doing an exec().  'current' is the process
	 * doing the exec and bprm->mm is the new process's mm.
	 */
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
			&page, NULL, NULL);
	if (ret <= 0)
		return NULL;

	if (write) {
		unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
		unsigned long ptr_size, limit;

		/*
		 * Since the stack will hold pointers to the strings, we
		 * must account for them as well.
		 *
		 * The size calculation is the entire vma while each arg page is
		 * built, so each time we get here it's calculating how far it
		 * is currently (rather than each call being just the newly
		 * added size from the arg page).  As a result, we need to
		 * always add the entire size of the pointers, so that on the
		 * last call to get_arg_page() we'll actually have the entire
		 * correct size.
		 */
		/*
		 * Fix bsc#1204381
		 *  -1 line, +1 line
		 */
		ptr_size = (max(bprm->argc, 1) + bprm->envc) * sizeof(void *);
		if (ptr_size > ULONG_MAX - size)
			goto fail;
		size += ptr_size;

		acct_arg_size(bprm, size / PAGE_SIZE);

		/*
		 * We've historically supported up to 32 pages (ARG_MAX)
		 * of argument strings even with small stacks
		 */
		if (size <= ARG_MAX)
			return page;

		/*
		 * Limit to 1/4 of the max stack size or 3/4 of _STK_LIM
		 * (whichever is smaller) for the argv+env strings.
		 * This ensures that:
		 *  - the remaining binfmt code will not run out of stack space,
		 *  - the program will have a reasonable amount of stack left
		 *    to work from.
		 */
		limit = _STK_LIM / 4 * 3;
		limit = min(limit, rlimit(RLIMIT_STACK) / 4);
		if (size > limit)
			goto fail;
	}

	return page;

fail:
	put_page(page);
	return NULL;
}

static void put_arg_page(struct page *page)
{
	put_page(page);
}

static void flush_arg_page(struct linux_binprm *bprm, unsigned long pos,
		struct page *page)
{
	flush_cache_page(bprm->vma, pos, page_to_pfn(page));
}

static int klpr___bprm_mm_init(struct linux_binprm *bprm)
{
	int err;
	struct vm_area_struct *vma = NULL;
	struct mm_struct *mm = bprm->mm;

	bprm->vma = vma = kmem_cache_zalloc((*klpe_vm_area_cachep), GFP_KERNEL);
	if (!vma)
		return -ENOMEM;

	if (down_write_killable(&mm->mmap_sem)) {
		err = -EINTR;
		goto err_free;
	}
	vma->vm_mm = mm;

	/*
	 * Place the stack at the largest stack address the architecture
	 * supports. Later, we'll move this to an appropriate place. We don't
	 * use STACK_TOP because that can depend on attributes which aren't
	 * configured yet.
	 */
	BUILD_BUG_ON(VM_STACK_FLAGS & VM_STACK_INCOMPLETE_SETUP);
	vma->vm_end = STACK_TOP_MAX;
	vma->vm_start = vma->vm_end - PAGE_SIZE;
	vma->vm_flags = VM_SOFTDIRTY | VM_STACK_FLAGS | VM_STACK_INCOMPLETE_SETUP;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	INIT_LIST_HEAD(&vma->anon_vma_chain);

	err = (*klpe_insert_vm_struct)(mm, vma);
	if (err)
		goto err;

	mm->stack_vm = mm->total_vm = 1;
	arch_bprm_mm_init(mm, vma);
	up_write(&mm->mmap_sem);
	bprm->p = vma->vm_end - sizeof(void *);
	return 0;
err:
	up_write(&mm->mmap_sem);
err_free:
	bprm->vma = NULL;
	kmem_cache_free((*klpe_vm_area_cachep), vma);
	return err;
}

static bool valid_arg_len(struct linux_binprm *bprm, long len)
{
	return len <= MAX_ARG_STRLEN;
}

static int klpr_bprm_mm_init(struct linux_binprm *bprm)
{
	int err;
	struct mm_struct *mm = NULL;

	bprm->mm = mm = (*klpe_mm_alloc)();
	err = -ENOMEM;
	if (!mm)
		goto err;

	err = klpr___bprm_mm_init(bprm);
	if (err)
		goto err;

	return 0;

err:
	if (mm) {
		bprm->mm = NULL;
		mmdrop(mm);
	}

	return err;
}

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static const char __user *get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
	const char __user *native;

#ifdef CONFIG_COMPAT
	if (unlikely(argv.is_compat)) {
		compat_uptr_t compat;

		if (get_user(compat, argv.ptr.compat + nr))
			return ERR_PTR(-EFAULT);

		return compat_ptr(compat);
	}
#endif

	if (get_user(native, argv.ptr.native + nr))
		return ERR_PTR(-EFAULT);

	return native;
}

static int count(struct user_arg_ptr argv, int max)
{
	int i = 0;

	if (argv.ptr.native != NULL) {
		for (;;) {
			const char __user *p = get_user_arg_ptr(argv, i);

			if (!p)
				break;

			if (IS_ERR(p))
				return -EFAULT;

			if (i >= max)
				return -E2BIG;
			++i;

			if (fatal_signal_pending(current))
				return -ERESTARTNOHAND;
			cond_resched();
		}
	}
	return i;
}

static int klpp_copy_strings(int argc, struct user_arg_ptr argv,
			struct linux_binprm *bprm)
{
	struct page *kmapped_page = NULL;
	char *kaddr = NULL;
	unsigned long kpos = 0;
	int ret;

	while (argc-- > 0) {
		const char __user *str;
		int len;
		unsigned long pos;

		ret = -EFAULT;
		str = get_user_arg_ptr(argv, argc);
		if (IS_ERR(str))
			goto out;

		len = strnlen_user(str, MAX_ARG_STRLEN);
		if (!len)
			goto out;

		ret = -E2BIG;
		if (!valid_arg_len(bprm, len))
			goto out;

		/* We're going to work our way backwords. */
		pos = bprm->p;
		str += len;
		bprm->p -= len;

		while (len > 0) {
			int offset, bytes_to_copy;

			if (fatal_signal_pending(current)) {
				ret = -ERESTARTNOHAND;
				goto out;
			}
			cond_resched();

			offset = pos % PAGE_SIZE;
			if (offset == 0)
				offset = PAGE_SIZE;

			bytes_to_copy = offset;
			if (bytes_to_copy > len)
				bytes_to_copy = len;

			offset -= bytes_to_copy;
			pos -= bytes_to_copy;
			str -= bytes_to_copy;
			len -= bytes_to_copy;

			if (!kmapped_page || kpos != (pos & PAGE_MASK)) {
				struct page *page;

				page = klpp_get_arg_page(bprm, pos, 1);
				if (!page) {
					ret = -E2BIG;
					goto out;
				}

				if (kmapped_page) {
					flush_kernel_dcache_page(kmapped_page);
					kunmap(kmapped_page);
					put_arg_page(kmapped_page);
				}
				kmapped_page = page;
				kaddr = kmap(kmapped_page);
				kpos = pos & PAGE_MASK;
				flush_arg_page(bprm, kpos, kmapped_page);
			}
			if (copy_from_user(kaddr+offset, str, bytes_to_copy)) {
				ret = -EFAULT;
				goto out;
			}
		}
	}
	ret = 0;
out:
	if (kmapped_page) {
		flush_kernel_dcache_page(kmapped_page);
		kunmap(kmapped_page);
		put_arg_page(kmapped_page);
	}
	return ret;
}

int klpp_copy_strings_kernel(int argc, const char *const *__argv,
			struct linux_binprm *bprm)
{
	int r;
	mm_segment_t oldfs = get_fs();
	struct user_arg_ptr argv = {
		.ptr.native = (const char __user *const  __user *)__argv,
	};

	set_fs(KERNEL_DS);
	r = klpp_copy_strings(argc, argv, bprm);
	set_fs(oldfs);

	return r;
}

static struct file *(*klpe_do_open_execat)(int fd, struct filename *name, int flags);

static void (*klpe_free_bprm)(struct linux_binprm *bprm);

static void check_unsafe_exec(struct linux_binprm *bprm)
{
	struct task_struct *p = current, *t;
	unsigned n_fs;

	if (p->ptrace)
		bprm->unsafe |= LSM_UNSAFE_PTRACE;

	/*
	 * This isn't strictly necessary, but it makes it harder for LSMs to
	 * mess up.
	 */
	if (task_no_new_privs(current))
		bprm->unsafe |= LSM_UNSAFE_NO_NEW_PRIVS;

	t = p;
	n_fs = 1;
	spin_lock(&p->fs->lock);
	rcu_read_lock();
	while_each_thread(p, t) {
		if (t->fs == p->fs)
			n_fs++;
	}
	rcu_read_unlock();

	if (p->fs->users > n_fs)
		bprm->unsafe |= LSM_UNSAFE_SHARE;
	else
		p->fs->in_exec = 1;
	spin_unlock(&p->fs->lock);
}

int klpp_remove_arg_zero(struct linux_binprm *bprm)
{
	int ret = 0;
	unsigned long offset;
	char *kaddr;
	struct page *page;

	if (!bprm->argc)
		return 0;

	do {
		offset = bprm->p & ~PAGE_MASK;
		page = klpp_get_arg_page(bprm, bprm->p, 0);
		if (!page) {
			ret = -EFAULT;
			goto out;
		}
		kaddr = kmap_atomic(page);

		for (; offset < PAGE_SIZE && kaddr[offset];
				offset++, bprm->p++)
			;

		kunmap_atomic(kaddr);
		put_arg_page(page);
	} while (offset == PAGE_SIZE);

	bprm->p++;
	bprm->argc--;
	ret = 0;

out:
	return ret;
}

static int klpr_exec_binprm(struct linux_binprm *bprm)
{
	pid_t old_pid, old_vpid;
	int ret;

	/* Need to fetch pid before load_binary changes it */
	old_pid = current->pid;
	rcu_read_lock();
	old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
	rcu_read_unlock();

	ret = search_binary_handler(bprm);
	if (ret >= 0) {
		klpr_audit_bprm(bprm);
		klpr_trace_sched_process_exec(current, old_pid, bprm);
		klpr_ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
		(*klpe_proc_exec_connector)(current);
	}

	return ret;
}

static int klpp_do_execveat_common(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
	char *pathbuf = NULL;
	struct linux_binprm *bprm;
	struct file *file;
	struct files_struct *displaced;
	int retval;

	if (IS_ERR(filename))
		return PTR_ERR(filename);

	/*
	 * We move the actual failure in case of RLIMIT_NPROC excess from
	 * set*uid() to execve() because too many poorly written programs
	 * don't check setuid() return code.  Here we additionally recheck
	 * whether NPROC limit is still exceeded.
	 */
	if ((current->flags & PF_NPROC_EXCEEDED) &&
	    atomic_read(&current_user()->processes) > rlimit(RLIMIT_NPROC)) {
		retval = -EAGAIN;
		goto out_ret;
	}

	/* We're below the limit (still or again), so we don't want to make
	 * further execve() calls fail. */
	current->flags &= ~PF_NPROC_EXCEEDED;

	retval = (*klpe_unshare_files)(&displaced);
	if (retval)
		goto out_ret;

	retval = -ENOMEM;
	bprm = kzalloc(sizeof(*bprm), GFP_KERNEL);
	if (!bprm)
		goto out_files;

	retval = (*klpe_prepare_bprm_creds)(bprm);
	if (retval)
		goto out_free;

	check_unsafe_exec(bprm);
	current->in_execve = 1;

	file = (*klpe_do_open_execat)(fd, filename, flags);
	retval = PTR_ERR(file);
	if (IS_ERR(file))
		goto out_unmark;

	(*klpe_sched_exec)();

	bprm->file = file;
	if (fd == AT_FDCWD || filename->name[0] == '/') {
		bprm->filename = filename->name;
	} else {
		if (filename->name[0] == '\0')
			pathbuf = kasprintf(GFP_TEMPORARY, "/dev/fd/%d", fd);
		else
			pathbuf = kasprintf(GFP_TEMPORARY, "/dev/fd/%d/%s",
					    fd, filename->name);
		if (!pathbuf) {
			retval = -ENOMEM;
			goto out_unmark;
		}
		/*
		 * Record that a name derived from an O_CLOEXEC fd will be
		 * inaccessible after exec. Relies on having exclusive access to
		 * current->files (due to unshare_files above).
		 */
		if (close_on_exec(fd, rcu_dereference_raw(current->files->fdt)))
			bprm->interp_flags |= BINPRM_FLAGS_PATH_INACCESSIBLE;
		bprm->filename = pathbuf;
	}
	bprm->interp = bprm->filename;

	retval = klpr_bprm_mm_init(bprm);
	if (retval)
		goto out_unmark;

	bprm->argc = count(argv, MAX_ARG_STRINGS);

	/*
	 * Fix bsc#1204381
	 *  +3 lines
	 */
	if (bprm->argc == 0)
		pr_warn_once("process '%s' launched '%s' with NULL argv: empty string added\n",
			     current->comm, bprm->filename);

	if ((retval = bprm->argc) < 0)
		goto out;

	bprm->envc = count(envp, MAX_ARG_STRINGS);
	if ((retval = bprm->envc) < 0)
		goto out;

	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;

	retval = klpp_copy_strings_kernel(1, &bprm->filename, bprm);
	if (retval < 0)
		goto out;

	bprm->exec = bprm->p;
	retval = klpp_copy_strings(bprm->envc, envp, bprm);
	if (retval < 0)
		goto out;

	retval = klpp_copy_strings(bprm->argc, argv, bprm);
	if (retval < 0)
		goto out;


	/*
	 * Fix bsc#1204381
	 *  +13 lines
	 */
	/*
	 * When argv is empty, add an empty string ("") as argv[0] to
	 * ensure confused userspace programs that start processing
	 * from argv[1] won't end up walking envp. See also
	 * bprm_stack_limits().
	 */
	if (bprm->argc == 0) {
		static const char *dummy_argv0 = "";
		retval = klpp_copy_strings_kernel(1, &dummy_argv0, bprm);
		if (retval < 0)
			goto out;
		bprm->argc = 1;
	}

	would_dump(bprm, bprm->file);

	retval = klpr_exec_binprm(bprm);
	if (retval < 0)
		goto out;

	/* execve succeeded */
	current->fs->in_exec = 0;
	current->in_execve = 0;
	(*klpe_acct_update_integrals)(current);
	(*klpe_task_numa_free)(current, false);
	(*klpe_free_bprm)(bprm);
	kfree(pathbuf);
	(*klpe_putname)(filename);
	if (displaced)
		(*klpe_put_files_struct)(displaced);
	return retval;

out:
	if (bprm->mm) {
		acct_arg_size(bprm, 0);
		mmput(bprm->mm);
	}

out_unmark:
	current->fs->in_exec = 0;
	current->in_execve = 0;

out_free:
	(*klpe_free_bprm)(bprm);
	kfree(pathbuf);

out_files:
	if (displaced)
		(*klpe_reset_files_struct)(displaced);
out_ret:
	(*klpe_putname)(filename);
	return retval;
}

int klpp_do_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };
	return klpp_do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

static int klpp_do_execveat(int fd, struct filename *filename,
		const char __user *const __user *__argv,
		const char __user *const __user *__envp,
		int flags)
{
	struct user_arg_ptr argv = { .ptr.native = __argv };
	struct user_arg_ptr envp = { .ptr.native = __envp };

	return klpp_do_execveat_common(fd, filename, argv, envp, flags);
}

#ifdef CONFIG_COMPAT
static int klpp_compat_do_execve(struct filename *filename,
	const compat_uptr_t __user *__argv,
	const compat_uptr_t __user *__envp)
{
	struct user_arg_ptr argv = {
		.is_compat = true,
		.ptr.compat = __argv,
	};
	struct user_arg_ptr envp = {
		.is_compat = true,
		.ptr.compat = __envp,
	};
	return klpp_do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}

static int klpp_compat_do_execveat(int fd, struct filename *filename,
			      const compat_uptr_t __user *__argv,
			      const compat_uptr_t __user *__envp,
			      int flags)
{
	struct user_arg_ptr argv = {
		.is_compat = true,
		.ptr.compat = __argv,
	};
	struct user_arg_ptr envp = {
		.is_compat = true,
		.ptr.compat = __envp,
	};
	return klpp_do_execveat_common(fd, filename, argv, envp, flags);
}
#endif

__SYSCALL_DEFINEx(3, _klpp_execve,
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp)
{
	return klpp_do_execve((*klpe_getname)(filename), argv, envp);
}

__SYSCALL_DEFINEx(5, _klpp_execveat,
		int, fd, const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp,
		int, flags)
{
	int lookup_flags = (flags & AT_EMPTY_PATH) ? LOOKUP_EMPTY : 0;

	return klpp_do_execveat(fd,
			   (*klpe_getname_flags)(filename, lookup_flags, NULL),
			   argv, envp, flags);
}

#ifdef CONFIG_COMPAT

COMPAT_SYSCALL_DEFINEx(3, _klpp_execve, const char __user *, filename,
	const compat_uptr_t __user *, argv,
	const compat_uptr_t __user *, envp)
{
	return klpp_compat_do_execve((*klpe_getname)(filename), argv, envp);
}

COMPAT_SYSCALL_DEFINEx(5, _klpp_execveat, int, fd,
		       const char __user *, filename,
		       const compat_uptr_t __user *, argv,
		       const compat_uptr_t __user *, envp,
		       int,  flags)
{
	int lookup_flags = (flags & AT_EMPTY_PATH) ? LOOKUP_EMPTY : 0;

	return klpp_compat_do_execveat(fd,
				  (*klpe_getname_flags)(filename, lookup_flags, NULL),
				  argv, envp, flags);
}
#endif



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1204381.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__audit_bprm", (void *)&klpe___audit_bprm },
	{ "__tracepoint_sched_process_exec",
	  (void *)&klpe___tracepoint_sched_process_exec },
	{ "acct_update_integrals", (void *)&klpe_acct_update_integrals },
	{ "do_open_execat", (void *)&klpe_do_open_execat },
	{ "free_bprm", (void *)&klpe_free_bprm },
	{ "getname", (void *)&klpe_getname },
	{ "getname_flags", (void *)&klpe_getname_flags },
	{ "insert_vm_struct", (void *)&klpe_insert_vm_struct },
	{ "mm_alloc", (void *)&klpe_mm_alloc },
	{ "prepare_bprm_creds", (void *)&klpe_prepare_bprm_creds },
	{ "proc_exec_connector", (void *)&klpe_proc_exec_connector },
	{ "ptrace_notify", (void *)&klpe_ptrace_notify },
	{ "put_files_struct", (void *)&klpe_put_files_struct },
	{ "putname", (void *)&klpe_putname },
	{ "reset_files_struct", (void *)&klpe_reset_files_struct },
	{ "sched_exec", (void *)&klpe_sched_exec },
	{ "task_numa_free", (void *)&klpe_task_numa_free },
	{ "unshare_files", (void *)&klpe_unshare_files },
	{ "vm_area_cachep", (void *)&klpe_vm_area_cachep },
};

int livepatch_bsc1204381_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
