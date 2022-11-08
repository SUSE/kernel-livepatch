#ifndef _LIVEPATCH_BSC1204381_H
#define _LIVEPATCH_BSC1204381_H

int livepatch_bsc1204381_init(void);
static inline void livepatch_bsc1204381_cleanup(void) {}


struct linux_binprm;
struct filename;

int klpp_remove_arg_zero(struct linux_binprm *);

int klpp_copy_strings_kernel(int argc, const char *const *argv,
			       struct linux_binprm *bprm);

int klpp_do_execve(struct filename *,
		     const char __user * const __user *,
		     const char __user * const __user *);


#include <linux/compat.h>
#include "klp_syscalls.h"

KLP_SYSCALL_DECLx(3, KLP_SYSCALL_SYM(klpp_execve),
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp);

#ifdef KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS
KLP_SYSCALL_DECLx(3, KLP_SYSCALL_COMPAT_STUB_SYM(klpp_execve),
		const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp);
#endif

KLP_SYSCALL_DECLx(5, KLP_SYSCALL_SYM(klpp_execveat),
		int, fd, const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp,
		int, flags);

#ifdef KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS
KLP_SYSCALL_DECLx(5, KLP_SYSCALL_COMPAT_STUB_SYM(klpp_execveat),
		int, fd, const char __user *, filename,
		const char __user *const __user *, argv,
		const char __user *const __user *, envp,
		int, flags);
#endif

#ifdef CONFIG_COMPAT

KLP_SYSCALL_DECLx(3, KLP_COMPAT_SYSCALL_SYM(klpp_execve),
	const char __user *, filename,
	const compat_uptr_t __user *, argv,
	const compat_uptr_t __user *, envp);

KLP_SYSCALL_DECLx(5, KLP_COMPAT_SYSCALL_SYM(klpp_execveat), int, fd,
		       const char __user *, filename,
		       const compat_uptr_t __user *, argv,
		       const compat_uptr_t __user *, envp,
		       int,  flags);

#endif

#endif /* _LIVEPATCH_BSC1204381_H */
