#ifndef _KLP_SYSCALLS_H
#define _KLP_SYSCALLS_H

#include <linux/version.h>
#include <linux/syscalls.h>

/*
 * For kernels after 4.17.0, syscalls' symbol names as constructed by
 * the kernel's __SYSCALL_DEFINEx macro depend on kernel version and
 * architecture.
*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0)
/* C.f. include/linux/syscalls.h */

#define KLP_SYSCALL_SYM(name) SyS_ ## name

#ifdef CONFIG_COMPAT
/* What comes out of COMPAT_SYSCALL_DEFINEx(). */
#define KLP_COMPAT_SYSCALL_SYM(name) compat_SyS_ ## name

#define KLP_SYSCALL_DECLx(x, sym, ...)			\
	asmlinkage long sym(__MAP(x,__SC_LONG,__VA_ARGS__))

#endif /* CONFIG_COMPAT */


#else /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) */


#if defined(CONFIG_X86_64)
/* C.f. arch/x86/include/asm/syscall_wrapper.h */
#define KLP_SYSCALL_SYM(name) __x64_sys_ ## name

#ifdef CONFIG_IA32_EMULATION
#define KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS 1
/* Compat stub for common syscalls. */
#define KLP_SYSCALL_COMPAT_STUB_SYM(name) __ia32_sys_ ## name
#endif /* CONFIG_IA32_EMULATION */

#ifdef CONFIG_COMPAT
/* What comes out of COMPAT_SYSCALL_DEFINEx(). */
#define KLP_COMPAT_SYSCALL_SYM(name) __ia32_compat_sys_ ## name
#endif /* CONFIG_COMPAT */

#define KLP_SYSCALL_DECLx(x, sym, ...)			\
	asmlinkage long sym(const struct pt_regs *)


#elif defined(CONFIG_S390)
/* C.f. arch/s390/include/asm/syscall_wrapper.h */
#define KLP_SYSCALL_SYM(name) __s390x_sys_ ## name

#ifdef CONFIG_COMPAT
#define KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS 1
/* Compat stub for common syscalls. */
#define KLP_SYSCALL_COMPAT_STUB_SYM(name) __s390_sys_ ## name
#define KLP_COMPAT_SYSCALL_SYM(name) __s390_compat_sys_ ## name
#endif /* CONFIG_COMPAT */

#define KLP_SYSCALL_DECLx(x, sym, ...)			\
	asmlinkage long sym(__MAP(x,__SC_LONG,__VA_ARGS__))


#else
/* C.f. include/linux/syscalls.h */
#define KLP_SYSCALL_SYM(name) __se_sys_ ## name

#ifdef CONFIG_COMPAT
#define KLP_COMPAT_SYSCALL_SYM(name) __se_compat_sys_ ## name
#endif /* CONFIG_COMPAT */

#define KLP_SYSCALL_DECLx(x, sym, ...)			\
	asmlinkage long sym(__MAP(x,__SC_LONG,__VA_ARGS__))


#endif

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0) */
#endif /* _KLP_SYSCALLS_H */
