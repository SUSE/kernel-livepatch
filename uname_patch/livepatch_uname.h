#ifndef _LIVEPATCH_UNAME_H
#define _LIVEPATCH_UNAME_H

#include <linux/utsname.h>
#include "../klp_syscalls.h"

extern KLP_SYSCALL_DECLx(1, KLP_SYSCALL_SYM(klp_newuname),
			 struct new_utsname __user *, name);

#ifdef KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS
extern KLP_SYSCALL_DECLx(1, KLP_SYSCALL_COMPAT_STUB_SYM(klp_newuname),
			 struct new_utsname __user *, name);
#endif /* KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS */

#endif
