#ifndef _LIVEPATCH_BSC1180032_H
#define _LIVEPATCH_BSC1180032_H

#include "klp_syscalls.h"

int livepatch_bsc1180032_init(void);
static inline void livepatch_bsc1180032_cleanup(void) {}


KLP_SYSCALL_DECLx(4, KLP_SYSCALL_SYM(klpp_epoll_ctl),
		  int, epfd, int, op, int, fd,
		  struct epoll_event __user *, event);

#if defined (KLP_ARCH_HAS_SYSCALL_COMPAT_STUBS)

KLP_SYSCALL_DECLx(4, KLP_SYSCALL_COMPAT_STUB_SYM(klpp_epoll_ctl),
		  int, epfd, int, op, int, fd,
		  struct epoll_event __user *, event);

#endif

#endif /* _LIVEPATCH_BSC1180032_H */
