#ifndef _LIVEPATCH_BSC1207190_H
#define _LIVEPATCH_BSC1207190_H

#if IS_ENABLED(CONFIG_SND)

int livepatch_bsc1207190_init(void);
void livepatch_bsc1207190_cleanup(void);

#include "../klp_syscalls.h"

KLP_SYSCALL_DECLx(3, KLP_COMPAT_SYSCALL_SYM(klpp_ioctl), unsigned int, fd, unsigned int, cmd,
		       compat_ulong_t, arg32);

#else /* !IS_ENABLED(CONFIG_SND) */

static inline int livepatch_bsc1207190_init(void) { return 0; }

static inline void livepatch_bsc1207190_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_SND) */
#endif /* _LIVEPATCH_BSC1207190_H */
