#ifndef _LIVEPATCH_BSC1267723_H
#define _LIVEPATCH_BSC1267723_H

#include <linux/types.h>

static inline int livepatch_bsc1267723_init(void) { return 0; }
static inline void livepatch_bsc1267723_cleanup(void) {}

void __noreturn klpp_make_task_dead(int signr);

#endif /* _LIVEPATCH_BSC1267723_H */
