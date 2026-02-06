#ifndef _LIVEPATCH_BSC1249205_H
#define _LIVEPATCH_BSC1249205_H

#include <linux/types.h>

int livepatch_bsc1249205_init(void);
static inline void livepatch_bsc1249205_cleanup(void) {}


struct task_struct;

void klpp_run_posix_cpu_timers(struct task_struct *task);
#endif /* _LIVEPATCH_BSC1249205_H */
