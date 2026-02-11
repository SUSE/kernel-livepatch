#ifndef _LIVEPATCH_BSC1249205_H
#define _LIVEPATCH_BSC1249205_H

#include <linux/types.h>

static inline int livepatch_bsc1249205_init(void) { return 0; }
static inline void livepatch_bsc1249205_cleanup(void) {}

void klpp_run_posix_cpu_timers(void);

#endif /* _LIVEPATCH_BSC1249205_H */
