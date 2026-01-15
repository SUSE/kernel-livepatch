#ifndef _LIVEPATCH_BSC1235815_H
#define _LIVEPATCH_BSC1235815_H

#if defined(CONFIG_S390)

#include <linux/perf_event.h>

int livepatch_bsc1235815_init(void);
static inline void livepatch_bsc1235815_cleanup(void) {}

void klpp_cpumsf_pmu_stop(struct perf_event *event, int flags);

#else

static inline int livepatch_bsc1235815_init(void) {return 0;}
static inline void livepatch_bsc1235815_cleanup(void) {}

#endif

#endif /* _LIVEPATCH_BSC1235815_H */
