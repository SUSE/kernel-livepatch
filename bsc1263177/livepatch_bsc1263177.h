#ifndef _LIVEPATCH_BSC1263177_H
#define _LIVEPATCH_BSC1263177_H

#include <linux/types.h>

static inline int livepatch_bsc1263177_init(void) { return 0; }
static inline void livepatch_bsc1263177_cleanup(void) {}

struct work_struct;

void klpp_cgwb_release_workfn(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1263177_H */
