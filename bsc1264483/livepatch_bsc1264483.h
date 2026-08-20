#ifndef _LIVEPATCH_BSC1264483_H
#define _LIVEPATCH_BSC1264483_H

#include <linux/types.h>

static inline int livepatch_bsc1264483_init(void) { return 0; }
static inline void livepatch_bsc1264483_cleanup(void) {}

struct work_struct;

void klpp_brcmf_fweh_event_worker(struct work_struct *work);

#endif /* _LIVEPATCH_BSC1264483_H */
