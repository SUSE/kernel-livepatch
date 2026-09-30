#ifndef _LIVEPATCH_BSC1267370_H
#define _LIVEPATCH_BSC1267370_H

#include <linux/types.h>

static inline int livepatch_bsc1267370_init(void) { return 0; }
static inline void livepatch_bsc1267370_cleanup(void) {}

struct xfrm_state;

int klpp___xfrm_state_delete(struct xfrm_state *x);

#endif /* _LIVEPATCH_BSC1267370_H */
