#ifndef _LIVEPATCH_BSC1270300_H
#define _LIVEPATCH_BSC1270300_H

#include <linux/types.h>

static inline int livepatch_bsc1270300_init(void) { return 0; }
static inline void livepatch_bsc1270300_cleanup(void) {}

struct epitem;
struct eventpoll;

bool klpp___ep_remove(struct eventpoll *ep, struct epitem *epi, bool force);

#endif /* _LIVEPATCH_BSC1270300_H */
