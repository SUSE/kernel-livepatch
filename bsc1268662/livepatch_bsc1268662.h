#ifndef _LIVEPATCH_BSC1268662_H
#define _LIVEPATCH_BSC1268662_H

#include <linux/types.h>

static inline int livepatch_bsc1268662_init(void) { return 0; }
static inline void livepatch_bsc1268662_cleanup(void) {}

struct net;

int klpp_vti6_init_net(struct net *net);

#endif /* _LIVEPATCH_BSC1268662_H */
