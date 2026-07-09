#ifndef _LIVEPATCH_BSC1267206_H
#define _LIVEPATCH_BSC1267206_H

#include <linux/types.h>

static inline int livepatch_bsc1267206_init(void) { return 0; }
static inline void livepatch_bsc1267206_cleanup(void) {}

struct net_device;

int klpp_bond_close(struct net_device *bond_dev);

#endif /* _LIVEPATCH_BSC1267206_H */
