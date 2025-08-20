#ifndef _LIVEPATCH_BSC1245805_H
#define _LIVEPATCH_BSC1245805_H

struct net_device;

static inline int livepatch_bsc1245805_init(void) { return 0; }
static inline void livepatch_bsc1245805_cleanup(void) {}
int klpp_ethnl_ops_begin(struct net_device *dev);

#endif /* _LIVEPATCH_BSC1245805_H */
