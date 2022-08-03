#ifndef _LIVEPATCH_BSC1200605_H
#define _LIVEPATCH_BSC1200605_H

static inline int livepatch_bsc1200605_init(void) { return 0; }
static inline void livepatch_bsc1200605_cleanup(void) {}


#include <linux/types.h>

struct in_device;

int klpp_ip_check_mc_rcu(struct in_device *in_dev, __be32 mc_addr, __be32 src_addr, u8 proto);

#endif /* _LIVEPATCH_BSC1200605_H */
