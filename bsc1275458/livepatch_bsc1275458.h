#ifndef _LIVEPATCH_BSC1275458_H
#define _LIVEPATCH_BSC1275458_H

#include <linux/types.h>

static inline int livepatch_bsc1275458_init(void) { return 0; }
static inline void livepatch_bsc1275458_cleanup(void) {}

struct in_device;

void klpp_ip_mc_destroy_dev(struct in_device *in_dev);

#endif /* _LIVEPATCH_BSC1275458_H */
