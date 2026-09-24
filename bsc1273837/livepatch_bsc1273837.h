#ifndef _LIVEPATCH_BSC1273837_H
#define _LIVEPATCH_BSC1273837_H

#include <linux/types.h>

static inline int livepatch_bsc1273837_init(void) { return 0; }
static inline void livepatch_bsc1273837_cleanup(void) {}

struct ethtool_stats;
struct net_device;

int klpp_ifb_get_sset_count(struct net_device *dev, int sset);
void klpp_ifb_get_ethtool_stats(struct net_device *dev, struct ethtool_stats *stats, u64 *data);
void klpp_ifb_get_strings(struct net_device *dev, u32 stringset, u8 *buf);

#endif /* _LIVEPATCH_BSC1273837_H */
