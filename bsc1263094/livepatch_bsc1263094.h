#ifndef _LIVEPATCH_BSC1263094_H
#define _LIVEPATCH_BSC1263094_H

#include <linux/types.h>

static inline int livepatch_bsc1263094_init(void) { return 0; }
static inline void livepatch_bsc1263094_cleanup(void) {}

struct ethtool_stats;
struct net_device;

int klpp_iavf_get_sset_count(struct net_device *netdev, int sset);
void klpp_iavf_get_ethtool_stats(struct net_device *netdev, struct ethtool_stats *stats, u64 *data);
void klpp_iavf_get_strings(struct net_device *netdev, u32 sset, u8 *data);

#endif /* _LIVEPATCH_BSC1263094_H */
