#ifndef _LIVEPATCH_BSC1269885_H
#define _LIVEPATCH_BSC1269885_H

#include <linux/types.h>

static inline int livepatch_bsc1269885_init(void) { return 0; }
static inline void livepatch_bsc1269885_cleanup(void) {}

struct cfg80211_beacon_data;
struct cfg80211_registered_device;
struct netlink_ext_ack;
struct nlattr;

int klpp_nl80211_parse_beacon(struct cfg80211_registered_device *rdev, struct nlattr *attrs[], struct cfg80211_beacon_data *bcn, struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1269885_H */
