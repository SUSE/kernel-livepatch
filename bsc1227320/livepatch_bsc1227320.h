#ifndef _LIVEPATCH_BSC1227320_H
#define _LIVEPATCH_BSC1227320_H

static inline int livepatch_bsc1227320_init(void) { return 0; }
static inline void livepatch_bsc1227320_cleanup(void) {}

struct wiphy;
struct net_device;
struct station_parameters;

int klpp_ieee80211_change_station(struct wiphy *wiphy,
				    struct net_device *dev, const u8 *mac,
				    struct station_parameters *params);

#endif /* _LIVEPATCH_BSC1227320_H */
