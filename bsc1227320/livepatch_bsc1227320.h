#ifndef _LIVEPATCH_BSC1227320_H
#define _LIVEPATCH_BSC1227320_H

#if IS_ENABLED(CONFIG_MAC80211)

int livepatch_bsc1227320_init(void);
void livepatch_bsc1227320_cleanup(void);

struct wiphy;
struct net_device;
struct station_parameters;

int klpp_ieee80211_change_station(struct wiphy *wiphy,
				    struct net_device *dev, const u8 *mac,
				    struct station_parameters *params);

#else /* !IS_ENABLED(CONFIG_MAC80211) */

static inline int livepatch_bsc1227320_init(void) { return 0; }
static inline void livepatch_bsc1227320_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MAC80211) */

#endif /* _LIVEPATCH_BSC1227320_H */
