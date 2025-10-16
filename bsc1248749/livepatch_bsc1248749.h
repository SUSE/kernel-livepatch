#ifndef _LIVEPATCH_BSC1248749_H
#define _LIVEPATCH_BSC1248749_H

struct wiphy;
struct net_device;

static inline int livepatch_bsc1248749_init(void) { return 0; }
static inline void livepatch_bsc1248749_cleanup(void) {}
int klpp_ieee80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
			const u8 *peer, enum nl80211_tdls_operation oper);

#endif /* _LIVEPATCH_BSC1248749_H */
