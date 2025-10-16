#ifndef _LIVEPATCH_BSC1248749_H
#define _LIVEPATCH_BSC1248749_H

#if IS_ENABLED(CONFIG_MAC80211)

struct wiphy;
struct net_device;

int livepatch_bsc1248749_init(void);
void livepatch_bsc1248749_cleanup(void);

int klpp_ieee80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
			const u8 *peer, enum nl80211_tdls_operation oper);

#else /* !IS_ENABLED(CONFIG_MAC80211) */

static inline int livepatch_bsc1248749_init(void) { return 0; }
static inline void livepatch_bsc1248749_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MAC80211) */

#endif /* _LIVEPATCH_BSC1248749_H */
