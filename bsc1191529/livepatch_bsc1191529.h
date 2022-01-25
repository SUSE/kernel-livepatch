#ifndef _LIVEPATCH_BSC1191529_H
#define _LIVEPATCH_BSC1191529_H

#if IS_ENABLED(CONFIG_ATH9K)

int livepatch_bsc1191529_init(void);
void livepatch_bsc1191529_cleanup(void);


struct ath_common;
struct ieee80211_key_conf;
struct ieee80211_hw;

void klpp_ath_key_delete(struct ath_common *common, struct ieee80211_key_conf *key);

void klpp_ath9k_stop(struct ieee80211_hw *hw);

#else /* !IS_ENABLED(CONFIG_ATH9K) */

static inline int livepatch_bsc1191529_init(void) { return 0; }

static inline void livepatch_bsc1191529_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ATH9K) */
#endif /* _LIVEPATCH_BSC1191529_H */
