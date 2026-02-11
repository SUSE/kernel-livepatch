#ifndef _LIVEPATCH_BSC1250314_H
#define _LIVEPATCH_BSC1250314_H

#if IS_ENABLED(CONFIG_MAC80211_HWSIM)

struct sk_buff;
struct genl_info;

int livepatch_bsc1250314_init(void);
void livepatch_bsc1250314_cleanup(void);

int klpp_hwsim_cloned_frame_received_nl(struct sk_buff *skb_2,
					struct genl_info *info);

#else /* !IS_ENABLED(CONFIG_MAC80211_HWSIM) */

static inline int livepatch_bsc1250314_init(void) { return 0; }
static inline void livepatch_bsc1250314_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MAC80211_HWSIM) */

#endif /* _LIVEPATCH_BSC1250314_H */
