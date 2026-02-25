#ifndef _LIVEPATCH_BSC1255577_H
#define _LIVEPATCH_BSC1255577_H

#if IS_ENABLED(CONFIG_ATH10K)

struct ath10k_htc_ep;
struct sk_buff;

int livepatch_bsc1255577_init(void);
void livepatch_bsc1255577_cleanup(void);
void klpp_ath10k_htc_notify_tx_completion(struct ath10k_htc_ep *ep,
				     struct sk_buff *skb);

#else /* !IS_ENABLED(CONFIG_ATH10K) */

static inline int livepatch_bsc1255577_init(void) { return 0; }
static inline void livepatch_bsc1255577_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ATH10K) */

#endif /* _LIVEPATCH_BSC1255577_H */
