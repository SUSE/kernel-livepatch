#ifndef _LIVEPATCH_BSC1272837_H
#define _LIVEPATCH_BSC1272837_H

#include <linux/types.h>

static inline int livepatch_bsc1272837_init(void) { return 0; }
static inline void livepatch_bsc1272837_cleanup(void) {}

struct esp_info;
struct sk_buff;
struct xfrm_state;

int klpp_esp6_output_head(struct xfrm_state *x, struct sk_buff *skb, struct esp_info *esp);
int klpp_esp_output_head(struct xfrm_state *x, struct sk_buff *skb, struct esp_info *esp);

#endif /* _LIVEPATCH_BSC1272837_H */
