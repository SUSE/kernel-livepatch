#ifndef _LIVEPATCH_BSC1263791_H
#define _LIVEPATCH_BSC1263791_H

#include <linux/types.h>

static inline int livepatch_bsc1263791_init(void) { return 0; }
static inline void livepatch_bsc1263791_cleanup(void) {}

struct nfc_llcp_local;
struct sk_buff;

void klpp_nfc_llcp_rx_skb(struct nfc_llcp_local *local, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1263791_H */
