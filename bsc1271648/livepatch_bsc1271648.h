#ifndef _LIVEPATCH_BSC1271648_H
#define _LIVEPATCH_BSC1271648_H

#include <linux/types.h>

static inline int livepatch_bsc1271648_init(void) { return 0; }
static inline void livepatch_bsc1271648_cleanup(void) {}

struct sk_buff;

int klpp_ip6_err_gen_icmpv6_unreach(struct sk_buff *skb, int nhs, int type, unsigned int data_len);

#endif /* _LIVEPATCH_BSC1271648_H */
