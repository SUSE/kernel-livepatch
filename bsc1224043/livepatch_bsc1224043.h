#ifndef _LIVEPATCH_BSC1224043_H
#define _LIVEPATCH_BSC1224043_H

static inline int livepatch_bsc1224043_init(void) { return 0; }
static inline void livepatch_bsc1224043_cleanup(void) {}

struct sk_buff;
struct genl_info;

int klpp_seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info);

#endif /* _LIVEPATCH_BSC1224043_H */
