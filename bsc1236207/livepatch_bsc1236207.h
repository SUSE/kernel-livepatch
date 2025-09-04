#ifndef _LIVEPATCH_BSC1236207_H
#define _LIVEPATCH_BSC1236207_H

static inline int livepatch_bsc1236207_init(void) { return 0; }
static inline void livepatch_bsc1236207_cleanup(void) {}

struct sk_buff;
struct napi_struct;
struct genl_info;

int klpp_netdev_nl_napi_fill_one(struct sk_buff *rsp, struct napi_struct *napi,
                                 const struct genl_info *info);
int klpp_netdev_nl_napi_get_doit(struct sk_buff *skb, struct genl_info *info);
#endif /* _LIVEPATCH_BSC1236207_H */
