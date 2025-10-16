#ifndef _LIVEPATCH_BSC1249534_H
#define _LIVEPATCH_BSC1249534_H

static inline int livepatch_bsc1249534_init(void) { return 0; }
static inline void livepatch_bsc1249534_cleanup(void) {}

struct sk_buff;
struct nfnl_info;
struct nlattr;

int klpp_nf_tables_newflowtable(struct sk_buff *skb,
                                const struct nfnl_info *info,
                                const struct nlattr *const nla[]);

int klpp_nf_tables_newchain(struct sk_buff *skb, const struct nfnl_info *info,
                            const struct nlattr *const nla[]);

#endif /* _LIVEPATCH_BSC1249534_H */
