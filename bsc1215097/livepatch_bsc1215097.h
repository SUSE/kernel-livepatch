#ifndef _LIVEPATCH_BSC1215097_H
#define _LIVEPATCH_BSC1215097_H

int livepatch_bsc1215097_init(void);
void livepatch_bsc1215097_cleanup(void);

struct sk_buff;
struct nfnl_info;
struct nlattr;

int klpp_nf_tables_delrule(struct sk_buff *skb, const struct nfnl_info *info,
			     const struct nlattr * const nla[]);

#endif /* _LIVEPATCH_BSC1215097_H */
