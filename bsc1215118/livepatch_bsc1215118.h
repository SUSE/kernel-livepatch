#ifndef _LIVEPATCH_BSC1215118_H
#define _LIVEPATCH_BSC1215118_H

int livepatch_bsc1215118_init(void);
void livepatch_bsc1215118_cleanup(void);

struct sk_buff;
struct nfnl_info;
struct nlattr;

int klpp_nf_tables_newrule(struct sk_buff *skb, const struct nfnl_info *info,
			     const struct nlattr * const nla[]);

#endif /* _LIVEPATCH_BSC1215118_H */
