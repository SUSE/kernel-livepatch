#ifndef _LIVEPATCH_BSC1213064_H
#define _LIVEPATCH_BSC1213064_H

int livepatch_bsc1213064_init(void);
void livepatch_bsc1213064_cleanup(void);

struct sk_buff;
struct nfnl_info;
struct nlattr;

int klpp_nf_tables_newrule(struct sk_buff *skb, const struct nfnl_info *info,
			     const struct nlattr * const nla[]);

struct nft_ctx;
struct nft_data;
struct nft_data_desc;

int klpp_nft_data_init(const struct nft_ctx *ctx,
		  struct nft_data *data, unsigned int size,
		  struct nft_data_desc *desc, const struct nlattr *nla);

#endif /* _LIVEPATCH_BSC1213064_H */
