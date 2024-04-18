#ifndef _LIVEPATCH_BSC1219435_H
#define _LIVEPATCH_BSC1219435_H

int livepatch_bsc1219435_init(void);
void livepatch_bsc1219435_cleanup(void);


struct nft_ctx;
struct nft_data;
struct nft_data_desc;
struct nlattr;

int klpp_nft_data_init(const struct nft_ctx *ctx,
		  struct nft_data *data, unsigned int size,
		  struct nft_data_desc *desc, const struct nlattr *nla);

#endif /* _LIVEPATCH_BSC1219435_H */
