#ifndef _LIVEPATCH_BSC1219432_H
#define _LIVEPATCH_BSC1219432_H

int livepatch_bsc1219432_init(void);
void livepatch_bsc1219432_cleanup(void);


struct nft_ctx;
struct nft_set;
struct nlattr;

int klpp_nft_del_setelem(struct nft_ctx *ctx, struct nft_set *set,
			   const struct nlattr *attr);

#endif /* _LIVEPATCH_BSC1219432_H */
