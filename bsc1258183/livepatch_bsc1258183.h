#ifndef _LIVEPATCH_BSC1258183_H
#define _LIVEPATCH_BSC1258183_H

static inline int livepatch_bsc1258183_init(void) { return 0; }
static inline void livepatch_bsc1258183_cleanup(void) {}

struct nft_ctx;
struct nft_set;
void klpp_nft_map_activate(const struct nft_ctx *ctx, struct nft_set *set);
#endif /* _LIVEPATCH_BSC1258183_H */
