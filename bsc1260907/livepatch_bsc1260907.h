#ifndef _LIVEPATCH_BSC1260907_H
#define _LIVEPATCH_BSC1260907_H

#include <linux/types.h>

static inline int livepatch_bsc1260907_init(void) { return 0; }
static inline void livepatch_bsc1260907_cleanup(void) {}

struct nft_ctx;
struct nft_set;

void klpp_nft_map_activate(const struct nft_ctx *ctx, struct nft_set *set);
void klpp_nft_map_deactivate(const struct nft_ctx *ctx, struct nft_set *set);

#endif /* _LIVEPATCH_BSC1260907_H */
