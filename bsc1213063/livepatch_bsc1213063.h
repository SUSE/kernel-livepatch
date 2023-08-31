#ifndef _LIVEPATCH_BSC1213063_H
#define _LIVEPATCH_BSC1213063_H

#if IS_ENABLED(CONFIG_NF_TABLES)

struct nft_expr;
struct nft_regs;
struct nft_pktinfo;

void klpp_nft_byteorder_eval(const struct nft_expr *expr,
			struct nft_regs *regs, const struct nft_pktinfo *pkt);

#endif /* IS_ENABLED(CONFIG_NF_TABLES) */

static inline int livepatch_bsc1213063_init(void) { return 0; }
static inline void livepatch_bsc1213063_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1213063_H */
