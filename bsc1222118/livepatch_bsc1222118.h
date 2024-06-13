#ifndef _LIVEPATCH_BSC1222118_H
#define _LIVEPATCH_BSC1222118_H


struct nft_expr;
struct nft_regs;
struct nft_pktinfo;

void klpp_nft_exthdr_ipv6_eval(const struct nft_expr *expr,
				 struct nft_regs *regs,
				 const struct nft_pktinfo *pkt);
void klpp_nft_exthdr_tcp_eval(const struct nft_expr *expr,
				struct nft_regs *regs,
				const struct nft_pktinfo *pkt);

static inline int livepatch_bsc1222118_init(void) { return 0; }
static inline void livepatch_bsc1222118_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1222118_H */
