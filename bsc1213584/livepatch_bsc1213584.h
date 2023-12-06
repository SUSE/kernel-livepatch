#ifndef _LIVEPATCH_BSC1213584_H
#define _LIVEPATCH_BSC1213584_H

struct net;
struct nft_ctx;
struct nft_chain;
struct nft_expr;
struct nlattr;

enum nfnl_abort_action;


void klpp_nft_chain_trans_bind(const struct nft_ctx *ctx, struct nft_chain *chain);
int klpp_nf_tables_bind_chain(const struct nft_ctx *ctx, struct nft_chain *chain);
int klpp___nf_tables_abort(struct net *net, enum nfnl_abort_action action);
int klpp_nft_immediate_init(const struct nft_ctx *ctx,
			      const struct nft_expr *expr,
			      const struct nlattr * const tb[]);

int bsc1213584_net_netfilter_nf_tables_api_init(void);
int bsc1213584_net_netfilter_nft_immediate_init(void);
void bsc1213584_net_netfilter_nf_tables_api_cleanup(void);
void bsc1213584_net_netfilter_nft_immediate_cleanup(void);

int livepatch_bsc1213584_init(void);
void livepatch_bsc1213584_cleanup(void);


#endif /* _LIVEPATCH_BSC1213584_H */
