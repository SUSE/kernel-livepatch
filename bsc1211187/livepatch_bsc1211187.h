#ifndef _LIVEPATCH_BSC1211187_H
#define _LIVEPATCH_BSC1211187_H


int livepatch_bsc1211187_init(void);
void livepatch_bsc1211187_cleanup(void);

struct nft_ctx;
struct nft_set;

void nf_tables_activate_set(const struct nft_ctx *ctx, struct nft_set *set);

struct nft_set_binding;
enum nft_trans_phase;

void klpp_nf_tables_deactivate_set(const struct nft_ctx *ctx, struct nft_set *set,
			      struct nft_set_binding *binding,
			      enum nft_trans_phase phase);

struct nft_expr;

void klpp_nft_dynset_activate(const struct nft_ctx *ctx,
				const struct nft_expr *expr);

void klpp_nft_lookup_activate(const struct nft_ctx *ctx,
				const struct nft_expr *expr);

void klpp_nft_objref_map_activate(const struct nft_ctx *ctx,
				    const struct nft_expr *expr);

int bsc1211187_net_netfilter_nf_tables_api_init(void);
void bsc1211187_net_netfilter_nf_tables_api_cleanup(void);

#endif /* _LIVEPATCH_BSC1211187_H */
