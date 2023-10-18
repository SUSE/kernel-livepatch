#ifndef _LIVEPATCH_BSC1214812_H
#define _LIVEPATCH_BSC1214812_H

int livepatch_bsc1214812_init(void);
void livepatch_bsc1214812_cleanup(void);

struct net;
struct nft_set;
struct nft_set_elem;

void klpp_nft_pipapo_remove(const struct net *net, const struct nft_set *set,
			      const struct nft_set_elem *elem);

#endif /* _LIVEPATCH_BSC1214812_H */
