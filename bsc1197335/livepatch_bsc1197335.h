#ifndef _LIVEPATCH_BSC1197335_H
#define _LIVEPATCH_BSC1197335_H

int livepatch_bsc1197335_init(void);
void livepatch_bsc1197335_cleanup(void);


struct nft_pktinfo;

unsigned int klpp_nft_do_chain(struct nft_pktinfo *pkt, void *priv);

#endif /* _LIVEPATCH_BSC1197335_H */
