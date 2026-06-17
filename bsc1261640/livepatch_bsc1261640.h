#ifndef _LIVEPATCH_BSC1261640_H
#define _LIVEPATCH_BSC1261640_H

struct nfsd4_compoundres;
struct nfsd4_op;

int livepatch_bsc1261640_init(void);
void livepatch_bsc1261640_cleanup(void);
void klpp_nfsd4_encode_operation(struct nfsd4_compoundres *resp, struct nfsd4_op *op);

#endif /* _LIVEPATCH_BSC1261640_H */
