#ifndef _LIVEPATCH_BSC1280285_H
#define _LIVEPATCH_BSC1280285_H

#include <linux/types.h>

int livepatch_bsc1280285_init(void);
void livepatch_bsc1280285_cleanup(void);


struct nfsd4_layoutget;
struct xdr_stream;

__be32 klpp_nfsd4_ff_encode_layoutget(struct xdr_stream *xdr, struct nfsd4_layoutget *lgp);
#endif /* _LIVEPATCH_BSC1280285_H */
