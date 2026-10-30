#ifndef _LIVEPATCH_BSC1280760_H
#define _LIVEPATCH_BSC1280760_H

#include <linux/types.h>

static inline int livepatch_bsc1280760_init(void) { return 0; }
static inline void livepatch_bsc1280760_cleanup(void) {}

struct rpc_rqst;
struct xdr_stream;

int klpp_gssx_dec_accept_sec_context(struct rpc_rqst *rqstp, struct xdr_stream *xdr, void *data);

#endif /* _LIVEPATCH_BSC1280760_H */
