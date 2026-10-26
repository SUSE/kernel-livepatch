#ifndef _LIVEPATCH_BSC1280760_H
#define _LIVEPATCH_BSC1280760_H

#include <linux/types.h>

int livepatch_bsc1280760_init(void);
void livepatch_bsc1280760_cleanup(void);


struct gssx_res_accept_sec_context;
struct rpc_rqst;
struct xdr_stream;

int klpp_gssx_dec_accept_sec_context(struct rpc_rqst *rqstp, struct xdr_stream *xdr, struct gssx_res_accept_sec_context *res);
#endif /* _LIVEPATCH_BSC1280760_H */
