#ifndef _LIVEPATCH_BSC1234854_H
#define _LIVEPATCH_BSC1234854_H

struct rpc_rqst;
struct xdr_stream;
struct nfsd4_callback;

int livepatch_bsc1234854_init(void);
void livepatch_bsc1234854_cleanup(void);
int klpp_nfs4_xdr_dec_cb_notify_lock(struct rpc_rqst *rqstp,
				     struct xdr_stream *xdr,
				     struct nfsd4_callback *cb);
int klpp_nfs4_xdr_dec_cb_layout(struct rpc_rqst *rqstp,
				struct xdr_stream *xdr,
				struct nfsd4_callback *cb);
int klpp_nfs4_xdr_dec_cb_recall(struct rpc_rqst *rqstp,
				struct xdr_stream *xdr,
				struct nfsd4_callback *cb);

#endif /* _LIVEPATCH_BSC1234854_H */
