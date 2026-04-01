#ifndef _LIVEPATCH_BSC1256780_H
#define _LIVEPATCH_BSC1256780_H

struct svc_rqst;
struct rpc_gss_wire_cred;

static inline int livepatch_bsc1256780_init(void) { return 0; }
static inline void livepatch_bsc1256780_cleanup(void) {}

int klpp_svcauth_gss_proxy_init(struct svc_rqst *rqstp,
				struct rpc_gss_wire_cred *gc);

#endif /* _LIVEPATCH_BSC1256780_H */
