#ifndef _LIVEPATCH_BSC1256780_H
#define _LIVEPATCH_BSC1256780_H

#include <linux/types.h>

struct svc_rqst;
struct rpc_gss_wire_cred;

int livepatch_bsc1256780_init(void);
void livepatch_bsc1256780_cleanup(void);

int klpp_svcauth_gss_proxy_init(struct svc_rqst *rqstp,
			struct rpc_gss_wire_cred *gc, __be32 *authp);

#endif /* _LIVEPATCH_BSC1256780_H */
