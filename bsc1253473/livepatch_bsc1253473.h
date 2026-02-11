#ifndef _LIVEPATCH_BSC1253473_H
#define _LIVEPATCH_BSC1253473_H

struct svc_rqst;

static inline int livepatch_bsc1253473_init(void) { return 0; }
static inline void livepatch_bsc1253473_cleanup(void) {}
int klpp_svcauth_gss_accept(struct svc_rqst *rqstp);

#endif /* _LIVEPATCH_BSC1253473_H */
