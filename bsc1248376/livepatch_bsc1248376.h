#ifndef _LIVEPATCH_BSC1248376_H
#define _LIVEPATCH_BSC1248376_H

#include <linux/types.h>

static inline int livepatch_bsc1248376_init(void) { return 0; }
static inline void livepatch_bsc1248376_cleanup(void) {}

struct svc_rqst;
ssize_t klpp_svc_tcp_read_msg(struct svc_rqst *rqstp, size_t buflen,
                                     size_t seek);
int klpp_svc_tcp_recvfrom(struct svc_rqst *rqstp);
#endif /* _LIVEPATCH_BSC1248376_H */
