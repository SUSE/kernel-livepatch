#ifndef _LIVEPATCH_BSC1270023_H
#define _LIVEPATCH_BSC1270023_H

#include <linux/types.h>

static inline int livepatch_bsc1270023_init(void) { return 0; }
static inline void livepatch_bsc1270023_cleanup(void) {}

struct sctp_association;
struct sctp_bind_addr;
struct sctp_chunk;
struct sctp_endpoint;

int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw, int len, __u16 port, gfp_t gfp);
struct sctp_association *klpp_sctp_unpack_cookie( const struct sctp_endpoint *ep, const struct sctp_association *asoc, struct sctp_chunk *chunk, gfp_t gfp, int *err, struct sctp_chunk **err_chk_p);

#endif /* _LIVEPATCH_BSC1270023_H */
