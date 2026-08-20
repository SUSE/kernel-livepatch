#ifndef _LIVEPATCH_BSC1270023_H
#define _LIVEPATCH_BSC1270023_H

#include <linux/types.h>

int livepatch_bsc1270023_init(void);
void livepatch_bsc1270023_cleanup(void);

int bsc1270023_net_sctp_sm_make_chunk_init(void);
void bsc1270023_net_sctp_sm_make_chunk_cleanup(void);

int bsc1270023_net_sctp_bind_addr_init(void);
void bsc1270023_net_sctp_bind_addr_cleanup(void);


struct sctp_association;
struct sctp_bind_addr;
struct sctp_chunk;
struct sctp_endpoint;

int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw, int len, __u16 port, gfp_t gfp);
struct sctp_association *klpp_sctp_unpack_cookie(const struct sctp_endpoint *, const struct sctp_association *, struct sctp_chunk *, gfp_t gfp, int *err, struct sctp_chunk **err_chk_p);
#endif /* _LIVEPATCH_BSC1270023_H */
