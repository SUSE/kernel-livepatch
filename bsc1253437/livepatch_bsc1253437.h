#ifndef _LIVEPATCH_BSC1253437_H
#define _LIVEPATCH_BSC1253437_H

#include <linux/types.h>
#include <net/sctp/sctp.h>

int livepatch_bsc1253437_init(void);
void livepatch_bsc1253437_cleanup(void);

int bsc1253437_net_sctp_bind_addr_init(void);
void bsc1253437_net_sctp_bind_addr_cleanup(void);

int bsc1253437_net_sctp_sm_make_chunk_init(void);
void bsc1253437_net_sctp_sm_make_chunk_cleanup(void);

int bsc1253437_net_sctp_sm_statefuns_init(void);
void bsc1253437_net_sctp_sm_statefuns_cleanup(void);


struct sctp_association;
struct sctp_bind_addr;
struct sctp_chunk;
struct sctp_endpoint;

int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw, int len, __u16 port, gfp_t gfp);
sctp_ierror_t klpp_sctp_sf_authenticate( const struct sctp_association *asoc, struct sctp_chunk *chunk);
struct sctp_association *klpp_sctp_unpack_cookie(const struct sctp_endpoint *, const struct sctp_association *, struct sctp_chunk *, gfp_t gfp, int *err, struct sctp_chunk **err_chk_p);
#endif /* _LIVEPATCH_BSC1253437_H */
