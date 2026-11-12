#ifndef _LIVEPATCH_BSC1277490_H
#define _LIVEPATCH_BSC1277490_H

#include <linux/types.h>

static inline int livepatch_bsc1277490_init(void) { return 0; }
static inline void livepatch_bsc1277490_cleanup(void) {}

struct sctp_association;
struct sctp_transport;

void klpp_sctp_assoc_rm_peer(struct sctp_association *asoc, struct sctp_transport *peer);

#endif /* _LIVEPATCH_BSC1277490_H */
