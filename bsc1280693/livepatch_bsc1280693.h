#ifndef _LIVEPATCH_BSC1280693_H
#define _LIVEPATCH_BSC1280693_H

#include <linux/types.h>
#include <net/sctp/structs.h>

static inline int livepatch_bsc1280693_init(void) { return 0; }
static inline void livepatch_bsc1280693_cleanup(void) {}

struct sctp_association;
struct sctp_transport;

struct sctp_transport *klpp_sctp_assoc_add_peer(struct sctp_association *asoc, const union sctp_addr *addr, const gfp_t gfp, const int peer_state);

#endif /* _LIVEPATCH_BSC1280693_H */
