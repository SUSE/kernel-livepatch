#ifndef _LIVEPATCH_BSC1272679_H
#define _LIVEPATCH_BSC1272679_H

#include <linux/types.h>

static inline int livepatch_bsc1272679_init(void) { return 0; }
static inline void livepatch_bsc1272679_cleanup(void) {}

struct sctp_association;

int klpp_sctp_wait_for_connect(struct sctp_association *asoc, long *timeo_p);

#endif /* _LIVEPATCH_BSC1272679_H */
