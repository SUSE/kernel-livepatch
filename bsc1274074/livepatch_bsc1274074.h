#ifndef _LIVEPATCH_BSC1274074_H
#define _LIVEPATCH_BSC1274074_H

#include <linux/types.h>

int livepatch_bsc1274074_init(void);
void livepatch_bsc1274074_cleanup(void);


struct sctp_association;
struct sctp_chunk;

struct sctp_chunk *klpp_sctp_process_asconf(struct sctp_association *asoc, struct sctp_chunk *asconf);
#endif /* _LIVEPATCH_BSC1274074_H */
