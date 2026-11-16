#ifndef _LIVEPATCH_BSC1277768_H
#define _LIVEPATCH_BSC1277768_H

#include <linux/types.h>

int livepatch_bsc1277768_init(void);
void livepatch_bsc1277768_cleanup(void);


struct sctp_outq;

void klpp_sctp_outq_flush(struct sctp_outq *q, int rtx_timeout, gfp_t gfp);
#endif /* _LIVEPATCH_BSC1277768_H */
