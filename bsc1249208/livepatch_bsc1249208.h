#ifndef _LIVEPATCH_BSC1249208_H
#define _LIVEPATCH_BSC1249208_H

#include <linux/types.h>

int livepatch_bsc1249208_init(void);
void livepatch_bsc1249208_cleanup(void);


struct sock;

int klpp_packet_set_ring(struct sock *sk, union tpacket_req_u *req_u, int closing, int tx_ring);
#endif /* _LIVEPATCH_BSC1249208_H */
