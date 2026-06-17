#ifndef _LIVEPATCH_BSC1263088_H
#define _LIVEPATCH_BSC1263088_H

struct socket;

int livepatch_bsc1263088_init(void);
void livepatch_bsc1263088_cleanup(void);

int klpp_packet_release(struct socket *sock);

#endif /* _LIVEPATCH_BSC1263088_H */
