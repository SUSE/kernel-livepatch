#ifndef _LIVEPATCH_BSC1249207_H
#define _LIVEPATCH_BSC1249207_H

struct sock;
struct sockaddr_vm;

int livepatch_bsc1249207_init(void);
void livepatch_bsc1249207_cleanup(void);
int klpp___vsock_bind(struct sock *sk, struct sockaddr_vm *addr);

#endif /* _LIVEPATCH_BSC1249207_H */
