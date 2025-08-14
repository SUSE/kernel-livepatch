#ifndef _LIVEPATCH_BSC1245218_H
#define _LIVEPATCH_BSC1245218_H

int livepatch_bsc1245218_init(void);
void livepatch_bsc1245218_cleanup(void);

int klpp_hash_accept(struct socket *sock, struct socket *newsock, int flags,
               bool kern);

#endif /* _LIVEPATCH_BSC1245218_H */
