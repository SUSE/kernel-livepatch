#ifndef _LIVEPATCH_BSC1263689_H
#define _LIVEPATCH_BSC1263689_H

#include <linux/types.h>

static inline int livepatch_bsc1263689_init(void) { return 0; }
static inline void livepatch_bsc1263689_cleanup(void) {}

struct aead_request;
struct msghdr;
struct socket;

int klpp_aead_recvmsg(struct socket *sock, struct msghdr *msg, size_t ignored, int flags);
int klpp_crypto_authenc_esn_decrypt(struct aead_request *req);
int klpp_crypto_authenc_esn_decrypt_tail(struct aead_request *req, unsigned int flags);

#endif /* _LIVEPATCH_BSC1263689_H */
