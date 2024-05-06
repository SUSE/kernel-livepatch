#ifndef _LIVEPATCH_BSC1220211_H
#define _LIVEPATCH_BSC1220211_H

void klpp_tls_encrypt_done(struct crypto_async_request *req, int err);

static inline int livepatch_bsc1220211_init(void) { return 0; }
static inline void livepatch_bsc1220211_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1220211_H */
