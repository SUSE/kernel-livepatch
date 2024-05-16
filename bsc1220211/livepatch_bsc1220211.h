#ifndef _LIVEPATCH_BSC1220211_H
#define _LIVEPATCH_BSC1220211_H


void klpp_tls_encrypt_done(struct crypto_async_request *req, int err);

int livepatch_bsc1220211_init(void);
void livepatch_bsc1220211_cleanup(void);


#endif /* _LIVEPATCH_BSC1220211_H */
