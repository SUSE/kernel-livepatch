#ifndef _LIVEPATCH_BSC1269766_H
#define _LIVEPATCH_BSC1269766_H

#include <linux/types.h>

static inline int livepatch_bsc1269766_init(void) { return 0; }
static inline void livepatch_bsc1269766_cleanup(void) {}

struct crypto_async_request;

int klpp_ccp_aes_rfc3686_complete(struct crypto_async_request *async_req, int ret);
int klpp_ccp_aes_complete(struct crypto_async_request *async_req, int ret);

#endif /* _LIVEPATCH_BSC1269766_H */
