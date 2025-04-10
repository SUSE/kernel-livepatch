#ifndef _LIVEPATCH_BSC1238788_H
#define _LIVEPATCH_BSC1238788_H

#if IS_ENABLED(CONFIG_CRYPTO_DEV_QAT)

int livepatch_bsc1238788_init(void);
void livepatch_bsc1238788_cleanup(void);

int klpp_qat_rsa_enc(struct akcipher_request *req);
int klpp_qat_rsa_dec(struct akcipher_request *req);

#else /* !IS_ENABLED(CONFIG_CRYPTO_DEV_QAT) */

static inline int livepatch_bsc1238788_init(void) { return 0; }
static inline void livepatch_bsc1238788_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_CRYPTO_DEV_QAT) */

#endif /* _LIVEPATCH_BSC1238788_H */
