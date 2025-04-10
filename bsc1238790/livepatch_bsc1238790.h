#ifndef _LIVEPATCH_BSC1238790_H
#define _LIVEPATCH_BSC1238790_H

#if IS_ENABLED(CONFIG_CRYPTO_DEV_QAT)

int livepatch_bsc1238790_init(void);
void livepatch_bsc1238790_cleanup(void);

int klpp_qat_dh_compute_value(struct kpp_request *req);

#else /* !IS_ENABLED(CONFIG_CRYPTO_DEV_QAT) */

static inline int livepatch_bsc1238790_init(void) { return 0; }
static inline void livepatch_bsc1238790_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_CRYPTO_DEV_QAT) */

#endif /* _LIVEPATCH_BSC1238790_H */
