#ifndef _LIVEPATCH_BSC1272139_H
#define _LIVEPATCH_BSC1272139_H

#include <linux/types.h>

static inline int livepatch_bsc1272139_init(void) { return 0; }
static inline void livepatch_bsc1272139_cleanup(void) {}

struct ceph_crypto_key;

int klpp___ceph_x_decrypt(struct ceph_crypto_key *secret, void *p, int ciphertext_len);

#endif /* _LIVEPATCH_BSC1272139_H */
