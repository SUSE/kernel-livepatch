#ifndef _LIVEPATCH_BSC1262404_H
#define _LIVEPATCH_BSC1262404_H

#include <linux/types.h>

static inline int livepatch_bsc1262404_init(void) { return 0; }
static inline void livepatch_bsc1262404_cleanup(void) {}

struct sock;
struct tls_context;
struct work_struct;

int klpp_tls_set_sw_offload(struct sock *sk, int tx);
void klpp_tls_encrypt_done(void *data, int err);
void klpp_tls_sw_cancel_work_tx(struct tls_context *tls_ctx);
void klpp_tx_work_handler(struct work_struct *work);
void klpp_tls_sw_write_space(struct sock *sk, struct tls_context *ctx);

#endif /* _LIVEPATCH_BSC1262404_H */
