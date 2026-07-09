#ifndef _LIVEPATCH_BSC1262759_H
#define _LIVEPATCH_BSC1262759_H

static inline int livepatch_bsc1262759_init(void) { return 0; }
static inline void livepatch_bsc1262759_cleanup(void) {}

struct sock;
int klpp_tls_push_record(struct sock *sk, int flags,
			   unsigned char record_type);
#endif /* _LIVEPATCH_BSC1262759_H */
