#ifndef _LIVEPATCH_BSC1248670_H
#define _LIVEPATCH_BSC1248670_H

#include <linux/types.h>

static inline int livepatch_bsc1248670_init(void) { return 0; }
static inline void livepatch_bsc1248670_cleanup(void) {}

struct sk_msg;
struct sock;

int klpp_bpf_exec_tx_verdict(struct sk_msg *msg, struct sock *sk, bool full_record, u8 record_type, ssize_t *copied, int flags);

#endif /* _LIVEPATCH_BSC1248670_H */
