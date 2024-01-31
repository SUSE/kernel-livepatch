#ifndef _LIVEPATCH_BSC1217522_H
#define _LIVEPATCH_BSC1217522_H

int livepatch_bsc1217522_init(void);
void livepatch_bsc1217522_cleanup(void);

struct sk_msg;
struct sock;

int klpp_bpf_exec_tx_verdict(struct sk_msg *msg, struct sock *sk,
			       bool full_record, u8 record_type,
			       ssize_t *copied, int flags);

#endif /* _LIVEPATCH_BSC1217522_H */
