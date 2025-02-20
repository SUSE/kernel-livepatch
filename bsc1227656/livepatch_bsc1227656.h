#ifndef _LIVEPATCH_BSC1227656_H
#define _LIVEPATCH_BSC1227656_H

#include <net/sock.h>
#include <net/strparser.h>

int livepatch_bsc1227656_init(void);
void livepatch_bsc1227656_cleanup(void);

int klpp_tls_sw_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
                        int nonblock, int flags, int *addr_len);
ssize_t klpp_tls_sw_splice_read(struct socket *sock, loff_t *ppos,
                                struct pipe_inode_info *pipe, size_t len,
                                unsigned int flags);
int klpp_tls_tx_records(struct sock *sk, int flags);
void klpp_tls_decrypt_done(struct crypto_async_request *req, int err);
void klpp_tls_encrypt_done(struct crypto_async_request *req, int err);
int klpp_tls_push_record(struct sock *sk, int flags, unsigned char record_type);
int klpp_decrypt_skb_update(struct sock *sk, struct sk_buff *skb,
                            struct iov_iter *dest, int *chunk, bool *zc);
int klpp_tls_read_size(struct strparser *strp, struct sk_buff *skb);

int klpp_tls_push_data(struct sock *sk, struct iov_iter *msg_iter, size_t size,
                       int flags, unsigned char record_type);
#endif /* _LIVEPATCH_BSC1227656_H */
