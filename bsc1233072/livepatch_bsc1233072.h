#ifndef _LIVEPATCH_BSC1233072_H
#define _LIVEPATCH_BSC1233072_H

static inline int livepatch_bsc1233072_init(void) { return 0; }
static inline void livepatch_bsc1233072_cleanup(void) {}

struct sock;
struct request_sock;
void klpp_inet_csk_reqsk_queue_drop(struct sock *sk, struct request_sock *req);
void klpp_reqsk_timer_handler(unsigned long data);
#endif /* _LIVEPATCH_BSC1233072_H */
