#ifndef _LIVEPATCH_BSC1218487_H
#define _LIVEPATCH_BSC1218487_H

static inline int livepatch_bsc1218487_init(void) { return 0; }
static inline void livepatch_bsc1218487_cleanup(void) {}

struct socket;
struct msghdr;
struct scm_cookie;

int klpp___scm_send(struct socket *sock, struct msghdr *msg, struct scm_cookie *p);

#endif /* _LIVEPATCH_BSC1218487_H */
