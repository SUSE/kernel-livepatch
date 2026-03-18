#ifndef _LIVEPATCH_BSC1255053_H
#define _LIVEPATCH_BSC1255053_H

#include <linux/types.h>

static inline int livepatch_bsc1255053_init(void) { return 0; }
static inline void livepatch_bsc1255053_cleanup(void) {}

struct sock;

bool klpp_mptcp_schedule_work(struct sock *sk);

#endif /* _LIVEPATCH_BSC1255053_H */
