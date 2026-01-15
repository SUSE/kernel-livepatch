#ifndef _LIVEPATCH_BSC1250665_H
#define _LIVEPATCH_BSC1250665_H

#include <linux/types.h>

static inline int livepatch_bsc1250665_init(void) { return 0; }
static inline void livepatch_bsc1250665_cleanup(void) {}

struct sock;

int klpp_sk_stream_wait_memory(struct sock *sk, long *timeo_p);

#endif /* _LIVEPATCH_BSC1250665_H */
