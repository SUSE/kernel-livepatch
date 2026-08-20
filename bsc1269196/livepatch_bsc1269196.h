#ifndef _LIVEPATCH_BSC1269196_H
#define _LIVEPATCH_BSC1269196_H

#include <linux/types.h>

static inline int livepatch_bsc1269196_init(void) { return 0; }
static inline void livepatch_bsc1269196_cleanup(void) {}

struct af_alg_control;
struct msghdr;

int klpp_af_alg_cmsg_send(struct msghdr *msg, struct af_alg_control *con);

#endif /* _LIVEPATCH_BSC1269196_H */
