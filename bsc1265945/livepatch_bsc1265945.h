#ifndef _LIVEPATCH_BSC1265945_H
#define _LIVEPATCH_BSC1265945_H

#include <linux/types.h>

static inline int livepatch_bsc1265945_init(void) { return 0; }
static inline void livepatch_bsc1265945_cleanup(void) {}

struct iov_iter;
struct rds_message;

int klpp_rds_message_copy_from_user(struct rds_message *rm, struct iov_iter *from, bool zcopy);

#endif /* _LIVEPATCH_BSC1265945_H */
