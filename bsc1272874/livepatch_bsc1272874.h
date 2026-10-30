#ifndef _LIVEPATCH_BSC1272874_H
#define _LIVEPATCH_BSC1272874_H

#include <linux/types.h>
#include <linux/uio.h>

static inline int livepatch_bsc1272874_init(void) { return 0; }
static inline void livepatch_bsc1272874_cleanup(void) {}

struct iov_iter;

ssize_t klpp_netfs_extract_user_iter(struct iov_iter *orig, size_t orig_len, struct iov_iter *new, iov_iter_extraction_t extraction_flags);

#endif /* _LIVEPATCH_BSC1272874_H */
