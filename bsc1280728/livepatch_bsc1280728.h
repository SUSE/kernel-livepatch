#ifndef _LIVEPATCH_BSC1280728_H
#define _LIVEPATCH_BSC1280728_H

#include <linux/types.h>

static inline int livepatch_bsc1280728_init(void) { return 0; }
static inline void livepatch_bsc1280728_cleanup(void) {}

struct xdr_buf;

void klpp_xdr_buf_trim(struct xdr_buf *buf, unsigned int len);

#endif /* _LIVEPATCH_BSC1280728_H */
