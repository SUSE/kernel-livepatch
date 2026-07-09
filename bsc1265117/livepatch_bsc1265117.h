#ifndef _LIVEPATCH_BSC1265117_H
#define _LIVEPATCH_BSC1265117_H

#include <linux/types.h>

static inline int livepatch_bsc1265117_init(void) { return 0; }
static inline void livepatch_bsc1265117_cleanup(void) {}

struct io_kiocb;

bool klpp_io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);

#endif /* _LIVEPATCH_BSC1265117_H */
