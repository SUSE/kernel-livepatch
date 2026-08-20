#ifndef _LIVEPATCH_BSC1268624_H
#define _LIVEPATCH_BSC1268624_H

#include <linux/types.h>

static inline int livepatch_bsc1268624_init(void) { return 0; }
static inline void livepatch_bsc1268624_cleanup(void) {}

struct io_cb_cancel_data;
struct io_wq;
struct io_wq_acct;

bool klpp_io_acct_cancel_pending_work(struct io_wq *wq, struct io_wq_acct *acct, struct io_cb_cancel_data *match);

#endif /* _LIVEPATCH_BSC1268624_H */
