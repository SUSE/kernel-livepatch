#ifndef _LIVEPATCH_BSC1277409_H
#define _LIVEPATCH_BSC1277409_H

#include <linux/types.h>

static inline int livepatch_bsc1277409_init(void) { return 0; }
static inline void livepatch_bsc1277409_cleanup(void) {}

struct srpt_rdma_ch;
struct srpt_recv_ioctx;

bool klpp_srpt_handle_new_iu(struct srpt_rdma_ch *ch, struct srpt_recv_ioctx *recv_ioctx);

#endif /* _LIVEPATCH_BSC1277409_H */
