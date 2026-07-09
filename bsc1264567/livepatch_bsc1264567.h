#ifndef _LIVEPATCH_BSC1264567_H
#define _LIVEPATCH_BSC1264567_H

#include <linux/types.h>

static inline int livepatch_bsc1264567_init(void) { return 0; }
static inline void livepatch_bsc1264567_cleanup(void) {}

struct ib_mr;
struct ib_pd;
struct ib_udata;

struct ib_mr *klpp_irdma_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 len, u64 virt, int new_access, struct ib_pd *new_pd, struct ib_udata *udata);

#endif /* _LIVEPATCH_BSC1264567_H */
