#ifndef _LIVEPATCH_BSC1269034_H
#define _LIVEPATCH_BSC1269034_H

#include <linux/types.h>

static inline int livepatch_bsc1269034_init(void) { return 0; }
static inline void livepatch_bsc1269034_cleanup(void) {}

struct ipc_ids;
struct kern_ipc_perm;

int klpp_ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int);

#endif /* _LIVEPATCH_BSC1269034_H */
