#ifndef _LIVEPATCH_BSC1271543_H
#define _LIVEPATCH_BSC1271543_H

#include <linux/types.h>

static inline int livepatch_bsc1271543_init(void) { return 0; }
static inline void livepatch_bsc1271543_cleanup(void) {}

struct xfs_bmbt_irec;
struct xfs_inode;

int klpp_xfs_reflink_allocate_cow(struct xfs_inode *ip, struct xfs_bmbt_irec *imap, struct xfs_bmbt_irec *cmap, bool *shared, uint *lockmode, bool convert_now);

#endif /* _LIVEPATCH_BSC1271543_H */
