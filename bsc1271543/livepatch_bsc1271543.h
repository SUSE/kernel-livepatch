#ifndef _LIVEPATCH_BSC1271543_H
#define _LIVEPATCH_BSC1271543_H

#include <linux/types.h>

int livepatch_bsc1271543_init(void);
void livepatch_bsc1271543_cleanup(void);


struct xfs_bmbt_irec;
struct xfs_inode;

int klpp_xfs_reflink_allocate_cow(struct xfs_inode *ip, struct xfs_bmbt_irec *imap, bool *shared, uint *lockmode);
#endif /* _LIVEPATCH_BSC1271543_H */
