#ifndef _LIVEPATCH_BSC1250280_H
#define _LIVEPATCH_BSC1250280_H

#include <linux/types.h>

int livepatch_bsc1250280_init(void);
static inline void livepatch_bsc1250280_cleanup(void) {}


struct inod;
struct super_bloc;

int klpp_inode_init_always(struct super_block *, struct inode *);
void klpp_module_memfree(void *module_region);

#endif /* _LIVEPATCH_BSC1250280_H */
