#ifndef _LIVEPATCH_BSC1233708_H
#define _LIVEPATCH_BSC1233708_H

struct dm_target;

int livepatch_bsc1233708_init(void);
void livepatch_bsc1233708_cleanup(void);
int klpp_cache_preresume(struct dm_target *ti);

#endif /* _LIVEPATCH_BSC1233708_H */
