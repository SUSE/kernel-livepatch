#ifndef _LIVEPATCH_BSC1251787_H
#define _LIVEPATCH_BSC1251787_H

#include <linux/types.h>

static inline int livepatch_bsc1251787_init(void) { return 0; }
static inline void livepatch_bsc1251787_cleanup(void) {}

struct config_item;

ssize_t klpp_lio_target_nacl_info_show(struct config_item *item, char *page);

#endif /* _LIVEPATCH_BSC1251787_H */
