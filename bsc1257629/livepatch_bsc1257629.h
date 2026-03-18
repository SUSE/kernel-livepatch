#ifndef _LIVEPATCH_BSC1257629_H
#define _LIVEPATCH_BSC1257629_H

#include <linux/types.h>

static inline int livepatch_bsc1257629_init(void) { return 0; }
static inline void livepatch_bsc1257629_cleanup(void) {}

struct rtw_dev;

void klpp_rtw_coex_tdma_timer_base(struct rtw_dev *rtwdev, u8 type);

#endif /* _LIVEPATCH_BSC1257629_H */
