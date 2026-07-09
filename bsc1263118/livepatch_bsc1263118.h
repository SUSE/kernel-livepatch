#ifndef _LIVEPATCH_BSC1263118_H
#define _LIVEPATCH_BSC1263118_H

#include <linux/types.h>

static inline int livepatch_bsc1263118_init(void) { return 0; }
static inline void livepatch_bsc1263118_cleanup(void) {}

struct canfd_frame;
struct cgw_csum_crc8;

void klpp_cgw_csum_crc8_rel(struct canfd_frame *cf, struct cgw_csum_crc8 *crc8);

#endif /* _LIVEPATCH_BSC1263118_H */
