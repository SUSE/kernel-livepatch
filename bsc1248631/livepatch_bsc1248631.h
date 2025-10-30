#ifndef _LIVEPATCH_BSC1248631_H
#define _LIVEPATCH_BSC1248631_H

#include <linux/types.h>

struct ice_hw;

static inline int livepatch_bsc1248631_init(void) { return 0; }
static inline void livepatch_bsc1248631_cleanup(void) {}

enum ice_ddp_state klpp_ice_copy_and_init_pkg(struct ice_hw *hw, const u8 *buf,
					 u32 len);

#endif /* _LIVEPATCH_BSC1248631_H */
