#ifndef _LIVEPATCH_BSC1231196_H
#define _LIVEPATCH_BSC1231196_H

static inline int livepatch_bsc1231196_init(void) { return 0; }
static inline void livepatch_bsc1231196_cleanup(void) {}

#if IS_ENABLED(CONFIG_DRM_AMDGPU)
struct clk_mgr;
void klpp_rn_notify_wm_ranges(struct clk_mgr *clk_mgr_base);
#endif

#endif /* _LIVEPATCH_BSC1231196_H */
