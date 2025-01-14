#ifndef _LIVEPATCH_BSC1226184_H
#define _LIVEPATCH_BSC1226184_H

#if IS_ENABLED(CONFIG_DRM_AMDGPU)

void klpp_mmhub_v3_3_print_l2_protection_fault_status(struct amdgpu_device *adev,
						      uint32_t status);


#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */

static inline int livepatch_bsc1226184_init(void) { return 0; }
static inline void livepatch_bsc1226184_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1226184_H */
