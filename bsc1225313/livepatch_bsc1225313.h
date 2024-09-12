#ifndef _LIVEPATCH_BSC1225313_H
#define _LIVEPATCH_BSC1225313_H

#if IS_ENABLED(CONFIG_DRM_AMDGPU)

#include <linux/types.h>

struct amdgpu_device;
struct ttm_buffer_object;

void klpp_amdgpu_ttm_gart_bind(struct amdgpu_device *adev,
				 struct ttm_buffer_object *tbo,
				 uint64_t flags);

#endif /* IS_ENABLED(CONFIG_DRM_AMDGPU) */

static inline int livepatch_bsc1225313_init(void) { return 0; }
static inline void livepatch_bsc1225313_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1225313_H */
