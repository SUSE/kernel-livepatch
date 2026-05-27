#ifndef _LIVEPATCH_BSC1260563_H
#define _LIVEPATCH_BSC1260563_H

#if IS_ENABLED(CONFIG_DRM_VMWGFX)

#include <linux/types.h>

typedef u32 uint32;

/* klp-ccp: from drivers/gpu/drm/vmwgfx/device_include/svga_reg.h */
typedef uint32 SVGAMobId;

typedef struct SVGAGuestPtr {
	uint32 gmrId;
	uint32 offset;
} SVGAGuestPtr;

struct vmw_private;
struct vmw_sw_context;
struct vmw_bo;

int klpp_vmw_translate_mob_ptr(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGAMobId *id,
				 struct vmw_bo **vmw_bo_p);

int klpp_vmw_translate_guest_ptr(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   SVGAGuestPtr *ptr,
				   struct vmw_bo **vmw_bo_p);

#endif

static inline int livepatch_bsc1260563_init(void) { return 0; }
static inline void livepatch_bsc1260563_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1260563_H */
