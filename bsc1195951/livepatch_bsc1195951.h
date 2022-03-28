#ifndef _LIVEPATCH_BSC1195951_H
#define _LIVEPATCH_BSC1195951_H

#if IS_ENABLED(CONFIG_DRM_VMWGFX)

#include <linux/types.h>

struct drm_file;
struct vmw_private;
struct drm_vmw_fence_rep;
struct vmw_fence_obj;

int klpp_vmw_execbuf_process(struct drm_file *file_priv,
				struct vmw_private *dev_priv,
				void __user *user_commands,
				void *kernel_commands,
				uint32_t command_size,
				uint64_t throttle_us,
				uint32_t dx_context_handle,
				struct drm_vmw_fence_rep __user
				*user_fence_rep,
				struct vmw_fence_obj **out_fence,
				uint32_t flags);


int livepatch_bsc1195951_init(void);
void livepatch_bsc1195951_cleanup(void);


#else /* !IS_ENABLED(CONFIG_DRM_VMWGFX) */
static inline int livepatch_bsc1195951_init(void) { return 0; }
static inline void livepatch_bsc1195951_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */
#endif /* _LIVEPATCH_BSC1195951_H */
