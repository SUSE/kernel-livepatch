#ifndef _LIVEPATCH_BSC1201655_H
#define _LIVEPATCH_BSC1201655_H

#if IS_ENABLED(CONFIG_DRM_VGEM)

int livepatch_bsc1201655_init(void);
void livepatch_bsc1201655_cleanup(void);


struct drm_file;
struct drm_device;
struct drm_mode_create_dumb;

int klpp_vgem_gem_dumb_create(struct drm_file *file, struct drm_device *dev,
				struct drm_mode_create_dumb *args);

#else /* !IS_ENABLED(CONFIG_DRM_VGEM) */

static inline int livepatch_bsc1201655_init(void) { return 0; }

static inline void livepatch_bsc1201655_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_VGEM) */
#endif /* _LIVEPATCH_BSC1201655_H */
