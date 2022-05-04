#ifndef _LIVEPATCH_BSC1195950_H
#define _LIVEPATCH_BSC1195950_H

#if IS_ENABLED(CONFIG_DRM_I915)

int livepatch_bsc1195950_init(void);
void livepatch_bsc1195950_cleanup(void);


struct i915_vma;
enum i915_cache_level;
struct drm_i915_gem_object;
enum i915_mm_subclass;

int klpp_i915_vma_bind(struct i915_vma *vma, enum i915_cache_level cache_level,
		  u32 flags);

void klpp___i915_gem_object_put_pages(struct drm_i915_gem_object *obj,
				 enum i915_mm_subclass subclass);

#else /* !IS_ENABLED(CONFIG_DRM_I915) */

static inline int livepatch_bsc1195950_init(void) { return 0; }

static inline void livepatch_bsc1195950_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_I915) */
#endif /* _LIVEPATCH_BSC1195950_H */
