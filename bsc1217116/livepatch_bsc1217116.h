#ifndef _LIVEPATCH_BSC1217116_H
#define _LIVEPATCH_BSC1217116_H

#if IS_ENABLED(CONFIG_DRM_QXL)

#include <linux/types.h>

int livepatch_bsc1217116_init(void);
void livepatch_bsc1217116_cleanup(void);

int bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_init(void);
void bsc1217116_drivers_gpu_drm_qxl_qxl_dumb_cleanup(void);

int bsc1217116_drivers_gpu_drm_qxl_qxl_gem_init(void);
void bsc1217116_drivers_gpu_drm_qxl_qxl_gem_cleanup(void);

int bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_init(void);
void bsc1217116_drivers_gpu_drm_qxl_qxl_ioctl_cleanup(void);

struct drm_file;
struct drm_device;
struct drm_mode_create_dumb;

int klpp_qxl_mode_dumb_create(struct drm_file *file_priv,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args);

struct qxl_device;
struct qxl_surface;
struct drm_gem_object;

int klpp_qxl_gem_object_create_with_handle(struct qxl_device *qdev,
				      struct drm_file *file_priv,
				      u32 domain,
				      size_t size,
				      struct qxl_surface *surf,
				      struct drm_gem_object **gobj,
				      uint32_t *handle);

int klpp_qxl_alloc_ioctl(struct drm_device *dev, void *data,
			   struct drm_file *file_priv);

int klpp_qxl_alloc_surf_ioctl(struct drm_device *dev, void *data,
				struct drm_file *file);

int klpp_qxl_gem_object_create_with_handle(struct qxl_device *qdev,
				      struct drm_file *file_priv,
				      u32 domain,
				      size_t size,
				      struct qxl_surface *surf,
				      struct drm_gem_object **gobj,
				      uint32_t *handle);

#else /* IS_ENABLED(CONFIG_DRM_QXL) */

static inline int livepatch_bsc1217116_init(void) { return 0; }
static inline void livepatch_bsc1217116_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_QXL) */

#endif /* _LIVEPATCH_BSC1217116_H */
