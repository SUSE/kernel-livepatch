#ifndef _LIVEPATCH_BSC1212348_H
#define _LIVEPATCH_BSC1212348_H

#if IS_ENABLED(CONFIG_DRM_VMWGFX)

#include <linux/types.h>

int livepatch_bsc1212348_init(void);
void livepatch_bsc1212348_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_bo_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_execbuf_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_gem_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_kms_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_kms_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_overlay_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_overlay_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_shader_cleanup(void);

int bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface_init(void);
void bsc1212348_drivers_gpu_drm_vmwgfx_vmwgfx_surface_cleanup(void);

struct drm_file;
struct vmw_buffer_object;

int klpp_vmw_user_bo_lookup(struct drm_file *filp,
			      uint32_t handle,
			      struct vmw_buffer_object **out);

struct drm_device;

int klpp_vmw_user_bo_synccpu_ioctl(struct drm_device *dev, void *data,
			      struct drm_file *file_priv);

struct drm_mode_create_dumb;

int klpp_vmw_dumb_create(struct drm_file *file_priv,
		    struct drm_device *dev,
		    struct drm_mode_create_dumb *args);

struct vmw_private;
struct vmw_sw_context;

typedef u32 uint32;

typedef struct {
	uint32 id;
	uint32 size;
} SVGA3dCmdHeader;

int klpp_vmw_cmd_dx_bind_query(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGA3dCmdHeader *header);

int klpp_vmw_cmd_end_gb_query(struct vmw_private *dev_priv,
				struct vmw_sw_context *sw_context,
				SVGA3dCmdHeader *header);

int klpp_vmw_cmd_end_query(struct vmw_private *dev_priv,
			     struct vmw_sw_context *sw_context,
			     SVGA3dCmdHeader *header);

int klpp_vmw_cmd_wait_gb_query(struct vmw_private *dev_priv,
				 struct vmw_sw_context *sw_context,
				 SVGA3dCmdHeader *header);

int klpp_vmw_cmd_wait_query(struct vmw_private *dev_priv,
			      struct vmw_sw_context *sw_context,
			      SVGA3dCmdHeader *header);

int klpp_vmw_cmd_dma(struct vmw_private *dev_priv,
		       struct vmw_sw_context *sw_context,
		       SVGA3dCmdHeader *header);

int klpp_vmw_cmd_bind_gb_surface(struct vmw_private *dev_priv,
				   struct vmw_sw_context *sw_context,
				   SVGA3dCmdHeader *header);

int klpp_vmw_cmd_bind_gb_shader(struct vmw_private *dev_priv,
				  struct vmw_sw_context *sw_context,
				  SVGA3dCmdHeader *header);

int klpp_vmw_cmd_dx_bind_shader(struct vmw_private *dev_priv,
				  struct vmw_sw_context *sw_context,
				  SVGA3dCmdHeader *header);

int klpp_vmw_cmd_dx_bind_streamoutput(struct vmw_private *dev_priv,
					struct vmw_sw_context *sw_context,
					SVGA3dCmdHeader *header);

struct drm_file;
struct drm_vmw_fence_rep;
struct vmw_fence_obj;

int klpp_vmw_execbuf_process(struct drm_file *file_priv,
			struct vmw_private *dev_priv,
			void __user *user_commands, void *kernel_commands,
			uint32_t command_size, uint64_t throttle_us,
			uint32_t dx_context_handle,
			struct drm_vmw_fence_rep __user *user_fence_rep,
			struct vmw_fence_obj **out_fence, uint32_t flags);

int klpp_vmw_gem_object_create_with_handle(struct vmw_private *dev_priv,
				      struct drm_file *filp,
				      uint32_t size,
				      uint32_t *handle,
				      struct vmw_buffer_object **p_vbo);

int klpp_vmw_gem_object_create_ioctl(struct drm_device *dev, void *data,
				struct drm_file *filp);

struct drm_mode_fb_cmd2;

struct drm_framebuffer *klpp_vmw_kms_fb_create(struct drm_device *dev,
						 struct drm_file *file_priv,
						 const struct drm_mode_fb_cmd2 *mode_cmd);

int klpp_vmw_overlay_ioctl(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);

int klpp_vmw_shader_define_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);

struct ttm_base_object;

void klpp_vmw_user_surface_base_release(struct ttm_base_object **p_base);

int klpp_vmw_surface_define_ioctl(struct drm_device *dev, void *data,
			     struct drm_file *file_priv);

struct drm_vmw_gb_surface_create_ext_req;
struct drm_vmw_gb_surface_create_rep;

int
klpp_vmw_gb_surface_define_internal(struct drm_device *dev,
			       struct drm_vmw_gb_surface_create_ext_req *req,
			       struct drm_vmw_gb_surface_create_rep *rep,
			       struct drm_file *file_priv);

struct drm_gem_object;

inline void
klpr_drm_gem_object_put(struct drm_gem_object *obj);


#else /* !IS_ENABLED(CONFIG_DRM_VMWGFX) */

static inline int livepatch_bsc1212348_init(void) { return 0; }
static inline void livepatch_bsc1212348_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_DRM_VMWGFX) */

#endif /* _LIVEPATCH_BSC1212348_H */
