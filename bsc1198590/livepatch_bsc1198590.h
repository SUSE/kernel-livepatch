#ifndef _LIVEPATCH_BSC1198590_H
#define _LIVEPATCH_BSC1198590_H

int livepatch_bsc1198590_init(void);
void livepatch_bsc1198590_cleanup(void);


struct drm_file;
struct drm_device;

bool klpp_drm_is_current_master(struct drm_file *fpriv);

int klpp_drm_setmaster_ioctl(struct drm_device *dev, void *data,
			struct drm_file *file_priv);

int klpp_drm_dropmaster_ioctl(struct drm_device *dev, void *data,
			 struct drm_file *file_priv);

void klpp_drm_master_release(struct drm_file *file_priv);

int klpp_drm_master_open(struct drm_file *file_priv);

bool klpp__drm_lease_held(struct drm_file *file_priv, int id);

bool klpp_drm_lease_held(struct drm_file *file_priv, int id);

uint32_t klpp_drm_lease_filter_crtcs(struct drm_file *file_priv, uint32_t crtcs);

int klpp_drm_mode_create_lease_ioctl(struct drm_device *dev,
				void *data, struct drm_file *file_priv);

int klpp_drm_mode_list_lessees_ioctl(struct drm_device *dev,
				void *data, struct drm_file *file_priv);

int klpp_drm_mode_get_lease_ioctl(struct drm_device *dev,
			     void *data, struct drm_file *file_priv);

int klpp_drm_mode_revoke_lease_ioctl(struct drm_device *dev,
				void *data, struct drm_file *file_priv);

#endif /* _LIVEPATCH_BSC1198590_H */
