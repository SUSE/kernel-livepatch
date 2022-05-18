#ifndef _BSC1198590_COMMON_H
#define _BSC1198590_COMMON_H

int bsc1198590_drm_auth_init(void);
void bsc1198590_drm_auth_cleanup(void);

int bsc1198590_drm_lease_init(void);
void bsc1198590_drm_lease_cleanup(void);


struct drm_file;

struct drm_master *klpp_drm_file_get_master(struct drm_file *file_priv);

#endif
