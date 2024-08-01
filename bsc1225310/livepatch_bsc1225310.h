#ifndef _LIVEPATCH_BSC1225310_H
#define _LIVEPATCH_BSC1225310_H

int livepatch_bsc1225310_init(void);
void livepatch_bsc1225310_cleanup(void);

struct drm_client_dev;

int klpp_drm_client_modeset_probe(struct drm_client_dev *client, unsigned int width, unsigned int height);

#endif /* _LIVEPATCH_BSC1225310_H */
