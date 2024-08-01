#ifndef _LIVEPATCH_BSC1225310_H
#define _LIVEPATCH_BSC1225310_H

int livepatch_bsc1225310_init(void);
void livepatch_bsc1225310_cleanup(void);

#include <linux/types.h>

struct drm_fb_helper;

void klpp_drm_setup_crtcs(struct drm_fb_helper *fb_helper,
			    u32 width, u32 height);

#endif /* _LIVEPATCH_BSC1225310_H */
