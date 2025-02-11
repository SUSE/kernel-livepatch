#ifndef _LIVEPATCH_BSC1236783_H
#define _LIVEPATCH_BSC1236783_H

#if IS_ENABLED(CONFIG_USB_VIDEO_CLASS)

static inline int livepatch_bsc1236783_init(void) { return 0; }
static inline void livepatch_bsc1236783_cleanup(void) {}


struct uvc_device;

int klpp_uvc_parse_standard_control(struct uvc_device *dev,
                                    const unsigned char *buffer, int buflen);

#else

static inline int livepatch_bsc1236783_init(void) { return 0; }
static inline void livepatch_bsc1236783_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_USB_VIDEO_CLASS) */

#endif /* _LIVEPATCH_BSC1236783_H */
