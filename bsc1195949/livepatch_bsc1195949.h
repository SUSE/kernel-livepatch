#ifndef _LIVEPATCH_BSC1195949_H
#define _LIVEPATCH_BSC1195949_H

#if IS_ENABLED(CONFIG_MEMSTICK_REALTEK_USB)

int livepatch_bsc1195949_init(void);
void livepatch_bsc1195949_cleanup(void);


struct platform_device;

int klpp_rtsx_usb_ms_drv_remove(struct platform_device *pdev);

#else /* !IS_ENABLED(CONFIG_MEMSTICK_REALTEK_USB) */

static inline int livepatch_bsc1195949_init(void) { return 0; }

static inline void livepatch_bsc1195949_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MEMSTICK_REALTEK_USB) */
#endif /* _LIVEPATCH_BSC1195949_H */
