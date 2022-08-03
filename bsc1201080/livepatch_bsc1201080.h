#ifndef _LIVEPATCH_BSC1201080_H
#define _LIVEPATCH_BSC1201080_H

#if IS_ENABLED(CONFIG_ATH9K_HTC)

int livepatch_bsc1201080_init(void);
void livepatch_bsc1201080_cleanup(void);


#include <linux/types.h>

struct htc_target;
struct device;

int klpp_ath9k_htc_probe_device(struct htc_target *htc_handle, struct device *dev,
			   u16 devid, char *product, u32 drv_info);

#else /* !IS_ENABLED(CONFIG_ATH9K_HTC) */

static inline int livepatch_bsc1201080_init(void) { return 0; }

static inline void livepatch_bsc1201080_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_ATH9K_HTC) */
#endif /* _LIVEPATCH_BSC1201080_H */
