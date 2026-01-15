#ifndef _LIVEPATCH_BSC1252563_H
#define _LIVEPATCH_BSC1252563_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_ATH9K_HTC)

int livepatch_bsc1252563_init(void);
void livepatch_bsc1252563_cleanup(void);

struct wmi;

int klpp_ath9k_wmi_cmd(struct wmi *wmi, enum wmi_cmd_id cmd_id, u8 *cmd_buf, u32 cmd_len, u8 *rsp_buf, u32 rsp_len, u32 timeout);
#else /* !IS_ENABLED(CONFIG_ATH9K_HTC) */

static inline int livepatch_bsc1252563_init(void) { return 0; }
static inline void livepatch_bsc1252563_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_ATH9K_HTC) */

#endif /* _LIVEPATCH_BSC1252563_H */
