#ifndef _LIVEPATCH_BSC1221302_H
#define _LIVEPATCH_BSC1221302_H

#if IS_ENABLED(CONFIG_IWLWIFI)

int livepatch_bsc1221302_init(void);
void livepatch_bsc1221302_cleanup(void);

struct iwl_fw_runtime;
enum iwl_fw_ini_time_point;
union iwl_dbg_tlv_tp_data;

void klpp__iwl_dbg_tlv_time_point(struct iwl_fw_runtime *fwrt,
			     enum iwl_fw_ini_time_point tp_id,
			     union iwl_dbg_tlv_tp_data *tp_data,
			     bool sync);

#else /* !IS_ENABLED(CONFIG_IWLWIFI) */

static inline int livepatch_bsc1221302_init(void) { return 0; }
static inline void livepatch_bsc1221302_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_IWLWIFI) */

#endif /* _LIVEPATCH_BSC1221302_H */
