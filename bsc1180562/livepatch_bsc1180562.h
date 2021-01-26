#ifndef _LIVEPATCH_BSC1180562_H
#define _LIVEPATCH_BSC1180562_H

#if IS_ENABLED(CONFIG_MWIFIEX)

int livepatch_bsc1180562_init(void);
void livepatch_bsc1180562_cleanup(void);


struct mwifiex_private;
struct host_cmd_ds_command;
struct cfg80211_ssid;

int
klpp_mwifiex_cmd_802_11_ad_hoc_start(struct mwifiex_private *priv,
				struct host_cmd_ds_command *cmd,
				struct cfg80211_ssid *req_ssid);

#else /* !IS_ENABLED(CONFIG_MWIFIEX) */

static inline int livepatch_bsc1180562_init(void) { return 0; }

static inline void livepatch_bsc1180562_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_MWIFIEX) */
#endif /* _LIVEPATCH_BSC1180562_H */
