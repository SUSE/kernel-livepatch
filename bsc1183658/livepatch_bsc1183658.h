#ifndef _LIVEPATCH_BSC1183658_H
#define _LIVEPATCH_BSC1183658_H

#if IS_ENABLED(CONFIG_R8188EU)

int livepatch_bsc1183658_init(void);
void livepatch_bsc1183658_cleanup(void);


struct net_device;
struct iw_request_info;
union iwreq_data;

int klpp_rtw_wx_set_scan(struct net_device *dev, struct iw_request_info *a,
			     union iwreq_data *wrqu, char *extra);

#else /* !IS_ENABLED(CONFIG_R8188EU) */

static inline int livepatch_bsc1183658_init(void) { return 0; }

static inline void livepatch_bsc1183658_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_R8188EU) */
#endif /* _LIVEPATCH_BSC1183658_H */
