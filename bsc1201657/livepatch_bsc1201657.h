#ifndef _LIVEPATCH_BSC1201657_H
#define _LIVEPATCH_BSC1201657_H

#if IS_ENABLED(CONFIG_CAN_MCBA_USB)

int livepatch_bsc1201657_init(void);
void livepatch_bsc1201657_cleanup(void);


#include <linux/netdevice.h>

struct sk_buff;
struct net_device;

netdev_tx_t klpp_mcba_usb_start_xmit(struct sk_buff *skb,
				       struct net_device *netdev);

#else /* !IS_ENABLED(CONFIG_CAN_MCBA_USB) */

static inline int livepatch_bsc1201657_init(void) { return 0; }

static inline void livepatch_bsc1201657_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_CAN_MCBA_USB) */
#endif /* _LIVEPATCH_BSC1201657_H */
