#ifndef _LIVEPATCH_BSC1229553_H
#define _LIVEPATCH_BSC1229553_H

#if IS_ENABLED(CONFIG_USB_NET_QMI_WWAN)

int klpp_qmi_wwan_rx_fixup(struct usbnet *dev, struct sk_buff *skb);

#endif /* IS_ENABLED(CONFIG_USB_NET_QMI_WWAN) */

static inline int livepatch_bsc1229553_init(void) { return 0; }
static inline void livepatch_bsc1229553_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1229553_H */
