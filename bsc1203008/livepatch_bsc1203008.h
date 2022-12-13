#ifndef _LIVEPATCH_BSC1203008_H
#define _LIVEPATCH_BSC1203008_H

#if IS_ENABLED(CONFIG_USB_NET_AX88179_178A)
struct usbnet;
struct sk_buff;
int klpp_ax88179_rx_fixup(struct usbnet *dev, struct sk_buff *skb);

int livepatch_bsc1203008_init(void);
void livepatch_bsc1203008_cleanup(void);

#else /* !IS_ENABLED(CONFIG_USB_NET_AX88179_178A) */
static inline int livepatch_bsc1203008_init(void) { return 0; }
static inline void livepatch_bsc1203008_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_USB_NET_AX88179_178A) */
#endif /* _LIVEPATCH_BSC1203008_H */
