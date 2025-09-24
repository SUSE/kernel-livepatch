#ifndef _LIVEPATCH_BSC1246754_H
#define _LIVEPATCH_BSC1246754_H

#include <linux/irqreturn.h>

static inline int livepatch_bsc1246754_init(void) { return 0; }
static inline void livepatch_bsc1246754_cleanup(void) {}

struct usb_hcd;
irqreturn_t klpp_xhci_irq(struct usb_hcd *hcd);

#endif /* _LIVEPATCH_BSC1246754_H */
