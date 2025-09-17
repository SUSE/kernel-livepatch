#ifndef _LIVEPATCH_BSC1248298_H
#define _LIVEPATCH_BSC1248298_H

static inline int livepatch_bsc1248298_init(void) { return 0; }
static inline void livepatch_bsc1248298_cleanup(void) {}

struct usb_composite_dev;
struct usb_ep;
int klpp_composite_os_desc_req_prepare(struct usb_composite_dev *cdev,
				  struct usb_ep *ep0);
#endif /* _LIVEPATCH_BSC1248298_H */
