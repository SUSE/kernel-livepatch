#ifndef _LIVEPATCH_BSC1185899_H
#define _LIVEPATCH_BSC1185899_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1185899_init(void);
void livepatch_bsc1185899_cleanup(void);


struct hci_dev;
struct hci_request;

int klpp_hci_req_sync(struct hci_dev *hdev, int (*req)(struct hci_request *req,
						  unsigned long opt),
		 unsigned long opt, u32 timeout, u8 *hci_status);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1185899_init(void) { return 0; }

static inline void livepatch_bsc1185899_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1185899_H */
