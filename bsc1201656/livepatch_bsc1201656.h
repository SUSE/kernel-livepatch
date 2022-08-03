#ifndef _LIVEPATCH_BSC1201656_H
#define _LIVEPATCH_BSC1201656_H

#if IS_ENABLED(CONFIG_NFC_ST21NFCA)

int livepatch_bsc1201656_init(void);
void livepatch_bsc1201656_cleanup(void);


struct nfc_hci_dev;
struct sk_buff;

int klpp_st21nfca_connectivity_event_received(struct nfc_hci_dev *hdev, u8 host,
				u8 event, struct sk_buff *skb);

#else /* !IS_ENABLED(CONFIG_NFC_ST21NFCA) */

static inline int livepatch_bsc1201656_init(void) { return 0; }

static inline void livepatch_bsc1201656_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NFC_ST21NFCA) */
#endif /* _LIVEPATCH_BSC1201656_H */
