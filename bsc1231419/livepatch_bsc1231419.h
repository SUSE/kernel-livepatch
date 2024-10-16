#ifndef _LIVEPATCH_BSC1231419_H
#define _LIVEPATCH_BSC1231419_H

static inline int livepatch_bsc1231419_init(void) { return 0; }
static inline void livepatch_bsc1231419_cleanup(void) {}

struct hci_dev;
struct sk_buff;

void klpp_hci_le_big_sync_established_evt(struct hci_dev *hdev, void *data,
					    struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1231419_H */
