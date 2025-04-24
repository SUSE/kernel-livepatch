#ifndef _LIVEPATCH_BSC1240840_H
#define _LIVEPATCH_BSC1240840_H

static inline int livepatch_bsc1240840_init(void) { return 0; }
static inline void livepatch_bsc1240840_cleanup(void) {}

void klpp_hci_event_packet(struct hci_dev *hdev, struct sk_buff *skb);

#endif /* _LIVEPATCH_BSC1240840_H */
