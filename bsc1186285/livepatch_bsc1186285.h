#ifndef _LIVEPATCH_BSC1186285_H
#define _LIVEPATCH_BSC1186285_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1186285_init(void);
void livepatch_bsc1186285_cleanup(void);


struct hci_conn;
struct hci_dev;
struct sk_buff;

struct hci_chan *klpp_hci_chan_create(struct hci_conn *conn);
void klpp_hci_event_packet(struct hci_dev *hdev, struct sk_buff *skb);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1186285_init(void) { return 0; }

static inline void livepatch_bsc1186285_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */
#endif /* _LIVEPATCH_BSC1186285_H */
