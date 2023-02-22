#ifndef _LIVEPATCH_BSC1206314_H
#define _LIVEPATCH_BSC1206314_H

#if IS_ENABLED(CONFIG_BT)

struct l2cap_chan;
struct l2cap_ctrl;
struct sk_buff;
int klpp_l2cap_rx_state_recv(struct l2cap_chan *chan,
			       struct l2cap_ctrl *control,
			       struct sk_buff *skb, u8 event);

struct l2cap_conn;
void klpp_l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb);

int livepatch_bsc1206314_init(void);
void livepatch_bsc1206314_cleanup(void);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1206314_init(void) { return 0; }
static inline void livepatch_bsc1206314_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */

#endif /* _LIVEPATCH_BSC1206314_H */
