#ifndef _LIVEPATCH_BSC1192042_H
#define _LIVEPATCH_BSC1192042_H

static inline int livepatch_bsc1192042_init(void) { return 0; }

static inline void livepatch_bsc1192042_cleanup(void) {}


struct l2tp_session;
struct sk_buff;

int klpp_l2tp_xmit_skb(struct l2tp_session *session, struct sk_buff *skb, int hdr_len);

#endif /* _LIVEPATCH_BSC1192042_H */
