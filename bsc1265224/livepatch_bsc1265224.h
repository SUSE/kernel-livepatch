#ifndef _LIVEPATCH_BSC1265224_H
#define _LIVEPATCH_BSC1265224_H

#include <linux/types.h>
#include <linux/netdev_features.h>

static inline int livepatch_bsc1265224_init(void) { return 0; }
static inline void livepatch_bsc1265224_cleanup(void) {}

struct list_head;
struct sk_buff;
struct sock;
struct udphdr;

bool klpp_skb_try_coalesce(struct sk_buff *to, struct sk_buff *from, bool *fragstolen, int *delta_truesize);
int klpp_skb_gro_receive(struct sk_buff *p, struct sk_buff *skb);
int klpp_skb_shift(struct sk_buff *tgt, struct sk_buff *skb, int shiftlen);
struct sk_buff *klpp___pskb_copy_fclone(struct sk_buff *skb, int headroom, gfp_t gfp_mask, bool fclone);
struct sk_buff *klpp_skb_segment(struct sk_buff *skb, netdev_features_t features);
struct sk_buff *klpp_udp_gro_receive(struct list_head *head, struct sk_buff *skb, struct udphdr *uh, struct sock *sk);

#endif /* _LIVEPATCH_BSC1265224_H */
