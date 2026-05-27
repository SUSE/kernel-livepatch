#ifndef _LIVEPATCH_BSC1265224_H
#define _LIVEPATCH_BSC1265224_H

#include <linux/types.h>

static inline int livepatch_bsc1265224_init(void) { return 0; }
static inline void livepatch_bsc1265224_cleanup(void) {}

struct sk_buff;

bool klpp_skb_try_coalesce(struct sk_buff *to, struct sk_buff *from, bool *fragstolen, int *delta_truesize);
int klpp_skb_gro_receive(struct sk_buff *p, struct sk_buff *skb);
int klpp_skb_shift(struct sk_buff *tgt, struct sk_buff *skb, int shiftlen);
struct sk_buff *klpp___pskb_copy_fclone(struct sk_buff *skb, int headroom, gfp_t gfp_mask, bool fclone);

#endif /* _LIVEPATCH_BSC1265224_H */
