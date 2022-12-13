#ifndef _LIVEPATCH_BSC1204576_H
#define _LIVEPATCH_BSC1204576_H

static inline int livepatch_bsc1204576_init(void) { return 0; }
static inline void livepatch_bsc1204576_cleanup(void) {}


struct sk_buff;
struct Qdisc;

int klpp_sfb_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1204576_H */
