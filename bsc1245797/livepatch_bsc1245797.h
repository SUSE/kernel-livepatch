#ifndef _LIVEPATCH_BSC1245797_H
#define _LIVEPATCH_BSC1245797_H

struct sk_buff;
struct Qdisc;

static inline int livepatch_bsc1245797_init(void) { return 0; }
static inline void livepatch_bsc1245797_cleanup(void) {}
int klpp_pfifo_tail_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			    struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1245797_H */
