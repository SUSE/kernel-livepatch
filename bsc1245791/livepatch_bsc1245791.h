#ifndef _LIVEPATCH_BSC1245791_H
#define _LIVEPATCH_BSC1245791_H

static inline int livepatch_bsc1245791_init(void) { return 0; }
static inline void livepatch_bsc1245791_cleanup(void) {}

int klpp_hfsc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                      struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1245791_H */
