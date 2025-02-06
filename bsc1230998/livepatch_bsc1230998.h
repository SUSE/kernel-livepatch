#ifndef _LIVEPATCH_BSC1230998_H
#define _LIVEPATCH_BSC1230998_H


int klpp_netem_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			 struct sk_buff **to_free);

static inline int livepatch_bsc1230998_init(void) { return 0; }
static inline void livepatch_bsc1230998_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1230998_H */
