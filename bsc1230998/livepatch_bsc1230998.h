#ifndef _LIVEPATCH_BSC1230998_H
#define _LIVEPATCH_BSC1230998_H

int livepatch_bsc1230998_init(void);
void livepatch_bsc1230998_cleanup(void);

int klpp_netem_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1230998_H */
