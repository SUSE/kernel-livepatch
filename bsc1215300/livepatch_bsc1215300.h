#ifndef _LIVEPATCH_BSC1215300_H
#define _LIVEPATCH_BSC1215300_H

int livepatch_bsc1215300_init(void);
void livepatch_bsc1215300_cleanup(void);

struct Qdisc;

struct sk_buff *klpp_qfq_dequeue(struct Qdisc *sch);

struct sk_buff;

int klpp_qfq_enqueue(struct sk_buff *skb, struct Qdisc *sch,
		       struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1215300_H */
