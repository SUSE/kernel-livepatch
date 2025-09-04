#ifndef _LIVEPATCH_BSC1245775_H
#define _LIVEPATCH_BSC1245775_H

int livepatch_bsc1245775_init(void);
void livepatch_bsc1245775_cleanup(void);

int klpp_hfsc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                      struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1245775_H */
