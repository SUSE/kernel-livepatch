#ifndef _LIVEPATCH_BSC1244235_H
#define _LIVEPATCH_BSC1244235_H

#include <linux/types.h>

static inline int livepatch_bsc1244235_init(void) { return 0; }
static inline void livepatch_bsc1244235_cleanup(void) {}

int klpp_hfsc_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
                           struct nlattr **tca, unsigned long *arg,
                           struct netlink_ext_ack *extack);

int klpp_hfsc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
                      struct sk_buff **to_free);

#endif /* _LIVEPATCH_BSC1244235_H */
