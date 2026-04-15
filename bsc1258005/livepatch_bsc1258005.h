#ifndef _LIVEPATCH_BSC1258005_H
#define _LIVEPATCH_BSC1258005_H

#include <linux/types.h>

static inline int livepatch_bsc1258005_init(void) { return 0; }
static inline void livepatch_bsc1258005_cleanup(void) {}

struct Qdisc;
struct netlink_ext_ack;
struct nlattr;
struct sk_buff;

int klpp_ets_qdisc_change(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack);
int klpp_ets_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *sch, struct sk_buff **to_free);
struct sk_buff *klpp_ets_qdisc_dequeue(struct Qdisc *sch);
void klpp_ets_class_qlen_notify(struct Qdisc *sch, unsigned long arg);
void klpp_ets_qdisc_reset(struct Qdisc *sch);

#endif /* _LIVEPATCH_BSC1258005_H */
