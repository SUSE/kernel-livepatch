#ifndef _LIVEPATCH_BSC1247315_H
#define _LIVEPATCH_BSC1247315_H

#include <linux/types.h>

static inline int livepatch_bsc1247315_init(void) { return 0; }
static inline void livepatch_bsc1247315_cleanup(void) {}

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;
struct sk_buff;
struct tcmsg;
struct gnet_dump;
struct qfq_class;

int klpp_qfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
                          struct nlattr **tca, unsigned long *arg,
                          struct netlink_ext_ack *extack);
int klpp_qfq_delete_class(struct Qdisc *sch, unsigned long arg,
                          struct netlink_ext_ack *extack);
int klpp_qfq_dump_class(struct Qdisc *sch, unsigned long arg,
                        struct sk_buff *skb, struct tcmsg *tcm);
int klpp_qfq_dump_class_stats(struct Qdisc *sch, unsigned long arg,
                              struct gnet_dump *d);
void klpp_qfq_destroy_qdisc(struct Qdisc *sch);
void klpp_qfq_destroy_class(struct Qdisc *sch, struct qfq_class *cl);

#endif /* _LIVEPATCH_BSC1247315_H */
