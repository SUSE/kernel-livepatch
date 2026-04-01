#ifndef _LIVEPATCH_BSC1257238_H
#define _LIVEPATCH_BSC1257238_H

#include <linux/types.h>

int livepatch_bsc1257238_init(void);
void livepatch_bsc1257238_cleanup(void);


struct Qdisc;
struct netlink_ext_ack;
struct nlattr;

int klpp_qfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid, struct nlattr **tca, unsigned long *arg, struct netlink_ext_ack *extack);
#endif /* _LIVEPATCH_BSC1257238_H */
