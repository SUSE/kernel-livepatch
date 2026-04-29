#ifndef _LIVEPATCH_BSC1258005_H
#define _LIVEPATCH_BSC1258005_H

#include <linux/types.h>

static inline int livepatch_bsc1258005_init(void) { return 0; }
static inline void livepatch_bsc1258005_cleanup(void) {}

struct Qdisc;
struct netlink_ext_ack;
struct nlattr;

int klpp_ets_qdisc_change(struct Qdisc *sch, struct nlattr *opt, struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1258005_H */
