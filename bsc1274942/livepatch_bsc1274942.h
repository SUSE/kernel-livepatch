#ifndef _LIVEPATCH_BSC1274942_H
#define _LIVEPATCH_BSC1274942_H

#include <linux/types.h>

static inline int livepatch_bsc1274942_init(void) { return 0; }
static inline void livepatch_bsc1274942_cleanup(void) {}

struct netlink_ext_ack;
struct nlattr;
struct qdisc_rate_table;
struct tc_ratespec;

struct qdisc_rate_table *klpp_qdisc_get_rtab(struct tc_ratespec *r, struct nlattr *tab, struct netlink_ext_ack *extack);
void klpp_qdisc_put_rtab(struct qdisc_rate_table *tab);

#endif /* _LIVEPATCH_BSC1274942_H */
