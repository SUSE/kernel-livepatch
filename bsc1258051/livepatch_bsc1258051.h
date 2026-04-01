#ifndef _LIVEPATCH_BSC1258051_H
#define _LIVEPATCH_BSC1258051_H

static inline int livepatch_bsc1258051_init(void) { return 0; }
static inline void livepatch_bsc1258051_cleanup(void) {}

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;
int klpp_teql_qdisc_init(struct Qdisc *sch, struct nlattr *opt,
			   struct netlink_ext_ack *extack);
#endif /* _LIVEPATCH_BSC1258051_H */
