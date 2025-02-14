#ifndef _LIVEPATCH_BSC1227371_H
#define _LIVEPATCH_BSC1227371_H

static inline int livepatch_bsc1227371_init(void) { return 0; }
static inline void livepatch_bsc1227371_cleanup(void) {}

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;

int klpp_taprio_change(struct Qdisc *sch, struct nlattr *opt,
			 struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1227371_H */
