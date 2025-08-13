#ifndef _LIVEPATCH_BSC1245776_H
#define _LIVEPATCH_BSC1245776_H

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;

static inline int livepatch_bsc1245776_init(void) { return 0; }
static inline void livepatch_bsc1245776_cleanup(void) {}
int klpp_sfq_init(struct Qdisc *sch, struct nlattr *opt,
		  struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1245776_H */
