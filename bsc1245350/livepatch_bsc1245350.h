#ifndef _LIVEPATCH_BSC1245350_H
#define _LIVEPATCH_BSC1245350_H

static inline int livepatch_bsc1245350_init(void) { return 0; }
static inline void livepatch_bsc1245350_cleanup(void) {}

int klpp_prio_tune(struct Qdisc *sch, struct nlattr *opt, struct
		   netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1245350_H */
