#ifndef _LIVEPATCH_BSC1239077_H
#define _LIVEPATCH_BSC1239077_H

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;

int livepatch_bsc1239077_init(void);
void livepatch_bsc1239077_cleanup(void);
int klpp_sfq_init(struct Qdisc *sch, struct nlattr *opt,
		  struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1239077_H */
