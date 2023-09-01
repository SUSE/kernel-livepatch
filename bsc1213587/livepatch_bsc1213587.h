#ifndef _LIVEPATCH_BSC1213587_H
#define _LIVEPATCH_BSC1213587_H

static inline int livepatch_bsc1213587_init(void) { return 0; }
static inline void livepatch_bsc1213587_cleanup(void) {}

struct net;
struct tcf_proto;
struct tc_u_knode;
struct nlattr;
struct netlink_ext_ack;

int klpp_u32_set_parms(struct net *net, struct tcf_proto *tp,
			 unsigned long base,
			 struct tc_u_knode *n, struct nlattr **tb,
			 struct nlattr *est, u32 flags, u32 fl_flags,
			 struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1213587_H */
