#ifndef _LIVEPATCH_BSC1268281_H
#define _LIVEPATCH_BSC1268281_H

#include <linux/types.h>

static inline int livepatch_bsc1268281_init(void) { return 0; }
static inline void livepatch_bsc1268281_cleanup(void) {}

struct net;
struct netlink_ext_ack;
struct nlattr;
struct tc_action;
struct tcf_proto;

int klpp_tcf_ct_init(struct net *net, struct nlattr *nla, struct nlattr *est, struct tc_action **a, struct tcf_proto *tp, u32 flags, struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1268281_H */
