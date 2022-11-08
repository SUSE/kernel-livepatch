#ifndef _LIVEPATCH_BSC1203613_H
#define _LIVEPATCH_BSC1203613_H

struct net;
struct sk_buff;
struct tcf_proto;
struct nlattr;
struct netlink_ext_ack;
int klpp_route4_change(struct net *net, struct sk_buff *in_skb,
			 struct tcf_proto *tp, unsigned long base, u32 handle,
			 struct nlattr **tca, void **arg, bool ovr,
			 struct netlink_ext_ack *extack);

int livepatch_bsc1203613_init(void);
void livepatch_bsc1203613_cleanup(void);

#endif /* _LIVEPATCH_BSC1203613_H */
