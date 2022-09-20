#ifndef _LIVEPATCH_BSC1199695_H
#define _LIVEPATCH_BSC1199695_H

int livepatch_bsc1199695_init(void);
void livepatch_bsc1199695_cleanup(void);


struct net;
struct sk_buff;
struct tcf_proto;
struct nlattr;
struct netlink_ext_ack;

int klpp_u32_change(struct net *net, struct sk_buff *in_skb,
		      struct tcf_proto *tp, unsigned long base, u32 handle,
		      struct nlattr **tca, void **arg, bool ovr,
		      struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1199695_H */
