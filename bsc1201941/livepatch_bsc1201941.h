#ifndef _LIVEPATCH_BSC1201941_H
#define _LIVEPATCH_BSC1201941_H

int livepatch_bsc1201941_init(void);
void livepatch_bsc1201941_cleanup(void);


struct net;
struct sock;
struct sk_buff;
struct nlmsghdr;
struct nlattr;

int klpp_nfqnl_recv_verdict(struct net *net, struct sock *ctnl,
			      struct sk_buff *skb,
			      const struct nlmsghdr *nlh,
			      const struct nlattr * const nfqa[]);

#endif /* _LIVEPATCH_BSC1201941_H */
