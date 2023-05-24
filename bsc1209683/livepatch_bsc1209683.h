#ifndef _LIVEPATCH_BSC1209683_H
#define _LIVEPATCH_BSC1209683_H

int livepatch_bsc1209683_init(void);
void livepatch_bsc1209683_cleanup(void);

struct net;
struct tcf_proto;
struct tcindex_data;
struct tcindex_filter_result;
struct nlattr;
struct netlink_ext_ack;

int
klpp_tcindex_set_parms(struct net *net, struct tcf_proto *tp, unsigned long base,
		  u32 handle, struct tcindex_data *p,
		  struct tcindex_filter_result *r, struct nlattr **tb,
		  struct nlattr *est, bool ovr, struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1209683_H */
