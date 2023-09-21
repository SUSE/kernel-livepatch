#ifndef _LIVEPATCH_BSC1210619_H
#define _LIVEPATCH_BSC1210619_H

int livepatch_bsc1210619_init(void);
void livepatch_bsc1210619_cleanup(void);


struct tcindex_filter_result;
struct tcf_proto;
struct netlink_ext_ack;

void klpp___tcindex_destroy_rexts(struct tcindex_filter_result *r);
void klpp_tcindex_destroy(struct tcf_proto *tp, bool rtnl_held,
			    struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1210619_H */
