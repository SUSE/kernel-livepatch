#ifndef _LIVEPATCH_BSC1210619_H
#define _LIVEPATCH_BSC1210619_H

int livepatch_bsc1210619_init(void);
void livepatch_bsc1210619_cleanup(void);


struct work_struct;
struct tcf_proto;
struct netlink_ext_ack;
struct tcindex_data;
struct tcindex_filter_result;
struct nlattr;

void klpp_tcindex_destroy_rexts_work(struct work_struct *work);

int klpp_tcindex_delete(struct tcf_proto *tp, void *arg, bool *last,
			  struct netlink_ext_ack *extack);

int
klpp_tcindex_set_parms(struct net *net, struct tcf_proto *tp, unsigned long base,
		  u32 handle, struct tcindex_data *p,
		  struct tcindex_filter_result *r, struct nlattr **tb,
		  struct nlattr *est, bool ovr, struct netlink_ext_ack *extack);

void klpp_tcindex_destroy(struct tcf_proto *tp,
			    struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1210619_H */
