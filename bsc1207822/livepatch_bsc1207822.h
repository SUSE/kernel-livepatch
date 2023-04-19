#ifndef _LIVEPATCH_BSC1207822_H
#define _LIVEPATCH_BSC1207822_H

#include <linux/types.h>

struct sk_buff;
struct net_device;

int klpp_rtnl_fill_ifinfo(struct sk_buff *skb, struct net_device *dev,
			int type, u32 pid, u32 seq, u32 change,
			unsigned int flags, u32 ext_filter_mask,
			u32 event, gfp_t gfp);

struct net;
struct Qdisc;
struct netlink_ext_ack;

struct tcf_block *klpp_tcf_block_find(struct net *net, struct Qdisc **q,
					u32 *parent, unsigned long *cl,
					int ifindex, u32 block_index,
					struct netlink_ext_ack *extack);

struct netlink_callback;

int klpp_tc_dump_tfilter(struct sk_buff *skb, struct netlink_callback *cb);

int klpp_tc_dump_chain(struct sk_buff *skb, struct netlink_callback *cb);

struct net_device;

struct Qdisc *klpp_qdisc_lookup(struct net_device *dev, u32 handle);
struct Qdisc *klpp_qdisc_lookup_rcu(struct net_device *dev, u32 handle);

struct nlmsghdr;

int klpp_qdisc_graft(struct net_device *dev, struct Qdisc *parent,
		       struct sk_buff *skb, struct nlmsghdr *n, u32 classid,
		       struct Qdisc *new, struct Qdisc *old,
		       struct netlink_ext_ack *extack);

int klpp_tc_get_qdisc(struct sk_buff *skb, struct nlmsghdr *n,
                          struct netlink_ext_ack *extack);

int klpp_tc_modify_qdisc(struct sk_buff *skb, struct nlmsghdr *n,
                             struct netlink_ext_ack *extack);

int klpp_tc_dump_qdisc(struct sk_buff *skb, struct netlink_callback *cb);

int klpp_tc_ctl_tclass(struct sk_buff *skb, struct nlmsghdr *n,
                             struct netlink_ext_ack *extack);

int klpp_tc_dump_tclass(struct sk_buff *skb, struct netlink_callback *cb);

void klpp_dev_activate(struct net_device *dev);

void klpp_dev_init_scheduler(struct net_device *dev);

void klpp_dev_shutdown(struct net_device *dev);

int bsc1207822_net_core_rtnetlink_init(void);
int bsc1207822_net_sched_cls_api_init(void);
int bsc1207822_net_sched_sch_api_init(void);
int bsc1207822_net_sched_sch_generic_init(void);

int livepatch_bsc1207822_init(void);
static inline void livepatch_bsc1207822_cleanup(void) {}

#endif /* _LIVEPATCH_BSC1207822_H */
