#ifndef _LIVEPATCH_BSC1210989_H
#define _LIVEPATCH_BSC1210989_H

int livepatch_bsc1210989_init(void);
void livepatch_bsc1210989_cleanup(void);

struct Qdisc;
struct nlattr;
struct netlink_ext_ack;

int klpp_qfq_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
			    struct nlattr **tca, unsigned long *arg,
			    struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1210989_H */
