#ifndef _LIVEPATCH_BSC1245793_H
#define _LIVEPATCH_BSC1245793_H

int livepatch_bsc1245793_init(void);
void livepatch_bsc1245793_cleanup(void);

int klpp_hfsc_change_class(struct Qdisc *sch, u32 classid, u32 parentid,
                           struct nlattr **tca, unsigned long *arg,
                           struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1245793_H */
