#ifndef _LIVEPATCH_BSC1215119_H
#define _LIVEPATCH_BSC1215119_H

static inline int livepatch_bsc1215119_init(void) { return 0; }
static inline void livepatch_bsc1215119_cleanup(void) {}

struct net;
struct tcf_proto;
struct fw_filter;
struct nlattr;
struct netlink_ext_ack;

int klpp_fw_set_parms(struct net *net, struct tcf_proto *tp,
			struct fw_filter *f, struct nlattr **tb,
			struct nlattr **tca, unsigned long base, u32 flags,
			struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1215119_H */
