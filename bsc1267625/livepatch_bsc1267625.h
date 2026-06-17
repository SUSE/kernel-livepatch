#ifndef _LIVEPATCH_BSC1267625_H
#define _LIVEPATCH_BSC1267625_H

#include <linux/types.h>

static inline int livepatch_bsc1267625_init(void) { return 0; }
static inline void livepatch_bsc1267625_cleanup(void) {}

struct sk_buff;
struct tc_action;
struct tcf_result;

int klpp_tcf_pedit_act(struct sk_buff *skb,
				    const struct tc_action *a,
				    struct tcf_result *res);


#endif /* _LIVEPATCH_BSC1267625_H */
