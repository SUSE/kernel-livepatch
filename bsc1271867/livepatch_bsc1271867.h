#ifndef _LIVEPATCH_BSC1271867_H
#define _LIVEPATCH_BSC1271867_H

#include <linux/types.h>

static inline int livepatch_bsc1271867_init(void) { return 0; }
static inline void livepatch_bsc1271867_cleanup(void) {}

struct Qdisc;
struct sk_buff;
struct tcf_qevent;

struct sk_buff *klpp_tcf_qevent_handle(struct tcf_qevent *qe, struct Qdisc *sch, struct sk_buff *skb, struct sk_buff **to_free, int *ret);

#endif /* _LIVEPATCH_BSC1271867_H */
