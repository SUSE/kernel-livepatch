#ifndef _LIVEPATCH_BSC1259126_H
#define _LIVEPATCH_BSC1259126_H

struct sk_buff;
struct tcf_proto;
struct tcf_result;

static inline int livepatch_bsc1259126_init(void) { return 0; }
static inline void livepatch_bsc1259126_cleanup(void) {}

int klpp_u32_classify(struct sk_buff *skb,
		   const struct tcf_proto *tp,
		   struct tcf_result *res);

#endif /* _LIVEPATCH_BSC1259126_H */
