#ifndef _LIVEPATCH_BSC1207189_H
#define _LIVEPATCH_BSC1207189_H

#if IS_ENABLED(CONFIG_NET_SCH_ATM)

int livepatch_bsc1207189_init(void);
void livepatch_bsc1207189_cleanup(void);


struct sk_buff;
struct Qdisc;

int klpp_atm_tc_enqueue(struct sk_buff *skb, struct Qdisc *sch,
			  struct sk_buff **to_free);

#else /* !IS_ENABLED(CONFIG_NET_SCH_ATM) */

static inline int livepatch_bsc1207189_init(void) { return 0; }

static inline void livepatch_bsc1207189_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NET_SCH_ATM) */
#endif /* _LIVEPATCH_BSC1207189_H */
