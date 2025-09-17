#ifndef _LIVEPATCH_BSC1246356_H
#define _LIVEPATCH_BSC1246356_H

struct sk_buff;
struct Qdisc;
struct hfsc_class;

static inline int livepatch_bsc1246356_init(void) { return 0; }
static inline void livepatch_bsc1246356_cleanup(void) {}
struct sk_buff *klpp_hfsc_dequeue(struct Qdisc *sch);
void klpp_update_ed(struct hfsc_class *cl, unsigned int next_len);
void klpp_hfsc_qlen_notify(struct Qdisc *sch, unsigned long arg);

#endif /* _LIVEPATCH_BSC1246356_H */
