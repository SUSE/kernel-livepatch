#ifndef _LIVEPATCH_BSC1208839_H
#define _LIVEPATCH_BSC1208839_H


struct task_struct;
struct rq;
struct rq_flags;

struct task_struct *
klpp_pick_next_task_rt(struct rq *rq, struct task_struct *prev, struct rq_flags *rf);

int livepatch_bsc1208839_init(void);
static inline void livepatch_bsc1208839_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1208839_H */
