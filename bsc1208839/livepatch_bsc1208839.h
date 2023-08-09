#ifndef _LIVEPATCH_BSC1208839_H
#define _LIVEPATCH_BSC1208839_H


struct task_struct;
struct rq;

struct task_struct *klpp__pick_next_task_rt(struct rq *rq);

static inline int livepatch_bsc1208839_init(void) { return 0; }
static inline void livepatch_bsc1208839_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1208839_H */
