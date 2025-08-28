#ifndef _LIVEPATCH_BSC1231943_H
#define _LIVEPATCH_BSC1231943_H

int livepatch_bsc1231943_init(void);
static inline void livepatch_bsc1231943_cleanup(void) {}

struct request;

struct bfq_queue *klpp_bfq_init_rq(struct request *rq);

#endif /* _LIVEPATCH_BSC1231943_H */
