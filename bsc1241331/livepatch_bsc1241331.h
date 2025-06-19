#ifndef _LIVEPATCH_BSC1241331_H
#define _LIVEPATCH_BSC1241331_H

struct bfq_data;
struct bfq_queue;
struct bfq_group;

int livepatch_bsc1241331_init(void);
static inline void livepatch_bsc1241331_cleanup(void) {}
void klpp_bfq_bfqq_move(struct bfq_data *bfqd, struct bfq_queue *bfqq,
		   struct bfq_group *bfqg);

#endif /* _LIVEPATCH_BSC1241331_H */
