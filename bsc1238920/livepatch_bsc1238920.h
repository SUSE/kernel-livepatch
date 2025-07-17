#ifndef _LIVEPATCH_BSC1238920_H
#define _LIVEPATCH_BSC1238920_H

int livepatch_bsc1238920_init(void);
static inline void livepatch_bsc1238920_cleanup(void) {}

struct request_queue;
struct blkcg_gq;
struct bio;
bool klpp_blk_throtl_bio(struct request_queue *q, struct blkcg_gq *blkg, struct bio *bio);
#endif /* _LIVEPATCH_BSC1238920_H */
