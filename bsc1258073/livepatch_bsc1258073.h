#ifndef _LIVEPATCH_BSC1258073_H
#define _LIVEPATCH_BSC1258073_H

struct virtnet_info;
struct receive_queue;
struct virtnet_rq_stats;

static inline int livepatch_bsc1258073_init(void) { return 0; }
static inline void livepatch_bsc1258073_cleanup(void) {}

void klpp_receive_buf(struct virtnet_info *vi, struct receive_queue *rq,
			void *buf, unsigned int len, void **ctx,
			unsigned int *xdp_xmit,
			struct virtnet_rq_stats *stats);

#endif /* _LIVEPATCH_BSC1258073_H */
