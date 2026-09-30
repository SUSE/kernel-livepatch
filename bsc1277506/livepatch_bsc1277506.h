#ifndef _LIVEPATCH_BSC1277506_H
#define _LIVEPATCH_BSC1277506_H

#include <linux/types.h>

static inline int livepatch_bsc1277506_init(void) { return 0; }
static inline void livepatch_bsc1277506_cleanup(void) {}

struct sk_buff;
struct veth_rq;
struct veth_stats;
struct veth_xdp_tx_bq;

struct sk_buff *klpp_veth_xdp_rcv_skb(struct veth_rq *rq, struct sk_buff *skb, struct veth_xdp_tx_bq *bq, struct veth_stats *stats);

#endif /* _LIVEPATCH_BSC1277506_H */
