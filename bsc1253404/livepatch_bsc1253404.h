#ifndef _LIVEPATCH_BSC1253404_H
#define _LIVEPATCH_BSC1253404_H

#include <linux/types.h>

struct sock;
struct xsk_buff;
struct xdp_desc;

static inline int livepatch_bsc1253404_init(void) { return 0; }
static inline void livepatch_bsc1253404_cleanup(void) {}

int klpp___xsk_generic_xmit(struct sock *sk);
u32 klpp_xsk_tx_peek_release_desc_batch(struct xsk_buff_pool *pool, u32 nb_pkts);
bool klpp_xsk_tx_peek_desc(struct xsk_buff_pool *pool, struct xdp_desc *desc);


#endif /* _LIVEPATCH_BSC1253404_H */
