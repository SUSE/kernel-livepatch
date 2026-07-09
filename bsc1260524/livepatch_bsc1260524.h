#ifndef _LIVEPATCH_BSC1260524_H
#define _LIVEPATCH_BSC1260524_H

#include <linux/types.h>

static inline int livepatch_bsc1260524_init(void) { return 0; }
static inline void livepatch_bsc1260524_cleanup(void) {}

struct br_cfm_mep;
struct br_cfm_peer_mep;
struct net_bridge;
struct netlink_ext_ack;

int klpp_br_cfm_cc_peer_mep_add(struct net_bridge *br, const u32 instance, u32 peer_mep_id, struct netlink_ext_ack *extack);
int klpp_br_cfm_cc_peer_mep_remove(struct net_bridge *br, const u32 instance, u32 peer_mep_id, struct netlink_ext_ack *extack);
void klpp_ccm_rx_timer_start(struct br_cfm_peer_mep *peer_mep);
void klpp_mep_delete_implementation(struct net_bridge *br, struct br_cfm_mep *mep);

#endif /* _LIVEPATCH_BSC1260524_H */
