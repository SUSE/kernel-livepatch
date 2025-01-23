#ifndef _LIVEPATCH_BSC1227369_H
#define _LIVEPATCH_BSC1227369_H

static inline int livepatch_bsc1227369_init(void) { return 0; }
static inline void livepatch_bsc1227369_cleanup(void) {}

int klpp_br_mst_vlan_set_msti(struct net_bridge_vlan *mv, u16 msti);
int klpp_br_mst_set_state(struct net_bridge_port *p, u16 msti, u8 state,
		     struct netlink_ext_ack *extack);

#endif /* _LIVEPATCH_BSC1227369_H */
