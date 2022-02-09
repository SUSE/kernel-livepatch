#ifndef _LIVEPATCH_BSC1195308_H
#define _LIVEPATCH_BSC1195308_H

int livepatch_bsc1195308_init(void);
void livepatch_bsc1195308_cleanup(void);


struct net;
struct tipc_mon_state;

void klpp_tipc_mon_rcv(struct net *net, void *data, u16 dlen, u32 addr,
		  struct tipc_mon_state *state, int bearer_id);

#endif /* _LIVEPATCH_BSC1195308_H */
