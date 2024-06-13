#ifndef _LIVEPATCH_BSC1220537_H
#define _LIVEPATCH_BSC1220537_H

int livepatch_bsc1220537_init(void);
void livepatch_bsc1220537_cleanup(void);

struct datapath;
struct sk_buff;
struct sw_flow_key;

void klpp_do_output(struct datapath *dp, struct sk_buff *skb, int out_port,
		      struct sw_flow_key *key);

#endif /* _LIVEPATCH_BSC1220537_H */
