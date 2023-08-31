#ifndef _LIVEPATCH_BSC1211395_H
#define _LIVEPATCH_BSC1211395_H

#include <linux/types.h>

int livepatch_bsc1211395_init(void);
static inline void livepatch_bsc1211395_cleanup(void) {}

struct sk_buff;

int klpp_ipv6_rthdr_rcv(struct sk_buff *skb);

size_t klpp_ipv6_rpl_srh_size(unsigned char n, unsigned char cmpri,
			 unsigned char cmpre);

int bsc1211395_net_ipv6_exthdrs_init(void);

#endif /* _LIVEPATCH_BSC1211395_H */
