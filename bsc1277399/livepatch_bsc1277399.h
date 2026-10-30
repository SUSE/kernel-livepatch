#ifndef _LIVEPATCH_BSC1277399_H
#define _LIVEPATCH_BSC1277399_H

#include <linux/types.h>

int livepatch_bsc1277399_init(void);
void livepatch_bsc1277399_cleanup(void);


struct netns_ipvs;
struct sk_buff;

int klpp_ip_vs_in_icmp(struct netns_ipvs *ipvs, struct sk_buff *skb, int *related, unsigned int hooknum);
#endif /* _LIVEPATCH_BSC1277399_H */
