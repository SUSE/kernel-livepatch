#ifndef _LIVEPATCH_BSC1285687_H
#define _LIVEPATCH_BSC1285687_H

#include <linux/types.h>
#include <net/ip.h>

int livepatch_bsc1285687_init(void);
void livepatch_bsc1285687_cleanup(void);

int bsc1285687_net_ipv4_ip_output_init(void);
static inline void bsc1285687_net_ipv4_ip_output_cleanup(void) {}

int bsc1285687_net_netfilter_nfnetlink_queue_init(void);
void bsc1285687_net_netfilter_nfnetlink_queue_cleanup(void);

static inline int ip_check_csum_start(const struct sk_buff *skb)
{
	if (unlikely(skb->csum_start < skb->network_header + ip_hdrlen(skb)))
		return -EINVAL;
	return 0;
}

#endif /* _LIVEPATCH_BSC1285687_H */
