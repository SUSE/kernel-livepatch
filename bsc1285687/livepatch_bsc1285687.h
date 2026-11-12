#ifndef _LIVEPATCH_BSC1285687_H
#define _LIVEPATCH_BSC1285687_H

#include <linux/types.h>
#include <net/ip.h>

static inline int livepatch_bsc1285687_init(void) { return 0; }
static inline void livepatch_bsc1285687_cleanup(void) {}

static inline int ip_check_csum_start(const struct sk_buff *skb)
{
	if (unlikely(skb->csum_start < skb->network_header + ip_hdrlen(skb)))
		return -EINVAL;
	return 0;
}

#endif /* _LIVEPATCH_BSC1285687_H */
