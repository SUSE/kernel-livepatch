#ifndef _LIVEPATCH_BSC1245778_H
#define _LIVEPATCH_BSC1245778_H

#include <linux/types.h>
#include <linux/netfilter/ipset/ip_set.h>

struct nlattr;

int livepatch_bsc1245778_init(void);
void livepatch_bsc1245778_cleanup(void);


int
klpp_bitmap_ip_uadt(struct ip_set *set, struct nlattr *tb[],
	       enum ipset_adt adt, u32 *lineno, u32 flags, bool retried);

#endif /* _LIVEPATCH_BSC1245778_H */
