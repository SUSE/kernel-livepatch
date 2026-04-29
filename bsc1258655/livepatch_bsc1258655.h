#ifndef _LIVEPATCH_BSC1258655_H
#define _LIVEPATCH_BSC1258655_H

#include <linux/types.h>

static inline int livepatch_bsc1258655_init(void) { return 0; }
static inline void livepatch_bsc1258655_cleanup(void) {}

struct rt6_info;
struct rtable;

void klpp_rt6_uncached_list_del(struct rt6_info *rt);
void klpp_rt_del_uncached_list(struct rtable *rt);

#endif /* _LIVEPATCH_BSC1258655_H */
