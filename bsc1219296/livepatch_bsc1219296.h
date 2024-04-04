#ifndef _LIVEPATCH_BSC1219296_H
#define _LIVEPATCH_BSC1219296_H

int livepatch_bsc1219296_init(void);
static inline void livepatch_bsc1219296_cleanup(void) {}


struct dst_ops;

int klpp_ip6_dst_gc(struct dst_ops *ops);

#endif /* _LIVEPATCH_BSC1219296_H */
