#ifndef _LIVEPATCH_BSC1218255_H
#define _LIVEPATCH_BSC1218255_H

static inline int livepatch_bsc1218255_init(void) { return 0; }
static inline void livepatch_bsc1218255_cleanup(void) {}

void klpp_igmp_start_timer(struct ip_mc_list *im, int max_delay);

#endif /* _LIVEPATCH_BSC1218255_H */
