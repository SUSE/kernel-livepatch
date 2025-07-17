#ifndef _LIVEPATCH_BSC1238912_H
#define _LIVEPATCH_BSC1238912_H

struct parsed_partitions;

static inline int livepatch_bsc1238912_init(void) { return 0; }
static inline void livepatch_bsc1238912_cleanup(void) {}
int klpp_mac_partition(struct parsed_partitions *state);

#endif /* _LIVEPATCH_BSC1238912_H */
