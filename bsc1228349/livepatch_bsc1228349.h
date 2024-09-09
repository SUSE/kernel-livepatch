#ifndef _LIVEPATCH_BSC1228349_H
#define _LIVEPATCH_BSC1228349_H

int livepatch_bsc1228349_init(void);
static inline void livepatch_bsc1228349_cleanup(void) {}

struct bpf_link;

void klpp_bpf_link_free(struct bpf_link *link);

#endif /* _LIVEPATCH_BSC1228349_H */
