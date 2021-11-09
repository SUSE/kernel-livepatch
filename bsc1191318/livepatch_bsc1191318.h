#ifndef _LIVEPATCH_BSC1191318_H
#define _LIVEPATCH_BSC1191318_H

int livepatch_bsc1191318_init(void);
static inline void livepatch_bsc1191318_cleanup(void) {}


union bpf_attr;

struct bpf_map *klpp_stack_map_alloc(union bpf_attr *attr);

#endif /* _LIVEPATCH_BSC1191318_H */
