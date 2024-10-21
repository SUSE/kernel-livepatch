#ifndef _LIVEPATCH_BSC1226327_H
#define _LIVEPATCH_BSC1226327_H

#include <linux/bpf.h>

static inline int livepatch_bsc1226327_init(void) { return 0; }
static inline void livepatch_bsc1226327_cleanup(void) {}

enum bpf_access_src;
int klpp_check_stack_access_within_bounds(
		struct bpf_verifier_env *env,
		int regno, int off, int access_size,
		enum bpf_access_src src, enum bpf_access_type type);

int klpp___sys_bpf(int cmd, bpfptr_t uattr, unsigned int size);

#endif /* _LIVEPATCH_BSC1226327_H */
