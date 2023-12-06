#ifndef _LIVEPATCH_BSC1215519_H
#define _LIVEPATCH_BSC1215519_H

int livepatch_bsc1215519_init(void);
static inline void livepatch_bsc1215519_cleanup(void) {}

struct bpf_verifier_env;

int klpp___mark_chain_precision(struct bpf_verifier_env *env, int regno,
				  int spi);

#endif /* _LIVEPATCH_BSC1215519_H */
