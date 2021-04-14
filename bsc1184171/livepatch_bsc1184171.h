#ifndef _LIVEPATCH_BSC1184171_H
#define _LIVEPATCH_BSC1184171_H

int livepatch_bsc1184171_init(void);
static inline void livepatch_bsc1184171_cleanup(void) {}


struct bpf_verifier_env;

int klpp_fixup_bpf_calls(struct bpf_verifier_env *env);

#endif /* _LIVEPATCH_BSC1184171_H */
