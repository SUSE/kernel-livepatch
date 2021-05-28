#ifndef _LIVEPATCH_BSC1186498_H
#define _LIVEPATCH_BSC1186498_H

int livepatch_bsc1186498_init(void);
static inline void livepatch_bsc1186498_cleanup(void) {}


struct bpf_verifier_env;
struct bpf_insn;
struct bpf_reg_state;

int klpp_adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   const struct bpf_reg_state *ptr_reg,
				   const struct bpf_reg_state *off_reg);

#endif /* _LIVEPATCH_BSC1186498_H */
