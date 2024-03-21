#ifndef _LIVEPATCH_BSC1215887_H
#define _LIVEPATCH_BSC1215887_H

#include <linux/types.h>

struct bpf_verifier_env;
enum bpf_arg_type;
enum bpf_dynptr_type;
struct bpf_func_state;
struct bpf_call_arg_meta;
enum bpf_access_type;
struct bpf_func_proto;
struct bpf_insn;
enum bpf_func_id;
enum bpf_reg_type;
struct bpf_verifier_state;
struct bpf_id_pair;
enum bpf_access_src;
struct bpf_reg_state;

/* verifier */
int klpp_check_func_arg_reg_off(struct bpf_verifier_env *env,
			   const struct bpf_reg_state *reg, int regno,
			   enum bpf_arg_type arg_type);
int klpp_do_check_common(struct bpf_verifier_env *env, int subprog);
int klpp_check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno,
			    int off, int bpf_size, enum bpf_access_type t,
			    int value_regno, bool strict_alignment_once);
int klpp_check_stack_range_initialized(struct bpf_verifier_env *env,
					 int regno, int off, int access_size,
					 bool zero_size_allowed,
					 enum bpf_access_src type,
					 struct bpf_call_arg_meta *meta);

int bsc1215887_kernel_bpf_verifier_init(void);

int livepatch_bsc1215887_init(void);
static inline void livepatch_bsc1215887_cleanup(void) {}


#endif /* _LIVEPATCH_BSC1215887_H */
