/*
 * livepatch_bsc1215887
 *
 * Fix for CVE-2023-39191, bsc#1215887
 *
 *  Upstream commit:
 *  8ab4cdcf03d0 ("bpf: Tidy up verifier check_func_arg()")
 *  cbd620fc18ca ("selftests/bpf: Copy over libbpf configs")
 *  dc444be8bae4 ("selftests/bpf: add extra test for using dynptr data slice after release")
 *  b239da34203f ("bpf: Add helper macro bpf_for_each_reg_in_vstate")
 *  e9e315b4a5de ("bpf: Move dynptr type check to is_dynptr_type_expected()")
 *  b94fa9f9dcf9 ("selftests/bpf: Add tests for dynamic pointers parameters in kfuncs")
 *  26c386ecf021 ("selftests/bpf: convert dynptr_fail and map_kptr_fail subtests to generic tester")
 *  6b75bd3d0367 ("bpf: Refactor ARG_PTR_TO_DYNPTR checks into process_dynptr_func")
 *  ac50fe51ce87 ("bpf: Propagate errors from process_* checks in check_func_arg")
 *  270605317366 ("bpf: Rework process_dynptr_func")
 *  184c9bdb8f65 ("bpf: Rework check_func_arg_reg_off")
 *  f6ee298fa140 ("bpf: Move PTR_TO_STACK alignment check to process_dynptr_func")
 *  76d16077bef0 ("bpf: Use memmove for bpf_dynptr_{read,write}")
 *  d6fefa1105da ("bpf: Fix state pruning for STACK_DYNPTR stack slots")
 *  79168a669d81 ("bpf: Fix missing var_off check for ARG_PTR_TO_DYNPTR")
 *  ef8fc7a07c0e ("bpf: Fix partial dynptr stack slot reads/writes")
 *  f8064ab90d66 ("bpf: Invalidate slices on destruction of dynptrs on stack")
 *  379d4ba831cf ("bpf: Allow reinitializing unreferenced dynptr stack slots")
 *  f5b625e5f8bb ("bpf: Combine dynptr_get_spi and is_spi_bounds_valid")
 *  1ee72bcbe48d ("bpf: Avoid recomputing spi in process_dynptr_func")
 *  91b875a5e43b ("selftests/bpf: convenience macro for use with 'asm volatile' blocks")
 *  f4d24edf1b92 ("selftests/bpf: Add dynptr pruning tests")
 *  ef4810135396 ("selftests/bpf: Add dynptr var_off tests")
 *  011edc8e49b8 ("selftests/bpf: Add dynptr partial slot overwrite tests")
 *  ae8e354c497a ("selftests/bpf: Add dynptr helper tests")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
 *
 *  Based on the original Linux kernel code. Other copyrights apply.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "livepatch_bsc1215887.h"

/* klp-ccp: from kernel/bpf/verifier.c */
#include <uapi/linux/btf.h>
#include <linux/bpf-cgroup.h>

/* klp-ccp: from include/linux/btf.h */
static void (*klpe_btf_put)(struct btf *btf);

static struct btf *(*klpe_btf_get_by_fd)(int fd);

static bool (*klpe_btf_is_module)(const struct btf *btf);
static struct module *(*klpe_btf_try_get_module)(const struct btf *btf);

static const struct btf_type *(*klpe_btf_type_skip_modifiers)(const struct btf *btf,
					       u32 id, u32 *res_id);

static const struct btf_type *
(*klpe_btf_resolve_size)(const struct btf *btf, const struct btf_type *type,
		 u32 *type_size);
static const char *(*klpe_btf_type_str)(const struct btf_type *t);

#ifdef CONFIG_BPF_SYSCALL

static const struct btf_type *(*klpe_btf_type_by_id)(const struct btf *btf, u32 type_id);
static const char *(*klpe_btf_name_by_offset)(const struct btf *btf, u32 offset);

static bool (*klpe_btf_kfunc_id_set_contains)(const struct btf *btf,
			       enum bpf_prog_type prog_type,
			       enum btf_kfunc_type type, u32 kfunc_btf_id);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from include/linux/bpf.h */
#ifdef CONFIG_BPF_JIT
static bool (*klpe_bpf_prog_has_trampoline)(const struct bpf_prog *prog);
#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_BPF_SYSCALL

static struct bpf_map_value_off_desc *(*klpe_bpf_map_kptr_off_contains)(struct bpf_map *map, u32 offset);

static int (*klpe_btf_struct_access)(struct bpf_verifier_log *log, const struct btf *btf,
		      const struct btf_type *t, int off, int size,
		      enum bpf_access_type atype,
		      u32 *next_btf_id, enum bpf_type_flag *flag);
static bool (*klpe_btf_struct_ids_match)(struct bpf_verifier_log *log,
			  const struct btf *btf, u32 id, int off,
			  const struct btf *need_btf, u32 need_type_id,
			  bool strict);

static int (*klpe_btf_check_subprog_arg_match)(struct bpf_verifier_env *env, int subprog,
				struct bpf_reg_state *regs);
static int (*klpe_btf_check_kfunc_arg_match)(struct bpf_verifier_env *env,
			      const struct btf *btf, u32 func_id,
			      struct bpf_reg_state *regs);
static int (*klpe_btf_prepare_func_args)(struct bpf_verifier_env *env, int subprog,
			  struct bpf_reg_state *reg);

#else /* !CONFIG_BPF_SYSCALL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_BPF_SYSCALL */

#if defined(CONFIG_NET)
static bool (*klpe_bpf_sock_common_is_valid_access)(int off, int size,
				     enum bpf_access_type type,
				     struct bpf_insn_access_aux *info);
static bool (*klpe_bpf_sock_is_valid_access)(int off, int size, enum bpf_access_type type,
			      struct bpf_insn_access_aux *info);

#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_INET

static bool (*klpe_bpf_tcp_sock_is_valid_access)(int off, int size, enum bpf_access_type type,
				  struct bpf_insn_access_aux *info);

static bool (*klpe_bpf_xdp_sock_is_valid_access)(int off, int size, enum bpf_access_type type,
				  struct bpf_insn_access_aux *info);

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_INET */

static int (*klpe_bpf_bprintf_prepare)(char *fmt, u32 fmt_size, const u64 *raw_args,
			u32 **bin_buf, u32 num_args);

/* klp-ccp: from kernel/bpf/verifier.c */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>

/* klp-ccp: from include/linux/filter.h */
static bool (*klpe_bpf_helper_changes_pkt_data)(void *func);

/* klp-ccp: from include/linux/tnum.h */
static struct tnum (*klpe_tnum_const)(u64 value);

static const struct tnum (*klpe_tnum_unknown);

static struct tnum (*klpe_tnum_range)(u64 min, u64 max);

static struct tnum (*klpe_tnum_cast)(struct tnum a, u8 size);

static bool (*klpe_tnum_in)(struct tnum a, struct tnum b);

/* klp-ccp: from include/linux/bpf_verifier.h */
static __printf(2, 0) void (*klpe_bpf_verifier_vlog)(struct bpf_verifier_log *log,
				      const char *fmt, va_list args);

static int (*klpe_bpf_prog_offload_verify_insn)(struct bpf_verifier_env *env,
				 int insn_idx, int prev_insn_idx);

static int (*klpe_check_ptr_off_reg)(struct bpf_verifier_env *env,
		      const struct bpf_reg_state *reg, int regno);
int klpp_check_func_arg_reg_off(struct bpf_verifier_env *env,
			   const struct bpf_reg_state *reg, int regno,
			   enum bpf_arg_type arg_type);

/* klp-ccp: from kernel/bpf/verifier.c */
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/stringify.h>
#include <linux/bsearch.h>
#include <linux/sort.h>

/* klp-ccp: from include/linux/perf_event.h */
#ifdef CONFIG_PERF_EVENTS

static int (*klpe_get_callchain_buffers)(int max_stack);

static int (*klpe_sysctl_perf_event_max_stack);

#else /* !CONFIG_PERF_EVENTS: */
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/bpf/verifier.c */
#include <linux/error-injection.h>
/* klp-ccp: from kernel/bpf/disasm.h */
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/stringify.h>

static const char *(*klpe_func_id_name)(int id);

typedef __printf(2, 3) void (*bpf_insn_print_t)(void *private_data,
						const char *, ...);
typedef const char *(*bpf_insn_revmap_call_t)(void *private_data,
					      const struct bpf_insn *insn);
typedef const char *(*bpf_insn_print_imm_t)(void *private_data,
					    const struct bpf_insn *insn,
					    __u64 full_imm);

struct bpf_insn_cbs {
	bpf_insn_print_t	cb_print;
	bpf_insn_revmap_call_t	cb_call;
	bpf_insn_print_imm_t	cb_imm;
	void			*private_data;
};

static void (*klpe_print_bpf_insn)(const struct bpf_insn_cbs *cbs,
		    const struct bpf_insn *insn,
		    bool allow_ptr_leaks);

/* klp-ccp: from kernel/bpf/verifier.c */
#define BPF_COMPLEXITY_LIMIT_STATES	64

#define BPF_MAP_KEY_POISON	(1ULL << 63)
#define BPF_MAP_KEY_SEEN	(1ULL << 62)

#define BPF_MAP_PTR_UNPRIV	1UL
#define BPF_MAP_PTR_POISON	((void *)((0xeB9FUL << 1) +						  POISON_POINTER_DELTA))
#define BPF_MAP_PTR(X)		((struct bpf_map *)((X) & ~BPF_MAP_PTR_UNPRIV))

static int (*klpe_acquire_reference_state)(struct bpf_verifier_env *env, int insn_idx);

static bool bpf_map_ptr_unpriv(const struct bpf_insn_aux_data *aux)
{
	return aux->map_ptr_state & BPF_MAP_PTR_UNPRIV;
}

static void bpf_map_ptr_store(struct bpf_insn_aux_data *aux,
			      const struct bpf_map *map, bool unpriv)
{
	BUILD_BUG_ON((unsigned long)BPF_MAP_PTR_POISON & BPF_MAP_PTR_UNPRIV);
	unpriv |= bpf_map_ptr_unpriv(aux);
	aux->map_ptr_state = (unsigned long)map |
			     (unpriv ? BPF_MAP_PTR_UNPRIV : 0UL);
}

static bool bpf_map_key_poisoned(const struct bpf_insn_aux_data *aux)
{
	return aux->map_key_state & BPF_MAP_KEY_POISON;
}

static bool bpf_map_key_unseen(const struct bpf_insn_aux_data *aux)
{
	return !(aux->map_key_state & BPF_MAP_KEY_SEEN);
}

static u64 bpf_map_key_immediate(const struct bpf_insn_aux_data *aux)
{
	return aux->map_key_state & ~(BPF_MAP_KEY_SEEN | BPF_MAP_KEY_POISON);
}

static void bpf_map_key_store(struct bpf_insn_aux_data *aux, u64 state)
{
	bool poisoned = bpf_map_key_poisoned(aux);

	aux->map_key_state = state | BPF_MAP_KEY_SEEN |
			     (poisoned ? BPF_MAP_KEY_POISON : 0ULL);
}

struct bpf_call_arg_meta {
	struct bpf_map *map_ptr;
	bool raw_mode;
	bool pkt_access;
	u8 release_regno;
	int regno;
	int access_size;
	int mem_size;
	u64 msize_max_value;
	int ref_obj_id;
	int map_uid;
	int func_id;
	struct btf *btf;
	u32 btf_id;
	struct btf *ret_btf;
	u32 ret_btf_id;
	u32 subprogno;
	struct bpf_map_value_off_desc *kptr_off_desc;
	u8 uninit_dynptr_regno;
};

static struct btf *(*klpe_btf_vmlinux);

static void (*klpe_bpf_vlog_reset)(struct bpf_verifier_log *log, u32 new_pos);

__printf(2, 3) static void klpr_verbose(void *private_data, const char *fmt, ...)
{
	struct bpf_verifier_env *env = private_data;
	va_list args;

	if (!bpf_verifier_log_needed(&env->log))
		return;

	va_start(args, fmt);
	(*klpe_bpf_verifier_vlog)(&env->log, fmt, args);
	va_end(args);
}

__printf(3, 4) static void (*klpe_verbose_linfo)(struct bpf_verifier_env *env,
					 u32 insn_off,
					 const char *prefix_fmt, ...);

struct klpp_bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			/* To distinguish map lookups from outer map
			 * the map_uid is non-zero for registers
			 * pointing to inner maps.
			 */
			u32 map_uid;
		};

		struct {
			struct btf *btf;
			u32 btf_id;
		};

		struct { /* for PTR_TO_MEM | PTR_TO_MEM_OR_NULL */
			u32 mem_size;
			u32 dynptr_id; /* for dynptr slices */
		};

		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;

		struct {
			unsigned long raw1;
			unsigned long raw2;
		} raw;

		u32 subprogno; /* for PTR_TO_FUNC */
	};
	u32 id;
	u32 ref_obj_id;
	struct tnum var_off;
	struct klpp_bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};

static void klpr_verbose_invalid_scalar(struct bpf_verifier_env *env,
				   struct bpf_reg_state *reg,
				   struct tnum *range, const char *ctx,
				   const char *reg_name)
{
	char tn_buf[48];

	klpr_verbose(env, "At %s the register %s ", ctx, reg_name);
	if (!tnum_is_unknown(reg->var_off)) {
		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		klpr_verbose(env, "has value %s", tn_buf);
	} else {
		klpr_verbose(env, "has unknown scalar value");
	}
	tnum_strn(tn_buf, sizeof(tn_buf), *range);
	klpr_verbose(env, " should have been in %s\n", tn_buf);
}

static bool type_is_pkt_pointer(enum bpf_reg_type type)
{
	return type == PTR_TO_PACKET ||
	       type == PTR_TO_PACKET_META;
}

static bool type_is_sk_pointer(enum bpf_reg_type type)
{
	return type == PTR_TO_SOCKET ||
		type == PTR_TO_SOCK_COMMON ||
		type == PTR_TO_TCP_SOCK ||
		type == PTR_TO_XDP_SOCK;
}

static bool type_is_rdonly_mem(u32 type)
{
	return type & MEM_RDONLY;
}

static bool arg_type_may_be_refcounted(enum bpf_arg_type type)
{
	return type == ARG_PTR_TO_SOCK_COMMON;
}

static bool type_may_be_null(u32 type)
{
	return type & PTR_MAYBE_NULL;
}

static bool may_be_acquire_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_sk_lookup_tcp ||
		func_id == BPF_FUNC_sk_lookup_udp ||
		func_id == BPF_FUNC_skc_lookup_tcp ||
		func_id == BPF_FUNC_map_lookup_elem ||
	        func_id == BPF_FUNC_ringbuf_reserve;
}

static bool is_acquire_function(enum bpf_func_id func_id,
				const struct bpf_map *map)
{
	enum bpf_map_type map_type = map ? map->map_type : BPF_MAP_TYPE_UNSPEC;

	if (func_id == BPF_FUNC_sk_lookup_tcp ||
	    func_id == BPF_FUNC_sk_lookup_udp ||
	    func_id == BPF_FUNC_skc_lookup_tcp ||
	    func_id == BPF_FUNC_ringbuf_reserve ||
	    func_id == BPF_FUNC_kptr_xchg)
		return true;

	if (func_id == BPF_FUNC_map_lookup_elem &&
	    (map_type == BPF_MAP_TYPE_SOCKMAP ||
	     map_type == BPF_MAP_TYPE_SOCKHASH))
		return true;

	return false;
}

static bool is_ptr_cast_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_tcp_sock ||
		func_id == BPF_FUNC_sk_fullsock ||
		func_id == BPF_FUNC_skc_to_tcp_sock ||
		func_id == BPF_FUNC_skc_to_tcp6_sock ||
		func_id == BPF_FUNC_skc_to_udp6_sock ||
		func_id == BPF_FUNC_skc_to_mptcp_sock ||
		func_id == BPF_FUNC_skc_to_tcp_timewait_sock ||
		func_id == BPF_FUNC_skc_to_tcp_request_sock;
}

static const char *(*klpe_reg_type_str)(struct bpf_verifier_env *env,
				enum bpf_reg_type type);

static int klpp___get_spi(s32 off)
{
	return (-off - 1) / BPF_REG_SIZE;
}

static struct bpf_func_state *klpp_func(struct bpf_verifier_env *env,
				   const struct bpf_reg_state *reg)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[reg->frameno];
}

static bool klpp_is_spi_bounds_valid(struct bpf_func_state *state, int spi, int nr_slots)
{
       int allocated_slots = state->allocated_stack / BPF_REG_SIZE;

       /* We need to check that slots between [spi - nr_slots + 1, spi] are
	* within [0, allocated_stack).
	*
	* Please note that the spi grows downwards. For example, a dynptr
	* takes the size of two stack slots; the first slot will be at
	* spi and the second slot will be at spi - 1.
	*/
       return spi - nr_slots + 1 >= 0 && spi < allocated_slots;
}

static int klpp_dynptr_get_spi(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	int off, spi;
	struct bpf_func_state *state;

	if (!tnum_is_const(reg->var_off)) {
		klpr_verbose(env, "dynptr has to be at a constant offset\n");
		return -EINVAL;
	}

	off = reg->off + reg->var_off.value;
	if (off % BPF_REG_SIZE) {
		klpr_verbose(env, "cannot pass in dynptr at an offset=%d\n", off);
		return -EINVAL;
	}

	spi = klpp___get_spi(off);
	if (spi < 1) {
		klpr_verbose(env, "cannot pass in dynptr at an offset=%d\n", off);
		return -EINVAL;
	}
	state = klpp_func(env, reg);
	if (!klpp_is_spi_bounds_valid(state, spi, BPF_DYNPTR_NR_SLOTS))
		return -ERANGE;
	return spi;
}

static const char *(*klpe_kernel_type_name)(const struct btf* btf, u32 id);

static void mark_stack_slot_scratched(struct bpf_verifier_env *env, u32 spi)
{
	env->scratched_stack_slots |= 1ULL << spi;
}

static bool verifier_state_scratched(const struct bpf_verifier_env *env)
{
	return env->scratched_regs || env->scratched_stack_slots;
}

static void mark_verifier_state_scratched(struct bpf_verifier_env *env)
{
	env->scratched_regs = ~0U;
	env->scratched_stack_slots = ~0ULL;
}

static enum bpf_dynptr_type arg_to_dynptr_type(enum bpf_arg_type arg_type)
{
	switch (arg_type & DYNPTR_TYPE_FLAG_MASK) {
	case DYNPTR_TYPE_LOCAL:
		return BPF_DYNPTR_TYPE_LOCAL;
	case DYNPTR_TYPE_RINGBUF:
		return BPF_DYNPTR_TYPE_RINGBUF;
	default:
		return BPF_DYNPTR_TYPE_INVALID;
	}
}

static bool dynptr_type_refcounted(enum bpf_dynptr_type type)
{
	return type == BPF_DYNPTR_TYPE_RINGBUF;
}

static void (*klpe___mark_reg_known)(struct bpf_reg_state *reg, u64 imm);

static void klpr___mark_reg_known_zero(struct bpf_reg_state *reg) {
	(*klpe___mark_reg_known)(reg, 0);
}

void klpp___mark_dynptr_reg(struct bpf_reg_state *reg, enum bpf_dynptr_type type,
			      bool first_slot, int dynptr_id)
{
	klpr___mark_reg_known_zero(reg);
	/* Give each dynptr a unique id to uniquely associate slices to it. */
	reg->id = dynptr_id;
	reg->dynptr.type = type;
	reg->dynptr.first_slot = first_slot;
}

static void klpp_mark_dynptr_stack_regs(struct bpf_verifier_env *env,
				   struct bpf_reg_state *sreg1,
				   struct bpf_reg_state *sreg2,
				   enum bpf_dynptr_type type)
{
	int id = ++env->id_gen;

	klpp___mark_dynptr_reg(sreg1, type, true, id);
	klpp___mark_dynptr_reg(sreg2, type, false, id);
}

static int klpp_destroy_if_dynptr_stack_slot(struct bpf_verifier_env *env,
				        struct bpf_func_state *state, int spi);

static int klpp_mark_stack_slots_dynptr(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
				   enum bpf_arg_type arg_type, int insn_idx)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	enum bpf_dynptr_type type;
	int spi, i, id, err;

	spi = klpp_dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;

	/* We cannot assume both spi and spi - 1 belong to the same dynptr,
	 * hence we need to call klpp_destroy_if_dynptr_stack_slot twice for both,
	 * to ensure that for the following example:
	 *	[d1][d1][d2][d2]
	 * spi    3   2   1   0
	 * So marking spi = 2 should lead to destruction of both d1 and d2. In
	 * case they do belong to same dynptr, second call won't see slot_type
	 * as STACK_DYNPTR and will simply skip destruction.
	 */
	err = klpp_destroy_if_dynptr_stack_slot(env, state, spi);
	if (err)
		return err;
	err = klpp_destroy_if_dynptr_stack_slot(env, state, spi - 1);
	if (err)
		return err;

	for (i = 0; i < BPF_REG_SIZE; i++) {
		state->stack[spi].slot_type[i] = STACK_DYNPTR;
		state->stack[spi - 1].slot_type[i] = STACK_DYNPTR;
	}

	type = arg_to_dynptr_type(arg_type);
	if (type == BPF_DYNPTR_TYPE_INVALID)
		return -EINVAL;

	klpp_mark_dynptr_stack_regs(env, &state->stack[spi].spilled_ptr,
			       &state->stack[spi - 1].spilled_ptr, type);

	if (dynptr_type_refcounted(type)) {
		/* The id is used to track proper releasing */
		id = (*klpe_acquire_reference_state)(env, insn_idx);
		if (id < 0)
			return id;

		state->stack[spi].spilled_ptr.ref_obj_id = id;
		state->stack[spi - 1].spilled_ptr.ref_obj_id = id;
	}

	state->stack[spi].spilled_ptr.live |= REG_LIVE_WRITTEN;
	state->stack[spi - 1].spilled_ptr.live |= REG_LIVE_WRITTEN;

	return 0;
}

static void klpr___mark_reg_not_init(const struct bpf_verifier_env *env,
				struct bpf_reg_state *reg);

static int (*klpe_release_reference)(struct bpf_verifier_env *env,
			     int ref_obj_id);

static int klpp_unmark_stack_slots_dynptr(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	int spi, i;

	spi = klpp_dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;

	for (i = 0; i < BPF_REG_SIZE; i++) {
		state->stack[spi].slot_type[i] = STACK_INVALID;
		state->stack[spi - 1].slot_type[i] = STACK_INVALID;
	}

	/* Invalidate any slices associated with this dynptr */
	if (dynptr_type_refcounted(state->stack[spi].spilled_ptr.dynptr.type))
		WARN_ON_ONCE((*klpe_release_reference)(env, state->stack[spi].spilled_ptr.ref_obj_id));
 
	klpr___mark_reg_not_init(env, &state->stack[spi].spilled_ptr);
	klpr___mark_reg_not_init(env, &state->stack[spi - 1].spilled_ptr);

	/* Why do we need to set REG_LIVE_WRITTEN for STACK_INVALID slot?
	 *
	 * While we don't allow reading STACK_INVALID, it is still possible to
	 * do <8 byte writes marking some but not all slots as STACK_MISC. Then,
	 * helpers or insns can do partial read of that part without failing,
	 * but check_stack_range_initialized, check_stack_read_var_off, and
	 * check_stack_read_fixed_off will do mark_reg_read for all 8-bytes of
	 * the slot conservatively. Hence we need to prevent those liveness
	 * marking walks.
	 *
	 * This was not a problem before because STACK_INVALID is only set by
	 * default (where the default reg state has its reg->parent as NULL), or
	 * in clean_live_states after REG_LIVE_DONE (at which point
	 * mark_reg_read won't walk reg->parent chain), but not randomly during
	 * verifier state exploration (like we did above). Hence, for our case
	 * parentage chain will still be live (i.e. reg->parent may be
	 * non-NULL), while earlier reg->parent was NULL, so we need
	 * REG_LIVE_WRITTEN to screen off read marker propagation when it is
	 * done later on reads or by mark_dynptr_read as well to unnecessary
	 * mark registers in verifier state.
	 */
	state->stack[spi].spilled_ptr.live |= REG_LIVE_WRITTEN;
	state->stack[spi - 1].spilled_ptr.live |= REG_LIVE_WRITTEN;

	return 0;
}

/* Invoke __expr over regsiters in __vst, setting __state and __reg */
#define bpf_for_each_reg_in_vstate(__vst, __state, __reg, __expr)   \
	({                                                               \
		struct bpf_verifier_state *___vstate = __vst;            \
		int ___i, ___j;                                          \
		for (___i = 0; ___i <= ___vstate->curframe; ___i++) {    \
			struct bpf_reg_state *___regs;                   \
			__state = ___vstate->frame[___i];                \
			___regs = __state->regs;                         \
			for (___j = 0; ___j < MAX_BPF_REG; ___j++) {     \
				__reg = &___regs[___j];                  \
				(void)(__expr);                          \
			}                                                \
			bpf_for_each_spilled_reg(___j, __state, __reg) { \
				if (!__reg)                              \
					continue;                        \
				(void)(__expr);                          \
			}                                                \
		}                                                        \
	})

static void klpr___mark_reg_unknown(const struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg);

static int klpp_destroy_if_dynptr_stack_slot(struct bpf_verifier_env *env,
				        struct bpf_func_state *state, int spi)
{
	struct bpf_func_state *fstate;
	struct bpf_reg_state *dreg;
	int i, dynptr_id;

	/* We always ensure that STACK_DYNPTR is never set partially,
	 * hence just checking for slot_type[0] is enough. This is
	 * different for STACK_SPILL, where it may be only set for
	 * 1 byte, so code has to use is_spilled_reg.
	 */
	if (state->stack[spi].slot_type[0] != STACK_DYNPTR)
		return 0;

	/* Reposition spi to first slot */
	if (!state->stack[spi].spilled_ptr.dynptr.first_slot)
		spi = spi + 1;

	if (dynptr_type_refcounted(state->stack[spi].spilled_ptr.dynptr.type)) {
		klpr_verbose(env, "cannot overwrite referenced dynptr\n");
		return -EINVAL;
	}

	mark_stack_slot_scratched(env, spi);
	mark_stack_slot_scratched(env, spi - 1);

	/* Writing partially to one dynptr stack slot destroys both. */
	for (i = 0; i < BPF_REG_SIZE; i++) {
		state->stack[spi].slot_type[i] = STACK_INVALID;
		state->stack[spi - 1].slot_type[i] = STACK_INVALID;
	}

	dynptr_id = state->stack[spi].spilled_ptr.id;
	/* Invalidate any slices associated with this dynptr */
	bpf_for_each_reg_in_vstate(env->cur_state, fstate, dreg, ({
		/* Dynptr slices are only PTR_TO_MEM_OR_NULL and PTR_TO_MEM */
		if (dreg->type != (PTR_TO_MEM | PTR_MAYBE_NULL) && dreg->type != PTR_TO_MEM)
			continue;
		if (((struct klpp_bpf_reg_state *)dreg)->dynptr_id == dynptr_id) {
			if (!env->allow_ptr_leaks)
				klpr___mark_reg_not_init(env, dreg);
			else
				klpr___mark_reg_unknown(env, dreg);
		}
	}));

	/* Do not release reference state, we are destroying dynptr on stack,
	 * not using some helper to release it. Just reset register.
	 */
	klpr___mark_reg_not_init(env, &state->stack[spi].spilled_ptr);
	klpr___mark_reg_not_init(env, &state->stack[spi - 1].spilled_ptr);

	/* Same reason as unmark_stack_slots_dynptr above */
	state->stack[spi].spilled_ptr.live |= REG_LIVE_WRITTEN;
	state->stack[spi - 1].spilled_ptr.live |= REG_LIVE_WRITTEN;

	return 0;
}

static bool klpp_is_dynptr_reg_valid_uninit(struct bpf_verifier_env *env, struct bpf_reg_state *reg, int spi)
{
	/* For -ERANGE (i.e. spi not falling into allocated stack slots), we
	 * will do check_mem_access to check and update stack bounds later, so
	 * return true for that case.
	 */
	if (spi < 0)
		return spi == -ERANGE;

	/* We allow overwriting existing unreferenced STACK_DYNPTR slots, see
	 * mark_stack_slots_dynptr which calls destroy_if_dynptr_stack_slot to
	 * ensure dynptr objects at the slots we are touching are completely
	 * destructed before we reinitialize them for a new one. For referenced
	 * ones, destroy_if_dynptr_stack_slot returns an error early instead of
	 * delaying it until the end where the user will get "Unreleased
	 * reference" error.
	 */
	return true;
}

static bool klpp_is_dynptr_reg_valid_init(struct bpf_verifier_env *env, struct bpf_reg_state *reg, int spi)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	int i;

	if (spi < 0)
		return false;

	if (!state->stack[spi].spilled_ptr.dynptr.first_slot)
		return false;

	for (i = 0; i < BPF_REG_SIZE; i++) {
		if (state->stack[spi].slot_type[i] != STACK_DYNPTR ||
		    state->stack[spi - 1].slot_type[i] != STACK_DYNPTR)
			return false;
	}

	return true;
}

static bool klpp_is_dynptr_type_expected(struct bpf_verifier_env *env,
				    struct bpf_reg_state *reg,
				    enum bpf_arg_type arg_type)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	enum bpf_dynptr_type dynptr_type;
	int spi;

	/* ARG_PTR_TO_DYNPTR takes any type of dynptr */
	if (arg_type == ARG_PTR_TO_DYNPTR)
		return true;

	dynptr_type = arg_to_dynptr_type(arg_type);
	spi = klpp_dynptr_get_spi(env, reg);
	if (spi < 0)
		return false;
	return state->stack[spi].spilled_ptr.dynptr.type == dynptr_type;
}

static bool is_spilled_reg(const struct bpf_stack_state *stack)
{
	return stack->slot_type[BPF_REG_SIZE - 1] == STACK_SPILL;
}

static void scrub_spilled_slot(u8 *stype)
{
	if (*stype != STACK_INVALID)
		*stype = STACK_MISC;
}

static void (*klpe_print_verifier_state)(struct bpf_verifier_env *env,
				 const struct bpf_func_state *state,
				 bool print_all);

static void (*klpe_print_insn_state)(struct bpf_verifier_env *env,
			     const struct bpf_func_state *state);

static void *(*klpe_copy_array)(void *dst, const void *src, size_t n, size_t size, gfp_t flags);

static void *(*klpe_realloc_array)(void *arr, size_t old_n, size_t new_n, size_t size);

static int klpr_copy_reference_state(struct bpf_func_state *dst, const struct bpf_func_state *src)
{
	dst->refs = (*klpe_copy_array)(dst->refs, src->refs, src->acquired_refs,
			       sizeof(struct bpf_reference_state), GFP_KERNEL);
	if (!dst->refs)
		return -ENOMEM;

	dst->acquired_refs = src->acquired_refs;
	return 0;
}

static int klpr_grow_stack_state(struct bpf_func_state *state, int size)
{
	size_t old_n = state->allocated_stack / BPF_REG_SIZE, n = size / BPF_REG_SIZE;

	if (old_n >= n)
		return 0;

	state->stack = (*klpe_realloc_array)(state->stack, old_n, n, sizeof(struct bpf_stack_state));
	if (!state->stack)
		return -ENOMEM;

	state->allocated_stack = size;
	return 0;
}

static int (*klpe_acquire_reference_state)(struct bpf_verifier_env *env, int insn_idx);

static void free_func_state(struct bpf_func_state *state)
{
	if (!state)
		return;
	kfree(state->refs);
	kfree(state->stack);
	kfree(state);
}

static void clear_jmp_history(struct bpf_verifier_state *state)
{
	kfree(state->jmp_history);
	state->jmp_history = NULL;
	state->jmp_history_cnt = 0;
}

static void (*klpe_free_verifier_state)(struct bpf_verifier_state *state,
				bool free_self);

static int (*klpe_copy_verifier_state)(struct bpf_verifier_state *dst_state,
			       const struct bpf_verifier_state *src);

static void update_branch_counts(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	while (st) {
		u32 br = --st->branches;

		/* WARN_ON(br > 1) technically makes sense here,
		 * but see comment in push_stack(), hence:
		 */
		WARN_ONCE((int)br < 0,
			  "BUG update_branch_counts:branches_to_explore=%d\n",
			  br);
		if (br)
			break;
		st = st->parent;
	}
}

static int (*klpe_pop_stack)(struct bpf_verifier_env *env, int *prev_insn_idx,
		     int *insn_idx, bool pop_log);

#define CALLER_SAVED_REGS 6
static const int (*klpe_caller_saved)[CALLER_SAVED_REGS];

static void (*klpe_mark_reg_known_zero)(struct bpf_verifier_env *env,
				struct bpf_reg_state *regs, u32 regno);

static bool reg_is_pkt_pointer(const struct bpf_reg_state *reg)
{
	return type_is_pkt_pointer(reg->type);
}

static void __mark_reg_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;

	reg->s32_min_value = S32_MIN;
	reg->s32_max_value = S32_MAX;
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
}

static void (*klpe_reg_bounds_sync)(struct bpf_reg_state *reg);

static void (*klpe___reg_combine_64_into_32)(struct bpf_reg_state *reg);

static void klpr___mark_reg_unknown(const struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg)
{
	/*
	 * Clear type, id, off, and union(map_ptr, range) and
	 * padding between 'type' and union
	 */
	memset(reg, 0, offsetof(struct bpf_reg_state, var_off));
	reg->type = SCALAR_VALUE;
	reg->var_off = (*klpe_tnum_unknown);
	reg->frameno = 0;
	reg->precise = env->subprog_cnt > 1 || !env->bpf_capable;
	__mark_reg_unbounded(reg);
}

static void (*klpe_mark_reg_unknown)(struct bpf_verifier_env *env,
			     struct bpf_reg_state *regs, u32 regno);

static void klpr___mark_reg_not_init(const struct bpf_verifier_env *env,
				struct bpf_reg_state *reg)
{
	klpr___mark_reg_unknown(env, reg);
	reg->type = NOT_INIT;
}

static void (*klpe_mark_reg_not_init)(struct bpf_verifier_env *env,
			      struct bpf_reg_state *regs, u32 regno);

static void klpr_mark_btf_ld_reg(struct bpf_verifier_env *env,
			    struct bpf_reg_state *regs, u32 regno,
			    enum bpf_reg_type reg_type,
			    struct btf *btf, u32 btf_id,
			    enum bpf_type_flag flag)
{
	if (reg_type == SCALAR_VALUE) {
		(*klpe_mark_reg_unknown)(env, regs, regno);
		return;
	}
	(*klpe_mark_reg_known_zero)(env, regs, regno);
	regs[regno].type = PTR_TO_BTF_ID | flag;
	regs[regno].btf = btf;
	regs[regno].btf_id = btf_id;
}

#define DEF_NOT_SUBREG	(0)
static void (*klpe_init_reg_state)(struct bpf_verifier_env *env,
			   struct bpf_func_state *state);

#define BPF_MAIN_FUNC (-1)
static void klpr_init_func_state(struct bpf_verifier_env *env,
			    struct bpf_func_state *state,
			    int callsite, int frameno, int subprogno)
{
	state->callsite = callsite;
	state->frameno = frameno;
	state->subprogno = subprogno;
	(*klpe_init_reg_state)(env, state);
	mark_verifier_state_scratched(env);
}

enum reg_arg_type {
	SRC_OP,		/* register is used as source operand */
	DST_OP,		/* register is used as destination operand */
	DST_OP_NO_MARK	/* same as above, check only, don't mark */
};

static int (*klpe_find_subprog)(struct bpf_verifier_env *env, int off);

#define MAX_KFUNC_BTFS	256

struct bpf_kfunc_btf {
	struct btf *btf;
	struct module *module;
	u16 offset;
};

struct bpf_kfunc_btf_tab {
	struct bpf_kfunc_btf descs[MAX_KFUNC_BTFS];
	u32 nr_descs;
};

static int (*klpe_kfunc_btf_cmp_by_off)(const void *a, const void *b);

static struct btf *klpr___find_kfunc_desc_btf(struct bpf_verifier_env *env,
					 s16 offset)
{
	struct bpf_kfunc_btf kf_btf = { .offset = offset };
	struct bpf_kfunc_btf_tab *tab;
	struct bpf_kfunc_btf *b;
	struct module *mod;
	struct btf *btf;
	int btf_fd;

	tab = env->prog->aux->kfunc_btf_tab;
	b = bsearch(&kf_btf, tab->descs, tab->nr_descs,
		    sizeof(tab->descs[0]), (*klpe_kfunc_btf_cmp_by_off));
	if (!b) {
		if (tab->nr_descs == MAX_KFUNC_BTFS) {
			klpr_verbose(env, "too many different module BTFs\n");
			return ERR_PTR(-E2BIG);
		}

		if (bpfptr_is_null(env->fd_array)) {
			klpr_verbose(env, "kfunc offset > 0 without fd_array is invalid\n");
			return ERR_PTR(-EPROTO);
		}

		if (copy_from_bpfptr_offset(&btf_fd, env->fd_array,
					    offset * sizeof(btf_fd),
					    sizeof(btf_fd)))
			return ERR_PTR(-EFAULT);

		btf = (*klpe_btf_get_by_fd)(btf_fd);
		if (IS_ERR(btf)) {
			klpr_verbose(env, "invalid module BTF fd specified\n");
			return btf;
		}

		if (!(*klpe_btf_is_module)(btf)) {
			klpr_verbose(env, "BTF fd for kfunc is not a module BTF\n");
			(*klpe_btf_put)(btf);
			return ERR_PTR(-EINVAL);
		}

		mod = (*klpe_btf_try_get_module)(btf);
		if (!mod) {
			(*klpe_btf_put)(btf);
			return ERR_PTR(-ENXIO);
		}

		b = &tab->descs[tab->nr_descs++];
		b->btf = btf;
		b->module = mod;
		b->offset = offset;

		sort(tab->descs, tab->nr_descs, sizeof(tab->descs[0]),
		     (*klpe_kfunc_btf_cmp_by_off), NULL);
	}
	return b->btf;
}

static struct btf *klpr_find_kfunc_desc_btf(struct bpf_verifier_env *env, s16 offset)
{
	if (offset) {
		if (offset < 0) {
			/* In the future, this can be allowed to increase limit
			 * of fd index into fd_array, interpreted as u16.
			 */
			klpr_verbose(env, "negative offset disallowed for kernel module function call\n");
			return ERR_PTR(-EINVAL);
		}

		return klpr___find_kfunc_desc_btf(env, offset);
	}
	return (*klpe_btf_vmlinux) ?: ERR_PTR(-ENOENT);
}

static int (*klpe_mark_reg_read)(struct bpf_verifier_env *env,
			 const struct bpf_reg_state *state,
			 struct bpf_reg_state *parent, u8 flag);

static int klpp_mark_dynptr_read(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	int spi, ret;

	spi = klpp_dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;
	/* Caller ensures dynptr is valid and initialized, which means spi is in
	 * bounds and spi is the first dynptr slot. Simply mark stack slot as
	 * read.
	 */
	ret = (*klpe_mark_reg_read)(env, &state->stack[spi].spilled_ptr,
			    state->stack[spi].spilled_ptr.parent, REG_LIVE_READ64);
	if (ret)
		return ret;
	return (*klpe_mark_reg_read)(env, &state->stack[spi - 1].spilled_ptr,
			     state->stack[spi - 1].spilled_ptr.parent, REG_LIVE_READ64);
}

static void mark_insn_zext(struct bpf_verifier_env *env,
			   struct bpf_reg_state *reg)
{
	s32 def_idx = reg->subreg_def;

	if (def_idx == DEF_NOT_SUBREG)
		return;

	env->insn_aux_data[def_idx - 1].zext_dst = true;
	/* The dst will be zero extended, so won't be sub-register anymore. */
	reg->subreg_def = DEF_NOT_SUBREG;
}

static int (*klpe_check_reg_arg)(struct bpf_verifier_env *env, u32 regno,
			 enum reg_arg_type t);

static int push_jmp_history(struct bpf_verifier_env *env,
			    struct bpf_verifier_state *cur)
{
	u32 cnt = cur->jmp_history_cnt;
	struct bpf_idx_pair *p;

	cnt++;
	p = krealloc(cur->jmp_history, cnt * sizeof(*p), GFP_USER);
	if (!p)
		return -ENOMEM;
	p[cnt - 1].idx = env->insn_idx;
	p[cnt - 1].prev_idx = env->prev_insn_idx;
	cur->jmp_history = p;
	cur->jmp_history_cnt = cnt;
	return 0;
}

static const char *(*klpe_disasm_kfunc_name)(void *data, const struct bpf_insn *insn);

static int (*klpe___mark_chain_precision)(struct bpf_verifier_env *env, int regno,
				  int spi);

static int klpr_mark_chain_precision(struct bpf_verifier_env *env, int regno)
{
	return (*klpe___mark_chain_precision)(env, regno, -1);
}

static int klpr_mark_chain_precision_stack(struct bpf_verifier_env *env, int spi)
{
	return (*klpe___mark_chain_precision)(env, -1, spi);
}

static bool is_spillable_regtype(enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case PTR_TO_MAP_VALUE:
	case PTR_TO_STACK:
	case PTR_TO_CTX:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET_END:
	case PTR_TO_FLOW_KEYS:
	case CONST_PTR_TO_MAP:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
	case PTR_TO_XDP_SOCK:
	case PTR_TO_BTF_ID:
	case PTR_TO_BUF:
	case PTR_TO_MEM:
	case PTR_TO_FUNC:
	case PTR_TO_MAP_KEY:
		return true;
	default:
		return false;
	}
}

static bool register_is_null(struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && tnum_equals_const(reg->var_off, 0);
}

static bool register_is_const(struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && tnum_is_const(reg->var_off);
}

static bool __is_scalar_unbounded(struct bpf_reg_state *reg)
{
	return tnum_is_unknown(reg->var_off) &&
	       reg->smin_value == S64_MIN && reg->smax_value == S64_MAX &&
	       reg->umin_value == 0 && reg->umax_value == U64_MAX &&
	       reg->s32_min_value == S32_MIN && reg->s32_max_value == S32_MAX &&
	       reg->u32_min_value == 0 && reg->u32_max_value == U32_MAX;
}

static bool register_is_bounded(struct bpf_reg_state *reg)
{
	return reg->type == SCALAR_VALUE && !__is_scalar_unbounded(reg);
}

static bool __is_pointer_value(bool allow_ptr_leaks,
			       const struct bpf_reg_state *reg)
{
	if (allow_ptr_leaks)
		return false;

	return reg->type != SCALAR_VALUE;
}

static void save_register_state(struct bpf_func_state *state,
				int spi, struct bpf_reg_state *reg,
				int size)
{
	int i;

	state->stack[spi].spilled_ptr = *reg;
	if (size == BPF_REG_SIZE)
		state->stack[spi].spilled_ptr.live |= REG_LIVE_WRITTEN;

	for (i = BPF_REG_SIZE; i > BPF_REG_SIZE - size; i--)
		state->stack[spi].slot_type[i - 1] = STACK_SPILL;

	/* size < 8 bytes spill */
	for (; i; i--)
		scrub_spilled_slot(&state->stack[spi].slot_type[i - 1]);
}

static int klpp_check_stack_write_fixed_off(struct bpf_verifier_env *env,
				       /* stack frame we're writing to */
				       struct bpf_func_state *state,
				       int off, int size, int value_regno,
				       int insn_idx)
{
	struct bpf_func_state *cur; /* state of the current function */
	int i, slot = -off - 1, spi = slot / BPF_REG_SIZE, err;
	u32 dst_reg = env->prog->insnsi[insn_idx].dst_reg;
	struct bpf_reg_state *reg = NULL;

	err = klpr_grow_stack_state(state, round_up(slot + 1, BPF_REG_SIZE));
	if (err)
		return err;
	/* caller checked that off % size == 0 and -MAX_BPF_STACK <= off < 0,
	 * so it's aligned access and [off, off + size) are within stack limits
	 */
	if (!env->allow_ptr_leaks &&
	    state->stack[spi].slot_type[0] == STACK_SPILL &&
	    size != BPF_REG_SIZE) {
		klpr_verbose(env, "attempt to corrupt spilled pointer on stack\n");
		return -EACCES;
	}

	cur = env->cur_state->frame[env->cur_state->curframe];
	if (value_regno >= 0)
		reg = &cur->regs[value_regno];
	if (!env->bypass_spec_v4) {
		bool sanitize = reg && is_spillable_regtype(reg->type);

		for (i = 0; i < size; i++) {
			if (state->stack[spi].slot_type[i] == STACK_INVALID) {
				sanitize = true;
				break;
			}
		}

		if (sanitize)
			env->insn_aux_data[insn_idx].sanitize_stack_spill = true;
	}

	err = klpp_destroy_if_dynptr_stack_slot(env, state, spi);
	if (err)
		return err;

	mark_stack_slot_scratched(env, spi);
	if (reg && !(off % BPF_REG_SIZE) && register_is_bounded(reg) &&
	    !register_is_null(reg) && env->bpf_capable) {
		if (dst_reg != BPF_REG_FP) {
			/* The backtracking logic can only recognize explicit
			 * stack slot address like [fp - 8]. Other spill of
			 * scalar via different register has to be conservative.
			 * Backtrack from here and mark all registers as precise
			 * that contributed into 'reg' being a constant.
			 */
			err = klpr_mark_chain_precision(env, value_regno);
			if (err)
				return err;
		}
		save_register_state(state, spi, reg, size);
	} else if (reg && is_spillable_regtype(reg->type)) {
		/* register containing pointer is being spilled into stack */
		if (size != BPF_REG_SIZE) {
			(*klpe_verbose_linfo)(env, insn_idx, "; ");
			klpr_verbose(env, "invalid size of register spill\n");
			return -EACCES;
		}
		if (state != cur && reg->type == PTR_TO_STACK) {
			klpr_verbose(env, "cannot spill pointers to stack into stack frame of the caller\n");
			return -EINVAL;
		}
		save_register_state(state, spi, reg, size);
	} else {
		u8 type = STACK_MISC;

		/* regular write of data into stack destroys any spilled ptr */
		state->stack[spi].spilled_ptr.type = NOT_INIT;
		/* Mark slots as STACK_MISC if they belonged to spilled ptr. */
		if (is_spilled_reg(&state->stack[spi]))
			for (i = 0; i < BPF_REG_SIZE; i++)
				scrub_spilled_slot(&state->stack[spi].slot_type[i]);

		/* only mark the slot as written if all 8 bytes were written
		 * otherwise read propagation may incorrectly stop too soon
		 * when stack slots are partially written.
		 * This heuristic means that read propagation will be
		 * conservative, since it will add reg_live_read marks
		 * to stack slots all the way to first state when programs
		 * writes+reads less than 8 bytes
		 */
		if (size == BPF_REG_SIZE)
			state->stack[spi].spilled_ptr.live |= REG_LIVE_WRITTEN;

		/* when we zero initialize stack slots mark them as such */
		if (reg && register_is_null(reg)) {
			/* backtracking doesn't work for STACK_ZERO yet. */
			err = klpr_mark_chain_precision(env, value_regno);
			if (err)
				return err;
			type = STACK_ZERO;
		}

		/* Mark slots affected by this stack write. */
		for (i = 0; i < size; i++)
			state->stack[spi].slot_type[(slot - i) % BPF_REG_SIZE] =
				type;
	}
	return 0;
}

static int klpp_check_stack_write_var_off(struct bpf_verifier_env *env,
				     /* func where register points to */
				     struct bpf_func_state *state,
				     int ptr_regno, int off, int size,
				     int value_regno, int insn_idx)
{
	struct bpf_func_state *cur; /* state of the current function */
	int min_off, max_off;
	int i, err;
	struct bpf_reg_state *ptr_reg = NULL, *value_reg = NULL;
	bool writing_zero = false;
	/* set if the fact that we're writing a zero is used to let any
	 * stack slots remain STACK_ZERO
	 */
	bool zero_used = false;

	cur = env->cur_state->frame[env->cur_state->curframe];
	ptr_reg = &cur->regs[ptr_regno];
	min_off = ptr_reg->smin_value + off;
	max_off = ptr_reg->smax_value + off + size;
	if (value_regno >= 0)
		value_reg = &cur->regs[value_regno];
	if (value_reg && register_is_null(value_reg))
		writing_zero = true;

	err = klpr_grow_stack_state(state, round_up(-min_off, BPF_REG_SIZE));
	if (err)
		return err;

	for (i = min_off; i < max_off; i++) {
		int spi;

		spi = klpp___get_spi(i);
		err = klpp_destroy_if_dynptr_stack_slot(env, state, spi);
		if (err)
			return err;
	}

	/* Variable offset writes destroy any spilled pointers in range. */
	for (i = min_off; i < max_off; i++) {
		u8 new_type, *stype;
		int slot, spi;

		slot = -i - 1;
		spi = slot / BPF_REG_SIZE;
		stype = &state->stack[spi].slot_type[slot % BPF_REG_SIZE];
		mark_stack_slot_scratched(env, spi);

		if (!env->allow_ptr_leaks
				&& *stype != NOT_INIT
				&& *stype != SCALAR_VALUE) {
			/* Reject the write if there's are spilled pointers in
			 * range. If we didn't reject here, the ptr status
			 * would be erased below (even though not all slots are
			 * actually overwritten), possibly opening the door to
			 * leaks.
			 */
			klpr_verbose(env, "spilled ptr in range of var-offset stack write; insn %d, ptr off: %d",
				insn_idx, i);
			return -EINVAL;
		}

		/* Erase all spilled pointers. */
		state->stack[spi].spilled_ptr.type = NOT_INIT;

		/* Update the slot type. */
		new_type = STACK_MISC;
		if (writing_zero && *stype == STACK_ZERO) {
			new_type = STACK_ZERO;
			zero_used = true;
		}
		/* If the slot is STACK_INVALID, we check whether it's OK to
		 * pretend that it will be initialized by this write. The slot
		 * might not actually be written to, and so if we mark it as
		 * initialized future reads might leak uninitialized memory.
		 * For privileged programs, we will accept such reads to slots
		 * that may or may not be written because, if we're reject
		 * them, the error would be too confusing.
		 */
		if (*stype == STACK_INVALID && !env->allow_uninit_stack) {
			klpr_verbose(env, "uninit stack in range of var-offset write prohibited for !root; insn %d, off: %d",
					insn_idx, i);
			return -EINVAL;
		}
		*stype = new_type;
	}
	if (zero_used) {
		/* backtracking doesn't work for STACK_ZERO yet. */
		err = klpr_mark_chain_precision(env, value_regno);
		if (err)
			return err;
	}
	return 0;
}

enum bpf_access_src {
	ACCESS_DIRECT = 1,  /* the access is performed by an instruction */
	ACCESS_HELPER = 2,  /* the access is performed by a helper */
};

int klpp_check_stack_range_initialized(struct bpf_verifier_env *env,
					 int regno, int off, int access_size,
					 bool zero_size_allowed,
					 enum bpf_access_src type,
					 struct bpf_call_arg_meta *meta);

static struct bpf_reg_state *reg_state(struct bpf_verifier_env *env, int regno)
{
	return cur_regs(env) + regno;
}

static int (*klpe_check_stack_read)(struct bpf_verifier_env *env,
			    int ptr_regno, int off, int size,
			    int dst_regno);

static int klpp_check_stack_write(struct bpf_verifier_env *env,
			     int ptr_regno, int off, int size,
			     int value_regno, int insn_idx)
{
	struct bpf_reg_state *reg = reg_state(env, ptr_regno);
	struct bpf_func_state *state = klpp_func(env, reg);
	int err;

	if (tnum_is_const(reg->var_off)) {
		off += reg->var_off.value;
		err = klpp_check_stack_write_fixed_off(env, state, off, size,
						  value_regno, insn_idx);
	} else {
		/* Variable offset stack reads need more conservative handling
		 * than fixed offset ones.
		 */
		err = klpp_check_stack_write_var_off(env, state,
						ptr_regno, off, size,
						value_regno, insn_idx);
	}
	return err;
}

static int (*klpe_check_map_access_type)(struct bpf_verifier_env *env, u32 regno,
				 int off, int size, enum bpf_access_type type);

static int (*klpe_check_mem_region_access)(struct bpf_verifier_env *env, u32 regno,
				   int off, int size, u32 mem_size,
				   bool zero_size_allowed);

static int (*klpe___check_ptr_off_reg)(struct bpf_verifier_env *env,
			       const struct bpf_reg_state *reg, int regno,
			       bool fixed_off_ok);

static int (*klpe_map_kptr_match_type)(struct bpf_verifier_env *env,
			       struct bpf_map_value_off_desc *off_desc,
			       struct bpf_reg_state *reg, u32 regno);

static int klpr_check_map_kptr_access(struct bpf_verifier_env *env, u32 regno,
				 int value_regno, int insn_idx,
				 struct bpf_map_value_off_desc *off_desc)
{
	struct bpf_insn *insn = &env->prog->insnsi[insn_idx];
	int class = BPF_CLASS(insn->code);
	struct bpf_reg_state *val_reg;

	/* Things we already checked for in check_map_access and caller:
	 *  - Reject cases where variable offset may touch kptr
	 *  - size of access (must be BPF_DW)
	 *  - tnum_is_const(reg->var_off)
	 *  - off_desc->offset == off + reg->var_off.value
	 */
	/* Only BPF_[LDX,STX,ST] | BPF_MEM | BPF_DW is supported */
	if (BPF_MODE(insn->code) != BPF_MEM) {
		klpr_verbose(env, "kptr in map can only be accessed using BPF_MEM instruction mode\n");
		return -EACCES;
	}

	/* We only allow loading referenced kptr, since it will be marked as
	 * untrusted, similar to unreferenced kptr.
	 */
	if (class != BPF_LDX && off_desc->type == BPF_KPTR_REF) {
		klpr_verbose(env, "store to referenced kptr disallowed\n");
		return -EACCES;
	}

	if (class == BPF_LDX) {
		val_reg = reg_state(env, value_regno);
		/* We can simply mark the value_regno receiving the pointer
		 * value from map as PTR_TO_BTF_ID, with the correct type.
		 */
		klpr_mark_btf_ld_reg(env, cur_regs(env), value_regno, PTR_TO_BTF_ID, off_desc->kptr.btf,
				off_desc->kptr.btf_id, PTR_MAYBE_NULL | PTR_UNTRUSTED);
		/* For mark_ptr_or_null_reg */
		val_reg->id = ++env->id_gen;
	} else if (class == BPF_STX) {
		val_reg = reg_state(env, value_regno);
		if (!register_is_null(val_reg) &&
		    (*klpe_map_kptr_match_type)(env, off_desc, val_reg, value_regno))
			return -EACCES;
	} else if (class == BPF_ST) {
		if (insn->imm) {
			klpr_verbose(env, "BPF_ST imm must be 0 when storing to kptr at off=%u\n",
				off_desc->offset);
			return -EACCES;
		}
	} else {
		klpr_verbose(env, "kptr in map can only be accessed using BPF_LDX/BPF_STX/BPF_ST\n");
		return -EACCES;
	}
	return 0;
}

static int (*klpe_check_map_access)(struct bpf_verifier_env *env, u32 regno,
			    int off, int size, bool zero_size_allowed,
			    enum bpf_access_src src);

#define MAX_PACKET_OFF 0xffff

static bool may_access_direct_pkt_data(struct bpf_verifier_env *env,
				       const struct bpf_call_arg_meta *meta,
				       enum bpf_access_type t)
{
	enum bpf_prog_type prog_type = resolve_prog_type(env->prog);

	switch (prog_type) {
	/* Program types only with direct read access go here! */
	case BPF_PROG_TYPE_LWT_IN:
	case BPF_PROG_TYPE_LWT_OUT:
	case BPF_PROG_TYPE_LWT_SEG6LOCAL:
	case BPF_PROG_TYPE_SK_REUSEPORT:
	case BPF_PROG_TYPE_FLOW_DISSECTOR:
	case BPF_PROG_TYPE_CGROUP_SKB:
		if (t == BPF_WRITE)
			return false;
		fallthrough;

	/* Program types with direct read + write access go here! */
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
	case BPF_PROG_TYPE_XDP:
	case BPF_PROG_TYPE_LWT_XMIT:
	case BPF_PROG_TYPE_SK_SKB:
	case BPF_PROG_TYPE_SK_MSG:
		if (meta)
			return meta->pkt_access;

		env->seen_direct_write = true;
		return true;

	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		if (t == BPF_WRITE)
			env->seen_direct_write = true;

		return true;

	default:
		return false;
	}
}

static int (*klpe_check_packet_access)(struct bpf_verifier_env *env, u32 regno, int off,
			       int size, bool zero_size_allowed);

static int klpr_check_ctx_access(struct bpf_verifier_env *env, int insn_idx, int off, int size,
			    enum bpf_access_type t, enum bpf_reg_type *reg_type,
			    struct btf **btf, u32 *btf_id)
{
	struct bpf_insn_access_aux info = {
		.reg_type = *reg_type,
		.log = &env->log,
	};

	if (env->ops->is_valid_access &&
	    env->ops->is_valid_access(off, size, t, env->prog, &info)) {
		/* A non zero info.ctx_field_size indicates that this field is a
		 * candidate for later verifier transformation to load the whole
		 * field and then apply a mask when accessed with a narrower
		 * access than actual ctx access size. A zero info.ctx_field_size
		 * will only allow for whole field access and rejects any other
		 * type of narrower access.
		 */
		*reg_type = info.reg_type;

		if (base_type(*reg_type) == PTR_TO_BTF_ID) {
			*btf = info.btf;
			*btf_id = info.btf_id;
		} else {
			env->insn_aux_data[insn_idx].ctx_field_size = info.ctx_field_size;
		}
		/* remember the offset of last byte accessed in ctx */
		if (env->prog->aux->max_ctx_offset < off + size)
			env->prog->aux->max_ctx_offset = off + size;
		return 0;
	}

	klpr_verbose(env, "invalid bpf_context access off=%d size=%d\n", off, size);
	return -EACCES;
}

static int klpr_check_flow_keys_access(struct bpf_verifier_env *env, int off,
				  int size)
{
	if (size < 0 || off < 0 ||
	    (u64)off + size > sizeof(struct bpf_flow_keys)) {
		klpr_verbose(env, "invalid access to flow keys off=%d size=%d\n",
			off, size);
		return -EACCES;
	}
	return 0;
}

static int klpr_check_sock_access(struct bpf_verifier_env *env, int insn_idx,
			     u32 regno, int off, int size,
			     enum bpf_access_type t)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = &regs[regno];
	struct bpf_insn_access_aux info = {};
	bool valid;

	if (reg->smin_value < 0) {
		klpr_verbose(env, "R%d min value is negative, either use unsigned index or do a if (index >=0) check.\n",
			regno);
		return -EACCES;
	}

	switch (reg->type) {
	case PTR_TO_SOCK_COMMON:
		valid = (*klpe_bpf_sock_common_is_valid_access)(off, size, t, &info);
		break;
	case PTR_TO_SOCKET:
		valid = (*klpe_bpf_sock_is_valid_access)(off, size, t, &info);
		break;
	case PTR_TO_TCP_SOCK:
		valid = (*klpe_bpf_tcp_sock_is_valid_access)(off, size, t, &info);
		break;
	case PTR_TO_XDP_SOCK:
		valid = (*klpe_bpf_xdp_sock_is_valid_access)(off, size, t, &info);
		break;
	default:
		valid = false;
	}


	if (valid) {
		env->insn_aux_data[insn_idx].ctx_field_size =
			info.ctx_field_size;
		return 0;
	}

	klpr_verbose(env, "R%d invalid %s access off=%d size=%d\n",
		regno, (*klpe_reg_type_str)(env, reg->type), off, size);

	return -EACCES;
}

static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
{
	return __is_pointer_value(env->allow_ptr_leaks, reg_state(env, regno));
}

static bool is_ctx_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return reg->type == PTR_TO_CTX;
}

static bool is_sk_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return type_is_sk_pointer(reg->type);
}

static bool is_pkt_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return type_is_pkt_pointer(reg->type);
}

static bool is_flow_key_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	/* Separate to is_ctx_reg() since we still want to allow BPF_ST here. */
	return reg->type == PTR_TO_FLOW_KEYS;
}

static int (*klpe_check_ptr_alignment)(struct bpf_verifier_env *env,
			       const struct bpf_reg_state *reg, int off,
			       int size, bool strict_alignment_once);

static int update_stack_depth(struct bpf_verifier_env *env,
			      const struct bpf_func_state *func,
			      int off)
{
	u16 stack = env->subprog_info[func->subprogno].stack_depth;

	if (stack >= -off)
		return 0;

	/* update known max for given subprogram */
	env->subprog_info[func->subprogno].stack_depth = -off;
	return 0;
}

static int klpr___check_buffer_access(struct bpf_verifier_env *env,
				 const char *buf_info,
				 const struct bpf_reg_state *reg,
				 int regno, int off, int size)
{
	if (off < 0) {
		klpr_verbose(env,
			"R%d invalid %s buffer access: off=%d, size=%d\n",
			regno, buf_info, off, size);
		return -EACCES;
	}
	if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		klpr_verbose(env,
			"R%d invalid variable buffer offset: off=%d, var_off=%s\n",
			regno, off, tn_buf);
		return -EACCES;
	}

	return 0;
}

static int klpr_check_tp_buffer_access(struct bpf_verifier_env *env,
				  const struct bpf_reg_state *reg,
				  int regno, int off, int size)
{
	int err;

	err = klpr___check_buffer_access(env, "tracepoint", reg, regno, off, size);
	if (err)
		return err;

	if (off + size > env->prog->aux->max_tp_access)
		env->prog->aux->max_tp_access = off + size;

	return 0;
}

static int klpr_check_buffer_access(struct bpf_verifier_env *env,
			       const struct bpf_reg_state *reg,
			       int regno, int off, int size,
			       bool zero_size_allowed,
			       u32 *max_access)
{
	const char *buf_info = type_is_rdonly_mem(reg->type) ? "rdonly" : "rdwr";
	int err;

	err = klpr___check_buffer_access(env, buf_info, reg, regno, off, size);
	if (err)
		return err;

	if (off + size > *max_access)
		*max_access = off + size;

	return 0;
}

static void (*klpe_zext_32_to_64)(struct bpf_reg_state *reg);

static void klpr_coerce_reg_to_size(struct bpf_reg_state *reg, int size)
{
	u64 mask;

	/* clear high bits in bit representation */
	reg->var_off = (*klpe_tnum_cast)(reg->var_off, size);

	/* fix arithmetic bounds */
	mask = ((u64)1 << (size * 8)) - 1;
	if ((reg->umin_value & ~mask) == (reg->umax_value & ~mask)) {
		reg->umin_value &= mask;
		reg->umax_value &= mask;
	} else {
		reg->umin_value = 0;
		reg->umax_value = mask;
	}
	reg->smin_value = reg->umin_value;
	reg->smax_value = reg->umax_value;

	/* If size is smaller than 32bit register the 32bit register
	 * values are also truncated so we push 64-bit bounds into
	 * 32-bit bounds. Above were truncated < 32-bits already.
	 */
	if (size >= 4)
		return;
	(*klpe___reg_combine_64_into_32)(reg);
}

static bool (*klpe_bpf_map_is_rdonly)(const struct bpf_map *map);

static int bpf_map_direct_read(struct bpf_map *map, int off, int size, u64 *val)
{
	void *ptr;
	u64 addr;
	int err;

	err = map->ops->map_direct_value_addr(map, &addr, off);
	if (err)
		return err;
	ptr = (void *)(long)addr + off;

	switch (size) {
	case sizeof(u8):
		*val = (u64)*(u8 *)ptr;
		break;
	case sizeof(u16):
		*val = (u64)*(u16 *)ptr;
		break;
	case sizeof(u32):
		*val = (u64)*(u32 *)ptr;
		break;
	case sizeof(u64):
		*val = *(u64 *)ptr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int klpr_check_ptr_to_btf_access(struct bpf_verifier_env *env,
				   struct bpf_reg_state *regs,
				   int regno, int off, int size,
				   enum bpf_access_type atype,
				   int value_regno)
{
	struct bpf_reg_state *reg = regs + regno;
	const struct btf_type *t = (*klpe_btf_type_by_id)(reg->btf, reg->btf_id);
	const char *tname = (*klpe_btf_name_by_offset)(reg->btf, t->name_off);
	enum bpf_type_flag flag = 0;
	u32 btf_id;
	int ret;

	if (off < 0) {
		klpr_verbose(env,
			"R%d is ptr_%s invalid negative access: off=%d\n",
			regno, tname, off);
		return -EACCES;
	}
	if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		klpr_verbose(env,
			"R%d is ptr_%s invalid variable offset: off=%d, var_off=%s\n",
			regno, tname, off, tn_buf);
		return -EACCES;
	}

	if (reg->type & MEM_USER) {
		klpr_verbose(env,
			"R%d is ptr_%s access user memory: off=%d\n",
			regno, tname, off);
		return -EACCES;
	}

	if (reg->type & MEM_PERCPU) {
		klpr_verbose(env,
			"R%d is ptr_%s access percpu memory: off=%d\n",
			regno, tname, off);
		return -EACCES;
	}

	if (env->ops->btf_struct_access) {
		ret = env->ops->btf_struct_access(&env->log, reg->btf, t,
						  off, size, atype, &btf_id, &flag);
	} else {
		if (atype != BPF_READ) {
			klpr_verbose(env, "only read is supported\n");
			return -EACCES;
		}

		ret = (*klpe_btf_struct_access)(&env->log, reg->btf, t, off, size,
					atype, &btf_id, &flag);
	}

	if (ret < 0)
		return ret;

	/* If this is an untrusted pointer, all pointers formed by walking it
	 * also inherit the untrusted flag.
	 */
	if (type_flag(reg->type) & PTR_UNTRUSTED)
		flag |= PTR_UNTRUSTED;

	if (atype == BPF_READ && value_regno >= 0)
		klpr_mark_btf_ld_reg(env, regs, value_regno, ret, reg->btf, btf_id, flag);

	return 0;
}

static int klpr_check_ptr_to_map_access(struct bpf_verifier_env *env,
				   struct bpf_reg_state *regs,
				   int regno, int off, int size,
				   enum bpf_access_type atype,
				   int value_regno)
{
	struct bpf_reg_state *reg = regs + regno;
	struct bpf_map *map = reg->map_ptr;
	enum bpf_type_flag flag = 0;
	const struct btf_type *t;
	const char *tname;
	u32 btf_id;
	int ret;

	if (!(*klpe_btf_vmlinux)) {
		klpr_verbose(env, "map_ptr access not supported without CONFIG_DEBUG_INFO_BTF\n");
		return -ENOTSUPP;
	}

	if (!map->ops->map_btf_id || !*map->ops->map_btf_id) {
		klpr_verbose(env, "map_ptr access not supported for map type %d\n",
			map->map_type);
		return -ENOTSUPP;
	}

	t = (*klpe_btf_type_by_id)((*klpe_btf_vmlinux), *map->ops->map_btf_id);
	tname = (*klpe_btf_name_by_offset)((*klpe_btf_vmlinux), t->name_off);

	if (!env->allow_ptr_to_map_access) {
		klpr_verbose(env,
			"%s access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN\n",
			tname);
		return -EPERM;
	}

	if (off < 0) {
		klpr_verbose(env, "R%d is %s invalid negative access: off=%d\n",
			regno, tname, off);
		return -EACCES;
	}

	if (atype != BPF_READ) {
		klpr_verbose(env, "only read from %s is supported\n", tname);
		return -EACCES;
	}

	ret = (*klpe_btf_struct_access)(&env->log, (*klpe_btf_vmlinux), t, off, size, atype, &btf_id, &flag);
	if (ret < 0)
		return ret;

	if (value_regno >= 0)
		klpr_mark_btf_ld_reg(env, regs, value_regno, ret, (*klpe_btf_vmlinux), btf_id, flag);

	return 0;
}

static int (*klpe_check_stack_access_within_bounds)(
		struct bpf_verifier_env *env,
		int regno, int off, int access_size,
		enum bpf_access_src src, enum bpf_access_type type);

int klpp_check_mem_access(struct bpf_verifier_env *env, int insn_idx, u32 regno,
			    int off, int bpf_size, enum bpf_access_type t,
			    int value_regno, bool strict_alignment_once)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = regs + regno;
	struct bpf_func_state *state;
	int size, err = 0;

	size = bpf_size_to_bytes(bpf_size);
	if (size < 0)
		return size;

	/* alignment checks will add in reg->off themselves */
	err = (*klpe_check_ptr_alignment)(env, reg, off, size, strict_alignment_once);
	if (err)
		return err;

	/* for access checks, reg->off is just part of off */
	off += reg->off;

	if (reg->type == PTR_TO_MAP_KEY) {
		if (t == BPF_WRITE) {
			klpr_verbose(env, "write to change key R%d not allowed\n", regno);
			return -EACCES;
		}

		err = (*klpe_check_mem_region_access)(env, regno, off, size,
					      reg->map_ptr->key_size, false);
		if (err)
			return err;
		if (value_regno >= 0)
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else if (reg->type == PTR_TO_MAP_VALUE) {
		struct bpf_map_value_off_desc *kptr_off_desc = NULL;

		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			klpr_verbose(env, "R%d leaks addr into map\n", value_regno);
			return -EACCES;
		}
		err = (*klpe_check_map_access_type)(env, regno, off, size, t);
		if (err)
			return err;
		err = (*klpe_check_map_access)(env, regno, off, size, false, ACCESS_DIRECT);
		if (err)
			return err;
		if (tnum_is_const(reg->var_off))
			kptr_off_desc = (*klpe_bpf_map_kptr_off_contains)(reg->map_ptr,
								  off + reg->var_off.value);
		if (kptr_off_desc) {
			err = klpr_check_map_kptr_access(env, regno, value_regno, insn_idx,
						    kptr_off_desc);
		} else if (t == BPF_READ && value_regno >= 0) {
			struct bpf_map *map = reg->map_ptr;

			/* if map is read-only, track its contents as scalars */
			if (tnum_is_const(reg->var_off) &&
			    (*klpe_bpf_map_is_rdonly)(map) &&
			    map->ops->map_direct_value_addr) {
				int map_off = off + reg->var_off.value;
				u64 val = 0;

				err = bpf_map_direct_read(map, map_off, size,
							  &val);
				if (err)
					return err;

				regs[value_regno].type = SCALAR_VALUE;
				(*klpe___mark_reg_known)(&regs[value_regno], val);
			} else
				(*klpe_mark_reg_unknown)(env, regs, value_regno);
		}
	} else if (base_type(reg->type) == PTR_TO_MEM) {
		bool rdonly_mem = type_is_rdonly_mem(reg->type);

		if (type_may_be_null(reg->type)) {
			klpr_verbose(env, "R%d invalid mem access '%s'\n", regno,
				(*klpe_reg_type_str)(env, reg->type));
			return -EACCES;
		}

		if (t == BPF_WRITE && rdonly_mem) {
			klpr_verbose(env, "R%d cannot write into %s\n",
				regno, (*klpe_reg_type_str)(env, reg->type));
			return -EACCES;
		}

		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			klpr_verbose(env, "R%d leaks addr into mem\n", value_regno);
			return -EACCES;
		}

		err = (*klpe_check_mem_region_access)(env, regno, off, size,
					      reg->mem_size, false);
		if (!err && value_regno >= 0 && (t == BPF_READ || rdonly_mem))
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else if (reg->type == PTR_TO_CTX) {
		enum bpf_reg_type reg_type = SCALAR_VALUE;
		struct btf *btf = NULL;
		u32 btf_id = 0;

		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			klpr_verbose(env, "R%d leaks addr into ctx\n", value_regno);
			return -EACCES;
		}

		err = (*klpe_check_ptr_off_reg)(env, reg, regno);
		if (err < 0)
			return err;

		err = klpr_check_ctx_access(env, insn_idx, off, size, t, &reg_type, &btf,
				       &btf_id);
		if (err)
			(*klpe_verbose_linfo)(env, insn_idx, "; ");
		if (!err && t == BPF_READ && value_regno >= 0) {
			/* ctx access returns either a scalar, or a
			 * PTR_TO_PACKET[_META,_END]. In the latter
			 * case, we know the offset is zero.
			 */
			if (reg_type == SCALAR_VALUE) {
				(*klpe_mark_reg_unknown)(env, regs, value_regno);
			} else {
				(*klpe_mark_reg_known_zero)(env, regs,
						    value_regno);
				if (type_may_be_null(reg_type))
					regs[value_regno].id = ++env->id_gen;
				/* A load of ctx field could have different
				 * actual load size with the one encoded in the
				 * insn. When the dst is PTR, it is for sure not
				 * a sub-register.
				 */
				regs[value_regno].subreg_def = DEF_NOT_SUBREG;
				if (base_type(reg_type) == PTR_TO_BTF_ID) {
					regs[value_regno].btf = btf;
					regs[value_regno].btf_id = btf_id;
				}
			}
			regs[value_regno].type = reg_type;
		}

	} else if (reg->type == PTR_TO_STACK) {
		/* Basic bounds checks. */
		err = (*klpe_check_stack_access_within_bounds)(env, regno, off, size, ACCESS_DIRECT, t);
		if (err)
			return err;

		state = klpp_func(env, reg);
		err = update_stack_depth(env, state, off);
		if (err)
			return err;

		if (t == BPF_READ)
			err = (*klpe_check_stack_read)(env, regno, off, size,
					       value_regno);
		else
			err = klpp_check_stack_write(env, regno, off, size,
						value_regno, insn_idx);
	} else if (reg_is_pkt_pointer(reg)) {
		if (t == BPF_WRITE && !may_access_direct_pkt_data(env, NULL, t)) {
			klpr_verbose(env, "cannot write into packet\n");
			return -EACCES;
		}
		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			klpr_verbose(env, "R%d leaks addr into packet\n",
				value_regno);
			return -EACCES;
		}
		err = (*klpe_check_packet_access)(env, regno, off, size, false);
		if (!err && t == BPF_READ && value_regno >= 0)
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else if (reg->type == PTR_TO_FLOW_KEYS) {
		if (t == BPF_WRITE && value_regno >= 0 &&
		    is_pointer_value(env, value_regno)) {
			klpr_verbose(env, "R%d leaks addr into flow keys\n",
				value_regno);
			return -EACCES;
		}

		err = klpr_check_flow_keys_access(env, off, size);
		if (!err && t == BPF_READ && value_regno >= 0)
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else if (type_is_sk_pointer(reg->type)) {
		if (t == BPF_WRITE) {
			klpr_verbose(env, "R%d cannot write into %s\n",
				regno, (*klpe_reg_type_str)(env, reg->type));
			return -EACCES;
		}
		err = klpr_check_sock_access(env, insn_idx, regno, off, size, t);
		if (!err && value_regno >= 0)
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else if (reg->type == PTR_TO_TP_BUFFER) {
		err = klpr_check_tp_buffer_access(env, reg, regno, off, size);
		if (!err && t == BPF_READ && value_regno >= 0)
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else if (base_type(reg->type) == PTR_TO_BTF_ID &&
		   !type_may_be_null(reg->type)) {
		err = klpr_check_ptr_to_btf_access(env, regs, regno, off, size, t,
					      value_regno);
	} else if (reg->type == CONST_PTR_TO_MAP) {
		err = klpr_check_ptr_to_map_access(env, regs, regno, off, size, t,
					      value_regno);
	} else if (base_type(reg->type) == PTR_TO_BUF) {
		bool rdonly_mem = type_is_rdonly_mem(reg->type);
		u32 *max_access;

		if (rdonly_mem) {
			if (t == BPF_WRITE) {
				klpr_verbose(env, "R%d cannot write into %s\n",
					regno, (*klpe_reg_type_str)(env, reg->type));
				return -EACCES;
			}
			max_access = &env->prog->aux->max_rdonly_access;
		} else {
			max_access = &env->prog->aux->max_rdwr_access;
		}

		err = klpr_check_buffer_access(env, reg, regno, off, size, false,
					  max_access);

		if (!err && value_regno >= 0 && (rdonly_mem || t == BPF_READ))
			(*klpe_mark_reg_unknown)(env, regs, value_regno);
	} else {
		klpr_verbose(env, "R%d invalid mem access '%s'\n", regno,
			(*klpe_reg_type_str)(env, reg->type));
		return -EACCES;
	}

	if (!err && size < BPF_REG_SIZE && value_regno >= 0 && t == BPF_READ &&
	    regs[value_regno].type == SCALAR_VALUE) {
		/* b/h/w load zero-extends, mark upper bits as known 0 */
		klpr_coerce_reg_to_size(&regs[value_regno], size);
	}
	return err;
}

static int klpr_check_atomic(struct bpf_verifier_env *env, int insn_idx, struct bpf_insn *insn)
{
	int load_reg;
	int err;

	switch (insn->imm) {
	case BPF_ADD:
	case BPF_ADD | BPF_FETCH:
	case BPF_AND:
	case BPF_AND | BPF_FETCH:
	case BPF_OR:
	case BPF_OR | BPF_FETCH:
	case BPF_XOR:
	case BPF_XOR | BPF_FETCH:
	case BPF_XCHG:
	case BPF_CMPXCHG:
		break;
	default:
		klpr_verbose(env, "BPF_ATOMIC uses invalid atomic opcode %02x\n", insn->imm);
		return -EINVAL;
	}

	if (BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) {
		klpr_verbose(env, "invalid atomic operand size\n");
		return -EINVAL;
	}

	/* check src1 operand */
	err = (*klpe_check_reg_arg)(env, insn->src_reg, SRC_OP);
	if (err)
		return err;

	/* check src2 operand */
	err = (*klpe_check_reg_arg)(env, insn->dst_reg, SRC_OP);
	if (err)
		return err;

	if (insn->imm == BPF_CMPXCHG) {
		/* Check comparison of R0 with memory location */
		const u32 aux_reg = BPF_REG_0;

		err = (*klpe_check_reg_arg)(env, aux_reg, SRC_OP);
		if (err)
			return err;

		if (is_pointer_value(env, aux_reg)) {
			klpr_verbose(env, "R%d leaks addr into mem\n", aux_reg);
			return -EACCES;
		}
	}

	if (is_pointer_value(env, insn->src_reg)) {
		klpr_verbose(env, "R%d leaks addr into mem\n", insn->src_reg);
		return -EACCES;
	}

	if (is_ctx_reg(env, insn->dst_reg) ||
	    is_pkt_reg(env, insn->dst_reg) ||
	    is_flow_key_reg(env, insn->dst_reg) ||
	    is_sk_reg(env, insn->dst_reg)) {
		klpr_verbose(env, "BPF_ATOMIC stores into R%d %s is not allowed\n",
			insn->dst_reg,
			(*klpe_reg_type_str)(env, reg_state(env, insn->dst_reg)->type));
		return -EACCES;
	}

	if (insn->imm & BPF_FETCH) {
		if (insn->imm == BPF_CMPXCHG)
			load_reg = BPF_REG_0;
		else
			load_reg = insn->src_reg;

		/* check and record load of old value */
		err = (*klpe_check_reg_arg)(env, load_reg, DST_OP);
		if (err)
			return err;
	} else {
		/* This instruction accesses a memory location but doesn't
		 * actually load it into a register.
		 */
		load_reg = -1;
	}

	/* Check whether we can read the memory, with second call for fetch
	 * case to simulate the register fill.
	 */
	err = klpp_check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
			       BPF_SIZE(insn->code), BPF_READ, -1, true);
	if (!err && load_reg >= 0)
		err = klpp_check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
				       BPF_SIZE(insn->code), BPF_READ, load_reg,
				       true);
	if (err)
		return err;

	/* Check whether we can write into the same memory. */
	err = klpp_check_mem_access(env, insn_idx, insn->dst_reg, insn->off,
			       BPF_SIZE(insn->code), BPF_WRITE, -1, true);
	if (err)
		return err;

	return 0;
}

int klpp_check_stack_range_initialized(
		struct bpf_verifier_env *env, int regno, int off,
		int access_size, bool zero_size_allowed,
		enum bpf_access_src type, struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *reg = reg_state(env, regno);
	struct bpf_func_state *state = klpp_func(env, reg);
	int err, min_off, max_off, i, j, slot, spi;
	char *err_extra = type == ACCESS_HELPER ? " indirect" : "";
	enum bpf_access_type bounds_check_type;
	/* Some accesses can write anything into the stack, others are
	 * read-only.
	 */
	bool clobber = false;

	if (access_size == 0 && !zero_size_allowed) {
		klpr_verbose(env, "invalid zero-sized read\n");
		return -EACCES;
	}

	if (type == ACCESS_HELPER) {
		/* The bounds checks for writes are more permissive than for
		 * reads. However, if raw_mode is not set, we'll do extra
		 * checks below.
		 */
		bounds_check_type = BPF_WRITE;
		clobber = true;
	} else {
		bounds_check_type = BPF_READ;
	}
	err = (*klpe_check_stack_access_within_bounds)(env, regno, off, access_size,
					       type, bounds_check_type);
	if (err)
		return err;


	if (tnum_is_const(reg->var_off)) {
		min_off = max_off = reg->var_off.value + off;
	} else {
		/* Variable offset is prohibited for unprivileged mode for
		 * simplicity since it requires corresponding support in
		 * Spectre masking for stack ALU.
		 * See also retrieve_ptr_limit().
		 */
		if (!env->bypass_spec_v1) {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			klpr_verbose(env, "R%d%s variable offset stack access prohibited for !root, var_off=%s\n",
				regno, err_extra, tn_buf);
			return -EACCES;
		}
		/* Only initialized buffer on stack is allowed to be accessed
		 * with variable offset. With uninitialized buffer it's hard to
		 * guarantee that whole memory is marked as initialized on
		 * helper return since specific bounds are unknown what may
		 * cause uninitialized stack leaking.
		 */
		if (meta && meta->raw_mode)
			meta = NULL;

		min_off = reg->smin_value + off;
		max_off = reg->smax_value + off;
	}

	if (meta && meta->raw_mode) {
		/* Ensure we won't be overwriting dynptrs when simulating byte
		 * by byte access in check_helper_call using meta.access_size.
		 * This would be a problem if we have a helper in the future
		 * which takes:
		 *
		 *	helper(uninit_mem, len, dynptr)
		 *
		 * Now, uninint_mem may overlap with dynptr pointer. Hence, it
		 * may end up writing to dynptr itself when touching memory from
		 * arg 1. This can be relaxed on a case by case basis for known
		 * safe cases, but reject due to the possibilitiy of aliasing by
		 * default.
		 */
		for (i = min_off; i < max_off + access_size; i++) {
			int stack_off = -i - 1;

			spi = klpp___get_spi(i);
			/* raw_mode may write past allocated_stack */
			if (state->allocated_stack <= stack_off)
				continue;
			if (state->stack[spi].slot_type[stack_off % BPF_REG_SIZE] == STACK_DYNPTR) {
				klpr_verbose(env, "potential write to dynptr at off=%d disallowed\n", i);
				return -EACCES;
			}
		}
		meta->access_size = access_size;
		meta->regno = regno;
		return 0;
	}

	for (i = min_off; i < max_off + access_size; i++) {
		u8 *stype;

		slot = -i - 1;
		spi = slot / BPF_REG_SIZE;
		if (state->allocated_stack <= slot)
			goto err;
		stype = &state->stack[spi].slot_type[slot % BPF_REG_SIZE];
		if (*stype == STACK_MISC)
			goto mark;
		if (*stype == STACK_ZERO) {
			if (clobber) {
				/* helper can write anything into the stack */
				*stype = STACK_MISC;
			}
			goto mark;
		}

		if (is_spilled_reg(&state->stack[spi]) &&
		    base_type(state->stack[spi].spilled_ptr.type) == PTR_TO_BTF_ID)
			goto mark;

		if (is_spilled_reg(&state->stack[spi]) &&
		    (state->stack[spi].spilled_ptr.type == SCALAR_VALUE ||
		     env->allow_ptr_leaks)) {
			if (clobber) {
				klpr___mark_reg_unknown(env, &state->stack[spi].spilled_ptr);
				for (j = 0; j < BPF_REG_SIZE; j++)
					scrub_spilled_slot(&state->stack[spi].slot_type[j]);
			}
			goto mark;
		}

err:
		if (tnum_is_const(reg->var_off)) {
			klpr_verbose(env, "invalid%s read from stack R%d off %d+%d size %d\n",
				err_extra, regno, min_off, i - min_off, access_size);
		} else {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			klpr_verbose(env, "invalid%s read from stack R%d var_off %s+%d size %d\n",
				err_extra, regno, tn_buf, i - min_off, access_size);
		}
		return -EACCES;
mark:
		/* reading any byte out of 8-byte 'spill_slot' will cause
		 * the whole slot to be marked as 'read'
		 */
		(*klpe_mark_reg_read)(env, &state->stack[spi].spilled_ptr,
			      state->stack[spi].spilled_ptr.parent,
			      REG_LIVE_READ64);
	}
	return update_stack_depth(env, state, min_off);
}

static int (*klpe_check_helper_mem_access)(struct bpf_verifier_env *env, int regno,
				   int access_size, bool zero_size_allowed,
				   struct bpf_call_arg_meta *meta);

static int (*klpe_check_mem_size_reg)(struct bpf_verifier_env *env,
			      struct bpf_reg_state *reg, u32 regno,
			      bool zero_size_allowed,
			      struct bpf_call_arg_meta *meta);

static int (*klpe_process_spin_lock)(struct bpf_verifier_env *env, int regno,
			     bool is_lock);

static int klpr_process_timer_func(struct bpf_verifier_env *env, int regno,
			      struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	bool is_const = tnum_is_const(reg->var_off);
	struct bpf_map *map = reg->map_ptr;
	u64 val = reg->var_off.value;

	if (!is_const) {
		klpr_verbose(env,
			"R%d doesn't have constant offset. bpf_timer has to be at the constant offset\n",
			regno);
		return -EINVAL;
	}
	if (!map->btf) {
		klpr_verbose(env, "map '%s' has to have BTF in order to use bpf_timer\n",
			map->name);
		return -EINVAL;
	}
	if (!map_value_has_timer(map)) {
		if (map->timer_off == -E2BIG)
			klpr_verbose(env,
				"map '%s' has more than one 'struct bpf_timer'\n",
				map->name);
		else if (map->timer_off == -ENOENT)
			klpr_verbose(env,
				"map '%s' doesn't have 'struct bpf_timer'\n",
				map->name);
		else
			klpr_verbose(env,
				"map '%s' is not a struct type or bpf_timer is mangled\n",
				map->name);
		return -EINVAL;
	}
	if (map->timer_off != val + reg->off) {
		klpr_verbose(env, "off %lld doesn't point to 'struct bpf_timer' that is at %d\n",
			val + reg->off, map->timer_off);
		return -EINVAL;
	}
	if (meta->map_ptr) {
		klpr_verbose(env, "verifier bug. Two map pointers in a timer helper\n");
		return -EFAULT;
	}
	meta->map_uid = reg->map_uid;
	meta->map_ptr = map;
	return 0;
}

static int klpr_process_kptr_func(struct bpf_verifier_env *env, int regno,
			     struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	struct bpf_map_value_off_desc *off_desc;
	struct bpf_map *map_ptr = reg->map_ptr;
	u32 kptr_off;
	int ret;

	if (!tnum_is_const(reg->var_off)) {
		klpr_verbose(env,
			"R%d doesn't have constant offset. kptr has to be at the constant offset\n",
			regno);
		return -EINVAL;
	}
	if (!map_ptr->btf) {
		klpr_verbose(env, "map '%s' has to have BTF in order to use bpf_kptr_xchg\n",
			map_ptr->name);
		return -EINVAL;
	}
	if (!map_value_has_kptrs(map_ptr)) {
		ret = PTR_ERR_OR_ZERO(map_ptr->kptr_off_tab);
		if (ret == -E2BIG)
			klpr_verbose(env, "map '%s' has more than %d kptr\n", map_ptr->name,
				BPF_MAP_VALUE_OFF_MAX);
		else if (ret == -EEXIST)
			klpr_verbose(env, "map '%s' has repeating kptr BTF tags\n", map_ptr->name);
		else
			klpr_verbose(env, "map '%s' has no valid kptr\n", map_ptr->name);
		return -EINVAL;
	}

	meta->map_ptr = map_ptr;
	kptr_off = reg->off + reg->var_off.value;
	off_desc = (*klpe_bpf_map_kptr_off_contains)(map_ptr, kptr_off);
	if (!off_desc) {
		klpr_verbose(env, "off=%d doesn't point to kptr\n", kptr_off);
		return -EACCES;
	}
	if (off_desc->type != BPF_KPTR_REF) {
		klpr_verbose(env, "off=%d kptr isn't referenced kptr\n", kptr_off);
		return -EACCES;
	}
	meta->kptr_off_desc = off_desc;
	return 0;
}

/* There are two register types representing a bpf_dynptr, one is PTR_TO_STACK
 * which points to a stack slot, and the other is CONST_PTR_TO_DYNPTR.
 *
 * syu: CONST_PTR_TO_DYNPTR pointer is not backported, so it can never be
 * encountered.
 *
 * In both cases we deal with the first 8 bytes, but need to mark the next 8
 * bytes as STACK_DYNPTR in case of PTR_TO_STACK. In case of
 * CONST_PTR_TO_DYNPTR, we are guaranteed to get the beginning of the object.
 *
 * Mutability of bpf_dynptr is at two levels, one is at the level of struct
 * bpf_dynptr itself, i.e. whether the helper is receiving a pointer to struct
 * bpf_dynptr or pointer to const struct bpf_dynptr. In the former case, it can
 * mutate the view of the dynptr and also possibly destroy it. In the latter
 * case, it cannot mutate the bpf_dynptr itself but it can still mutate the
 * memory that dynptr points to.
 *
 * The verifier will keep track both levels of mutation (bpf_dynptr's in
 * reg->type and the memory's in reg->dynptr.type), but there is no support for
 * readonly dynptr view yet, hence only the first case is tracked and checked.
 *
 * This is consistent with how C applies the const modifier to a struct object,
 * where the pointer itself inside bpf_dynptr becomes const but not what it
 * points to.
 *
 * Helpers which do not mutate the bpf_dynptr set MEM_RDONLY in their argument
 * type, and declare it as 'const struct bpf_dynptr *' in their prototype.
 */
static int klpp_process_dynptr_func(struct bpf_verifier_env *env, int regno,
			enum bpf_arg_type arg_type,
			struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	int spi = 0;

	/* MEM_UNINIT and MEM_RDONLY are exclusive, when applied to an
	 * ARG_PTR_TO_DYNPTR (or ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_*):
	 */
	if ((arg_type & (MEM_UNINIT | MEM_RDONLY)) == (MEM_UNINIT | MEM_RDONLY)) {
		klpr_verbose(env, "verifier internal error: misconfigured dynptr helper type flags\n");
		return -EFAULT;
	}
	/* CONST_PTR_TO_DYNPTR already has fixed and var_off as 0 due to
	 * check_func_arg_reg_off's logic. We only need to check offset
	 * and its alignment for PTR_TO_STACK.
	 */
	if (reg->type == PTR_TO_STACK) {
		spi = klpp_dynptr_get_spi(env, reg);
		if (spi < 0 && spi != -ERANGE)
			return spi;
	}

	/*  MEM_UNINIT - Points to memory that is an appropriate candidate for
	 *		 constructing a mutable bpf_dynptr object.
	 *
	 *		 Currently, this is only possible with PTR_TO_STACK
	 *		 pointing to a region of at least 16 bytes which doesn't
	 *		 contain an existing bpf_dynptr.
	 *
	 *  MEM_RDONLY - Points to a initialized bpf_dynptr that will not be
	 *		 mutated or destroyed. However, the memory it points to
	 *		 may be mutated.
	 *
	 *  None       - Points to a initialized dynptr that can be mutated and
	 *		 destroyed, including mutation of the memory it points
	 *		 to.
	 */
	if (arg_type & MEM_UNINIT) {
		if (!klpp_is_dynptr_reg_valid_uninit(env, reg, spi)) {
			klpr_verbose(env, "Dynptr has to be an uninitialized dynptr\n");
			return -EINVAL;
		}

		/* We only support one dynptr being uninitialized at the moment,
		 * which is sufficient for the helper functions we have right now.
		 */
		if (meta->uninit_dynptr_regno) {
			klpr_verbose(env, "verifier internal error: multiple uninitialized dynptr args\n");
			return -EFAULT;
		}

		meta->uninit_dynptr_regno = regno;
	} else /* MEM_RDONLY and None case from above */ {
		int err;

		if (!klpp_is_dynptr_reg_valid_init(env, reg, spi)) {
			klpr_verbose(env,
				"Expected an initialized dynptr as arg #%d\n",
				regno);
			return -EINVAL;
		}

		/* Fold modifiers (in this case, MEM_RDONLY) when checking expected type */
		if (!klpp_is_dynptr_type_expected(env, reg, arg_type & ~MEM_RDONLY)) {
			const char *err_extra = "";

			switch (arg_type & DYNPTR_TYPE_FLAG_MASK) {
			case DYNPTR_TYPE_LOCAL:
				err_extra = "local";
				break;
			case DYNPTR_TYPE_RINGBUF:
				err_extra = "ringbuf";
				break;
			default:
				err_extra = "<unknown>";
				break;
			}
			klpr_verbose(env,
				"Expected a dynptr of type %s as arg #%d\n",
				err_extra, regno);
			return -EINVAL;
		}

		err = klpp_mark_dynptr_read(env, reg);
		if (err)
			return err;
	}
	return 0;
}


static bool arg_type_is_mem_size(enum bpf_arg_type type)
{
	return type == ARG_CONST_SIZE ||
	       type == ARG_CONST_SIZE_OR_ZERO;
}

static bool arg_type_is_alloc_size(enum bpf_arg_type type)
{
	return type == ARG_CONST_ALLOC_SIZE_OR_ZERO;
}

static bool arg_type_is_int_ptr(enum bpf_arg_type type)
{
	return type == ARG_PTR_TO_INT ||
	       type == ARG_PTR_TO_LONG;
}

static bool arg_type_is_release(enum bpf_arg_type type)
{
	return type & OBJ_RELEASE;
}

static bool arg_type_is_dynptr(enum bpf_arg_type type)
{
	return base_type(type) == ARG_PTR_TO_DYNPTR;
}

static int int_ptr_type_to_size(enum bpf_arg_type type)
{
	if (type == ARG_PTR_TO_INT)
		return sizeof(u32);
	else if (type == ARG_PTR_TO_LONG)
		return sizeof(u64);

	return -EINVAL;
}

static int klpr_resolve_map_arg_type(struct bpf_verifier_env *env,
				 const struct bpf_call_arg_meta *meta,
				 enum bpf_arg_type *arg_type)
{
	if (!meta->map_ptr) {
		/* kernel subsystem misconfigured verifier */
		klpr_verbose(env, "invalid map_ptr to access map->type\n");
		return -EACCES;
	}

	switch (meta->map_ptr->map_type) {
	case BPF_MAP_TYPE_SOCKMAP:
	case BPF_MAP_TYPE_SOCKHASH:
		if (*arg_type == ARG_PTR_TO_MAP_VALUE) {
			*arg_type = ARG_PTR_TO_BTF_ID_SOCK_COMMON;
		} else {
			klpr_verbose(env, "invalid arg_type for sockmap/sockhash\n");
			return -EINVAL;
		}
		break;
	case BPF_MAP_TYPE_BLOOM_FILTER:
		if (meta->func_id == BPF_FUNC_map_peek_elem)
			*arg_type = ARG_PTR_TO_MAP_VALUE;
		break;
	default:
		break;
	}
	return 0;
}

struct bpf_reg_types {
	const enum bpf_reg_type types[10];
	u32 *btf_id;
};

static const struct bpf_reg_types *(*klpe_compatible_reg_types)[__BPF_ARG_TYPE_MAX]

#ifdef CONFIG_NET

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
;

static int klpr_check_reg_type(struct bpf_verifier_env *env, u32 regno,
			  enum bpf_arg_type arg_type,
			  const u32 *arg_btf_id,
			  struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	enum bpf_reg_type expected, type = reg->type;
	const struct bpf_reg_types *compatible;
	int i, j;

	compatible = (*klpe_compatible_reg_types)[base_type(arg_type)];
	if (!compatible) {
		klpr_verbose(env, "verifier internal error: unsupported arg type %d\n", arg_type);
		return -EFAULT;
	}

	/* ARG_PTR_TO_MEM + RDONLY is compatible with PTR_TO_MEM and PTR_TO_MEM + RDONLY,
	 * but ARG_PTR_TO_MEM is compatible only with PTR_TO_MEM and NOT with PTR_TO_MEM + RDONLY
	 *
	 * Same for MAYBE_NULL:
	 *
	 * ARG_PTR_TO_MEM + MAYBE_NULL is compatible with PTR_TO_MEM and PTR_TO_MEM + MAYBE_NULL,
	 * but ARG_PTR_TO_MEM is compatible only with PTR_TO_MEM but NOT with PTR_TO_MEM + MAYBE_NULL
	 *
	 * Therefore we fold these flags depending on the arg_type before comparison.
	 */
	if (arg_type & MEM_RDONLY)
		type &= ~MEM_RDONLY;
	if (arg_type & PTR_MAYBE_NULL)
		type &= ~PTR_MAYBE_NULL;

	for (i = 0; i < ARRAY_SIZE(compatible->types); i++) {
		expected = compatible->types[i];
		if (expected == NOT_INIT)
			break;

		if (type == expected)
			goto found;
	}

	klpr_verbose(env, "R%d type=%s expected=", regno, (*klpe_reg_type_str)(env, reg->type));
	for (j = 0; j + 1 < i; j++)
		klpr_verbose(env, "%s, ", (*klpe_reg_type_str)(env, compatible->types[j]));
	klpr_verbose(env, "%s\n", (*klpe_reg_type_str)(env, compatible->types[j]));
	return -EACCES;

found:
	if (reg->type == PTR_TO_BTF_ID) {
		/* For bpf_sk_release, it needs to match against first member
		 * 'struct sock_common', hence make an exception for it. This
		 * allows bpf_sk_release to work for multiple socket types.
		 */
		bool strict_type_match = arg_type_is_release(arg_type) &&
					 meta->func_id != BPF_FUNC_sk_release;

		if (!arg_btf_id) {
			if (!compatible->btf_id) {
				klpr_verbose(env, "verifier internal error: missing arg compatible BTF ID\n");
				return -EFAULT;
			}
			arg_btf_id = compatible->btf_id;
		}

		if (meta->func_id == BPF_FUNC_kptr_xchg) {
			if ((*klpe_map_kptr_match_type)(env, meta->kptr_off_desc, reg, regno))
				return -EACCES;
		} else if (!(*klpe_btf_struct_ids_match)(&env->log, reg->btf, reg->btf_id, reg->off,
						 (*klpe_btf_vmlinux), *arg_btf_id,
						 strict_type_match)) {
			klpr_verbose(env, "R%d is of type %s but %s is expected\n",
				regno, (*klpe_kernel_type_name)(reg->btf, reg->btf_id),
				(*klpe_kernel_type_name)((*klpe_btf_vmlinux), *arg_btf_id));
			return -EACCES;
		}
	}

	return 0;
}

int klpp_check_func_arg_reg_off(struct bpf_verifier_env *env,
			   const struct bpf_reg_state *reg, int regno,
			   enum bpf_arg_type arg_type)
{
	u32 type = reg->type;

	/* When referenced register is passed to release function, its fixed
	 * offset must be 0.
	 *
	 * We will check arg_type_is_release reg has ref_obj_id when storing
	 * meta->release_regno.
	 */
	if (arg_type_is_release(arg_type)) {
		/* ARG_PTR_TO_DYNPTR with OBJ_RELEASE is a bit special, as it
		 * may not directly point to the object being released, but to
		 * dynptr pointing to such object, which might be at some offset
		 * on the stack. In that case, we simply to fallback to the
		 * default handling.
		 */
		if (arg_type_is_dynptr(arg_type) && type == PTR_TO_STACK)
			return 0;
		/* Doing check_ptr_off_reg check for the offset will catch this
		 * because fixed_off_ok is false, but checking here allows us
		 * to give the user a better error message.
		 */
		if (reg->off) {
			klpr_verbose(env, "R%d must have zero offset when passed to release func or trusted arg to kfunc\n",
				regno);
			return -EINVAL;
		}
		return (*klpe___check_ptr_off_reg)(env, reg, regno, false);
	}

	switch (type) {
	/* Pointer types where both fixed and variable offset is explicitly allowed: */
	case PTR_TO_STACK:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_MAP_KEY:
	case PTR_TO_MAP_VALUE:
	case PTR_TO_MEM:
	case PTR_TO_MEM | MEM_RDONLY:
	case PTR_TO_MEM | MEM_ALLOC:
	case PTR_TO_BUF:
	case PTR_TO_BUF | MEM_RDONLY:
	case SCALAR_VALUE:
		return 0;
	/* All the rest must be rejected, except PTR_TO_BTF_ID which allows
	 * fixed offset.
	 */
	case PTR_TO_BTF_ID:
		/* When referenced PTR_TO_BTF_ID is passed to release function,
		 * its fixed offset must be 0. In the other cases, fixed offset
		 * can be non-zero. This was already checked above. So pass
		 * fixed_off_ok as true to allow fixed offset for all other
		 * cases. var_off always must be 0 for PTR_TO_BTF_ID, hence we
		 * still need to do checks instead of returning.
		 */
		return (*klpe___check_ptr_off_reg)(env, reg, regno, true);
	default:
		return (*klpe___check_ptr_off_reg)(env, reg, regno, false);
	}
}

static int klpp_dynptr_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	int spi;

	spi = klpp_dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;
	return state->stack[spi].spilled_ptr.id;
}

static u32 klpp_dynptr_ref_obj_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = klpp_func(env, reg);
	int spi;

	spi = klpp_dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;

	return state->stack[spi].spilled_ptr.ref_obj_id;
}

static int klpp_check_func_arg(struct bpf_verifier_env *env, u32 arg,
			  struct bpf_call_arg_meta *meta,
			  const struct bpf_func_proto *fn)
{
	u32 regno = BPF_REG_1 + arg;
	struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
	enum bpf_arg_type arg_type = fn->arg_type[arg];
	enum bpf_reg_type type = reg->type;
	int err = 0;

	klpr_verbose(env, "klpp_check_func_arg: arg: %d, arg_type: %d, type: %d\n", arg, arg_type, type);

	if (arg_type == ARG_DONTCARE)
		return 0;

	err = (*klpe_check_reg_arg)(env, regno, SRC_OP);
	if (err)
		return err;

	if (arg_type == ARG_ANYTHING) {
		if (is_pointer_value(env, regno)) {
			klpr_verbose(env, "R%d leaks addr into helper function\n",
				regno);
			return -EACCES;
		}
		return 0;
	}

	if (type_is_pkt_pointer(type) &&
	    !may_access_direct_pkt_data(env, meta, BPF_READ)) {
		klpr_verbose(env, "helper access to the packet is not allowed\n");
		return -EACCES;
	}

	if (base_type(arg_type) == ARG_PTR_TO_MAP_VALUE) {
		err = klpr_resolve_map_arg_type(env, meta, &arg_type);
		if (err)
			return err;
	}

	if (register_is_null(reg) && type_may_be_null(arg_type))
		/* A NULL register has a SCALAR_VALUE type, so skip
		 * type checking.
		 */
		goto skip_type_check;

	err = klpr_check_reg_type(env, regno, arg_type, fn->arg_btf_id[arg], meta);
	if (err)
		return err;

	err = klpp_check_func_arg_reg_off(env, reg, regno, arg_type);
	if (err)
		return err;

skip_type_check:
	if (arg_type_is_release(arg_type)) {
		if (arg_type_is_dynptr(arg_type)) {
			struct bpf_func_state *state = klpp_func(env, reg);
			int spi;

			/* Only dynptr created on stack can be released, thus
			 * the get_spi and stack state checks for spilled_ptr
			 * should only be done before process_dynptr_func for
			 * PTR_TO_STACK.
			 */
			if (reg->type == PTR_TO_STACK) {
				spi = klpp_dynptr_get_spi(env, reg);
				if (spi < 0 || !state->stack[spi].spilled_ptr.ref_obj_id) {
					klpr_verbose(env, "arg %d is an unacquired reference\n", regno);
					return -EINVAL;
				}
			} else {
				klpr_verbose(env, "cannot release unowned const bpf_dynptr\n");
				return -EINVAL;
			}
		} else if (!reg->ref_obj_id && !register_is_null(reg)) {
			klpr_verbose(env, "R%d must be referenced when passed to release function\n",
				regno);
			return -EINVAL;
		}
		if (meta->release_regno) {
			klpr_verbose(env, "verifier internal error: more than one release argument\n");
			return -EFAULT;
		}
		meta->release_regno = regno;
	}

	if (reg->ref_obj_id) {
		if (meta->ref_obj_id) {
			klpr_verbose(env, "verifier internal error: more than one arg with ref_obj_id R%d %u %u\n",
				regno, reg->ref_obj_id,
				meta->ref_obj_id);
			return -EFAULT;
		}
		meta->ref_obj_id = reg->ref_obj_id;
	}

	if (arg_type == ARG_CONST_MAP_PTR) {
		/* bpf_map_xxx(map_ptr) call: remember that map_ptr */
		if (meta->map_ptr) {
			/* Use map_uid (which is unique id of inner map) to reject:
			 * inner_map1 = bpf_map_lookup_elem(outer_map, key1)
			 * inner_map2 = bpf_map_lookup_elem(outer_map, key2)
			 * if (inner_map1 && inner_map2) {
			 *     timer = bpf_map_lookup_elem(inner_map1);
			 *     if (timer)
			 *         // mismatch would have been allowed
			 *         bpf_timer_init(timer, inner_map2);
			 * }
			 *
			 * Comparing map_ptr is enough to distinguish normal and outer maps.
			 */
			if (meta->map_ptr != reg->map_ptr ||
			    meta->map_uid != reg->map_uid) {
				klpr_verbose(env,
					"timer pointer in R1 map_uid=%d doesn't match map pointer in R2 map_uid=%d\n",
					meta->map_uid, reg->map_uid);
				return -EINVAL;
			}
		}
		meta->map_ptr = reg->map_ptr;
		meta->map_uid = reg->map_uid;
	} else if (arg_type == ARG_PTR_TO_MAP_KEY) {
		/* bpf_map_xxx(..., map_ptr, ..., key) call:
		 * check that [key, key + map->key_size) are within
		 * stack limits and initialized
		 */
		if (!meta->map_ptr) {
			/* in function declaration map_ptr must come before
			 * map_key, so that it's verified and known before
			 * we have to check map_key here. Otherwise it means
			 * that kernel subsystem misconfigured verifier
			 */
			klpr_verbose(env, "invalid map_ptr to access map->key\n");
			return -EACCES;
		}
		err = (*klpe_check_helper_mem_access)(env, regno,
					      meta->map_ptr->key_size, false,
					      NULL);
	} else if (base_type(arg_type) == ARG_PTR_TO_MAP_VALUE) {
		if (type_may_be_null(arg_type) && register_is_null(reg))
			return 0;

		/* bpf_map_xxx(..., map_ptr, ..., value) call:
		 * check [value, value + map->value_size) validity
		 */
		if (!meta->map_ptr) {
			/* kernel subsystem misconfigured verifier */
			klpr_verbose(env, "invalid map_ptr to access map->value\n");
			return -EACCES;
		}
		meta->raw_mode = arg_type & MEM_UNINIT;
		err = (*klpe_check_helper_mem_access)(env, regno,
					      meta->map_ptr->value_size, false,
					      meta);
	} else if (arg_type == ARG_PTR_TO_PERCPU_BTF_ID) {
		if (!reg->btf_id) {
			klpr_verbose(env, "Helper has invalid btf_id in R%d\n", regno);
			return -EACCES;
		}
		meta->ret_btf = reg->btf;
		meta->ret_btf_id = reg->btf_id;
	} else if (arg_type == ARG_PTR_TO_SPIN_LOCK) {
		if (meta->func_id == BPF_FUNC_spin_lock) {
			if ((*klpe_process_spin_lock)(env, regno, true))
				return -EACCES;
		} else if (meta->func_id == BPF_FUNC_spin_unlock) {
			if ((*klpe_process_spin_lock)(env, regno, false))
				return -EACCES;
		} else {
			klpr_verbose(env, "verifier internal error\n");
			return -EFAULT;
		}
	} else if (arg_type == ARG_PTR_TO_TIMER) {
		if (klpr_process_timer_func(env, regno, meta))
			return -EACCES;
	} else if (arg_type == ARG_PTR_TO_FUNC) {
		meta->subprogno = reg->subprogno;
	} else if (base_type(arg_type) == ARG_PTR_TO_MEM) {
		/* The access to this pointer is only checked when we hit the
		 * next is_mem_size argument below.
		 */
		meta->raw_mode = arg_type & MEM_UNINIT;
	} else if (arg_type_is_mem_size(arg_type)) {
		bool zero_size_allowed = (arg_type == ARG_CONST_SIZE_OR_ZERO);

		err = (*klpe_check_mem_size_reg)(env, reg, regno, zero_size_allowed, meta);
	} else if (arg_type_is_dynptr(arg_type)) {
		if (klpp_process_dynptr_func(env, regno, arg_type, meta))
			return -EACCES;
	} else if (arg_type_is_alloc_size(arg_type)) {
		if (!tnum_is_const(reg->var_off)) {
			klpr_verbose(env, "R%d is not a known constant'\n",
				regno);
			return -EACCES;
		}
		meta->mem_size = reg->var_off.value;
	} else if (arg_type_is_int_ptr(arg_type)) {
		int size = int_ptr_type_to_size(arg_type);

		err = (*klpe_check_helper_mem_access)(env, regno, size, false, meta);
		if (err)
			return err;
		err = (*klpe_check_ptr_alignment)(env, reg, 0, size, true);
	} else if (arg_type == ARG_PTR_TO_CONST_STR) {
		struct bpf_map *map = reg->map_ptr;
		int map_off;
		u64 map_addr;
		char *str_ptr;

		if (!(*klpe_bpf_map_is_rdonly)(map)) {
			klpr_verbose(env, "R%d does not point to a readonly map'\n", regno);
			return -EACCES;
		}

		if (!tnum_is_const(reg->var_off)) {
			klpr_verbose(env, "R%d is not a constant address'\n", regno);
			return -EACCES;
		}

		if (!map->ops->map_direct_value_addr) {
			klpr_verbose(env, "no direct value access support for this map type\n");
			return -EACCES;
		}

		err = (*klpe_check_map_access)(env, regno, reg->off,
				       map->value_size - reg->off, false,
				       ACCESS_HELPER);
		if (err)
			return err;

		map_off = reg->off + reg->var_off.value;
		err = map->ops->map_direct_value_addr(map, &map_addr, map_off);
		if (err) {
			klpr_verbose(env, "direct value access on string failed\n");
			return err;
		}

		str_ptr = (char *)(long)(map_addr);
		if (!strnchr(str_ptr + map_off, map->value_size - map_off, 0)) {
			klpr_verbose(env, "string is not zero-terminated\n");
			return -EINVAL;
		}
	} else if (arg_type == ARG_PTR_TO_KPTR) {
		if (klpr_process_kptr_func(env, regno, meta))
			return -EACCES;
	}

	return err;
}

static bool (*klpe_may_update_sockmap)(struct bpf_verifier_env *env, int func_id);

static bool allow_tail_call_in_subprogs(struct bpf_verifier_env *env)
{
	return env->prog->jit_requested && IS_ENABLED(CONFIG_X86_64);
}

static int klpr_check_map_func_compatibility(struct bpf_verifier_env *env,
					struct bpf_map *map, int func_id)
{
	if (!map)
		return 0;

	/* We need a two way check, first is from map perspective ... */
	switch (map->map_type) {
	case BPF_MAP_TYPE_PROG_ARRAY:
		if (func_id != BPF_FUNC_tail_call)
			goto error;
		break;
	case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		if (func_id != BPF_FUNC_perf_event_read &&
		    func_id != BPF_FUNC_perf_event_output &&
		    func_id != BPF_FUNC_skb_output &&
		    func_id != BPF_FUNC_perf_event_read_value &&
		    func_id != BPF_FUNC_xdp_output)
			goto error;
		break;
	case BPF_MAP_TYPE_RINGBUF:
		if (func_id != BPF_FUNC_ringbuf_output &&
		    func_id != BPF_FUNC_ringbuf_reserve &&
		    func_id != BPF_FUNC_ringbuf_query &&
		    func_id != BPF_FUNC_ringbuf_reserve_dynptr &&
		    func_id != BPF_FUNC_ringbuf_submit_dynptr &&
		    func_id != BPF_FUNC_ringbuf_discard_dynptr)
			goto error;
		break;
	case BPF_MAP_TYPE_STACK_TRACE:
		if (func_id != BPF_FUNC_get_stackid)
			goto error;
		break;
	case BPF_MAP_TYPE_CGROUP_ARRAY:
		if (func_id != BPF_FUNC_skb_under_cgroup &&
		    func_id != BPF_FUNC_current_task_under_cgroup)
			goto error;
		break;
	case BPF_MAP_TYPE_CGROUP_STORAGE:
	case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		if (func_id != BPF_FUNC_get_local_storage)
			goto error;
		break;
	case BPF_MAP_TYPE_DEVMAP:
	case BPF_MAP_TYPE_DEVMAP_HASH:
		if (func_id != BPF_FUNC_redirect_map &&
		    func_id != BPF_FUNC_map_lookup_elem)
			goto error;
		break;
	/* Restrict bpf side of cpumap and xskmap, open when use-cases
	 * appear.
	 */
	case BPF_MAP_TYPE_CPUMAP:
		if (func_id != BPF_FUNC_redirect_map)
			goto error;
		break;
	case BPF_MAP_TYPE_XSKMAP:
		if (func_id != BPF_FUNC_redirect_map &&
		    func_id != BPF_FUNC_map_lookup_elem)
			goto error;
		break;
	case BPF_MAP_TYPE_ARRAY_OF_MAPS:
	case BPF_MAP_TYPE_HASH_OF_MAPS:
		if (func_id != BPF_FUNC_map_lookup_elem)
			goto error;
		break;
	case BPF_MAP_TYPE_SOCKMAP:
		if (func_id != BPF_FUNC_sk_redirect_map &&
		    func_id != BPF_FUNC_sock_map_update &&
		    func_id != BPF_FUNC_map_delete_elem &&
		    func_id != BPF_FUNC_msg_redirect_map &&
		    func_id != BPF_FUNC_sk_select_reuseport &&
		    func_id != BPF_FUNC_map_lookup_elem &&
		    !(*klpe_may_update_sockmap)(env, func_id))
			goto error;
		break;
	case BPF_MAP_TYPE_SOCKHASH:
		if (func_id != BPF_FUNC_sk_redirect_hash &&
		    func_id != BPF_FUNC_sock_hash_update &&
		    func_id != BPF_FUNC_map_delete_elem &&
		    func_id != BPF_FUNC_msg_redirect_hash &&
		    func_id != BPF_FUNC_sk_select_reuseport &&
		    func_id != BPF_FUNC_map_lookup_elem &&
		    !(*klpe_may_update_sockmap)(env, func_id))
			goto error;
		break;
	case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
		if (func_id != BPF_FUNC_sk_select_reuseport)
			goto error;
		break;
	case BPF_MAP_TYPE_QUEUE:
	case BPF_MAP_TYPE_STACK:
		if (func_id != BPF_FUNC_map_peek_elem &&
		    func_id != BPF_FUNC_map_pop_elem &&
		    func_id != BPF_FUNC_map_push_elem)
			goto error;
		break;
	case BPF_MAP_TYPE_SK_STORAGE:
		if (func_id != BPF_FUNC_sk_storage_get &&
		    func_id != BPF_FUNC_sk_storage_delete)
			goto error;
		break;
	case BPF_MAP_TYPE_INODE_STORAGE:
		if (func_id != BPF_FUNC_inode_storage_get &&
		    func_id != BPF_FUNC_inode_storage_delete)
			goto error;
		break;
	case BPF_MAP_TYPE_TASK_STORAGE:
		if (func_id != BPF_FUNC_task_storage_get &&
		    func_id != BPF_FUNC_task_storage_delete)
			goto error;
		break;
	case BPF_MAP_TYPE_BLOOM_FILTER:
		if (func_id != BPF_FUNC_map_peek_elem &&
		    func_id != BPF_FUNC_map_push_elem)
			goto error;
		break;
	default:
		break;
	}

	/* ... and second from the function itself. */
	switch (func_id) {
	case BPF_FUNC_tail_call:
		if (map->map_type != BPF_MAP_TYPE_PROG_ARRAY)
			goto error;
		if (env->subprog_cnt > 1 && !allow_tail_call_in_subprogs(env)) {
			klpr_verbose(env, "tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls\n");
			return -EINVAL;
		}
		break;
	case BPF_FUNC_perf_event_read:
	case BPF_FUNC_perf_event_output:
	case BPF_FUNC_perf_event_read_value:
	case BPF_FUNC_skb_output:
	case BPF_FUNC_xdp_output:
		if (map->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
			goto error;
		break;
	case BPF_FUNC_ringbuf_output:
	case BPF_FUNC_ringbuf_reserve:
	case BPF_FUNC_ringbuf_query:
	case BPF_FUNC_ringbuf_reserve_dynptr:
	case BPF_FUNC_ringbuf_submit_dynptr:
	case BPF_FUNC_ringbuf_discard_dynptr:
		if (map->map_type != BPF_MAP_TYPE_RINGBUF)
			goto error;
		break;
	case BPF_FUNC_get_stackid:
		if (map->map_type != BPF_MAP_TYPE_STACK_TRACE)
			goto error;
		break;
	case BPF_FUNC_current_task_under_cgroup:
	case BPF_FUNC_skb_under_cgroup:
		if (map->map_type != BPF_MAP_TYPE_CGROUP_ARRAY)
			goto error;
		break;
	case BPF_FUNC_redirect_map:
		if (map->map_type != BPF_MAP_TYPE_DEVMAP &&
		    map->map_type != BPF_MAP_TYPE_DEVMAP_HASH &&
		    map->map_type != BPF_MAP_TYPE_CPUMAP &&
		    map->map_type != BPF_MAP_TYPE_XSKMAP)
			goto error;
		break;
	case BPF_FUNC_sk_redirect_map:
	case BPF_FUNC_msg_redirect_map:
	case BPF_FUNC_sock_map_update:
		if (map->map_type != BPF_MAP_TYPE_SOCKMAP)
			goto error;
		break;
	case BPF_FUNC_sk_redirect_hash:
	case BPF_FUNC_msg_redirect_hash:
	case BPF_FUNC_sock_hash_update:
		if (map->map_type != BPF_MAP_TYPE_SOCKHASH)
			goto error;
		break;
	case BPF_FUNC_get_local_storage:
		if (map->map_type != BPF_MAP_TYPE_CGROUP_STORAGE &&
		    map->map_type != BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
			goto error;
		break;
	case BPF_FUNC_sk_select_reuseport:
		if (map->map_type != BPF_MAP_TYPE_REUSEPORT_SOCKARRAY &&
		    map->map_type != BPF_MAP_TYPE_SOCKMAP &&
		    map->map_type != BPF_MAP_TYPE_SOCKHASH)
			goto error;
		break;
	case BPF_FUNC_map_pop_elem:
		if (map->map_type != BPF_MAP_TYPE_QUEUE &&
		    map->map_type != BPF_MAP_TYPE_STACK)
			goto error;
		break;
	case BPF_FUNC_map_peek_elem:
	case BPF_FUNC_map_push_elem:
		if (map->map_type != BPF_MAP_TYPE_QUEUE &&
		    map->map_type != BPF_MAP_TYPE_STACK &&
		    map->map_type != BPF_MAP_TYPE_BLOOM_FILTER)
			goto error;
		break;
	case BPF_FUNC_map_lookup_percpu_elem:
		if (map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY &&
		    map->map_type != BPF_MAP_TYPE_PERCPU_HASH &&
		    map->map_type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
			goto error;
		break;
	case BPF_FUNC_sk_storage_get:
	case BPF_FUNC_sk_storage_delete:
		if (map->map_type != BPF_MAP_TYPE_SK_STORAGE)
			goto error;
		break;
	case BPF_FUNC_inode_storage_get:
	case BPF_FUNC_inode_storage_delete:
		if (map->map_type != BPF_MAP_TYPE_INODE_STORAGE)
			goto error;
		break;
	case BPF_FUNC_task_storage_get:
	case BPF_FUNC_task_storage_delete:
		if (map->map_type != BPF_MAP_TYPE_TASK_STORAGE)
			goto error;
		break;
	default:
		break;
	}

	return 0;
error:
	klpr_verbose(env, "cannot pass map_type %d into func %s#%d\n",
		map->map_type, (*klpe_func_id_name)(func_id), func_id);
	return -EINVAL;
}

static bool check_raw_mode_ok(const struct bpf_func_proto *fn)
{
	int count = 0;

	if (fn->arg1_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg2_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg3_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg4_type == ARG_PTR_TO_UNINIT_MEM)
		count++;
	if (fn->arg5_type == ARG_PTR_TO_UNINIT_MEM)
		count++;

	/* We only support one arg being in raw mode at the moment,
	 * which is sufficient for the helper functions we have
	 * right now.
	 */
	return count <= 1;
}

static bool check_args_pair_invalid(enum bpf_arg_type arg_curr,
				    enum bpf_arg_type arg_next)
{
	return (base_type(arg_curr) == ARG_PTR_TO_MEM) !=
		arg_type_is_mem_size(arg_next);
}

static bool check_arg_pair_ok(const struct bpf_func_proto *fn)
{
	/* bpf_xxx(..., buf, len) call will access 'len'
	 * bytes from memory 'buf'. Both arg types need
	 * to be paired, so make sure there's no buggy
	 * helper function specification.
	 */
	if (arg_type_is_mem_size(fn->arg1_type) ||
	    base_type(fn->arg5_type) == ARG_PTR_TO_MEM ||
	    check_args_pair_invalid(fn->arg1_type, fn->arg2_type) ||
	    check_args_pair_invalid(fn->arg2_type, fn->arg3_type) ||
	    check_args_pair_invalid(fn->arg3_type, fn->arg4_type) ||
	    check_args_pair_invalid(fn->arg4_type, fn->arg5_type))
		return false;

	return true;
}

static bool check_refcount_ok(const struct bpf_func_proto *fn, int func_id)
{
	int count = 0;

	if (arg_type_may_be_refcounted(fn->arg1_type))
		count++;
	if (arg_type_may_be_refcounted(fn->arg2_type))
		count++;
	if (arg_type_may_be_refcounted(fn->arg3_type))
		count++;
	if (arg_type_may_be_refcounted(fn->arg4_type))
		count++;
	if (arg_type_may_be_refcounted(fn->arg5_type))
		count++;

	/* A reference acquiring function cannot acquire
	 * another refcounted ptr.
	 */
	if (may_be_acquire_function(func_id) && count)
		return false;

	/* We only support one arg being unreferenced at the moment,
	 * which is sufficient for the helper functions we have right now.
	 */
	return count <= 1;
}

static bool check_btf_id_ok(const struct bpf_func_proto *fn)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(fn->arg_type); i++) {
		if (base_type(fn->arg_type[i]) == ARG_PTR_TO_BTF_ID && !fn->arg_btf_id[i])
			return false;

		if (base_type(fn->arg_type[i]) != ARG_PTR_TO_BTF_ID && fn->arg_btf_id[i])
			return false;
	}

	return true;
}

static int check_func_proto(const struct bpf_func_proto *fn, int func_id,
			    struct bpf_call_arg_meta *meta)
{
	return check_raw_mode_ok(fn) &&
	       check_arg_pair_ok(fn) &&
	       check_btf_id_ok(fn) &&
	       check_refcount_ok(fn, func_id) ? 0 : -EINVAL;
}

static bool reg_is_pkt_pointer_any(const struct bpf_reg_state *reg)
{
	return reg_is_pkt_pointer(reg) ||
	       reg->type == PTR_TO_PACKET_END;
}

static void klpr___clear_all_pkt_pointers(struct bpf_verifier_env *env,
				     struct bpf_func_state *state)
{
	struct bpf_reg_state *regs = state->regs, *reg;
	int i;

	for (i = 0; i < MAX_BPF_REG; i++)
		if (reg_is_pkt_pointer_any(&regs[i]))
			(*klpe_mark_reg_unknown)(env, regs, i);

	bpf_for_each_spilled_reg(i, state, reg) {
		if (!reg)
			continue;
		if (reg_is_pkt_pointer_any(reg))
			klpr___mark_reg_unknown(env, reg);
	}
}

static void klpr_clear_all_pkt_pointers(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	int i;

	for (i = 0; i <= vstate->curframe; i++)
		klpr___clear_all_pkt_pointers(env, vstate->frame[i]);
}

typedef int (*set_callee_state_fn)(struct bpf_verifier_env *env,
				   struct bpf_func_state *caller,
				   struct bpf_func_state *callee,
				   int insn_idx);

static int (*klpe___check_func_call)(struct bpf_verifier_env *env, struct bpf_insn *insn,
			     int *insn_idx, int subprog,
			     set_callee_state_fn set_callee_state_cb);

static int (*klpe_set_callee_state)(struct bpf_verifier_env *env,
			    struct bpf_func_state *caller,
			    struct bpf_func_state *callee, int insn_idx);

static int klpr_check_func_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			   int *insn_idx)
{
	int subprog, target_insn;

	target_insn = *insn_idx + insn->imm + 1;
	subprog = (*klpe_find_subprog)(env, target_insn);
	if (subprog < 0) {
		klpr_verbose(env, "verifier bug. No program starts at insn %d\n",
			target_insn);
		return -EFAULT;
	}

	return (*klpe___check_func_call)(env, insn, insn_idx, subprog, (*klpe_set_callee_state));
}

static int (*klpe_set_map_elem_callback_state)(struct bpf_verifier_env *env,
				       struct bpf_func_state *caller,
				       struct bpf_func_state *callee,
				       int insn_idx);

static int (*klpe_set_loop_callback_state)(struct bpf_verifier_env *env,
				   struct bpf_func_state *caller,
				   struct bpf_func_state *callee,
				   int insn_idx);

static int (*klpe_set_timer_callback_state)(struct bpf_verifier_env *env,
				    struct bpf_func_state *caller,
				    struct bpf_func_state *callee,
				    int insn_idx);

static int (*klpe_set_find_vma_callback_state)(struct bpf_verifier_env *env,
				       struct bpf_func_state *caller,
				       struct bpf_func_state *callee,
				       int insn_idx);

static int klpr_prepare_func_exit(struct bpf_verifier_env *env, int *insn_idx)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_func_state *caller, *callee;
	struct bpf_reg_state *r0;
	int err;

	callee = state->frame[state->curframe];
	r0 = &callee->regs[BPF_REG_0];
	if (r0->type == PTR_TO_STACK) {
		/* technically it's ok to return caller's stack pointer
		 * (or caller's caller's pointer) back to the caller,
		 * since these pointers are valid. Only current stack
		 * pointer will be invalid as soon as function exits,
		 * but let's be conservative
		 */
		klpr_verbose(env, "cannot return stack pointer to the caller\n");
		return -EINVAL;
	}

	state->curframe--;
	caller = state->frame[state->curframe];
	if (callee->in_callback_fn) {
		/* enforce R0 return value range [0, 1]. */
		struct tnum range = (*klpe_tnum_range)(0, 1);

		if (r0->type != SCALAR_VALUE) {
			klpr_verbose(env, "R0 not a scalar value\n");
			return -EACCES;
		}
		if (!(*klpe_tnum_in)(range, r0->var_off)) {
			klpr_verbose_invalid_scalar(env, r0, &range, "callback return", "R0");
			return -EINVAL;
		}
	} else {
		/* return to the caller whatever r0 had in the callee */
		caller->regs[BPF_REG_0] = *r0;
	}

	/* Transfer references to the caller */
	err = klpr_copy_reference_state(caller, callee);
	if (err)
		return err;

	*insn_idx = callee->callsite + 1;
	if (env->log.level & BPF_LOG_LEVEL) {
		klpr_verbose(env, "returning from callee:\n");
		(*klpe_print_verifier_state)(env, callee, true);
		klpr_verbose(env, "to caller at %d:\n", *insn_idx);
		(*klpe_print_verifier_state)(env, caller, true);
	}
	/* clear everything in the callee */
	free_func_state(callee);
	state->frame[state->curframe + 1] = NULL;
	return 0;
}

static void klpr_do_refine_retval_range(struct bpf_reg_state *regs, int ret_type,
				   int func_id,
				   struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *ret_reg = &regs[BPF_REG_0];

	if (ret_type != RET_INTEGER ||
	    (func_id != BPF_FUNC_get_stack &&
	     func_id != BPF_FUNC_get_task_stack &&
	     func_id != BPF_FUNC_probe_read_str &&
	     func_id != BPF_FUNC_probe_read_kernel_str &&
	     func_id != BPF_FUNC_probe_read_user_str))
		return;

	ret_reg->smax_value = meta->msize_max_value;
	ret_reg->s32_max_value = meta->msize_max_value;
	ret_reg->smin_value = -MAX_ERRNO;
	ret_reg->s32_min_value = -MAX_ERRNO;
	(*klpe_reg_bounds_sync)(ret_reg);
}

static int
klpr_record_func_map(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
		int func_id, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_map *map = meta->map_ptr;

	if (func_id != BPF_FUNC_tail_call &&
	    func_id != BPF_FUNC_map_lookup_elem &&
	    func_id != BPF_FUNC_map_update_elem &&
	    func_id != BPF_FUNC_map_delete_elem &&
	    func_id != BPF_FUNC_map_push_elem &&
	    func_id != BPF_FUNC_map_pop_elem &&
	    func_id != BPF_FUNC_map_peek_elem &&
	    func_id != BPF_FUNC_for_each_map_elem &&
	    func_id != BPF_FUNC_redirect_map &&
	    func_id != BPF_FUNC_map_lookup_percpu_elem)
		return 0;

	if (map == NULL) {
		klpr_verbose(env, "kernel subsystem misconfigured verifier\n");
		return -EINVAL;
	}

	/* In case of read-only, some additional restrictions
	 * need to be applied in order to prevent altering the
	 * state of the map from program side.
	 */
	if ((map->map_flags & BPF_F_RDONLY_PROG) &&
	    (func_id == BPF_FUNC_map_delete_elem ||
	     func_id == BPF_FUNC_map_update_elem ||
	     func_id == BPF_FUNC_map_push_elem ||
	     func_id == BPF_FUNC_map_pop_elem)) {
		klpr_verbose(env, "write into map forbidden\n");
		return -EACCES;
	}

	if (!BPF_MAP_PTR(aux->map_ptr_state))
		bpf_map_ptr_store(aux, meta->map_ptr,
				  !meta->map_ptr->bypass_spec_v1);
	else if (BPF_MAP_PTR(aux->map_ptr_state) != meta->map_ptr)
		bpf_map_ptr_store(aux, BPF_MAP_PTR_POISON,
				  !meta->map_ptr->bypass_spec_v1);
	return 0;
}

static int
klpr_record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
		int func_id, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_reg_state *regs = cur_regs(env), *reg;
	struct bpf_map *map = meta->map_ptr;
	u64 val, max;
	int err;

	if (func_id != BPF_FUNC_tail_call)
		return 0;
	if (!map || map->map_type != BPF_MAP_TYPE_PROG_ARRAY) {
		klpr_verbose(env, "kernel subsystem misconfigured verifier\n");
		return -EINVAL;
	}

	reg = &regs[BPF_REG_3];
	val = reg->var_off.value;
	max = map->max_entries;

	if (!(register_is_const(reg) && val < max)) {
		bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
		return 0;
	}

	err = klpr_mark_chain_precision(env, BPF_REG_3);
	if (err)
		return err;
	if (bpf_map_key_unseen(aux))
		bpf_map_key_store(aux, val);
	else if (!bpf_map_key_poisoned(aux) &&
		  bpf_map_key_immediate(aux) != val)
		bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
	return 0;
}

static int (*klpe_check_reference_leak)(struct bpf_verifier_env *env);

static int klpr_check_bpf_snprintf_call(struct bpf_verifier_env *env,
				   struct bpf_reg_state *regs)
{
	struct bpf_reg_state *fmt_reg = &regs[BPF_REG_3];
	struct bpf_reg_state *data_len_reg = &regs[BPF_REG_5];
	struct bpf_map *fmt_map = fmt_reg->map_ptr;
	int err, fmt_map_off, num_args;
	u64 fmt_addr;
	char *fmt;

	/* data must be an array of u64 */
	if (data_len_reg->var_off.value % 8)
		return -EINVAL;
	num_args = data_len_reg->var_off.value / 8;

	/* fmt being ARG_PTR_TO_CONST_STR guarantees that var_off is const
	 * and map_direct_value_addr is set.
	 */
	fmt_map_off = fmt_reg->off + fmt_reg->var_off.value;
	err = fmt_map->ops->map_direct_value_addr(fmt_map, &fmt_addr,
						  fmt_map_off);
	if (err) {
		klpr_verbose(env, "verifier bug\n");
		return -EFAULT;
	}
	fmt = (char *)(long)fmt_addr + fmt_map_off;

	/* We are also guaranteed that fmt+fmt_map_off is NULL terminated, we
	 * can focus on validating the format specifiers.
	 */
	err = (*klpe_bpf_bprintf_prepare)(fmt, UINT_MAX, NULL, NULL, num_args);
	if (err < 0)
		klpr_verbose(env, "Invalid format string\n");

	return err;
}

static int klpr_check_get_func_ip(struct bpf_verifier_env *env)
{
	enum bpf_prog_type type = resolve_prog_type(env->prog);
	int func_id = BPF_FUNC_get_func_ip;

	if (type == BPF_PROG_TYPE_TRACING) {
		if (!(*klpe_bpf_prog_has_trampoline)(env->prog)) {
			klpr_verbose(env, "func %s#%d supported only for fentry/fexit/fmod_ret programs\n",
				(*klpe_func_id_name)(func_id), func_id);
			return -ENOTSUPP;
		}
		return 0;
	} else if (type == BPF_PROG_TYPE_KPROBE) {
		return 0;
	}

	klpr_verbose(env, "func %s#%d not supported for program type %d\n",
		(*klpe_func_id_name)(func_id), func_id, type);
	return -ENOTSUPP;
}

static bool is_dynptr_ref_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_dynptr_data;
}

static int klpp_check_helper_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			     int *insn_idx_p)
{
	const struct bpf_func_proto *fn = NULL;
	enum bpf_return_type ret_type;
	enum bpf_type_flag ret_flag;
	struct bpf_reg_state *regs;
	struct bpf_call_arg_meta meta;
	int insn_idx = *insn_idx_p;
	bool changes_data;
	int i, err, func_id, dynptr_id = 0;

	/* find function prototype */
	func_id = insn->imm;
	if (func_id < 0 || func_id >= __BPF_FUNC_MAX_ID) {
		klpr_verbose(env, "invalid func %s#%d\n", (*klpe_func_id_name)(func_id),
			func_id);
		return -EINVAL;
	}

	if (env->ops->get_func_proto)
		fn = env->ops->get_func_proto(func_id, env->prog);
	if (!fn) {
		klpr_verbose(env, "unknown func %s#%d\n", (*klpe_func_id_name)(func_id),
			func_id);
		return -EINVAL;
	}

	/* eBPF programs must be GPL compatible to use GPL-ed functions */
	if (!env->prog->gpl_compatible && fn->gpl_only) {
		klpr_verbose(env, "cannot call GPL-restricted function from non-GPL compatible program\n");
		return -EINVAL;
	}

	if (fn->allowed && !fn->allowed(env->prog)) {
		klpr_verbose(env, "helper call is not allowed in probe\n");
		return -EINVAL;
	}

	/* With LD_ABS/IND some JITs save/restore skb from r1. */
	changes_data = (*klpe_bpf_helper_changes_pkt_data)(fn->func);
	if (changes_data && fn->arg1_type != ARG_PTR_TO_CTX) {
		klpr_verbose(env, "kernel subsystem misconfigured func %s#%d: r1 != ctx\n",
			(*klpe_func_id_name)(func_id), func_id);
		return -EINVAL;
	}

	memset(&meta, 0, sizeof(meta));
	meta.pkt_access = fn->pkt_access;

	err = check_func_proto(fn, func_id, &meta);
	if (err) {
		klpr_verbose(env, "kernel subsystem misconfigured func %s#%d\n",
			(*klpe_func_id_name)(func_id), func_id);
		return err;
	}

	meta.func_id = func_id;
	/* check args */
	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
		err = klpp_check_func_arg(env, i, &meta, fn);
		if (err)
			return err;
	}

	err = klpr_record_func_map(env, &meta, func_id, insn_idx);
	if (err)
		return err;

	err = klpr_record_func_key(env, &meta, func_id, insn_idx);
	if (err)
		return err;

	/* Mark slots with STACK_MISC in case of raw mode, stack offset
	 * is inferred from register state.
	 */
	for (i = 0; i < meta.access_size; i++) {
		err = klpp_check_mem_access(env, insn_idx, meta.regno, i, BPF_B,
				       BPF_WRITE, -1, false);
		if (err)
			return err;
	}

	regs = cur_regs(env);

	if (meta.uninit_dynptr_regno) {
		/* we write BPF_DW bits (8 bytes) at a time */
		for (i = 0; i < BPF_DYNPTR_SIZE; i += 8) {
			err = klpp_check_mem_access(env, insn_idx, meta.uninit_dynptr_regno,
					       i, BPF_DW, BPF_WRITE, -1, false);
			if (err)
				return err;
		}

		err = klpp_mark_stack_slots_dynptr(env, &regs[meta.uninit_dynptr_regno],
					      fn->arg_type[meta.uninit_dynptr_regno - BPF_REG_1],
					      insn_idx);
		if (err)
			return err;
	}

	if (meta.release_regno) {
		err = -EINVAL;
		if (arg_type_is_dynptr(fn->arg_type[meta.release_regno - BPF_REG_1])) {
			err = klpp_unmark_stack_slots_dynptr(env, &regs[meta.release_regno]);
		} else if (meta.ref_obj_id) {
			err = (*klpe_release_reference)(env, meta.ref_obj_id);
		} else if (register_is_null(&regs[meta.release_regno])) {
			/* meta.ref_obj_id can only be 0 if register that is meant to be
			 * released is NULL, which must be > R0.
			 */
			err = 0;
		}
		if (err) {
			klpr_verbose(env, "func %s#%d reference has not been acquired before\n",
				(*klpe_func_id_name)(func_id), func_id);
			return err;
		}
	}

	switch (func_id) {
	case BPF_FUNC_tail_call:
		err = (*klpe_check_reference_leak)(env);
		if (err) {
			klpr_verbose(env, "tail_call would lead to reference leak\n");
			return err;
		}
		break;
	case BPF_FUNC_get_local_storage:
		/* check that flags argument in get_local_storage(map, flags) is 0,
		 * this is required because get_local_storage() can't return an error.
		 */
		if (!register_is_null(&regs[BPF_REG_2])) {
			klpr_verbose(env, "get_local_storage() doesn't support non-zero flags\n");
			return -EINVAL;
		}
		break;
	case BPF_FUNC_for_each_map_elem:
		err = (*klpe___check_func_call)(env, insn, insn_idx_p, meta.subprogno,
					(*klpe_set_map_elem_callback_state));
		break;
	case BPF_FUNC_timer_set_callback:
		err = (*klpe___check_func_call)(env, insn, insn_idx_p, meta.subprogno,
					(*klpe_set_timer_callback_state));
		break;
	case BPF_FUNC_find_vma:
		err = (*klpe___check_func_call)(env, insn, insn_idx_p, meta.subprogno,
					(*klpe_set_find_vma_callback_state));
		break;
	case BPF_FUNC_snprintf:
		err = klpr_check_bpf_snprintf_call(env, regs);
		break;
	case BPF_FUNC_loop:
		err = (*klpe___check_func_call)(env, insn, insn_idx_p, meta.subprogno,
					(*klpe_set_loop_callback_state));
		break;
	case BPF_FUNC_dynptr_from_mem:
		if (regs[BPF_REG_1].type != PTR_TO_MAP_VALUE) {
			klpr_verbose(env, "Unsupported reg type %s for bpf_dynptr_from_mem data\n",
				(*klpe_reg_type_str)(env, regs[BPF_REG_1].type));
			return -EACCES;
		}
	   break;
	case BPF_FUNC_dynptr_data:
		for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
			if (arg_type_is_dynptr(fn->arg_type[i])) {
				struct bpf_reg_state *reg = &regs[BPF_REG_1 + i];
				int id, ref_obj_id;

				if (dynptr_id) {
					klpr_verbose(env, "verifier internal error: meta.dynptr_id already set\n");
					return -EFAULT;
				}

				if (meta.ref_obj_id) {
					klpr_verbose(env, "verifier internal error: meta.ref_obj_id already set\n");
					return -EFAULT;
				}

				id = klpp_dynptr_id(env, reg);
				if (id < 0) {
					klpr_verbose(env, "verifier internal error: failed to obtain dynptr id\n");
					return id;
				}

				ref_obj_id = klpp_dynptr_ref_obj_id(env, reg);
				if (ref_obj_id < 0) {
					klpr_verbose(env, "verifier internal error: failed to obtain dynptr ref_obj_id\n");
					return ref_obj_id;
				}

				dynptr_id = id;
				meta.ref_obj_id = ref_obj_id;
				break;
			}
		}
		if (i == MAX_BPF_FUNC_REG_ARGS) {
			klpr_verbose(env, "verifier internal error: no dynptr in bpf_dynptr_data()\n");
			return -EFAULT;
		}
		break;
	}

	if (err)
		return err;

	/* reset caller saved regs */
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		(*klpe_mark_reg_not_init)(env, regs, (*klpe_caller_saved)[i]);
		(*klpe_check_reg_arg)(env, (*klpe_caller_saved)[i], DST_OP_NO_MARK);
	}

	/* helper call returns 64-bit value. */
	regs[BPF_REG_0].subreg_def = DEF_NOT_SUBREG;

	/* update return register (already marked as written above) */
	ret_type = fn->ret_type;
	ret_flag = type_flag(fn->ret_type);
	if (ret_type == RET_INTEGER) {
		/* sets type to SCALAR_VALUE */
		(*klpe_mark_reg_unknown)(env, regs, BPF_REG_0);
	} else if (ret_type == RET_VOID) {
		regs[BPF_REG_0].type = NOT_INIT;
	} else if (base_type(ret_type) == RET_PTR_TO_MAP_VALUE) {
		/* There is no offset yet applied, variable or fixed */
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		/* remember map_ptr, so that check_map_access()
		 * can check 'value_size' boundary of memory access
		 * to map element returned from bpf_map_lookup_elem()
		 */
		if (meta.map_ptr == NULL) {
			klpr_verbose(env,
				"kernel subsystem misconfigured verifier\n");
			return -EINVAL;
		}
		regs[BPF_REG_0].map_ptr = meta.map_ptr;
		regs[BPF_REG_0].map_uid = meta.map_uid;
		regs[BPF_REG_0].type = PTR_TO_MAP_VALUE | ret_flag;
		if (!type_may_be_null(ret_type) &&
		    map_value_has_spin_lock(meta.map_ptr)) {
			regs[BPF_REG_0].id = ++env->id_gen;
		}
	} else if (base_type(ret_type) == RET_PTR_TO_SOCKET) {
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		regs[BPF_REG_0].type = PTR_TO_SOCKET | ret_flag;
	} else if (base_type(ret_type) == RET_PTR_TO_SOCK_COMMON) {
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		regs[BPF_REG_0].type = PTR_TO_SOCK_COMMON | ret_flag;
	} else if (base_type(ret_type) == RET_PTR_TO_TCP_SOCK) {
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		regs[BPF_REG_0].type = PTR_TO_TCP_SOCK | ret_flag;
	} else if (base_type(ret_type) == RET_PTR_TO_ALLOC_MEM) {
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		regs[BPF_REG_0].type = PTR_TO_MEM | ret_flag;
		regs[BPF_REG_0].mem_size = meta.mem_size;
	} else if (base_type(ret_type) == RET_PTR_TO_MEM_OR_BTF_ID) {
		const struct btf_type *t;

		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		t = (*klpe_btf_type_skip_modifiers)(meta.ret_btf, meta.ret_btf_id, NULL);
		if (!btf_type_is_struct(t)) {
			u32 tsize;
			const struct btf_type *ret;
			const char *tname;

			/* resolve the type size of ksym. */
			ret = (*klpe_btf_resolve_size)(meta.ret_btf, t, &tsize);
			if (IS_ERR(ret)) {
				tname = (*klpe_btf_name_by_offset)(meta.ret_btf, t->name_off);
				klpr_verbose(env, "unable to resolve the size of type '%s': %ld\n",
					tname, PTR_ERR(ret));
				return -EINVAL;
			}
			regs[BPF_REG_0].type = PTR_TO_MEM | ret_flag;
			regs[BPF_REG_0].mem_size = tsize;
		} else {
			/* MEM_RDONLY may be carried from ret_flag, but it
			 * doesn't apply on PTR_TO_BTF_ID. Fold it, otherwise
			 * it will confuse the check of PTR_TO_BTF_ID in
			 * check_mem_access().
			 */
			ret_flag &= ~MEM_RDONLY;

			regs[BPF_REG_0].type = PTR_TO_BTF_ID | ret_flag;
			regs[BPF_REG_0].btf = meta.ret_btf;
			regs[BPF_REG_0].btf_id = meta.ret_btf_id;
		}
	} else if (base_type(ret_type) == RET_PTR_TO_BTF_ID) {
		struct btf *ret_btf;
		int ret_btf_id;

		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		regs[BPF_REG_0].type = PTR_TO_BTF_ID | ret_flag;
		if (func_id == BPF_FUNC_kptr_xchg) {
			ret_btf = meta.kptr_off_desc->kptr.btf;
			ret_btf_id = meta.kptr_off_desc->kptr.btf_id;
		} else {
			ret_btf = (*klpe_btf_vmlinux);
			ret_btf_id = *fn->ret_btf_id;
		}
		if (ret_btf_id == 0) {
			klpr_verbose(env, "invalid return type %u of func %s#%d\n",
				base_type(ret_type), (*klpe_func_id_name)(func_id),
				func_id);
			return -EINVAL;
		}
		regs[BPF_REG_0].btf = ret_btf;
		regs[BPF_REG_0].btf_id = ret_btf_id;
	} else {
		klpr_verbose(env, "unknown return type %u of func %s#%d\n",
			base_type(ret_type), (*klpe_func_id_name)(func_id), func_id);
		return -EINVAL;
	}

	if (type_may_be_null(regs[BPF_REG_0].type))
		regs[BPF_REG_0].id = ++env->id_gen;

	if (is_dynptr_ref_function(func_id))
		((struct klpp_bpf_reg_state *)&regs[BPF_REG_0])->dynptr_id = dynptr_id;

	if (is_ptr_cast_function(func_id) || is_dynptr_ref_function(func_id)) {
		/* For release_reference() */
		regs[BPF_REG_0].ref_obj_id = meta.ref_obj_id;
	} else if (is_acquire_function(func_id, meta.map_ptr)) {
		int id = (*klpe_acquire_reference_state)(env, insn_idx);

		if (id < 0)
			return id;
		/* For mark_ptr_or_null_reg() */
		regs[BPF_REG_0].id = id;
		/* For release_reference() */
		regs[BPF_REG_0].ref_obj_id = id;
	}

	klpr_do_refine_retval_range(regs, fn->ret_type, func_id, &meta);

	err = klpr_check_map_func_compatibility(env, meta.map_ptr, func_id);
	if (err)
		return err;

	if ((func_id == BPF_FUNC_get_stack ||
	     func_id == BPF_FUNC_get_task_stack) &&
	    !env->prog->has_callchain_buf) {
		const char *err_str;

#ifdef CONFIG_PERF_EVENTS
		err = (*klpe_get_callchain_buffers)((*klpe_sysctl_perf_event_max_stack));
		err_str = "cannot get callchain buffer for func %s#%d\n";
#else
#error "klp-ccp: non-taken branch"
#endif
		if (err) {
			klpr_verbose(env, err_str, (*klpe_func_id_name)(func_id), func_id);
			return err;
		}

		env->prog->has_callchain_buf = true;
	}

	if (func_id == BPF_FUNC_get_stackid || func_id == BPF_FUNC_get_stack)
		env->prog->call_get_stack = true;

	if (func_id == BPF_FUNC_get_func_ip) {
		if (klpr_check_get_func_ip(env))
			return -ENOTSUPP;
		env->prog->call_get_func_ip = true;
	}

	if (changes_data)
		klpr_clear_all_pkt_pointers(env);
	return 0;
}

static void (*klpe_mark_btf_func_reg_size)(struct bpf_verifier_env *env, u32 regno,
				   size_t reg_size);

static int klpr_check_kfunc_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			    int *insn_idx_p)
{
	const struct btf_type *t, *func, *func_proto, *ptr_type;
	struct bpf_reg_state *regs = cur_regs(env);
	const char *func_name, *ptr_type_name;
	u32 i, nargs, func_id, ptr_type_id;
	int err, insn_idx = *insn_idx_p;
	const struct btf_param *args;
	struct btf *desc_btf;
	bool acq;

	/* skip for now, but return error when we find this in fixup_kfunc_call */
	if (!insn->imm)
		return 0;

	desc_btf = klpr_find_kfunc_desc_btf(env, insn->off);
	if (IS_ERR(desc_btf))
		return PTR_ERR(desc_btf);

	func_id = insn->imm;
	func = (*klpe_btf_type_by_id)(desc_btf, func_id);
	func_name = (*klpe_btf_name_by_offset)(desc_btf, func->name_off);
	func_proto = (*klpe_btf_type_by_id)(desc_btf, func->type);

	if (!(*klpe_btf_kfunc_id_set_contains)(desc_btf, resolve_prog_type(env->prog),
				      BTF_KFUNC_TYPE_CHECK, func_id)) {
		klpr_verbose(env, "calling kernel function %s is not allowed\n",
			func_name);
		return -EACCES;
	}

	acq = (*klpe_btf_kfunc_id_set_contains)(desc_btf, resolve_prog_type(env->prog),
					BTF_KFUNC_TYPE_ACQUIRE, func_id);

	/* Check the arguments */
	err = (*klpe_btf_check_kfunc_arg_match)(env, desc_btf, func_id, regs);
	if (err < 0)
		return err;
	/* In case of release function, we get register number of refcounted
	 * PTR_TO_BTF_ID back from btf_check_kfunc_arg_match, do the release now
	 */
	if (err) {
		err = (*klpe_release_reference)(env, regs[err].ref_obj_id);
		if (err) {
			klpr_verbose(env, "kfunc %s#%d reference has not been acquired before\n",
				func_name, func_id);
			return err;
		}
	}

	for (i = 0; i < CALLER_SAVED_REGS; i++)
		(*klpe_mark_reg_not_init)(env, regs, (*klpe_caller_saved)[i]);

	/* Check return type */
	t = (*klpe_btf_type_skip_modifiers)(desc_btf, func_proto->type, NULL);

	if (acq && !btf_type_is_ptr(t)) {
		klpr_verbose(env, "acquire kernel function does not return PTR_TO_BTF_ID\n");
		return -EINVAL;
	}

	if (btf_type_is_scalar(t)) {
		(*klpe_mark_reg_unknown)(env, regs, BPF_REG_0);
		(*klpe_mark_btf_func_reg_size)(env, BPF_REG_0, t->size);
	} else if (btf_type_is_ptr(t)) {
		ptr_type = (*klpe_btf_type_skip_modifiers)(desc_btf, t->type,
						   &ptr_type_id);
		if (!btf_type_is_struct(ptr_type)) {
			ptr_type_name = (*klpe_btf_name_by_offset)(desc_btf,
							   ptr_type->name_off);
			klpr_verbose(env, "kernel function %s returns pointer type %s %s is not supported\n",
				func_name, (*klpe_btf_type_str)(ptr_type),
				ptr_type_name);
			return -EINVAL;
		}
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_0);
		regs[BPF_REG_0].btf = desc_btf;
		regs[BPF_REG_0].type = PTR_TO_BTF_ID;
		regs[BPF_REG_0].btf_id = ptr_type_id;
		if ((*klpe_btf_kfunc_id_set_contains)(desc_btf, resolve_prog_type(env->prog),
					      BTF_KFUNC_TYPE_RET_NULL, func_id)) {
			regs[BPF_REG_0].type |= PTR_MAYBE_NULL;
			/* For mark_ptr_or_null_reg, see 93c230e3f5bd6 */
			regs[BPF_REG_0].id = ++env->id_gen;
		}
		(*klpe_mark_btf_func_reg_size)(env, BPF_REG_0, sizeof(void *));
		if (acq) {
			int id = (*klpe_acquire_reference_state)(env, insn_idx);

			if (id < 0)
				return id;
			regs[BPF_REG_0].id = id;
			regs[BPF_REG_0].ref_obj_id = id;
		}
	} /* else { add_kfunc_call() ensures it is btf_type_is_void(t) } */

	nargs = btf_type_vlen(func_proto);
	args = (const struct btf_param *)(func_proto + 1);
	for (i = 0; i < nargs; i++) {
		u32 regno = i + 1;

		t = (*klpe_btf_type_skip_modifiers)(desc_btf, args[i].type, NULL);
		if (btf_type_is_ptr(t))
			(*klpe_mark_btf_func_reg_size)(env, regno, sizeof(void *));
		else
			/* scalar. ensured by btf_check_kfunc_arg_match() */
			(*klpe_mark_btf_func_reg_size)(env, regno, t->size);
	}

	return 0;
}

static struct bpf_insn_aux_data *cur_aux(struct bpf_verifier_env *env)
{
	return &env->insn_aux_data[env->insn_idx];
}

static void sanitize_mark_insn_seen(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *vstate = env->cur_state;

	/* If we simulate paths under speculation, we don't update the
	 * insn as 'seen' such that when we verify unreachable paths in
	 * the non-speculative domain, sanitize_dead_code() can still
	 * rewrite/sanitize them.
	 */
	if (!vstate->speculative)
		env->insn_aux_data[env->insn_idx].seen = env->pass_cnt;
}

static int (*klpe_adjust_reg_min_max_vals)(struct bpf_verifier_env *env,
				   struct bpf_insn *insn);

static int klpr_check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = cur_regs(env);
	u8 opcode = BPF_OP(insn->code);
	int err;

	if (opcode == BPF_END || opcode == BPF_NEG) {
		if (opcode == BPF_NEG) {
			if (BPF_SRC(insn->code) != 0 ||
			    insn->src_reg != BPF_REG_0 ||
			    insn->off != 0 || insn->imm != 0) {
				klpr_verbose(env, "BPF_NEG uses reserved fields\n");
				return -EINVAL;
			}
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0 ||
			    (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) ||
			    BPF_CLASS(insn->code) == BPF_ALU64) {
				klpr_verbose(env, "BPF_END uses reserved fields\n");
				return -EINVAL;
			}
		}

		/* check src operand */
		err = (*klpe_check_reg_arg)(env, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		if (is_pointer_value(env, insn->dst_reg)) {
			klpr_verbose(env, "R%d pointer arithmetic prohibited\n",
				insn->dst_reg);
			return -EACCES;
		}

		/* check dest operand */
		err = (*klpe_check_reg_arg)(env, insn->dst_reg, DST_OP);
		if (err)
			return err;

	} else if (opcode == BPF_MOV) {

		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm != 0 || insn->off != 0) {
				klpr_verbose(env, "BPF_MOV uses reserved fields\n");
				return -EINVAL;
			}

			/* check src operand */
			err = (*klpe_check_reg_arg)(env, insn->src_reg, SRC_OP);
			if (err)
				return err;
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
				klpr_verbose(env, "BPF_MOV uses reserved fields\n");
				return -EINVAL;
			}
		}

		/* check dest operand, mark as required later */
		err = (*klpe_check_reg_arg)(env, insn->dst_reg, DST_OP_NO_MARK);
		if (err)
			return err;

		if (BPF_SRC(insn->code) == BPF_X) {
			struct bpf_reg_state *src_reg = regs + insn->src_reg;
			struct bpf_reg_state *dst_reg = regs + insn->dst_reg;

			if (BPF_CLASS(insn->code) == BPF_ALU64) {
				/* case: R1 = R2
				 * copy register state to dest reg
				 */
				if (src_reg->type == SCALAR_VALUE && !src_reg->id)
					/* Assign src and dst registers the same ID
					 * that will be used by find_equal_scalars()
					 * to propagate min/max range.
					 */
					src_reg->id = ++env->id_gen;
				*dst_reg = *src_reg;
				dst_reg->live |= REG_LIVE_WRITTEN;
				dst_reg->subreg_def = DEF_NOT_SUBREG;
			} else {
				/* R1 = (u32) R2 */
				if (is_pointer_value(env, insn->src_reg)) {
					klpr_verbose(env,
						"R%d partial copy of pointer\n",
						insn->src_reg);
					return -EACCES;
				} else if (src_reg->type == SCALAR_VALUE) {
					*dst_reg = *src_reg;
					/* Make sure ID is cleared otherwise
					 * dst_reg min/max could be incorrectly
					 * propagated into src_reg by find_equal_scalars()
					 */
					dst_reg->id = 0;
					dst_reg->live |= REG_LIVE_WRITTEN;
					dst_reg->subreg_def = env->insn_idx + 1;
				} else {
					(*klpe_mark_reg_unknown)(env, regs,
							 insn->dst_reg);
				}
				(*klpe_zext_32_to_64)(dst_reg);
				(*klpe_reg_bounds_sync)(dst_reg);
			}
		} else {
			/* case: R = imm
			 * remember the value we stored into this reg
			 */
			/* clear any state __mark_reg_known doesn't set */
			(*klpe_mark_reg_unknown)(env, regs, insn->dst_reg);
			regs[insn->dst_reg].type = SCALAR_VALUE;
			if (BPF_CLASS(insn->code) == BPF_ALU64) {
				(*klpe___mark_reg_known)(regs + insn->dst_reg,
						 insn->imm);
			} else {
				(*klpe___mark_reg_known)(regs + insn->dst_reg,
						 (u32)insn->imm);
			}
		}

	} else if (opcode > BPF_END) {
		klpr_verbose(env, "invalid BPF_ALU opcode %x\n", opcode);
		return -EINVAL;

	} else {	/* all other ALU ops: and, sub, xor, add, ... */

		if (BPF_SRC(insn->code) == BPF_X) {
			if (insn->imm != 0 || insn->off != 0) {
				klpr_verbose(env, "BPF_ALU uses reserved fields\n");
				return -EINVAL;
			}
			/* check src1 operand */
			err = (*klpe_check_reg_arg)(env, insn->src_reg, SRC_OP);
			if (err)
				return err;
		} else {
			if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
				klpr_verbose(env, "BPF_ALU uses reserved fields\n");
				return -EINVAL;
			}
		}

		/* check src2 operand */
		err = (*klpe_check_reg_arg)(env, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		if ((opcode == BPF_MOD || opcode == BPF_DIV) &&
		    BPF_SRC(insn->code) == BPF_K && insn->imm == 0) {
			klpr_verbose(env, "div by zero\n");
			return -EINVAL;
		}

		if ((opcode == BPF_LSH || opcode == BPF_RSH ||
		     opcode == BPF_ARSH) && BPF_SRC(insn->code) == BPF_K) {
			int size = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;

			if (insn->imm < 0 || insn->imm >= size) {
				klpr_verbose(env, "invalid shift %d\n", insn->imm);
				return -EINVAL;
			}
		}

		/* check dest operand */
		err = (*klpe_check_reg_arg)(env, insn->dst_reg, DST_OP_NO_MARK);
		if (err)
			return err;

		return (*klpe_adjust_reg_min_max_vals)(env, insn);
	}

	return 0;
}

static int (*klpe_check_cond_jmp_op)(struct bpf_verifier_env *env,
			     struct bpf_insn *insn, int *insn_idx);

static int klpr_check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_insn_aux_data *aux = cur_aux(env);
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *dst_reg;
	struct bpf_map *map;
	int err;

	if (BPF_SIZE(insn->code) != BPF_DW) {
		klpr_verbose(env, "invalid BPF_LD_IMM insn\n");
		return -EINVAL;
	}
	if (insn->off != 0) {
		klpr_verbose(env, "BPF_LD_IMM64 uses reserved fields\n");
		return -EINVAL;
	}

	err = (*klpe_check_reg_arg)(env, insn->dst_reg, DST_OP);
	if (err)
		return err;

	dst_reg = &regs[insn->dst_reg];
	if (insn->src_reg == 0) {
		u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;

		dst_reg->type = SCALAR_VALUE;
		(*klpe___mark_reg_known)(&regs[insn->dst_reg], imm);
		return 0;
	}

	/* All special src_reg cases are listed below. From this point onwards
	 * we either succeed and assign a corresponding dst_reg->type after
	 * zeroing the offset, or fail and reject the program.
	 */
	(*klpe_mark_reg_known_zero)(env, regs, insn->dst_reg);

	if (insn->src_reg == BPF_PSEUDO_BTF_ID) {
		dst_reg->type = aux->btf_var.reg_type;
		switch (base_type(dst_reg->type)) {
		case PTR_TO_MEM:
			dst_reg->mem_size = aux->btf_var.mem_size;
			break;
		case PTR_TO_BTF_ID:
			dst_reg->btf = aux->btf_var.btf;
			dst_reg->btf_id = aux->btf_var.btf_id;
			break;
		default:
			klpr_verbose(env, "bpf verifier is misconfigured\n");
			return -EFAULT;
		}
		return 0;
	}

	if (insn->src_reg == BPF_PSEUDO_FUNC) {
		struct bpf_prog_aux *aux = env->prog->aux;
		u32 subprogno = (*klpe_find_subprog)(env,
					     env->insn_idx + insn->imm + 1);

		if (!aux->func_info) {
			klpr_verbose(env, "missing btf func_info\n");
			return -EINVAL;
		}
		if (aux->func_info_aux[subprogno].linkage != BTF_FUNC_STATIC) {
			klpr_verbose(env, "callback function not static\n");
			return -EINVAL;
		}

		dst_reg->type = PTR_TO_FUNC;
		dst_reg->subprogno = subprogno;
		return 0;
	}

	map = env->used_maps[aux->map_index];
	dst_reg->map_ptr = map;

	if (insn->src_reg == BPF_PSEUDO_MAP_VALUE ||
	    insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE) {
		dst_reg->type = PTR_TO_MAP_VALUE;
		dst_reg->off = aux->map_off;
		if (map_value_has_spin_lock(map))
			dst_reg->id = ++env->id_gen;
	} else if (insn->src_reg == BPF_PSEUDO_MAP_FD ||
		   insn->src_reg == BPF_PSEUDO_MAP_IDX) {
		dst_reg->type = CONST_PTR_TO_MAP;
	} else {
		klpr_verbose(env, "bpf verifier is misconfigured\n");
		return -EINVAL;
	}

	return 0;
}

static bool may_access_skb(enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_SOCKET_FILTER:
	case BPF_PROG_TYPE_SCHED_CLS:
	case BPF_PROG_TYPE_SCHED_ACT:
		return true;
	default:
		return false;
	}
}

static int klpr_check_ld_abs(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_reg_state *regs = cur_regs(env);
	static const int ctx_reg = BPF_REG_6;
	u8 mode = BPF_MODE(insn->code);
	int i, err;

	if (!may_access_skb(resolve_prog_type(env->prog))) {
		klpr_verbose(env, "BPF_LD_[ABS|IND] instructions not allowed for this program type\n");
		return -EINVAL;
	}

	if (!env->ops->gen_ld_abs) {
		klpr_verbose(env, "bpf verifier is misconfigured\n");
		return -EINVAL;
	}

	if (insn->dst_reg != BPF_REG_0 || insn->off != 0 ||
	    BPF_SIZE(insn->code) == BPF_DW ||
	    (mode == BPF_ABS && insn->src_reg != BPF_REG_0)) {
		klpr_verbose(env, "BPF_LD_[ABS|IND] uses reserved fields\n");
		return -EINVAL;
	}

	/* check whether implicit source operand (register R6) is readable */
	err = (*klpe_check_reg_arg)(env, ctx_reg, SRC_OP);
	if (err)
		return err;

	/* Disallow usage of BPF_LD_[ABS|IND] with reference tracking, as
	 * gen_ld_abs() may terminate the program at runtime, leading to
	 * reference leak.
	 */
	err = (*klpe_check_reference_leak)(env);
	if (err) {
		klpr_verbose(env, "BPF_LD_[ABS|IND] cannot be mixed with socket references\n");
		return err;
	}

	if (env->cur_state->active_spin_lock) {
		klpr_verbose(env, "BPF_LD_[ABS|IND] cannot be used inside bpf_spin_lock-ed region\n");
		return -EINVAL;
	}

	if (regs[ctx_reg].type != PTR_TO_CTX) {
		klpr_verbose(env,
			"at the time of BPF_LD_ABS|IND R6 != pointer to skb\n");
		return -EINVAL;
	}

	if (mode == BPF_IND) {
		/* check explicit source operand */
		err = (*klpe_check_reg_arg)(env, insn->src_reg, SRC_OP);
		if (err)
			return err;
	}

	err = (*klpe_check_ptr_off_reg)(env, &regs[ctx_reg], ctx_reg);
	if (err < 0)
		return err;

	/* reset caller saved regs to unreadable */
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		(*klpe_mark_reg_not_init)(env, regs, (*klpe_caller_saved)[i]);
		(*klpe_check_reg_arg)(env, (*klpe_caller_saved)[i], DST_OP_NO_MARK);
	}

	/* mark destination R0 register as readable, since it contains
	 * the value fetched from the packet.
	 * Already marked as written above.
	 */
	(*klpe_mark_reg_unknown)(env, regs, BPF_REG_0);
	/* ld_abs load up to 32-bit skb data. */
	regs[BPF_REG_0].subreg_def = env->insn_idx + 1;
	return 0;
}

static int klpr_check_return_code(struct bpf_verifier_env *env)
{
	struct tnum enforce_attach_type_range = (*klpe_tnum_unknown);
	const struct bpf_prog *prog = env->prog;
	struct bpf_reg_state *reg;
	struct tnum range = (*klpe_tnum_range)(0, 1);
	enum bpf_prog_type prog_type = resolve_prog_type(env->prog);
	int err;
	struct bpf_func_state *frame = env->cur_state->frame[0];
	const bool is_subprog = frame->subprogno;

	/* LSM and struct_ops func-ptr's return type could be "void" */
	if (!is_subprog &&
	    (prog_type == BPF_PROG_TYPE_STRUCT_OPS ||
	     prog_type == BPF_PROG_TYPE_LSM) &&
	    !prog->aux->attach_func_proto->type)
		return 0;

	/* eBPF calling convention is such that R0 is used
	 * to return the value from eBPF program.
	 * Make sure that it's readable at this time
	 * of bpf_exit, which means that program wrote
	 * something into it earlier
	 */
	err = (*klpe_check_reg_arg)(env, BPF_REG_0, SRC_OP);
	if (err)
		return err;

	if (is_pointer_value(env, BPF_REG_0)) {
		klpr_verbose(env, "R0 leaks addr as return value\n");
		return -EACCES;
	}

	reg = cur_regs(env) + BPF_REG_0;

	if (frame->in_async_callback_fn) {
		/* enforce return zero from async callbacks like timer */
		if (reg->type != SCALAR_VALUE) {
			klpr_verbose(env, "In async callback the register R0 is not a known value (%s)\n",
				(*klpe_reg_type_str)(env, reg->type));
			return -EINVAL;
		}

		if (!(*klpe_tnum_in)((*klpe_tnum_const)(0), reg->var_off)) {
			klpr_verbose_invalid_scalar(env, reg, &range, "async callback", "R0");
			return -EINVAL;
		}
		return 0;
	}

	if (is_subprog) {
		if (reg->type != SCALAR_VALUE) {
			klpr_verbose(env, "At subprogram exit the register R0 is not a scalar value (%s)\n",
				(*klpe_reg_type_str)(env, reg->type));
			return -EINVAL;
		}
		return 0;
	}

	switch (prog_type) {
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
		if (env->prog->expected_attach_type == BPF_CGROUP_UDP4_RECVMSG ||
		    env->prog->expected_attach_type == BPF_CGROUP_UDP6_RECVMSG ||
		    env->prog->expected_attach_type == BPF_CGROUP_INET4_GETPEERNAME ||
		    env->prog->expected_attach_type == BPF_CGROUP_INET6_GETPEERNAME ||
		    env->prog->expected_attach_type == BPF_CGROUP_INET4_GETSOCKNAME ||
		    env->prog->expected_attach_type == BPF_CGROUP_INET6_GETSOCKNAME)
			range = (*klpe_tnum_range)(1, 1);
		if (env->prog->expected_attach_type == BPF_CGROUP_INET4_BIND ||
		    env->prog->expected_attach_type == BPF_CGROUP_INET6_BIND)
			range = (*klpe_tnum_range)(0, 3);
		break;
	case BPF_PROG_TYPE_CGROUP_SKB:
		if (env->prog->expected_attach_type == BPF_CGROUP_INET_EGRESS) {
			range = (*klpe_tnum_range)(0, 3);
			enforce_attach_type_range = (*klpe_tnum_range)(2, 3);
		}
		break;
	case BPF_PROG_TYPE_CGROUP_SOCK:
	case BPF_PROG_TYPE_SOCK_OPS:
	case BPF_PROG_TYPE_CGROUP_DEVICE:
	case BPF_PROG_TYPE_CGROUP_SYSCTL:
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		break;
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
		if (!env->prog->aux->attach_btf_id)
			return 0;
		range = (*klpe_tnum_const)(0);
		break;
	case BPF_PROG_TYPE_TRACING:
		switch (env->prog->expected_attach_type) {
		case BPF_TRACE_FENTRY:
		case BPF_TRACE_FEXIT:
			range = (*klpe_tnum_const)(0);
			break;
		case BPF_TRACE_RAW_TP:
		case BPF_MODIFY_RETURN:
			return 0;
		case BPF_TRACE_ITER:
			break;
		default:
			return -ENOTSUPP;
		}
		break;
	case BPF_PROG_TYPE_SK_LOOKUP:
		range = (*klpe_tnum_range)(SK_DROP, SK_PASS);
		break;
	case BPF_PROG_TYPE_EXT:
		/* freplace program can return anything as its return value
		 * depends on the to-be-replaced kernel func or bpf program.
		 */
	default:
		return 0;
	}

	if (reg->type != SCALAR_VALUE) {
		klpr_verbose(env, "At program exit the register R0 is not a known value (%s)\n",
			(*klpe_reg_type_str)(env, reg->type));
		return -EINVAL;
	}

	if (!(*klpe_tnum_in)(range, reg->var_off)) {
		klpr_verbose_invalid_scalar(env, reg, &range, "program exit", "R0");
		return -EINVAL;
	}

	if (!tnum_is_unknown(enforce_attach_type_range) &&
	    (*klpe_tnum_in)(enforce_attach_type_range, reg->var_off))
		env->prog->enforce_expected_attach_type = 1;
	return 0;
}

static u32 state_htab_size(struct bpf_verifier_env *env)
{
	return env->prog->len;
}

static struct bpf_verifier_state_list **explored_state(
					struct bpf_verifier_env *env,
					int idx)
{
	struct bpf_verifier_state *cur = env->cur_state;
	struct bpf_func_state *state = cur->frame[cur->curframe];

	return &env->explored_states[(idx ^ state->callsite) % state_htab_size(env)];
}

static bool (*klpe_range_within)(struct bpf_reg_state *old,
			 struct bpf_reg_state *cur);

static bool check_ids(u32 old_id, u32 cur_id, struct bpf_id_pair *idmap)
{
	unsigned int i;

	for (i = 0; i < BPF_ID_MAP_SIZE; i++) {
		if (!idmap[i].old) {
			/* Reached an empty slot; haven't seen this id before */
			idmap[i].old = old_id;
			idmap[i].cur = cur_id;
			return true;
		}
		if (idmap[i].old == old_id)
			return idmap[i].cur == cur_id;
	}
	/* We ran out of idmap slots, which should be impossible */
	WARN_ON_ONCE(1);
	return false;
}

static void klpr_clean_func_state(struct bpf_verifier_env *env,
			     struct bpf_func_state *st)
{
	enum bpf_reg_liveness live;
	int i, j;

	for (i = 0; i < BPF_REG_FP; i++) {
		live = st->regs[i].live;
		/* liveness must not touch this register anymore */
		st->regs[i].live |= REG_LIVE_DONE;
		if (!(live & REG_LIVE_READ))
			/* since the register is unused, clear its state
			 * to make further comparison simpler
			 */
			klpr___mark_reg_not_init(env, &st->regs[i]);
	}

	for (i = 0; i < st->allocated_stack / BPF_REG_SIZE; i++) {
		live = st->stack[i].spilled_ptr.live;
		/* liveness must not touch this stack slot anymore */
		st->stack[i].spilled_ptr.live |= REG_LIVE_DONE;
		if (!(live & REG_LIVE_READ)) {
			klpr___mark_reg_not_init(env, &st->stack[i].spilled_ptr);
			for (j = 0; j < BPF_REG_SIZE; j++)
				st->stack[i].slot_type[j] = STACK_INVALID;
		}
	}
}

static void klpr_clean_verifier_state(struct bpf_verifier_env *env,
				 struct bpf_verifier_state *st)
{
	int i;

	if (st->frame[0]->regs[0].live & REG_LIVE_DONE)
		/* all regs in this state in all frames were already marked */
		return;

	for (i = 0; i <= st->curframe; i++)
		klpr_clean_func_state(env, st->frame[i]);
}

static void klpr_clean_live_states(struct bpf_verifier_env *env, int insn,
			      struct bpf_verifier_state *cur)
{
	struct bpf_verifier_state_list *sl;
	int i;

	sl = *explored_state(env, insn);
	while (sl) {
		if (sl->state.branches)
			goto next;
		if (sl->state.insn_idx != insn ||
		    sl->state.curframe != cur->curframe)
			goto next;
		for (i = 0; i <= cur->curframe; i++)
			if (sl->state.frame[i]->callsite != cur->frame[i]->callsite)
				goto next;
		klpr_clean_verifier_state(env, &sl->state);
next:
		sl = sl->next;
	}
}

static bool klpr_regsafe(struct bpf_verifier_env *env, struct bpf_reg_state *rold,
		    struct bpf_reg_state *rcur, struct bpf_id_pair *idmap)
{
	bool equal;

	if (!(rold->live & REG_LIVE_READ))
		/* explored state didn't use this */
		return true;

	equal = memcmp(rold, rcur, offsetof(struct bpf_reg_state, parent)) == 0;

	if (rold->type == PTR_TO_STACK)
		/* two stack pointers are equal only if they're pointing to
		 * the same stack frame, since fp-8 in foo != fp-8 in bar
		 */
		return equal && rold->frameno == rcur->frameno;

	if (equal)
		return true;

	if (rold->type == NOT_INIT)
		/* explored state can't have used this */
		return true;
	if (rcur->type == NOT_INIT)
		return false;
	switch (base_type(rold->type)) {
	case SCALAR_VALUE:
		if (env->explore_alu_limits)
			return false;
		if (rcur->type == SCALAR_VALUE) {
			if (!rold->precise && !rcur->precise)
				return true;
			/* new val must satisfy old val knowledge */
			return (*klpe_range_within)(rold, rcur) &&
			       (*klpe_tnum_in)(rold->var_off, rcur->var_off);
		} else {
			/* We're trying to use a pointer in place of a scalar.
			 * Even if the scalar was unbounded, this could lead to
			 * pointer leaks because scalars are allowed to leak
			 * while pointers are not. We could make this safe in
			 * special cases if root is calling us, but it's
			 * probably not worth the hassle.
			 */
			return false;
		}
	case PTR_TO_MAP_KEY:
	case PTR_TO_MAP_VALUE:
		/* a PTR_TO_MAP_VALUE could be safe to use as a
		 * PTR_TO_MAP_VALUE_OR_NULL into the same map.
		 * However, if the old PTR_TO_MAP_VALUE_OR_NULL then got NULL-
		 * checked, doing so could have affected others with the same
		 * id, and we can't check for that because we lost the id when
		 * we converted to a PTR_TO_MAP_VALUE.
		 */
		if (type_may_be_null(rold->type)) {
			if (!type_may_be_null(rcur->type))
				return false;
			if (memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)))
				return false;
			/* Check our ids match any regs they're supposed to */
			return check_ids(rold->id, rcur->id, idmap);
		}

		/* If the new min/max/var_off satisfy the old ones and
		 * everything else matches, we are OK.
		 * 'id' is not compared, since it's only used for maps with
		 * bpf_spin_lock inside map element and in such cases if
		 * the rest of the prog is valid for one map element then
		 * it's valid for all map elements regardless of the key
		 * used in bpf_map_lookup()
		 */
		return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 &&
		       (*klpe_range_within)(rold, rcur) &&
		       (*klpe_tnum_in)(rold->var_off, rcur->var_off);
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET:
		if (rcur->type != rold->type)
			return false;
		/* We must have at least as much range as the old ptr
		 * did, so that any accesses which were safe before are
		 * still safe.  This is true even if old range < old off,
		 * since someone could have accessed through (ptr - k), or
		 * even done ptr -= k in a register, to get a safe access.
		 */
		if (rold->range > rcur->range)
			return false;
		/* If the offsets don't match, we can't trust our alignment;
		 * nor can we be sure that we won't fall out of range.
		 */
		if (rold->off != rcur->off)
			return false;
		/* id relations must be preserved */
		if (rold->id && !check_ids(rold->id, rcur->id, idmap))
			return false;
		/* new val must satisfy old val knowledge */
		return (*klpe_range_within)(rold, rcur) &&
		       (*klpe_tnum_in)(rold->var_off, rcur->var_off);
	case PTR_TO_CTX:
	case CONST_PTR_TO_MAP:
	case PTR_TO_PACKET_END:
	case PTR_TO_FLOW_KEYS:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
	case PTR_TO_XDP_SOCK:
		/* Only valid matches are exact, which memcmp() above
		 * would have accepted
		 */
	default:
		/* Don't know what's going on, just say it's not safe */
		return false;
	}

	/* Shouldn't get here; if we do, say it's not safe */
	WARN_ON_ONCE(1);
	return false;
}

static bool klpp_stacksafe(struct bpf_verifier_env *env, struct bpf_func_state *old,
		      struct bpf_func_state *cur, struct bpf_id_pair *idmap)
{
	int i, spi;

	/* walk slots of the explored stack and ignore any additional
	 * slots in the current stack, since explored(safe) state
	 * didn't use them
	 */
	for (i = 0; i < old->allocated_stack; i++) {
		spi = i / BPF_REG_SIZE;

		if (!(old->stack[spi].spilled_ptr.live & REG_LIVE_READ)) {
			i += BPF_REG_SIZE - 1;
			/* explored state didn't use this */
			continue;
		}

		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_INVALID)
			continue;

		/* explored stack has more populated slots than current stack
		 * and these slots were used
		 */
		if (i >= cur->allocated_stack)
			return false;

		/* if old state was safe with misc data in the stack
		 * it will be safe with zero-initialized stack.
		 * The opposite is not true
		 */
		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_MISC &&
		    cur->stack[spi].slot_type[i % BPF_REG_SIZE] == STACK_ZERO)
			continue;
		if (old->stack[spi].slot_type[i % BPF_REG_SIZE] !=
		    cur->stack[spi].slot_type[i % BPF_REG_SIZE])
			/* Ex: old explored (safe) state has STACK_SPILL in
			 * this stack slot, but current has STACK_MISC ->
			 * this verifier states are not equivalent,
			 * return false to continue verification of this path
			 */
			return false;
		if (i % BPF_REG_SIZE != BPF_REG_SIZE - 1)
			continue;
		/* Both old and cur are having same slot_type */
		switch (old->stack[spi].slot_type[BPF_REG_SIZE - 1]) {
		case STACK_SPILL:
			/* when explored and current stack slot are both storing
			 * spilled registers, check that stored pointers types
			 * are the same as well.
			 * Ex: explored safe path could have stored
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -8}
			 * but current path has stored:
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -16}
			 * such verifier states are not equivalent.
			 * return false to continue verification of this path
			 */
			if (!klpr_regsafe(env, &old->stack[spi].spilled_ptr,
				     &cur->stack[spi].spilled_ptr, idmap))
				return false;
			break;
		case STACK_DYNPTR:
		{
			const struct bpf_reg_state *old_reg, *cur_reg;

			old_reg = &old->stack[spi].spilled_ptr;
			cur_reg = &cur->stack[spi].spilled_ptr;
			if (old_reg->dynptr.type != cur_reg->dynptr.type ||
			    old_reg->dynptr.first_slot != cur_reg->dynptr.first_slot ||
			    !check_ids(old_reg->ref_obj_id, cur_reg->ref_obj_id, idmap))
				return false;
			break;
		}
		case STACK_MISC:
		case STACK_ZERO:
		case STACK_INVALID:
			continue;
		/* Ensure that new unhandled slot types return false by default */
		default:
			return false;
		}
	}
	return true;
}

static bool refsafe(struct bpf_func_state *old, struct bpf_func_state *cur)
{
	if (old->acquired_refs != cur->acquired_refs)
		return false;
	return !memcmp(old->refs, cur->refs,
		       sizeof(*old->refs) * old->acquired_refs);
}

static bool klpr_func_states_equal(struct bpf_verifier_env *env, struct bpf_func_state *old,
			      struct bpf_func_state *cur)
{
	int i;

	memset(env->idmap_scratch, 0, sizeof(env->idmap_scratch));
	for (i = 0; i < MAX_BPF_REG; i++)
		if (!klpr_regsafe(env, &old->regs[i], &cur->regs[i],
			     env->idmap_scratch))
			return false;

	if (!klpp_stacksafe(env, old, cur, env->idmap_scratch))
		return false;

	if (!refsafe(old, cur))
		return false;

	return true;
}

static bool klpr_states_equal(struct bpf_verifier_env *env,
			 struct bpf_verifier_state *old,
			 struct bpf_verifier_state *cur)
{
	int i;

	if (old->curframe != cur->curframe)
		return false;

	/* Verification state from speculative execution simulation
	 * must never prune a non-speculative execution one.
	 */
	if (old->speculative && !cur->speculative)
		return false;

	if (old->active_spin_lock != cur->active_spin_lock)
		return false;

	/* for states to be equal callsites have to be the same
	 * and all frame states need to be equivalent
	 */
	for (i = 0; i <= old->curframe; i++) {
		if (old->frame[i]->callsite != cur->frame[i]->callsite)
			return false;
		if (!klpr_func_states_equal(env, old->frame[i], cur->frame[i]))
			return false;
	}
	return true;
}

static int (*klpe_propagate_liveness_reg)(struct bpf_verifier_env *env,
				  struct bpf_reg_state *reg,
				  struct bpf_reg_state *parent_reg);

static int klpr_propagate_liveness(struct bpf_verifier_env *env,
			      const struct bpf_verifier_state *vstate,
			      struct bpf_verifier_state *vparent)
{
	struct bpf_reg_state *state_reg, *parent_reg;
	struct bpf_func_state *state, *parent;
	int i, frame, err = 0;

	if (vparent->curframe != vstate->curframe) {
		WARN(1, "propagate_live: parent frame %d current frame %d\n",
		     vparent->curframe, vstate->curframe);
		return -EFAULT;
	}
	/* Propagate read liveness of registers... */
	BUILD_BUG_ON(BPF_REG_FP + 1 != MAX_BPF_REG);
	for (frame = 0; frame <= vstate->curframe; frame++) {
		parent = vparent->frame[frame];
		state = vstate->frame[frame];
		parent_reg = parent->regs;
		state_reg = state->regs;
		/* We don't need to worry about FP liveness, it's read-only */
		for (i = frame < vstate->curframe ? BPF_REG_6 : 0; i < BPF_REG_FP; i++) {
			err = (*klpe_propagate_liveness_reg)(env, &state_reg[i],
						     &parent_reg[i]);
			if (err < 0)
				return err;
			if (err == REG_LIVE_READ64)
				mark_insn_zext(env, &parent_reg[i]);
		}

		/* Propagate stack slots. */
		for (i = 0; i < state->allocated_stack / BPF_REG_SIZE &&
			    i < parent->allocated_stack / BPF_REG_SIZE; i++) {
			parent_reg = &parent->stack[i].spilled_ptr;
			state_reg = &state->stack[i].spilled_ptr;
			err = (*klpe_propagate_liveness_reg)(env, state_reg,
						     parent_reg);
			if (err < 0)
				return err;
		}
	}
	return 0;
}

static int klpr_propagate_precision(struct bpf_verifier_env *env,
			       const struct bpf_verifier_state *old)
{
	struct bpf_reg_state *state_reg;
	struct bpf_func_state *state;
	int i, err = 0;

	state = old->frame[old->curframe];
	state_reg = state->regs;
	for (i = 0; i < BPF_REG_FP; i++, state_reg++) {
		if (state_reg->type != SCALAR_VALUE ||
		    !state_reg->precise)
			continue;
		if (env->log.level & BPF_LOG_LEVEL2)
			klpr_verbose(env, "propagating r%d\n", i);
		err = klpr_mark_chain_precision(env, i);
		if (err < 0)
			return err;
	}

	for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
		if (!is_spilled_reg(&state->stack[i]))
			continue;
		state_reg = &state->stack[i].spilled_ptr;
		if (state_reg->type != SCALAR_VALUE ||
		    !state_reg->precise)
			continue;
		if (env->log.level & BPF_LOG_LEVEL2)
			klpr_verbose(env, "propagating fp%d\n",
				(-i - 1) * BPF_REG_SIZE);
		err = klpr_mark_chain_precision_stack(env, i);
		if (err < 0)
			return err;
	}
	return 0;
}

static bool states_maybe_looping(struct bpf_verifier_state *old,
				 struct bpf_verifier_state *cur)
{
	struct bpf_func_state *fold, *fcur;
	int i, fr = cur->curframe;

	if (old->curframe != fr)
		return false;

	fold = old->frame[fr];
	fcur = cur->frame[fr];
	for (i = 0; i < MAX_BPF_REG; i++)
		if (memcmp(&fold->regs[i], &fcur->regs[i],
			   offsetof(struct bpf_reg_state, parent)))
			return false;
	return true;
}

static int klpr_is_state_visited(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state_list *new_sl;
	struct bpf_verifier_state_list *sl, **pprev;
	struct bpf_verifier_state *cur = env->cur_state, *new;
	int i, j, err, states_cnt = 0;
	bool add_new_state = env->test_state_freq ? true : false;

	cur->last_insn_idx = env->prev_insn_idx;
	if (!env->insn_aux_data[insn_idx].prune_point)
		/* this 'insn_idx' instruction wasn't marked, so we will not
		 * be doing state search here
		 */
		return 0;

	/* bpf progs typically have pruning point every 4 instructions
	 * http://vger.kernel.org/bpfconf2019.html#session-1
	 * Do not add new state for future pruning if the verifier hasn't seen
	 * at least 2 jumps and at least 8 instructions.
	 * This heuristics helps decrease 'total_states' and 'peak_states' metric.
	 * In tests that amounts to up to 50% reduction into total verifier
	 * memory consumption and 20% verifier time speedup.
	 */
	if (env->jmps_processed - env->prev_jmps_processed >= 2 &&
	    env->insn_processed - env->prev_insn_processed >= 8)
		add_new_state = true;

	pprev = explored_state(env, insn_idx);
	sl = *pprev;

	klpr_clean_live_states(env, insn_idx, cur);

	while (sl) {
		states_cnt++;
		if (sl->state.insn_idx != insn_idx)
			goto next;

		if (sl->state.branches) {
			struct bpf_func_state *frame = sl->state.frame[sl->state.curframe];

			if (frame->in_async_callback_fn &&
			    frame->async_entry_cnt != cur->frame[cur->curframe]->async_entry_cnt) {
				/* Different async_entry_cnt means that the verifier is
				 * processing another entry into async callback.
				 * Seeing the same state is not an indication of infinite
				 * loop or infinite recursion.
				 * But finding the same state doesn't mean that it's safe
				 * to stop processing the current state. The previous state
				 * hasn't yet reached bpf_exit, since state.branches > 0.
				 * Checking in_async_callback_fn alone is not enough either.
				 * Since the verifier still needs to catch infinite loops
				 * inside async callbacks.
				 */
			} else if (states_maybe_looping(&sl->state, cur) &&
				   klpr_states_equal(env, &sl->state, cur)) {
				(*klpe_verbose_linfo)(env, insn_idx, "; ");
				klpr_verbose(env, "infinite loop detected at insn %d\n", insn_idx);
				return -EINVAL;
			}
			/* if the verifier is processing a loop, avoid adding new state
			 * too often, since different loop iterations have distinct
			 * states and may not help future pruning.
			 * This threshold shouldn't be too low to make sure that
			 * a loop with large bound will be rejected quickly.
			 * The most abusive loop will be:
			 * r1 += 1
			 * if r1 < 1000000 goto pc-2
			 * 1M insn_procssed limit / 100 == 10k peak states.
			 * This threshold shouldn't be too high either, since states
			 * at the end of the loop are likely to be useful in pruning.
			 */
			if (env->jmps_processed - env->prev_jmps_processed < 20 &&
			    env->insn_processed - env->prev_insn_processed < 100)
				add_new_state = false;
			goto miss;
		}
		if (klpr_states_equal(env, &sl->state, cur)) {
			sl->hit_cnt++;
			/* reached equivalent register/stack state,
			 * prune the search.
			 * Registers read by the continuation are read by us.
			 * If we have any write marks in env->cur_state, they
			 * will prevent corresponding reads in the continuation
			 * from reaching our parent (an explored_state).  Our
			 * own state will get the read marks recorded, but
			 * they'll be immediately forgotten as we're pruning
			 * this state and will pop a new one.
			 */
			err = klpr_propagate_liveness(env, &sl->state, cur);

			/* if previous state reached the exit with precision and
			 * current state is equivalent to it (except precsion marks)
			 * the precision needs to be propagated back in
			 * the current state.
			 */
			err = err ? : push_jmp_history(env, cur);
			err = err ? : klpr_propagate_precision(env, &sl->state);
			if (err)
				return err;
			return 1;
		}
miss:
		/* when new state is not going to be added do not increase miss count.
		 * Otherwise several loop iterations will remove the state
		 * recorded earlier. The goal of these heuristics is to have
		 * states from some iterations of the loop (some in the beginning
		 * and some at the end) to help pruning.
		 */
		if (add_new_state)
			sl->miss_cnt++;
		/* heuristic to determine whether this state is beneficial
		 * to keep checking from state equivalence point of view.
		 * Higher numbers increase max_states_per_insn and verification time,
		 * but do not meaningfully decrease insn_processed.
		 */
		if (sl->miss_cnt > sl->hit_cnt * 3 + 3) {
			/* the state is unlikely to be useful. Remove it to
			 * speed up verification
			 */
			*pprev = sl->next;
			if (sl->state.frame[0]->regs[0].live & REG_LIVE_DONE) {
				u32 br = sl->state.branches;

				WARN_ONCE(br,
					  "BUG live_done but branches_to_explore %d\n",
					  br);
				(*klpe_free_verifier_state)(&sl->state, false);
				kfree(sl);
				env->peak_states--;
			} else {
				/* cannot free this state, since parentage chain may
				 * walk it later. Add it for free_list instead to
				 * be freed at the end of verification
				 */
				sl->next = env->free_list;
				env->free_list = sl;
			}
			sl = *pprev;
			continue;
		}
next:
		pprev = &sl->next;
		sl = *pprev;
	}

	if (env->max_states_per_insn < states_cnt)
		env->max_states_per_insn = states_cnt;

	if (!env->bpf_capable && states_cnt > BPF_COMPLEXITY_LIMIT_STATES)
		return push_jmp_history(env, cur);

	if (!add_new_state)
		return push_jmp_history(env, cur);

	/* There were no equivalent states, remember the current one.
	 * Technically the current state is not proven to be safe yet,
	 * but it will either reach outer most bpf_exit (which means it's safe)
	 * or it will be rejected. When there are no loops the verifier won't be
	 * seeing this tuple (frame[0].callsite, frame[1].callsite, .. insn_idx)
	 * again on the way to bpf_exit.
	 * When looping the sl->state.branches will be > 0 and this state
	 * will not be considered for equivalence until branches == 0.
	 */
	new_sl = kzalloc(sizeof(struct bpf_verifier_state_list), GFP_KERNEL);
	if (!new_sl)
		return -ENOMEM;
	env->total_states++;
	env->peak_states++;
	env->prev_jmps_processed = env->jmps_processed;
	env->prev_insn_processed = env->insn_processed;

	/* add new state to the head of linked list */
	new = &new_sl->state;
	err = (*klpe_copy_verifier_state)(new, cur);
	if (err) {
		(*klpe_free_verifier_state)(new, false);
		kfree(new_sl);
		return err;
	}
	new->insn_idx = insn_idx;
	WARN_ONCE(new->branches != 1,
		  "BUG is_state_visited:branches_to_explore=%d insn %d\n", new->branches, insn_idx);

	cur->parent = new;
	cur->first_insn_idx = insn_idx;
	clear_jmp_history(cur);
	new_sl->next = *explored_state(env, insn_idx);
	*explored_state(env, insn_idx) = new_sl;
	/* connect new state to parentage chain. Current frame needs all
	 * registers connected. Only r6 - r9 of the callers are alive (pushed
	 * to the stack implicitly by JITs) so in callers' frames connect just
	 * r6 - r9 as an optimization. Callers will have r1 - r5 connected to
	 * the state of the call instruction (with WRITTEN set), and r0 comes
	 * from callee with its full parentage chain, anyway.
	 */
	/* clear write marks in current state: the writes we did are not writes
	 * our child did, so they don't screen off its reads from us.
	 * (There are no read marks in current state, because reads always mark
	 * their parent and current state never has children yet.  Only
	 * explored_states can get read marks.)
	 */
	for (j = 0; j <= cur->curframe; j++) {
		for (i = j < cur->curframe ? BPF_REG_6 : 0; i < BPF_REG_FP; i++)
			cur->frame[j]->regs[i].parent = &new->frame[j]->regs[i];
		for (i = 0; i < BPF_REG_FP; i++)
			cur->frame[j]->regs[i].live = REG_LIVE_NONE;
	}

	/* all stack frames are accessible from callee, clear them all */
	for (j = 0; j <= cur->curframe; j++) {
		struct bpf_func_state *frame = cur->frame[j];
		struct bpf_func_state *newframe = new->frame[j];

		for (i = 0; i < frame->allocated_stack / BPF_REG_SIZE; i++) {
			frame->stack[i].spilled_ptr.live = REG_LIVE_NONE;
			frame->stack[i].spilled_ptr.parent =
						&newframe->stack[i].spilled_ptr;
		}
	}
	return 0;
}

static bool reg_type_mismatch_ok(enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case PTR_TO_CTX:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
	case PTR_TO_XDP_SOCK:
	case PTR_TO_BTF_ID:
		return false;
	default:
		return true;
	}
}

static bool reg_type_mismatch(enum bpf_reg_type src, enum bpf_reg_type prev)
{
	return src != prev && (!reg_type_mismatch_ok(src) ||
			       !reg_type_mismatch_ok(prev));
}

static int klpr_do_check(struct bpf_verifier_env *env)
{
	bool pop_log = !(env->log.level & BPF_LOG_LEVEL2);
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_insn *insns = env->prog->insnsi;
	struct bpf_reg_state *regs;
	int insn_cnt = env->prog->len;
	bool do_print_state = false;
	int prev_insn_idx = -1;

	for (;;) {
		struct bpf_insn *insn;
		u8 class;
		int err;

		env->prev_insn_idx = prev_insn_idx;
		if (env->insn_idx >= insn_cnt) {
			klpr_verbose(env, "invalid insn idx %d insn_cnt %d\n",
				env->insn_idx, insn_cnt);
			return -EFAULT;
		}

		insn = &insns[env->insn_idx];
		class = BPF_CLASS(insn->code);

		if (++env->insn_processed > BPF_COMPLEXITY_LIMIT_INSNS) {
			klpr_verbose(env,
				"BPF program is too large. Processed %d insn\n",
				env->insn_processed);
			return -E2BIG;
		}

		err = klpr_is_state_visited(env, env->insn_idx);
		if (err < 0)
			return err;
		if (err == 1) {
			/* found equivalent state, can prune the search */
			if (env->log.level & BPF_LOG_LEVEL) {
				if (do_print_state)
					klpr_verbose(env, "\nfrom %d to %d%s: safe\n",
						env->prev_insn_idx, env->insn_idx,
						env->cur_state->speculative ?
						" (speculative execution)" : "");
				else
					klpr_verbose(env, "%d: safe\n", env->insn_idx);
			}
			goto process_bpf_exit;
		}

		if (signal_pending(current))
			return -EAGAIN;

		if (need_resched())
			cond_resched();

		if (env->log.level & BPF_LOG_LEVEL2 && do_print_state) {
			klpr_verbose(env, "\nfrom %d to %d%s:",
				env->prev_insn_idx, env->insn_idx,
				env->cur_state->speculative ?
				" (speculative execution)" : "");
			(*klpe_print_verifier_state)(env, state->frame[state->curframe], true);
			do_print_state = false;
		}

		if (env->log.level & BPF_LOG_LEVEL) {
			const struct bpf_insn_cbs cbs = {
				.cb_call	= (*klpe_disasm_kfunc_name),
				.cb_print	= klpr_verbose,
				.private_data	= env,
			};

			if (verifier_state_scratched(env))
				(*klpe_print_insn_state)(env, state->frame[state->curframe]);

			(*klpe_verbose_linfo)(env, env->insn_idx, "; ");
			env->prev_log_len = env->log.len_used;
			klpr_verbose(env, "%d: ", env->insn_idx);
			(*klpe_print_bpf_insn)(&cbs, insn, env->allow_ptr_leaks);
			env->prev_insn_print_len = env->log.len_used - env->prev_log_len;
			env->prev_log_len = env->log.len_used;
		}

		if (bpf_prog_is_dev_bound(env->prog->aux)) {
			err = (*klpe_bpf_prog_offload_verify_insn)(env, env->insn_idx,
							   env->prev_insn_idx);
			if (err)
				return err;
		}

		regs = cur_regs(env);
		sanitize_mark_insn_seen(env);
		prev_insn_idx = env->insn_idx;

		if (class == BPF_ALU || class == BPF_ALU64) {
			err = klpr_check_alu_op(env, insn);
			if (err)
				return err;

		} else if (class == BPF_LDX) {
			enum bpf_reg_type *prev_src_type, src_reg_type;

			/* check for reserved fields is already done */

			/* check src operand */
			err = (*klpe_check_reg_arg)(env, insn->src_reg, SRC_OP);
			if (err)
				return err;

			err = (*klpe_check_reg_arg)(env, insn->dst_reg, DST_OP_NO_MARK);
			if (err)
				return err;

			src_reg_type = regs[insn->src_reg].type;

			/* check that memory (src_reg + off) is readable,
			 * the state of dst_reg will be updated by this func
			 */
			err = klpp_check_mem_access(env, env->insn_idx, insn->src_reg,
					       insn->off, BPF_SIZE(insn->code),
					       BPF_READ, insn->dst_reg, false);
			if (err)
				return err;

			prev_src_type = &env->insn_aux_data[env->insn_idx].ptr_type;

			if (*prev_src_type == NOT_INIT) {
				/* saw a valid insn
				 * dst_reg = *(u32 *)(src_reg + off)
				 * save type to validate intersecting paths
				 */
				*prev_src_type = src_reg_type;

			} else if (reg_type_mismatch(src_reg_type, *prev_src_type)) {
				/* ABuser program is trying to use the same insn
				 * dst_reg = *(u32*) (src_reg + off)
				 * with different pointer types:
				 * src_reg == ctx in one branch and
				 * src_reg == stack|map in some other branch.
				 * Reject it.
				 */
				klpr_verbose(env, "same insn cannot be used with different pointers\n");
				return -EINVAL;
			}

		} else if (class == BPF_STX) {
			enum bpf_reg_type *prev_dst_type, dst_reg_type;

			if (BPF_MODE(insn->code) == BPF_ATOMIC) {
				err = klpr_check_atomic(env, env->insn_idx, insn);
				if (err)
					return err;
				env->insn_idx++;
				continue;
			}

			if (BPF_MODE(insn->code) != BPF_MEM || insn->imm != 0) {
				klpr_verbose(env, "BPF_STX uses reserved fields\n");
				return -EINVAL;
			}

			/* check src1 operand */
			err = (*klpe_check_reg_arg)(env, insn->src_reg, SRC_OP);
			if (err)
				return err;
			/* check src2 operand */
			err = (*klpe_check_reg_arg)(env, insn->dst_reg, SRC_OP);
			if (err)
				return err;

			dst_reg_type = regs[insn->dst_reg].type;

			/* check that memory (dst_reg + off) is writeable */
			err = klpp_check_mem_access(env, env->insn_idx, insn->dst_reg,
					       insn->off, BPF_SIZE(insn->code),
					       BPF_WRITE, insn->src_reg, false);
			if (err)
				return err;

			prev_dst_type = &env->insn_aux_data[env->insn_idx].ptr_type;

			if (*prev_dst_type == NOT_INIT) {
				*prev_dst_type = dst_reg_type;
			} else if (reg_type_mismatch(dst_reg_type, *prev_dst_type)) {
				klpr_verbose(env, "same insn cannot be used with different pointers\n");
				return -EINVAL;
			}

		} else if (class == BPF_ST) {
			if (BPF_MODE(insn->code) != BPF_MEM ||
			    insn->src_reg != BPF_REG_0) {
				klpr_verbose(env, "BPF_ST uses reserved fields\n");
				return -EINVAL;
			}
			/* check src operand */
			err = (*klpe_check_reg_arg)(env, insn->dst_reg, SRC_OP);
			if (err)
				return err;

			if (is_ctx_reg(env, insn->dst_reg)) {
				klpr_verbose(env, "BPF_ST stores into R%d %s is not allowed\n",
					insn->dst_reg,
					(*klpe_reg_type_str)(env, reg_state(env, insn->dst_reg)->type));
				return -EACCES;
			}

			/* check that memory (dst_reg + off) is writeable */
			err = klpp_check_mem_access(env, env->insn_idx, insn->dst_reg,
					       insn->off, BPF_SIZE(insn->code),
					       BPF_WRITE, -1, false);
			if (err)
				return err;

		} else if (class == BPF_JMP || class == BPF_JMP32) {
			u8 opcode = BPF_OP(insn->code);

			env->jmps_processed++;
			if (opcode == BPF_CALL) {
				if (BPF_SRC(insn->code) != BPF_K ||
				    (insn->src_reg != BPF_PSEUDO_KFUNC_CALL
				     && insn->off != 0) ||
				    (insn->src_reg != BPF_REG_0 &&
				     insn->src_reg != BPF_PSEUDO_CALL &&
				     insn->src_reg != BPF_PSEUDO_KFUNC_CALL) ||
				    insn->dst_reg != BPF_REG_0 ||
				    class == BPF_JMP32) {
					klpr_verbose(env, "BPF_CALL uses reserved fields\n");
					return -EINVAL;
				}

				if (env->cur_state->active_spin_lock &&
				    (insn->src_reg == BPF_PSEUDO_CALL ||
				     insn->imm != BPF_FUNC_spin_unlock)) {
					klpr_verbose(env, "function calls are not allowed while holding a lock\n");
					return -EINVAL;
				}
				if (insn->src_reg == BPF_PSEUDO_CALL)
					err = klpr_check_func_call(env, insn, &env->insn_idx);
				else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL)
					err = klpr_check_kfunc_call(env, insn, &env->insn_idx);
				else
					err = klpp_check_helper_call(env, insn, &env->insn_idx);
				if (err)
					return err;
			} else if (opcode == BPF_JA) {
				if (BPF_SRC(insn->code) != BPF_K ||
				    insn->imm != 0 ||
				    insn->src_reg != BPF_REG_0 ||
				    insn->dst_reg != BPF_REG_0 ||
				    class == BPF_JMP32) {
					klpr_verbose(env, "BPF_JA uses reserved fields\n");
					return -EINVAL;
				}

				env->insn_idx += insn->off + 1;
				continue;

			} else if (opcode == BPF_EXIT) {
				if (BPF_SRC(insn->code) != BPF_K ||
				    insn->imm != 0 ||
				    insn->src_reg != BPF_REG_0 ||
				    insn->dst_reg != BPF_REG_0 ||
				    class == BPF_JMP32) {
					klpr_verbose(env, "BPF_EXIT uses reserved fields\n");
					return -EINVAL;
				}

				if (env->cur_state->active_spin_lock) {
					klpr_verbose(env, "bpf_spin_unlock is missing\n");
					return -EINVAL;
				}

				if (state->curframe) {
					/* exit from nested function */
					err = klpr_prepare_func_exit(env, &env->insn_idx);
					if (err)
						return err;
					do_print_state = true;
					continue;
				}

				err = (*klpe_check_reference_leak)(env);
				if (err)
					return err;

				err = klpr_check_return_code(env);
				if (err)
					return err;
process_bpf_exit:
				mark_verifier_state_scratched(env);
				update_branch_counts(env, env->cur_state);
				err = (*klpe_pop_stack)(env, &prev_insn_idx,
						&env->insn_idx, pop_log);
				if (err < 0) {
					if (err != -ENOENT)
						return err;
					break;
				} else {
					do_print_state = true;
					continue;
				}
			} else {
				err = (*klpe_check_cond_jmp_op)(env, insn, &env->insn_idx);
				if (err)
					return err;
			}
		} else if (class == BPF_LD) {
			u8 mode = BPF_MODE(insn->code);

			if (mode == BPF_ABS || mode == BPF_IND) {
				err = klpr_check_ld_abs(env, insn);
				if (err)
					return err;

			} else if (mode == BPF_IMM) {
				err = klpr_check_ld_imm(env, insn);
				if (err)
					return err;

				env->insn_idx++;
				sanitize_mark_insn_seen(env);
			} else {
				klpr_verbose(env, "invalid BPF_LD mode\n");
				return -EINVAL;
			}
		} else {
			klpr_verbose(env, "unknown insn class %d\n", class);
			return -EINVAL;
		}

		env->insn_idx++;
	}

	return 0;
}

static void klpr_free_states(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state_list *sl, *sln;
	int i;

	sl = env->free_list;
	while (sl) {
		sln = sl->next;
		(*klpe_free_verifier_state)(&sl->state, false);
		kfree(sl);
		sl = sln;
	}
	env->free_list = NULL;

	if (!env->explored_states)
		return;

	for (i = 0; i < state_htab_size(env); i++) {
		sl = env->explored_states[i];

		while (sl) {
			sln = sl->next;
			(*klpe_free_verifier_state)(&sl->state, false);
			kfree(sl);
			sl = sln;
		}
		env->explored_states[i] = NULL;
	}
}

int klpp_do_check_common(struct bpf_verifier_env *env, int subprog)
{
	bool pop_log = !(env->log.level & BPF_LOG_LEVEL2);
	struct bpf_verifier_state *state;
	struct bpf_reg_state *regs;
	int ret, i;

	env->prev_linfo = NULL;
	env->pass_cnt++;

	state = kzalloc(sizeof(struct bpf_verifier_state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->curframe = 0;
	state->speculative = false;
	state->branches = 1;
	state->frame[0] = kzalloc(sizeof(struct bpf_func_state), GFP_KERNEL);
	if (!state->frame[0]) {
		kfree(state);
		return -ENOMEM;
	}
	env->cur_state = state;
	klpr_init_func_state(env, state->frame[0],
			BPF_MAIN_FUNC /* callsite */,
			0 /* frameno */,
			subprog);

	regs = state->frame[state->curframe]->regs;
	if (subprog || env->prog->type == BPF_PROG_TYPE_EXT) {
		ret = (*klpe_btf_prepare_func_args)(env, subprog, regs);
		if (ret)
			goto out;
		for (i = BPF_REG_1; i <= BPF_REG_5; i++) {
			if (regs[i].type == PTR_TO_CTX)
				(*klpe_mark_reg_known_zero)(env, regs, i);
			else if (regs[i].type == SCALAR_VALUE) {
				(*klpe_mark_reg_unknown)(env, regs, i);
			}
			else if (base_type(regs[i].type) == PTR_TO_MEM) {
				const u32 mem_size = regs[i].mem_size;

				(*klpe_mark_reg_known_zero)(env, regs, i);
				regs[i].mem_size = mem_size;
				regs[i].id = ++env->id_gen;
			}
		}
	} else {
		/* 1st arg to a function */
		regs[BPF_REG_1].type = PTR_TO_CTX;
		(*klpe_mark_reg_known_zero)(env, regs, BPF_REG_1);
		ret = (*klpe_btf_check_subprog_arg_match)(env, subprog, regs);
		if (ret == -EFAULT)
			/* unlikely verifier bug. abort.
			 * ret == 0 and ret < 0 are sadly acceptable for
			 * main() function due to backward compatibility.
			 * Like socket filter program may be written as:
			 * int bpf_prog(struct pt_regs *ctx)
			 * and never dereference that ctx in the program.
			 * 'struct pt_regs' is a type mismatch for socket
			 * filter that should be using 'struct __sk_buff'.
			 */
			goto out;
	}

	ret = klpr_do_check(env);
out:
	/* check for NULL is necessary, since cur_state can be freed inside
	 * do_check() under memory pressure.
	 */
	if (env->cur_state) {
		(*klpe_free_verifier_state)(env->cur_state, true);
		env->cur_state = NULL;
	}
	while (!(*klpe_pop_stack)(env, NULL, NULL, false));
	if (!ret && pop_log)
		(*klpe_bpf_vlog_reset)(&env->log, 0);
	klpr_free_states(env);
	return ret;
}


#include <linux/kernel.h>
#include "../kallsyms_relocs.h"


static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__check_func_call", (void *)&klpe___check_func_call },
	{ "__check_ptr_off_reg", (void *)&klpe___check_ptr_off_reg },
	{ "__mark_chain_precision", (void *)&klpe___mark_chain_precision },
	{ "__mark_reg_known", (void *)&klpe___mark_reg_known },
	{ "__reg_combine_64_into_32", (void *)&klpe___reg_combine_64_into_32 },
	{ "acquire_reference_state", (void *)&klpe_acquire_reference_state },
	{ "adjust_reg_min_max_vals", (void *)&klpe_adjust_reg_min_max_vals },
	{ "bpf_bprintf_prepare", (void *)&klpe_bpf_bprintf_prepare },
	{ "bpf_helper_changes_pkt_data",
	  (void *)&klpe_bpf_helper_changes_pkt_data },
	{ "bpf_map_is_rdonly", (void *)&klpe_bpf_map_is_rdonly },
	{ "bpf_map_kptr_off_contains",
	  (void *)&klpe_bpf_map_kptr_off_contains },
	{ "bpf_prog_has_trampoline", (void *)&klpe_bpf_prog_has_trampoline },
	{ "bpf_prog_offload_verify_insn",
	  (void *)&klpe_bpf_prog_offload_verify_insn },
	{ "bpf_sock_common_is_valid_access",
	  (void *)&klpe_bpf_sock_common_is_valid_access },
	{ "bpf_sock_is_valid_access", (void *)&klpe_bpf_sock_is_valid_access },
	{ "bpf_tcp_sock_is_valid_access",
	  (void *)&klpe_bpf_tcp_sock_is_valid_access },
	{ "bpf_verifier_vlog", (void *)&klpe_bpf_verifier_vlog },
	{ "bpf_vlog_reset", (void *)&klpe_bpf_vlog_reset },
	{ "bpf_xdp_sock_is_valid_access",
	  (void *)&klpe_bpf_xdp_sock_is_valid_access },
	{ "btf_check_kfunc_arg_match",
	  (void *)&klpe_btf_check_kfunc_arg_match },
	{ "btf_check_subprog_arg_match",
	  (void *)&klpe_btf_check_subprog_arg_match },
	{ "btf_get_by_fd", (void *)&klpe_btf_get_by_fd },
	{ "btf_is_module", (void *)&klpe_btf_is_module },
	{ "btf_kfunc_id_set_contains",
	  (void *)&klpe_btf_kfunc_id_set_contains },
	{ "btf_name_by_offset", (void *)&klpe_btf_name_by_offset },
	{ "btf_prepare_func_args", (void *)&klpe_btf_prepare_func_args },
	{ "btf_put", (void *)&klpe_btf_put },
	{ "btf_resolve_size", (void *)&klpe_btf_resolve_size },
	{ "btf_struct_access", (void *)&klpe_btf_struct_access },
	{ "btf_struct_ids_match", (void *)&klpe_btf_struct_ids_match },
	{ "btf_try_get_module", (void *)&klpe_btf_try_get_module },
	{ "btf_type_by_id", (void *)&klpe_btf_type_by_id },
	{ "btf_type_skip_modifiers", (void *)&klpe_btf_type_skip_modifiers },
	{ "btf_type_str", (void *)&klpe_btf_type_str },
	{ "btf_vmlinux", (void *)&klpe_btf_vmlinux },
	{ "caller_saved", (void *)&klpe_caller_saved },
	{ "check_cond_jmp_op", (void *)&klpe_check_cond_jmp_op },
	{ "check_helper_mem_access", (void *)&klpe_check_helper_mem_access },
	{ "check_map_access", (void *)&klpe_check_map_access },
	{ "check_map_access_type", (void *)&klpe_check_map_access_type },
	{ "check_mem_region_access", (void *)&klpe_check_mem_region_access },
	{ "check_mem_size_reg", (void *)&klpe_check_mem_size_reg },
	{ "check_packet_access", (void *)&klpe_check_packet_access },
	{ "check_ptr_alignment", (void *)&klpe_check_ptr_alignment },
	{ "check_ptr_off_reg", (void *)&klpe_check_ptr_off_reg },
	{ "check_reference_leak", (void *)&klpe_check_reference_leak },
	{ "check_reg_arg", (void *)&klpe_check_reg_arg },
	{ "check_stack_access_within_bounds",
	  (void *)&klpe_check_stack_access_within_bounds },
	{ "check_stack_read", (void *)&klpe_check_stack_read },
	{ "compatible_reg_types", (void *)&klpe_compatible_reg_types },
	{ "copy_array", (void *)&klpe_copy_array },
	{ "copy_verifier_state", (void *)&klpe_copy_verifier_state },
	{ "disasm_kfunc_name", (void *)&klpe_disasm_kfunc_name },
	{ "find_subprog", (void *)&klpe_find_subprog },
	{ "free_verifier_state", (void *)&klpe_free_verifier_state },
	{ "func_id_name", (void *)&klpe_func_id_name },
	{ "get_callchain_buffers", (void *)&klpe_get_callchain_buffers },
	{ "init_reg_state", (void *)&klpe_init_reg_state },
	{ "kernel_type_name", (void *)&klpe_kernel_type_name },
	{ "kfunc_btf_cmp_by_off", (void *)&klpe_kfunc_btf_cmp_by_off },
	{ "map_kptr_match_type", (void *)&klpe_map_kptr_match_type },
	{ "mark_btf_func_reg_size", (void *)&klpe_mark_btf_func_reg_size },
	{ "mark_reg_known_zero", (void *)&klpe_mark_reg_known_zero },
	{ "mark_reg_not_init", (void *)&klpe_mark_reg_not_init },
	{ "mark_reg_read", (void *)&klpe_mark_reg_read },
	{ "mark_reg_unknown", (void *)&klpe_mark_reg_unknown },
	{ "may_update_sockmap", (void *)&klpe_may_update_sockmap },
	{ "pop_stack", (void *)&klpe_pop_stack },
	{ "print_bpf_insn", (void *)&klpe_print_bpf_insn },
	{ "print_insn_state", (void *)&klpe_print_insn_state },
	{ "print_verifier_state", (void *)&klpe_print_verifier_state },
	{ "process_spin_lock", (void *)&klpe_process_spin_lock },
	{ "propagate_liveness_reg", (void *)&klpe_propagate_liveness_reg },
	{ "range_within", (void *)&klpe_range_within },
	{ "realloc_array", (void *)&klpe_realloc_array },
	{ "release_reference", (void *)&klpe_release_reference },
	{ "reg_bounds_sync", (void *)&klpe_reg_bounds_sync },
	{ "reg_type_str", (void *)&klpe_reg_type_str },
	{ "set_callee_state", (void *)&klpe_set_callee_state },
	{ "set_find_vma_callback_state",
	  (void *)&klpe_set_find_vma_callback_state },
	{ "set_loop_callback_state", (void *)&klpe_set_loop_callback_state },
	{ "set_map_elem_callback_state",
	  (void *)&klpe_set_map_elem_callback_state },
	{ "set_timer_callback_state", (void *)&klpe_set_timer_callback_state },
	{ "sysctl_perf_event_max_stack",
	  (void *)&klpe_sysctl_perf_event_max_stack },
	{ "tnum_cast", (void *)&klpe_tnum_cast },
	{ "tnum_const", (void *)&klpe_tnum_const },
	{ "tnum_in", (void *)&klpe_tnum_in },
	{ "tnum_range", (void *)&klpe_tnum_range },
	{ "tnum_unknown", (void *)&klpe_tnum_unknown },
	{ "verbose_linfo", (void *)&klpe_verbose_linfo },
	{ "zext_32_to_64", (void *)&klpe_zext_32_to_64 },
};

int livepatch_bsc1215887_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
