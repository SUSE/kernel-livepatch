/*
 * livepatch_bsc1186498
 *
 * Fix for CVE-2021-33200, bsc#1186498
 *
 *  Upstream commits:
 *   3d0220f6861d ("bpf: Wrap aux data inside bpf_sanitize_info container")
 *   bb01a1bba579 ("bpf: Fix mask direction swap upon off reg sign change")
 *   a7036191277f ("bpf: No need to simulate speculative domain for immediates")
 *
 *  SLE12-SP3 commits:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  e930239a6765fc77e59f6aefb7f1b5f9152e16d1
 *  3ce8728d7b4c92402c287a8fd096c186e0931bce
 *
 *  SLE15-SP2 commits:
 *  79be05a019332ba206411c10bd3f81ee93d598b9
 *  a8864c36a4ffa3d7921f1aeb4fe5c1f5ff6c6a76
 *  fc0b52a7e2e8ff17eb857272493d1c8288ef887f
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

/* klp-ccp: from kernel/bpf/verifier.c */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>

/* klp-ccp: from include/linux/tnum.h */
static struct tnum (*klpe_tnum_add)(struct tnum a, struct tnum b);

static struct tnum (*klpe_tnum_sub)(struct tnum a, struct tnum b);

/* klp-ccp: from include/linux/bpf_verifier.h */
static void (*klpe_bpf_verifier_vlog)(struct bpf_verifier_log *log, const char *fmt,
		       va_list args);

/* klp-ccp: from kernel/bpf/verifier.c */
#include <linux/filter.h>
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/stringify.h>
/* klp-ccp: from kernel/bpf/disasm.h */
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/stringify.h>

static const char *const (*klpe_bpf_alu_string)[16];

/* klp-ccp: from kernel/bpf/verifier.c */
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

static bool type_is_pkt_pointer(enum bpf_reg_type type)
{
	return type == PTR_TO_PACKET ||
	       type == PTR_TO_PACKET_META;
}

static const char * const (*klpe_reg_type_str)[];

static struct bpf_verifier_state *(*klpe_push_stack)(struct bpf_verifier_env *env,
					     int insn_idx, int prev_insn_idx,
					     bool speculative);

static bool reg_is_pkt_pointer(const struct bpf_reg_state *reg)
{
	return type_is_pkt_pointer(reg->type);
}

static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	/* min signed is max(sign bit) | min(other bits) */
	reg->smin_value = max_t(s64, reg->smin_value,
				reg->var_off.value | (reg->var_off.mask & S64_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->smax_value = min_t(s64, reg->smax_value,
				reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value,
			      reg->var_off.value | reg->var_off.mask);
}

static void (*klpe___reg_deduce_bounds)(struct bpf_reg_state *reg);

static void (*klpe___reg_bound_offset)(struct bpf_reg_state *reg);

static void (*klpe___mark_reg_unknown)(struct bpf_reg_state *reg);

static int (*klpe_check_stack_access)(struct bpf_verifier_env *env,
			      const struct bpf_reg_state *reg,
			      int off, int size);

static int (*klpe_check_map_access)(struct bpf_verifier_env *env, u32 regno,
			    int off, int size, bool zero_size_allowed);

static bool signed_add_overflows(s64 a, s64 b)
{
	/* Do the add in u64, where overflow is well-defined */
	s64 res = (s64)((u64)a + (u64)b);

	if (b < 0)
		return res > a;
	return res < a;
}

static bool signed_sub_overflows(s64 a, s64 b)
{
	/* Do the sub in u64, where overflow is well-defined */
	s64 res = (s64)((u64)a - (u64)b);

	if (b < 0)
		return res < a;
	return res > a;
}

static bool (*klpe_check_reg_sane_offset)(struct bpf_verifier_env *env,
				  const struct bpf_reg_state *reg,
				  enum bpf_reg_type type);

static struct bpf_insn_aux_data *cur_aux(struct bpf_verifier_env *env)
{
	return &env->insn_aux_data[env->insn_idx];
}

enum {
	REASON_BOUNDS	= -1,
	REASON_TYPE	= -2,
	REASON_PATHS	= -3,
	REASON_LIMIT	= -4,
	REASON_STACK	= -5,
};

static int klpp_retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
			      /*
			       * Fix CVE-2021-33200
			       *  -2 lines, +1 line
			       */
			      u32 *alu_limit, bool mask_to_left)
{
	/*
	 * Fix CVE-2021-33200
	 *  -3 lines
	 */
	u32 max = 0, ptr_limit = 0;

	/*
	 * Fix CVE-2021-33200
	 *  -3 lines
	 */

	switch (ptr_reg->type) {
	case PTR_TO_STACK:
		/* Indirect variable offset stack access is prohibited in
		 * unprivileged mode so it's not handled here.
		 *
		 * Offset 0 is out-of-bounds, but acceptable start for the
		 * left direction, see BPF_REG_FP. Also, unknown scalar
		 * offset where we would need to deal with min/max bounds is
		 * currently prohibited for unprivileged.
		 */
		max = MAX_BPF_STACK + mask_to_left;
		ptr_limit = -(ptr_reg->var_off.value + ptr_reg->off);
		break;
	case PTR_TO_MAP_VALUE:
		max = ptr_reg->map_ptr->value_size;
		ptr_limit = (mask_to_left ?
			     ptr_reg->smin_value :
			     ptr_reg->umax_value) + ptr_reg->off;
		break;
	default:
		return REASON_TYPE;
	}

	if (ptr_limit >= max)
		return REASON_LIMIT;
	*alu_limit = ptr_limit;
	return 0;
}

static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
				    const struct bpf_insn *insn)
{
	return env->allow_ptr_leaks || BPF_SRC(insn->code) == BPF_K;
}

static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
				       u32 alu_state, u32 alu_limit)
{
	/* If we arrived here from different branches with different
	 * state or limits to sanitize, then this won't work.
	 */
	if (aux->alu_state &&
	    (aux->alu_state != alu_state ||
	     aux->alu_limit != alu_limit))
		return REASON_PATHS;

	/* Corresponding fixup done in fixup_bpf_calls(). */
	aux->alu_state = alu_state;
	aux->alu_limit = alu_limit;
	return 0;
}

static bool sanitize_needed(u8 opcode)
{
	return opcode == BPF_ADD || opcode == BPF_SUB;
}

/* New. */
struct bpf_sanitize_info {
	struct bpf_insn_aux_data aux;
	bool mask_to_left;
};

static int klpp_sanitize_ptr_alu(struct bpf_verifier_env *env,
			    struct bpf_insn *insn,
			    const struct bpf_reg_state *ptr_reg,
			    const struct bpf_reg_state *off_reg,
			    struct bpf_reg_state *dst_reg,
			    /*
			     * Fix CVE-2021-33200
			     *  -1 line, +1 line
			     */
			    struct bpf_sanitize_info *info,
			    const bool commit_window)
{
	/*
	 * Fix CVE-2021-33200
	 *  -1 line, +1 line
	 */
	struct bpf_insn_aux_data *aux = commit_window ? cur_aux(env) : &info->aux;
	struct bpf_verifier_state *vstate = env->cur_state;
	bool off_is_neg = off_reg->smin_value < 0;
	bool ptr_is_dst_reg = ptr_reg == dst_reg;
	u8 opcode = BPF_OP(insn->code);
	u32 alu_state, alu_limit;
	struct bpf_reg_state tmp;
	bool ret;
	int err;

	if (can_skip_alu_sanitation(env, insn))
		return 0;

	/* We already marked aux for masking from non-speculative
	 * paths, thus we got here in the first place. We only care
	 * to explore bad access from here.
	 */
	if (vstate->speculative)
		goto do_sim;

	/*
	 * Fix CVE-2021-33200
	 *  -1 line, +10 lines
	 */
	if (!commit_window) {
		if (!tnum_is_const(off_reg->var_off) &&
		    (off_reg->smin_value < 0) != (off_reg->smax_value < 0))
			return REASON_BOUNDS;

		info->mask_to_left = (opcode == BPF_ADD &&  off_is_neg) ||
				     (opcode == BPF_SUB && !off_is_neg);
	}

	err = klpp_retrieve_ptr_limit(ptr_reg, &alu_limit, info->mask_to_left);
	if (err < 0)
		return err;

	if (commit_window) {
		/* In commit phase we narrow the masking window based on
		 * the observed pointer move after the simulated operation.
		 */
		/*
		 * Fix CVE-2021-33200
		 *  -2 lines, +2 lines
		 */
		alu_state = info->aux.alu_state;
		alu_limit = abs(info->aux.alu_limit - alu_limit);
	} else {
		alu_state  = off_is_neg ? BPF_ALU_NEG_VALUE : 0;
		alu_state |= ptr_is_dst_reg ?
			     BPF_ALU_SANITIZE_SRC : BPF_ALU_SANITIZE_DST;
	}

	err = update_alu_sanitation_state(aux, alu_state, alu_limit);
	if (err < 0)
		return err;
do_sim:
	/* If we're in commit phase, we're done here given we already
	 * pushed the truncated dst_reg into the speculative verification
	 * stack.
	 */
	if (commit_window)
		return 0;

	/* Simulate and find potential out-of-bounds access under
	 * speculative execution from truncation as a result of
	 * masking when off was not within expected range. If off
	 * sits in dst, then we temporarily need to move ptr there
	 * to simulate dst (== 0) +/-= ptr. Needed, for example,
	 * for cases where we use K-based arithmetic in one direction
	 * and truncated reg-based in the other in order to explore
	 * bad access.
	 */
	if (!ptr_is_dst_reg) {
		tmp = *dst_reg;
		*dst_reg = *ptr_reg;
	}
	ret = (*klpe_push_stack)(env, env->insn_idx + 1, env->insn_idx, true);
	if (!ptr_is_dst_reg && ret)
		*dst_reg = tmp;
	return !ret ? REASON_STACK : 0;
}

static int (*klpe_sanitize_err)(struct bpf_verifier_env *env,
			const struct bpf_insn *insn, int reason,
			const struct bpf_reg_state *off_reg,
			const struct bpf_reg_state *dst_reg);

static int klpr_sanitize_check_bounds(struct bpf_verifier_env *env,
				 const struct bpf_insn *insn,
				 const struct bpf_reg_state *dst_reg)
{
	u32 dst = insn->dst_reg;

	/* For unprivileged we require that resulting offset must be in bounds
	 * in order to be able to sanitize access later on.
	 */
	if (env->allow_ptr_leaks)
		return 0;

	switch (dst_reg->type) {
	case PTR_TO_STACK:
		if ((*klpe_check_stack_access)(env, dst_reg,
				       dst_reg->off + dst_reg->var_off.value, 1)) {
			klpr_verbose(env, "R%d stack pointer arithmetic goes out of range, "
				"prohibited for !root\n", dst);
			return -EACCES;
		}
		break;
	case PTR_TO_MAP_VALUE:
		if ((*klpe_check_map_access)(env, dst, dst_reg->off, 1, false)) {
			klpr_verbose(env, "R%d pointer arithmetic of map value goes out of range, "
				"prohibited for !root\n", dst);
			return -EACCES;
		}
		break;
	default:
		break;
	}

	return 0;
}

int klpp_adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   const struct bpf_reg_state *ptr_reg,
				   const struct bpf_reg_state *off_reg)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	struct bpf_reg_state *regs = state->regs, *dst_reg;
	bool known = tnum_is_const(off_reg->var_off);
	s64 smin_val = off_reg->smin_value, smax_val = off_reg->smax_value,
	    smin_ptr = ptr_reg->smin_value, smax_ptr = ptr_reg->smax_value;
	u64 umin_val = off_reg->umin_value, umax_val = off_reg->umax_value,
	    umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
	/*
	 * Fix CVE-2021-33200
	 *  -1 line, +1 line
	 */
	struct bpf_sanitize_info info = {};
	u8 opcode = BPF_OP(insn->code);
	u32 dst = insn->dst_reg;
	int ret;

	dst_reg = &regs[dst];

	if ((known && (smin_val != smax_val || umin_val != umax_val)) ||
	    smin_val > smax_val || umin_val > umax_val) {
		/* Taint dst register if offset had invalid bounds derived from
		 * e.g. dead branches.
		 */
		(*klpe___mark_reg_unknown)(dst_reg);
		return 0;
	}

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		/* 32-bit ALU ops on pointers produce (meaningless) scalars */
		klpr_verbose(env,
			"R%d 32-bit pointer arithmetic prohibited\n",
			dst);
		return -EACCES;
	}

	switch (ptr_reg->type) {
	case PTR_TO_MAP_VALUE_OR_NULL:
		klpr_verbose(env, "R%d pointer arithmetic on %s prohibited, null-check it first\n",
			dst, (*klpe_reg_type_str)[ptr_reg->type]);
		return -EACCES;
	case CONST_PTR_TO_MAP:
	case PTR_TO_PACKET_END:
		klpr_verbose(env, "R%d pointer arithmetic on %s prohibited\n",
			dst, (*klpe_reg_type_str)[ptr_reg->type]);
		return -EACCES;
	default:
		break;
	}

	/* In case of 'scalar += pointer', dst_reg inherits pointer type and id.
	 * The id may be overwritten later if we create a new variable offset.
	 */
	dst_reg->type = ptr_reg->type;
	dst_reg->id = ptr_reg->id;

	if (!(*klpe_check_reg_sane_offset)(env, off_reg, ptr_reg->type) ||
	    !(*klpe_check_reg_sane_offset)(env, ptr_reg, ptr_reg->type))
		return -EINVAL;

	if (sanitize_needed(opcode)) {
		ret = klpp_sanitize_ptr_alu(env, insn, ptr_reg, off_reg, dst_reg,
				       /*
					* Fix CVE-2021-33200
					*  -1 line, +1 line
					*/
				       &info, false);
		if (ret < 0)
			return (*klpe_sanitize_err)(env, insn, ret, off_reg, dst_reg);
	}

	switch (opcode) {
	case BPF_ADD:
		/* We can take a fixed offset as long as it doesn't overflow
		 * the s32 'off' field
		 */
		if (known && (ptr_reg->off + smin_val ==
			      (s64)(s32)(ptr_reg->off + smin_val))) {
			/* pointer += K.  Accumulate it into fixed offset */
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->off = ptr_reg->off + smin_val;
			dst_reg->raw = ptr_reg->raw;
			break;
		}
		/* A new variable offset is created.  Note that off_reg->off
		 * == 0, since it's a scalar.
		 * dst_reg gets the pointer type and since some positive
		 * integer value was added to the pointer, give it a new 'id'
		 * if it's a PTR_TO_PACKET.
		 * this creates a new 'base' pointer, off_reg (variable) gets
		 * added into the variable offset, and we copy the fixed offset
		 * from ptr_reg.
		 */
		if (signed_add_overflows(smin_ptr, smin_val) ||
		    signed_add_overflows(smax_ptr, smax_val)) {
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = smin_ptr + smin_val;
			dst_reg->smax_value = smax_ptr + smax_val;
		}
		if (umin_ptr + umin_val < umin_ptr ||
		    umax_ptr + umax_val < umax_ptr) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			dst_reg->umin_value = umin_ptr + umin_val;
			dst_reg->umax_value = umax_ptr + umax_val;
		}
		dst_reg->var_off = (*klpe_tnum_add)(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		dst_reg->raw = ptr_reg->raw;
		if (reg_is_pkt_pointer(ptr_reg)) {
			dst_reg->id = ++env->id_gen;
			/* something was added to pkt_ptr, set range to zero */
			dst_reg->raw = 0;
		}
		break;
	case BPF_SUB:
		if (dst_reg == off_reg) {
			/* scalar -= pointer.  Creates an unknown scalar */
			klpr_verbose(env, "R%d tried to subtract pointer from scalar\n",
				dst);
			return -EACCES;
		}
		/* We don't allow subtraction from FP, because (according to
		 * test_verifier.c test "invalid fp arithmetic", JITs might not
		 * be able to deal with it.
		 */
		if (ptr_reg->type == PTR_TO_STACK) {
			klpr_verbose(env, "R%d subtraction from stack pointer prohibited\n",
				dst);
			return -EACCES;
		}
		if (known && (ptr_reg->off - smin_val ==
			      (s64)(s32)(ptr_reg->off - smin_val))) {
			/* pointer -= K.  Subtract it from fixed offset */
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->id = ptr_reg->id;
			dst_reg->off = ptr_reg->off - smin_val;
			dst_reg->raw = ptr_reg->raw;
			break;
		}
		/* A new variable offset is created.  If the subtrahend is known
		 * nonnegative, then any reg->range we had before is still good.
		 */
		if (signed_sub_overflows(smin_ptr, smax_val) ||
		    signed_sub_overflows(smax_ptr, smin_val)) {
			/* Overflow possible, we know nothing */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		} else {
			dst_reg->smin_value = smin_ptr - smax_val;
			dst_reg->smax_value = smax_ptr - smin_val;
		}
		if (umin_ptr < umax_val) {
			/* Overflow possible, we know nothing */
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			/* Cannot overflow (as long as bounds are consistent) */
			dst_reg->umin_value = umin_ptr - umax_val;
			dst_reg->umax_value = umax_ptr - umin_val;
		}
		dst_reg->var_off = (*klpe_tnum_sub)(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		dst_reg->raw = ptr_reg->raw;
		if (reg_is_pkt_pointer(ptr_reg)) {
			dst_reg->id = ++env->id_gen;
			/* something was added to pkt_ptr, set range to zero */
			if (smin_val < 0)
				dst_reg->raw = 0;
		}
		break;
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		/* bitwise ops on pointers are troublesome, prohibit. */
		klpr_verbose(env, "R%d bitwise operator %s on pointer prohibited\n",
			dst, (*klpe_bpf_alu_string)[opcode >> 4]);
		return -EACCES;
	default:
		/* other operators (e.g. MUL,LSH) produce non-pointer results */
		klpr_verbose(env, "R%d pointer arithmetic with %s operator prohibited\n",
			dst, (*klpe_bpf_alu_string)[opcode >> 4]);
		return -EACCES;
	}

	if (!(*klpe_check_reg_sane_offset)(env, dst_reg, ptr_reg->type))
		return -EINVAL;

	__update_reg_bounds(dst_reg);
	(*klpe___reg_deduce_bounds)(dst_reg);
	(*klpe___reg_bound_offset)(dst_reg);

	if (klpr_sanitize_check_bounds(env, insn, dst_reg) < 0)
		return -EACCES;
	if (sanitize_needed(opcode)) {
		ret = klpp_sanitize_ptr_alu(env, insn, dst_reg, off_reg, dst_reg,
				       /*
					* Fix CVE-2021-33200
					*  -1 line, +1 line
					*/
				       &info, true);
		if (ret < 0)
			return (*klpe_sanitize_err)(env, insn, ret, off_reg, dst_reg);
	}

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1186498.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "reg_type_str", (void *)&klpe_reg_type_str },
	{ "bpf_alu_string", (void *)&klpe_bpf_alu_string },
	{ "tnum_add", (void *)&klpe_tnum_add },
	{ "tnum_sub", (void *)&klpe_tnum_sub },
	{ "bpf_verifier_vlog", (void *)&klpe_bpf_verifier_vlog },
	{ "__reg_deduce_bounds", (void *)&klpe___reg_deduce_bounds },
	{ "__reg_bound_offset", (void *)&klpe___reg_bound_offset },
	{ "__mark_reg_unknown", (void *)&klpe___mark_reg_unknown },
	{ "check_stack_access", (void *)&klpe_check_stack_access },
	{ "check_map_access", (void *)&klpe_check_map_access },
	{ "push_stack", (void *)&klpe_push_stack },
	{ "check_reg_sane_offset", (void *)&klpe_check_reg_sane_offset },
	{ "sanitize_err", (void *)&klpe_sanitize_err },
};

int livepatch_bsc1186498_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
