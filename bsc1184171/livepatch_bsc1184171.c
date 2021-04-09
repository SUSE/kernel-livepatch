/*
 * livepatch_bsc1184171
 *
 * Fix for CVE-2021-3444, bsc#1184171
 *
 *  Upstream commits:
 *  f6b1b3bf0d5f ("bpf: fix subprog verifier bypass by div/mod by 0 exception")
 *  e88b2c6e5a4d ("bpf: Fix 32 bit src register truncation on div/mod")
 *  9b00f1b78809 ("bpf: Fix truncation handling for mod32 dst reg wrt zero")
 *
 *  SLE12-SP3 commits:
 *  not affected
 *
 *  SLE12-SP4 and SLE15 commits:
 *  4d5a2c3a76269d8dbdef3c808ccedf74d8a2290a
 *  be700f6ec993cc16765c6c91e951f3863c0676bc
 *  0962666853d66ee46670e10869856459bd54b674
 *  c609295233b309d2dfdb22bfa34fa29023637634
 *  e62aa97929ee1f9529f0e2c9410f6b84335a5fdb
 *
 *  SLE12-SP5 and SLE15-SP1 commits:
 *  28a8195c1e9d1e4c06d98d748b834c2f1d9dd84d
 *  be700f6ec993cc16765c6c91e951f3863c0676bc
 *  0962666853d66ee46670e10869856459bd54b674
 *  c609295233b309d2dfdb22bfa34fa29023637634
 *  e62aa97929ee1f9529f0e2c9410f6b84335a5fdb
 *
 *  SLE15-SP2 commits:
 *  1c93d3e99ed731c3211114014f7d82161cde66a3
 *  af158b0f69bdceb6e9a919be09435707256e2bd9
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

/* klp-ccp: from include/linux/bpf.h */
static void (*klpe_bpf_user_rnd_init_once)(void);

/* klp-ccp: from kernel/bpf/verifier.c */
#include <linux/bpf_verifier.h>

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

static const char *(*klpe_func_id_name)(int id);

/* klp-ccp: from kernel/bpf/verifier.c */
#define BPF_MAP_PTR_UNPRIV	1UL
#define BPF_MAP_PTR_POISON	((void *)((0xeB9FUL << 1) +	\
					  POISON_POINTER_DELTA))
#define BPF_MAP_PTR(X)		((struct bpf_map *)((X) & ~BPF_MAP_PTR_UNPRIV))

static bool bpf_map_ptr_poisoned(const struct bpf_insn_aux_data *aux)
{
	return BPF_MAP_PTR(aux->map_state) == BPF_MAP_PTR_POISON;
}

static bool bpf_map_ptr_unpriv(const struct bpf_insn_aux_data *aux)
{
	return aux->map_state & BPF_MAP_PTR_UNPRIV;
}

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

static struct bpf_prog *(*klpe_bpf_patch_insn_data)(struct bpf_verifier_env *env, u32 off,
					    const struct bpf_insn *patch, u32 len);

int klpp_fixup_bpf_calls(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = prog->insnsi;
	const struct bpf_func_proto *fn;
	const int insn_cnt = prog->len;
	const struct bpf_map_ops *ops;
	struct bpf_insn_aux_data *aux;
	struct bpf_insn insn_buf[16];
	struct bpf_prog *new_prog;
	struct bpf_map *map_ptr;
	int i, cnt, delta = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (insn->code == (BPF_ALU64 | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			struct bpf_insn *patchlet;
			struct bpf_insn chk_and_div[] = {
				/* [R,W]x div 0 -> 0 */
				BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
					     BPF_MOV | BPF_X,
					     BPF_REG_AX, insn->src_reg,
					     0, 0),
				BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 2),
				BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg),
				BPF_JMP_IMM(BPF_JA, 0, 0, 1),
				*insn,
			};
			struct bpf_insn chk_and_mod[] = {
				/* [R,W]x mod 0 -> [R,W]x */
				BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
					     BPF_MOV | BPF_X,
					     BPF_REG_AX, insn->src_reg,
					     0, 0),
				/*
				 * Fix CVE-2021-3444
				 *  -1 line, +1 line
				 */
				BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0,
					    1 + (is64 ? 0 : 1)),
				*insn,
				BPF_JMP_IMM(BPF_JA, 0, 0, 1),
				BPF_MOV32_REG(insn->dst_reg, insn->dst_reg),
			};
			patchlet = isdiv ? chk_and_div : chk_and_mod;
			cnt = isdiv ? ARRAY_SIZE(chk_and_div) :
				      ARRAY_SIZE(chk_and_mod) - (is64 ? 2 : 0);

			new_prog = (*klpe_bpf_patch_insn_data)(env, i + delta, patchlet, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		if (BPF_CLASS(insn->code) == BPF_LD &&
		    (BPF_MODE(insn->code) == BPF_ABS ||
		     BPF_MODE(insn->code) == BPF_IND)) {
			cnt = env->ops->gen_ld_abs(insn, insn_buf);
			if (cnt == 0 || cnt >= ARRAY_SIZE(insn_buf)) {
				klpr_verbose(env, "bpf verifier is misconfigured\n");
				return -EINVAL;
			}

			new_prog = (*klpe_bpf_patch_insn_data)(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		if (insn->code == (BPF_ALU64 | BPF_ADD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_SUB | BPF_X)) {
			const u8 code_add = BPF_ALU64 | BPF_ADD | BPF_X;
			const u8 code_sub = BPF_ALU64 | BPF_SUB | BPF_X;
			struct bpf_insn insn_buf[16];
			struct bpf_insn *patch = &insn_buf[0];
			bool issrc, isneg;
			u32 off_reg;

			aux = &env->insn_aux_data[i + delta];
			if (!aux->alu_state ||
			    aux->alu_state == BPF_ALU_NON_POINTER)
				continue;

			isneg = aux->alu_state & BPF_ALU_NEG_VALUE;
			issrc = (aux->alu_state & BPF_ALU_SANITIZE) ==
				BPF_ALU_SANITIZE_SRC;

			off_reg = issrc ? insn->src_reg : insn->dst_reg;
			if (isneg)
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
			*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
			*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);
			*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);
			*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);
			*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);
			if (issrc) {
				*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX,
							 off_reg);
				insn->src_reg = BPF_REG_AX;
			} else {
				*patch++ = BPF_ALU64_REG(BPF_AND, off_reg,
							 BPF_REG_AX);
			}
			if (isneg)
				insn->code = insn->code == code_add ?
					     code_sub : code_add;
			*patch++ = *insn;
			if (issrc && isneg)
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
			cnt = patch - insn_buf;

			new_prog = (*klpe_bpf_patch_insn_data)(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		if (insn->code != (BPF_JMP | BPF_CALL))
			continue;
		if (insn->src_reg == BPF_PSEUDO_CALL)
			continue;

		if (insn->imm == BPF_FUNC_get_route_realm)
			prog->dst_needed = 1;
		if (insn->imm == BPF_FUNC_get_prandom_u32)
			(*klpe_bpf_user_rnd_init_once)();
		if (insn->imm == BPF_FUNC_tail_call) {
			/* If we tail call into other programs, we
			 * cannot make any assumptions since they can
			 * be replaced dynamically during runtime in
			 * the program array.
			 */
			prog->cb_access = 1;
			env->prog->aux->stack_depth = MAX_BPF_STACK;

			/* mark bpf_tail_call as different opcode to avoid
			 * conditional branch in the interpeter for every normal
			 * call and to prevent accidental JITing by JIT compiler
			 * that doesn't support bpf_tail_call yet
			 */
			insn->imm = 0;
			insn->code = BPF_JMP | BPF_TAIL_CALL;

			aux = &env->insn_aux_data[i + delta];
			if (!bpf_map_ptr_unpriv(aux))
				continue;

			/* instead of changing every JIT dealing with tail_call
			 * emit two extra insns:
			 * if (index >= max_entries) goto out;
			 * index &= array->index_mask;
			 * to avoid out-of-bounds cpu speculation
			 */
			if (bpf_map_ptr_poisoned(aux)) {
				klpr_verbose(env, "tail_call abusing map_ptr\n");
				return -EINVAL;
			}

			map_ptr = BPF_MAP_PTR(aux->map_state);
			insn_buf[0] = BPF_JMP_IMM(BPF_JGE, BPF_REG_3,
						  map_ptr->max_entries, 2);
			insn_buf[1] = BPF_ALU32_IMM(BPF_AND, BPF_REG_3,
						    container_of(map_ptr,
								 struct bpf_array,
								 map)->index_mask);
			insn_buf[2] = *insn;
			cnt = 3;
			new_prog = (*klpe_bpf_patch_insn_data)(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		/* BPF_EMIT_CALL() assumptions in some of the map_gen_lookup
		 * and other inlining handlers are currently limited to 64 bit
		 * only.
		 */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    (insn->imm == BPF_FUNC_map_lookup_elem ||
		     insn->imm == BPF_FUNC_map_update_elem ||
		     insn->imm == BPF_FUNC_map_delete_elem)) {
			aux = &env->insn_aux_data[i + delta];
			if (bpf_map_ptr_poisoned(aux))
				goto patch_call_imm;

			map_ptr = BPF_MAP_PTR(aux->map_state);
			ops = map_ptr->ops;
			if (insn->imm == BPF_FUNC_map_lookup_elem &&
			    ops->map_gen_lookup) {
				cnt = ops->map_gen_lookup(map_ptr, insn_buf);
				if (cnt == 0 || cnt >= ARRAY_SIZE(insn_buf)) {
					klpr_verbose(env, "bpf verifier is misconfigured\n");
					return -EINVAL;
				}

				new_prog = (*klpe_bpf_patch_insn_data)(env, i + delta,
							       insn_buf, cnt);
				if (!new_prog)
					return -ENOMEM;

				delta    += cnt - 1;
				env->prog = prog = new_prog;
				insn      = new_prog->insnsi + i + delta;
				continue;
			}

			BUILD_BUG_ON(!__same_type(ops->map_lookup_elem,
				     (void *(*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_delete_elem,
				     (int (*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_update_elem,
				     (int (*)(struct bpf_map *map, void *key, void *value,
					      u64 flags))NULL));
			switch (insn->imm) {
			case BPF_FUNC_map_lookup_elem:
				insn->imm = BPF_CAST_CALL(ops->map_lookup_elem) -
					    __bpf_call_base;
				continue;
			case BPF_FUNC_map_update_elem:
				insn->imm = BPF_CAST_CALL(ops->map_update_elem) -
					    __bpf_call_base;
				continue;
			case BPF_FUNC_map_delete_elem:
				insn->imm = BPF_CAST_CALL(ops->map_delete_elem) -
					    __bpf_call_base;
				continue;
			}

			goto patch_call_imm;
		}

patch_call_imm:
		fn = env->ops->get_func_proto(insn->imm, env->prog);
		/* all functions that have prototype and verifier allowed
		 * programs to call them, must be real in-kernel functions
		 */
		if (!fn->func) {
			klpr_verbose(env,
				"kernel subsystem misconfigured func %s#%d\n",
				(*klpe_func_id_name)(insn->imm), insn->imm);
			return -EFAULT;
		}
		insn->imm = fn->func - __bpf_call_base;
	}

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184171.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bpf_user_rnd_init_once", (void *)&klpe_bpf_user_rnd_init_once },
	{ "bpf_verifier_vlog", (void *)&klpe_bpf_verifier_vlog },
	{ "func_id_name", (void *)&klpe_func_id_name },
	{ "bpf_patch_insn_data", (void *)&klpe_bpf_patch_insn_data },
};

int livepatch_bsc1184171_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
