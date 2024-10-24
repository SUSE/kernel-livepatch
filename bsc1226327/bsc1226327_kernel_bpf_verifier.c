/*
 * bsc1226327_kernel_bpf_verifier
 *
 * Fix for CVE-2024-35905, bsc#1226327
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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
#include <uapi/linux/btf.h>
#include <linux/bpf-cgroup.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <net/netlink.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/stringify.h>
#include <linux/bsearch.h>

#include <linux/ctype.h>
#include <linux/error-injection.h>

#include <linux/btf_ids.h>
#include <linux/poison.h>
#include <linux/module.h>
#include <linux/cpumask.h>

/* klp-ccp: from kernel/bpf/disasm.h */
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/stringify.h>

/* klp-ccp: from kernel/bpf/verifier.c */
__printf(2, 3) static void verbose(void *private_data, const char *fmt, ...)
{
	struct bpf_verifier_env *env = private_data;
	va_list args;

	if (!bpf_verifier_log_needed(&env->log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
}

static struct bpf_func_state *func(struct bpf_verifier_env *env,
				   const struct bpf_reg_state *reg)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[reg->frameno];
}

extern void *realloc_array(void *arr, size_t old_n, size_t new_n, size_t size);

static int grow_stack_state(struct bpf_verifier_env *env, struct bpf_func_state *state, int size)
{
	size_t old_n = state->allocated_stack / BPF_REG_SIZE, n;

	/* The stack size is always a multiple of BPF_REG_SIZE. */
	size = round_up(size, BPF_REG_SIZE);
	n = size / BPF_REG_SIZE;

	if (old_n >= n)
		return 0;

	state->stack = realloc_array(state->stack, old_n, n, sizeof(struct bpf_stack_state));
	if (!state->stack)
		return -ENOMEM;

	state->allocated_stack = size;

	/* update known max for given subprogram */
	if (env->subprog_info[state->subprogno].stack_depth < size)
		env->subprog_info[state->subprogno].stack_depth = size;

	return 0;
}

enum bpf_access_src {
	ACCESS_DIRECT = 1,  /* the access is performed by an instruction */
	ACCESS_HELPER = 2,  /* the access is performed by a helper */
};

static int check_stack_slot_within_bounds(struct bpf_verifier_env *env,
                                          s64 off,
                                          struct bpf_func_state *state,
                                          enum bpf_access_type t)
{
	int min_valid_off;

	if (t == BPF_WRITE || env->allow_uninit_stack)
		min_valid_off = -MAX_BPF_STACK;
	else
		min_valid_off = -state->allocated_stack;

	if (off < min_valid_off || off > -1)
		return -EACCES;
	return 0;
}

int klpp_check_stack_access_within_bounds(
		struct bpf_verifier_env *env,
		int regno, int off, int access_size,
		enum bpf_access_src src, enum bpf_access_type type)
{
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = regs + regno;
	struct bpf_func_state *state = func(env, reg);
	s64 min_off, max_off;
	int err;
	char *err_extra;

	if (src == ACCESS_HELPER)
		/* We don't know if helpers are reading or writing (or both). */
		err_extra = " indirect access to";
	else if (type == BPF_READ)
		err_extra = " read from";
	else
		err_extra = " write to";

	if (tnum_is_const(reg->var_off)) {
		min_off = (s64)reg->var_off.value + off;
		max_off = min_off + access_size;
	} else {
		if (reg->smax_value >= BPF_MAX_VAR_OFF ||
		    reg->smin_value <= -BPF_MAX_VAR_OFF) {
			verbose(env, "invalid unbounded variable-offset%s stack R%d\n",
				err_extra, regno);
			return -EACCES;
		}
		min_off = reg->smin_value + off;
		max_off = reg->smax_value + off + access_size;
	}

	err = check_stack_slot_within_bounds(env, min_off, state, type);
	if (!err && max_off > 0)
		err = -EINVAL; /* out of stack access into non-negative offsets */
	if (!err && access_size < 0)
		/* access_size should not be negative (or overflow an int); others checks
		 * along the way should have prevented such an access.
		 */
		err = -EFAULT; /* invalid negative access size; integer overflow? */

	if (err) {
		if (tnum_is_const(reg->var_off)) {
			verbose(env, "invalid%s stack R%d off=%d size=%d\n",
				err_extra, regno, off, access_size);
		} else {
			char tn_buf[48];

			tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
			verbose(env, "invalid variable-offset%s stack R%d var_off=%s off=%d size=%d\n",
				err_extra, regno, tn_buf, off, access_size);
		}
		return err;
	}

	/* Note that there is no stack access with offset zero, so the needed stack
	 * size is -min_off, not -min_off+1.
	 */
	return grow_stack_state(env, state, -min_off /* size */);
}

#include <linux/livepatch.h>

extern typeof(bpf_verifier_vlog) bpf_verifier_vlog
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_verifier_vlog);
extern typeof(realloc_array) realloc_array
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, realloc_array);
