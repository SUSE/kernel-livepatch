/*
 * livepatch_bsc1184710
 *
 * Fix for CVE-2021-29154, bsc#1184710
 *
 *  Upstream commit:
 *  e4d4d456436b ("bpf, x86: Validate computation of branch displacements for
 *                 x86-64")
 *
 *  SLE12-SP3 commit:
 *  d4aa4679f82944236b68f1969a970859ae12e3ea
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  1d1eb4dbab82da8873f60c7bd7133b1ff6969f15
 *
 *  SLE15-SP2 commit:
 *  f5833e594c79ecc1bc5546a572b1b4ad698111bb
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

#if IS_ENABLED(CONFIG_X86_64)

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1184710.h"
#include "../kallsyms_relocs.h"

/* klp-ccp: from arch/x86/net/bpf_jit_comp.c */
#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <asm/set_memory.h>
#include <asm/nospec-branch.h>
#include <linux/bpf.h>

static u8 *emit_code(u8 *ptr, u32 bytes, unsigned int len)
{
	if (len == 1)
		*ptr = bytes;
	else if (len == 2)
		*(u16 *)ptr = bytes;
	else {
		*(u32 *)ptr = bytes;
		barrier();
	}
	return ptr + len;
}

#define EMIT(bytes, len) \
	do { prog = emit_code(prog, bytes, len); cnt += len; } while (0)

#define EMIT1(b1)		EMIT(b1, 1)
#define EMIT2(b1, b2)		EMIT((b1) + ((b2) << 8), 2)
#define EMIT3(b1, b2, b3)	EMIT((b1) + ((b2) << 8) + ((b3) << 16), 3)
#define EMIT4(b1, b2, b3, b4)   EMIT((b1) + ((b2) << 8) + ((b3) << 16) + ((b4) << 24), 4)
#define EMIT1_off32(b1, off) \
	do {EMIT1(b1); EMIT(off, 4); } while (0)
#define EMIT2_off32(b1, b2, off) \
	do {EMIT2(b1, b2); EMIT(off, 4); } while (0)
#define EMIT3_off32(b1, b2, b3, off) \
	do {EMIT3(b1, b2, b3); EMIT(off, 4); } while (0)
#define EMIT4_off32(b1, b2, b3, b4, off) \
	do {EMIT4(b1, b2, b3, b4); EMIT(off, 4); } while (0)

static bool is_imm8(int value)
{
	return value <= 127 && value >= -128;
}

static bool is_simm32(s64 value)
{
	return value == (s64)(s32)value;
}

static bool is_uimm32(u64 value)
{
	return value == (u64)(u32)value;
}

#define KLPR_EMIT_mov(DST, SRC) \
	do {if (DST != SRC) \
		    EMIT3(add_2mod(0x48, DST, SRC), 0x89, klpr_add_2reg(0xC0, DST, SRC)); \
	} while (0)

static int bpf_size_to_x86_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 4; /* imm32 */
	else
		return 0;
}

#define X86_JB  0x72
#define X86_JAE 0x73
#define X86_JE  0x74
#define X86_JNE 0x75
#define X86_JBE 0x76
#define X86_JA  0x77
#define X86_JL  0x7C
#define X86_JGE 0x7D
#define X86_JLE 0x7E
#define X86_JG  0x7F

#define AUX_REG (MAX_BPF_JIT_REG + 1)

static const int (*klpe_reg2hex)[];

static bool is_ereg(u32 reg)
{
	return (1 << reg) & (BIT(BPF_REG_5) |
			     BIT(AUX_REG) |
			     BIT(BPF_REG_7) |
			     BIT(BPF_REG_8) |
			     BIT(BPF_REG_9) |
			     BIT(BPF_REG_AX));
}

static u8 add_1mod(u8 byte, u32 reg)
{
	if (is_ereg(reg))
		byte |= 1;
	return byte;
}

static u8 add_2mod(u8 byte, u32 r1, u32 r2)
{
	if (is_ereg(r1))
		byte |= 1;
	if (is_ereg(r2))
		byte |= 4;
	return byte;
}

static u8 klpr_add_1reg(u8 byte, u32 dst_reg)
{
	return byte + (*klpe_reg2hex)[dst_reg];
}

static u8 klpr_add_2reg(u8 byte, u32 dst_reg, u32 src_reg)
{
	return byte + (*klpe_reg2hex)[dst_reg] + ((*klpe_reg2hex)[src_reg] << 3);
}

struct jit_context {
	int cleanup_addr; /* epilogue code offset */
};

#define BPF_MAX_INSN_SIZE	128
#define BPF_INSN_SAFETY		64

#define PROLOGUE_SIZE		20

static void emit_prologue(u8 **pprog, u32 stack_depth, bool ebpf_from_cbpf)
{
	u8 *prog = *pprog;
	int cnt = 0;

	EMIT1(0x55);             /* push rbp */
	EMIT3(0x48, 0x89, 0xE5); /* mov rbp, rsp */
	/* sub rsp, rounded_stack_depth */
	EMIT3_off32(0x48, 0x81, 0xEC, round_up(stack_depth, 8));
	EMIT1(0x53);             /* push rbx */
	EMIT2(0x41, 0x55);       /* push r13 */
	EMIT2(0x41, 0x56);       /* push r14 */
	EMIT2(0x41, 0x57);       /* push r15 */
	if (!ebpf_from_cbpf) {
		/* zero init tail_call_cnt */
		EMIT2(0x6a, 0x00);
		BUILD_BUG_ON(cnt != PROLOGUE_SIZE);
	}
	*pprog = prog;
}

static void emit_bpf_tail_call(u8 **pprog)
{
	u8 *prog = *pprog;
	int label1, label2, label3;
	int cnt = 0;

	/* rdi - pointer to ctx
	 * rsi - pointer to bpf_array
	 * rdx - index in bpf_array
	 */

	/* if (index >= array->map.max_entries)
	 *   goto out;
	 */
	EMIT2(0x89, 0xD2);                        /* mov edx, edx */
	EMIT3(0x39, 0x56,                         /* cmp dword ptr [rsi + 16], edx */
	      offsetof(struct bpf_array, map.max_entries));
#define OFFSET1 (41 + RETPOLINE_RAX_BPF_JIT_SIZE) /* number of bytes to jump */
	EMIT2(X86_JBE, OFFSET1);                  /* jbe out */
	label1 = cnt;

	/* if (tail_call_cnt > MAX_TAIL_CALL_CNT)
	 *   goto out;
	 */
	EMIT2_off32(0x8B, 0x85, -36 - MAX_BPF_STACK); /* mov eax, dword ptr [rbp - 548] */
	EMIT3(0x83, 0xF8, MAX_TAIL_CALL_CNT);     /* cmp eax, MAX_TAIL_CALL_CNT */
#define OFFSET2 (30 + RETPOLINE_RAX_BPF_JIT_SIZE)
	EMIT2(X86_JA, OFFSET2);                   /* ja out */
	label2 = cnt;
	EMIT3(0x83, 0xC0, 0x01);                  /* add eax, 1 */
	EMIT2_off32(0x89, 0x85, -36 - MAX_BPF_STACK); /* mov dword ptr [rbp -548], eax */

	/* prog = array->ptrs[index]; */
	EMIT4_off32(0x48, 0x8B, 0x84, 0xD6,       /* mov rax, [rsi + rdx * 8 + offsetof(...)] */
		    offsetof(struct bpf_array, ptrs));

	/* if (prog == NULL)
	 *   goto out;
	 */
	EMIT3(0x48, 0x85, 0xC0);		  /* test rax,rax */
#define OFFSET3 (8 + RETPOLINE_RAX_BPF_JIT_SIZE)
	EMIT2(X86_JE, OFFSET3);                   /* je out */
	label3 = cnt;

	/* goto *(prog->bpf_func + prologue_size); */
	EMIT4(0x48, 0x8B, 0x40,                   /* mov rax, qword ptr [rax + 32] */
	      offsetof(struct bpf_prog, bpf_func));
	EMIT4(0x48, 0x83, 0xC0, PROLOGUE_SIZE);   /* add rax, prologue_size */

	/* now we're ready to jump into next BPF program
	 * rdi == ctx (1st arg)
	 * rax == prog->bpf_func + prologue_size
	 */
	RETPOLINE_RAX_BPF_JIT();

	/* out: */
	BUILD_BUG_ON(cnt - label1 != OFFSET1);
	BUILD_BUG_ON(cnt - label2 != OFFSET2);
	BUILD_BUG_ON(cnt - label3 != OFFSET3);
	*pprog = prog;
}

static void (*klpe_emit_mov_imm32)(u8 **pprog, bool sign_propagate,
			   u32 dst_reg, const u32 imm32);

static void klpr_emit_mov_imm64(u8 **pprog, u32 dst_reg,
			   const u32 imm32_hi, const u32 imm32_lo)
{
	u8 *prog = *pprog;
	int cnt = 0;

	if (is_uimm32(((u64)imm32_hi << 32) | (u32)imm32_lo)) {
		/* For emitting plain u32, where sign bit must not be
		 * propagated LLVM tends to load imm64 over mov32
		 * directly, so save couple of bytes by just doing
		 * 'mov %eax, imm32' instead.
		 */
		(*klpe_emit_mov_imm32)(&prog, false, dst_reg, imm32_lo);
	} else {
		/* movabsq %rax, imm64 */
		EMIT2(add_1mod(0x48, dst_reg), klpr_add_1reg(0xB8, dst_reg));
		EMIT(imm32_lo, 4);
		EMIT(imm32_hi, 4);
	}

	*pprog = prog;
}

int klpp_do_jit(struct bpf_prog *bpf_prog, int *addrs, u8 *image,
		  int oldproglen, struct jit_context *ctx)
{
	struct bpf_insn *insn = bpf_prog->insnsi;
	int insn_cnt = bpf_prog->len;
	bool seen_exit = false;
	u8 temp[BPF_MAX_INSN_SIZE + BPF_INSN_SAFETY];
	int i, cnt = 0;
	int proglen = 0;
	u8 *prog = temp;

	emit_prologue(&prog, bpf_prog->aux->stack_depth,
		      bpf_prog_was_classic(bpf_prog));

	for (i = 0; i < insn_cnt; i++, insn++) {
		const s32 imm32 = insn->imm;
		u32 dst_reg = insn->dst_reg;
		u32 src_reg = insn->src_reg;
		u8 b2 = 0, b3 = 0;
		s64 jmp_offset;
		u8 jmp_cond;
		int ilen;
		u8 *func;

		switch (insn->code) {
			/* ALU */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_ADD | BPF_X:
		case BPF_ALU64 | BPF_SUB | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b2 = 0x01; break;
			case BPF_SUB: b2 = 0x29; break;
			case BPF_AND: b2 = 0x21; break;
			case BPF_OR: b2 = 0x09; break;
			case BPF_XOR: b2 = 0x31; break;
			}
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_2mod(0x48, dst_reg, src_reg));
			else if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT1(add_2mod(0x40, dst_reg, src_reg));
			EMIT2(b2, klpr_add_2reg(0xC0, dst_reg, src_reg));
			break;

			/* mov dst, src */
		case BPF_ALU64 | BPF_MOV | BPF_X:
			KLPR_EMIT_mov(dst_reg, src_reg);
			break;

			/* mov32 dst, src */
		case BPF_ALU | BPF_MOV | BPF_X:
			if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT1(add_2mod(0x40, dst_reg, src_reg));
			EMIT2(0x89, klpr_add_2reg(0xC0, dst_reg, src_reg));
			break;

			/* neg dst */
		case BPF_ALU | BPF_NEG:
		case BPF_ALU64 | BPF_NEG:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));
			EMIT2(0xF7, klpr_add_1reg(0xD8, dst_reg));
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b3 = 0xC0; break;
			case BPF_SUB: b3 = 0xE8; break;
			case BPF_AND: b3 = 0xE0; break;
			case BPF_OR: b3 = 0xC8; break;
			case BPF_XOR: b3 = 0xF0; break;
			}

			if (is_imm8(imm32))
				EMIT3(0x83, klpr_add_1reg(b3, dst_reg), imm32);
			else
				EMIT2_off32(0x81, klpr_add_1reg(b3, dst_reg), imm32);
			break;

		case BPF_ALU64 | BPF_MOV | BPF_K:
		case BPF_ALU | BPF_MOV | BPF_K:
			(*klpe_emit_mov_imm32)(&prog, BPF_CLASS(insn->code) == BPF_ALU64,
				       dst_reg, imm32);
			break;

		case BPF_LD | BPF_IMM | BPF_DW:
			klpr_emit_mov_imm64(&prog, dst_reg, insn[1].imm, insn[0].imm);
			insn++;
			i++;
			break;

			/* dst %= src, dst /= src, dst %= imm32, dst /= imm32 */
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			EMIT1(0x50); /* push rax */
			EMIT1(0x52); /* push rdx */

			if (BPF_SRC(insn->code) == BPF_X)
				/* mov r11, src_reg */
				KLPR_EMIT_mov(AUX_REG, src_reg);
			else
				/* mov r11, imm32 */
				EMIT3_off32(0x49, 0xC7, 0xC3, imm32);

			/* mov rax, dst_reg */
			KLPR_EMIT_mov(BPF_REG_0, dst_reg);

			/* xor edx, edx
			 * equivalent to 'xor rdx, rdx', but one byte less
			 */
			EMIT2(0x31, 0xd2);

			if (BPF_SRC(insn->code) == BPF_X) {
				/* if (src_reg == 0) return 0 */

				/* cmp r11, 0 */
				EMIT4(0x49, 0x83, 0xFB, 0x00);

				/* jne .+9 (skip over pop, pop, xor and jmp) */
				EMIT2(X86_JNE, 1 + 1 + 2 + 5);
				EMIT1(0x5A); /* pop rdx */
				EMIT1(0x58); /* pop rax */
				EMIT2(0x31, 0xc0); /* xor eax, eax */

				/* jmp cleanup_addr
				 * addrs[i] - 11, because there are 11 bytes
				 * after this insn: div, mov, pop, pop, mov
				 */
				jmp_offset = ctx->cleanup_addr - (addrs[i] - 11);
				EMIT1_off32(0xE9, jmp_offset);
			}

			if (BPF_CLASS(insn->code) == BPF_ALU64)
				/* div r11 */
				EMIT3(0x49, 0xF7, 0xF3);
			else
				/* div r11d */
				EMIT3(0x41, 0xF7, 0xF3);

			if (BPF_OP(insn->code) == BPF_MOD)
				/* mov r11, rdx */
				EMIT3(0x49, 0x89, 0xD3);
			else
				/* mov r11, rax */
				EMIT3(0x49, 0x89, 0xC3);

			EMIT1(0x5A); /* pop rdx */
			EMIT1(0x58); /* pop rax */

			/* mov dst_reg, r11 */
			KLPR_EMIT_mov(dst_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_X:
			EMIT1(0x50); /* push rax */
			EMIT1(0x52); /* push rdx */

			/* mov r11, dst_reg */
			KLPR_EMIT_mov(AUX_REG, dst_reg);

			if (BPF_SRC(insn->code) == BPF_X)
				/* mov rax, src_reg */
				KLPR_EMIT_mov(BPF_REG_0, src_reg);
			else
				/* mov rax, imm32 */
				(*klpe_emit_mov_imm32)(&prog, true,
					       BPF_REG_0, imm32);

			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, AUX_REG));
			else if (is_ereg(AUX_REG))
				EMIT1(add_1mod(0x40, AUX_REG));
			/* mul(q) r11 */
			EMIT2(0xF7, klpr_add_1reg(0xE0, AUX_REG));

			/* mov r11, rax */
			KLPR_EMIT_mov(AUX_REG, BPF_REG_0);

			EMIT1(0x5A); /* pop rdx */
			EMIT1(0x58); /* pop rax */

			/* mov dst_reg, r11 */
			KLPR_EMIT_mov(dst_reg, AUX_REG);
			break;

			/* shifts */
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_LSH: b3 = 0xE0; break;
			case BPF_RSH: b3 = 0xE8; break;
			case BPF_ARSH: b3 = 0xF8; break;
			}
			EMIT3(0xC1, klpr_add_1reg(b3, dst_reg), imm32);
			break;

		case BPF_ALU | BPF_LSH | BPF_X:
		case BPF_ALU | BPF_RSH | BPF_X:
		case BPF_ALU | BPF_ARSH | BPF_X:
		case BPF_ALU64 | BPF_LSH | BPF_X:
		case BPF_ALU64 | BPF_RSH | BPF_X:
		case BPF_ALU64 | BPF_ARSH | BPF_X:

			/* check for bad case when dst_reg == rcx */
			if (dst_reg == BPF_REG_4) {
				/* mov r11, dst_reg */
				KLPR_EMIT_mov(AUX_REG, dst_reg);
				dst_reg = AUX_REG;
			}

			if (src_reg != BPF_REG_4) { /* common case */
				EMIT1(0x51); /* push rcx */

				/* mov rcx, src_reg */
				KLPR_EMIT_mov(BPF_REG_4, src_reg);
			}

			/* shl %rax, %cl | shr %rax, %cl | sar %rax, %cl */
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, dst_reg));
			else if (is_ereg(dst_reg))
				EMIT1(add_1mod(0x40, dst_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_LSH: b3 = 0xE0; break;
			case BPF_RSH: b3 = 0xE8; break;
			case BPF_ARSH: b3 = 0xF8; break;
			}
			EMIT2(0xD3, klpr_add_1reg(b3, dst_reg));

			if (src_reg != BPF_REG_4)
				EMIT1(0x59); /* pop rcx */

			if (insn->dst_reg == BPF_REG_4)
				/* mov dst_reg, r11 */
				KLPR_EMIT_mov(insn->dst_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_END | BPF_FROM_BE:
			switch (imm32) {
			case 16:
				/* emit 'ror %ax, 8' to swap lower 2 bytes */
				EMIT1(0x66);
				if (is_ereg(dst_reg))
					EMIT1(0x41);
				EMIT3(0xC1, klpr_add_1reg(0xC8, dst_reg), 8);

				/* emit 'movzwl eax, ax' */
				if (is_ereg(dst_reg))
					EMIT3(0x45, 0x0F, 0xB7);
				else
					EMIT2(0x0F, 0xB7);
				EMIT1(klpr_add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 32:
				/* emit 'bswap eax' to swap lower 4 bytes */
				if (is_ereg(dst_reg))
					EMIT2(0x41, 0x0F);
				else
					EMIT1(0x0F);
				EMIT1(klpr_add_1reg(0xC8, dst_reg));
				break;
			case 64:
				/* emit 'bswap rax' to swap 8 bytes */
				EMIT3(add_1mod(0x48, dst_reg), 0x0F,
				      klpr_add_1reg(0xC8, dst_reg));
				break;
			}
			break;

		case BPF_ALU | BPF_END | BPF_FROM_LE:
			switch (imm32) {
			case 16:
				/* emit 'movzwl eax, ax' to zero extend 16-bit
				 * into 64 bit
				 */
				if (is_ereg(dst_reg))
					EMIT3(0x45, 0x0F, 0xB7);
				else
					EMIT2(0x0F, 0xB7);
				EMIT1(klpr_add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 32:
				/* emit 'mov eax, eax' to clear upper 32-bits */
				if (is_ereg(dst_reg))
					EMIT1(0x45);
				EMIT2(0x89, klpr_add_2reg(0xC0, dst_reg, dst_reg));
				break;
			case 64:
				/* nop */
				break;
			}
			break;

			/* ST: *(u8*)(dst_reg + off) = imm */
		case BPF_ST | BPF_MEM | BPF_B:
			if (is_ereg(dst_reg))
				EMIT2(0x41, 0xC6);
			else
				EMIT1(0xC6);
			goto st;
		case BPF_ST | BPF_MEM | BPF_H:
			if (is_ereg(dst_reg))
				EMIT3(0x66, 0x41, 0xC7);
			else
				EMIT2(0x66, 0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_W:
			if (is_ereg(dst_reg))
				EMIT2(0x41, 0xC7);
			else
				EMIT1(0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_DW:
			EMIT2(add_1mod(0x48, dst_reg), 0xC7);

st:			if (is_imm8(insn->off))
				EMIT2(klpr_add_1reg(0x40, dst_reg), insn->off);
			else
				EMIT1_off32(klpr_add_1reg(0x80, dst_reg), insn->off);

			EMIT(imm32, bpf_size_to_x86_bytes(BPF_SIZE(insn->code)));
			break;

			/* STX: *(u8*)(dst_reg + off) = src_reg */
		case BPF_STX | BPF_MEM | BPF_B:
			/* emit 'mov byte ptr [rax + off], al' */
			if (is_ereg(dst_reg) || is_ereg(src_reg) ||
			    /* have to add extra byte for x86 SIL, DIL regs */
			    src_reg == BPF_REG_1 || src_reg == BPF_REG_2)
				EMIT2(add_2mod(0x40, dst_reg, src_reg), 0x88);
			else
				EMIT1(0x88);
			goto stx;
		case BPF_STX | BPF_MEM | BPF_H:
			if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT3(0x66, add_2mod(0x40, dst_reg, src_reg), 0x89);
			else
				EMIT2(0x66, 0x89);
			goto stx;
		case BPF_STX | BPF_MEM | BPF_W:
			if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT2(add_2mod(0x40, dst_reg, src_reg), 0x89);
			else
				EMIT1(0x89);
			goto stx;
		case BPF_STX | BPF_MEM | BPF_DW:
			EMIT2(add_2mod(0x48, dst_reg, src_reg), 0x89);
stx:			if (is_imm8(insn->off))
				EMIT2(klpr_add_2reg(0x40, dst_reg, src_reg), insn->off);
			else
				EMIT1_off32(klpr_add_2reg(0x80, dst_reg, src_reg),
					    insn->off);
			break;

			/* LDX: dst_reg = *(u8*)(src_reg + off) */
		case BPF_LDX | BPF_MEM | BPF_B:
			/* emit 'movzx rax, byte ptr [rax + off]' */
			EMIT3(add_2mod(0x48, src_reg, dst_reg), 0x0F, 0xB6);
			goto ldx;
		case BPF_LDX | BPF_MEM | BPF_H:
			/* emit 'movzx rax, word ptr [rax + off]' */
			EMIT3(add_2mod(0x48, src_reg, dst_reg), 0x0F, 0xB7);
			goto ldx;
		case BPF_LDX | BPF_MEM | BPF_W:
			/* emit 'mov eax, dword ptr [rax+0x14]' */
			if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT2(add_2mod(0x40, src_reg, dst_reg), 0x8B);
			else
				EMIT1(0x8B);
			goto ldx;
		case BPF_LDX | BPF_MEM | BPF_DW:
			/* emit 'mov rax, qword ptr [rax+0x14]' */
			EMIT2(add_2mod(0x48, src_reg, dst_reg), 0x8B);
ldx:			/* if insn->off == 0 we can save one extra byte, but
			 * special case of x86 r13 which always needs an offset
			 * is not worth the hassle
			 */
			if (is_imm8(insn->off))
				EMIT2(klpr_add_2reg(0x40, src_reg, dst_reg), insn->off);
			else
				EMIT1_off32(klpr_add_2reg(0x80, src_reg, dst_reg),
					    insn->off);
			break;

			/* STX XADD: lock *(u32*)(dst_reg + off) += src_reg */
		case BPF_STX | BPF_XADD | BPF_W:
			/* emit 'lock add dword ptr [rax + off], eax' */
			if (is_ereg(dst_reg) || is_ereg(src_reg))
				EMIT3(0xF0, add_2mod(0x40, dst_reg, src_reg), 0x01);
			else
				EMIT2(0xF0, 0x01);
			goto xadd;
		case BPF_STX | BPF_XADD | BPF_DW:
			EMIT3(0xF0, add_2mod(0x48, dst_reg, src_reg), 0x01);
xadd:			if (is_imm8(insn->off))
				EMIT2(klpr_add_2reg(0x40, dst_reg, src_reg), insn->off);
			else
				EMIT1_off32(klpr_add_2reg(0x80, dst_reg, src_reg),
					    insn->off);
			break;

			/* call */
		case BPF_JMP | BPF_CALL:
			func = (u8 *) __bpf_call_base + imm32;
			jmp_offset = func - (image + addrs[i]);
			if (!imm32 || !is_simm32(jmp_offset)) {
				pr_err("unsupported bpf func %d addr %p image %p\n",
				       imm32, func, image);
				return -EINVAL;
			}
			EMIT1_off32(0xE8, jmp_offset);
			break;

		case BPF_JMP | BPF_TAIL_CALL:
			emit_bpf_tail_call(&prog);
			break;

			/* cond jump */
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JNE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JLT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JLE | BPF_X:
		case BPF_JMP | BPF_JSGT | BPF_X:
		case BPF_JMP | BPF_JSLT | BPF_X:
		case BPF_JMP | BPF_JSGE | BPF_X:
		case BPF_JMP | BPF_JSLE | BPF_X:
			/* cmp dst_reg, src_reg */
			EMIT3(add_2mod(0x48, dst_reg, src_reg), 0x39,
			      klpr_add_2reg(0xC0, dst_reg, src_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_X:
			/* test dst_reg, src_reg */
			EMIT3(add_2mod(0x48, dst_reg, src_reg), 0x85,
			      klpr_add_2reg(0xC0, dst_reg, src_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_K:
			/* test dst_reg, imm32 */
			EMIT1(add_1mod(0x48, dst_reg));
			EMIT2_off32(0xF7, klpr_add_1reg(0xC0, dst_reg), imm32);
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JNE | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JLT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JLE | BPF_K:
		case BPF_JMP | BPF_JSGT | BPF_K:
		case BPF_JMP | BPF_JSLT | BPF_K:
		case BPF_JMP | BPF_JSGE | BPF_K:
		case BPF_JMP | BPF_JSLE | BPF_K:
			/* cmp dst_reg, imm8/32 */
			EMIT1(add_1mod(0x48, dst_reg));

			if (is_imm8(imm32))
				EMIT3(0x83, klpr_add_1reg(0xF8, dst_reg), imm32);
			else
				EMIT2_off32(0x81, klpr_add_1reg(0xF8, dst_reg), imm32);

emit_cond_jmp:		/* convert BPF opcode to x86 */
			switch (BPF_OP(insn->code)) {
			case BPF_JEQ:
				jmp_cond = X86_JE;
				break;
			case BPF_JSET:
			case BPF_JNE:
				jmp_cond = X86_JNE;
				break;
			case BPF_JGT:
				/* GT is unsigned '>', JA in x86 */
				jmp_cond = X86_JA;
				break;
			case BPF_JLT:
				/* LT is unsigned '<', JB in x86 */
				jmp_cond = X86_JB;
				break;
			case BPF_JGE:
				/* GE is unsigned '>=', JAE in x86 */
				jmp_cond = X86_JAE;
				break;
			case BPF_JLE:
				/* LE is unsigned '<=', JBE in x86 */
				jmp_cond = X86_JBE;
				break;
			case BPF_JSGT:
				/* signed '>', GT in x86 */
				jmp_cond = X86_JG;
				break;
			case BPF_JSLT:
				/* signed '<', LT in x86 */
				jmp_cond = X86_JL;
				break;
			case BPF_JSGE:
				/* signed '>=', GE in x86 */
				jmp_cond = X86_JGE;
				break;
			case BPF_JSLE:
				/* signed '<=', LE in x86 */
				jmp_cond = X86_JLE;
				break;
			default: /* to silence gcc warning */
				return -EFAULT;
			}
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (is_imm8(jmp_offset)) {
				EMIT2(jmp_cond, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT2_off32(0x0F, jmp_cond + 0x10, jmp_offset);
			} else {
				pr_err("cond_jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}

			break;

		case BPF_JMP | BPF_JA:
			if (insn->off == -1)
				/* -1 jmp instructions will always jump
				 * backwards two bytes. Explicitly handling
				 * this case avoids wasting too many passes
				 * when there are long sequences of replaced
				 * dead code.
				 */
				jmp_offset = -2;
			else
				jmp_offset = addrs[i + insn->off] - addrs[i];

			if (!jmp_offset)
				/* optimize out nop jumps */
				break;
emit_jmp:
			if (is_imm8(jmp_offset)) {
				EMIT2(0xEB, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT1_off32(0xE9, jmp_offset);
			} else {
				pr_err("jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}
			break;

		case BPF_JMP | BPF_EXIT:
			if (seen_exit) {
				jmp_offset = ctx->cleanup_addr - addrs[i];
				goto emit_jmp;
			}
			seen_exit = true;
			/* update cleanup_addr */
			ctx->cleanup_addr = proglen;
			if (!bpf_prog_was_classic(bpf_prog))
				EMIT1(0x5B); /* get rid of tail_call_cnt */
			EMIT2(0x41, 0x5F);   /* pop r15 */
			EMIT2(0x41, 0x5E);   /* pop r14 */
			EMIT2(0x41, 0x5D);   /* pop r13 */
			EMIT1(0x5B);         /* pop rbx */
			EMIT1(0xC9);         /* leave */
			EMIT1(0xC3);         /* ret */
			break;

		default:
			/* By design x64 JIT should support all BPF instructions
			 * This error will be seen if new instruction was added
			 * to interpreter, but not to JIT
			 * or if there is junk in bpf_prog
			 */
			pr_err("bpf_jit: unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}

		ilen = prog - temp;
		if (ilen > BPF_MAX_INSN_SIZE) {
			pr_err("bpf_jit: fatal insn size error\n");
			return -EFAULT;
		}

		if (image) {
			/*
			 * Fix CVE-2021-29154
			 *  -1 line, +10 lines
			 */
			/*
			 * When populating the image, assert that:
			 *
			 *  i) We do not write beyond the allocated space, and
			 * ii) addrs[i] did not change from the prior run, in order
			 *     to validate assumptions made for computing branch
			 *     displacements.
			 */
			if (unlikely(proglen + ilen > oldproglen ||
				     proglen + ilen != addrs[i])) {
				pr_err("bpf_jit: fatal error\n");
				return -EFAULT;
			}
			memcpy(image + proglen, temp, ilen);
		}
		proglen += ilen;
		addrs[i] = proglen;
		prog = temp;
	}
	return proglen;
}



static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "reg2hex", (void *)&klpe_reg2hex },
	{ "emit_mov_imm32", (void *)&klpe_emit_mov_imm32 },
};

int livepatch_bsc1184710_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_X86_64) */
