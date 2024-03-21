/*
 * livepatch_bsc1216898
 *
 * Fix for CVE-2023-46813, bsc#1216898
 *
 *  Upstream commit:
 *  b9cb9c45583b ("x86/sev: Check IOBM for IOIO exceptions from user-space")
 *  a37cd2a59d0c ("x86/sev: Disable MMIO emulation from user mode")
 *  63e44bc52047 ("x86/sev: Check for user-space IOIO pointing to kernel space")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  5dae47e1d4effa3159c6abf39ca949cb962ea833
 *  2b690360b8e083196da7f241bc9f09538114c11d
 *  816f81787de65d0076db71090593216c6545e652
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT)

/* klp-ccp: from arch/x86/lib/insn-eval.c */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ratelimit.h>
#include <linux/mmu_context.h>
#include <asm/desc_defs.h>
#include <asm/desc.h>
#include <asm/insn.h>

static bool (*klpe_fault_in_kernel_space)(unsigned long address);

static bool (*klpe_insn_decode_from_regs)(struct insn *insn, struct pt_regs *regs,
				       	  unsigned char buf[MAX_INSN_SIZE], int buf_size);

static int (*klpe_insn_get_effective_ip)(struct pt_regs *regs, unsigned long *ip);

static unsigned long (*klpe_insn_get_seg_base)(struct pt_regs *regs, int seg_reg_idx);

static bool (*klpe_insn_has_rep_prefix)(struct insn *insn);

#include <asm/io_bitmap.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/sev.h>
#include <asm/svm.h>

/* klp-ccp: from arch/x86/lib/insn-eval.c */
#include <asm/ldt.h>

static enum es_result vc_ioio_check(struct pt_regs *regs, u16 port, size_t size)
{
	/*
	 * In the original fix there was a BUG_ON on the statement below. But to
	 * be safe just return ES_EXCEPTION.
	 */
	if (size > 4)
		goto fault;

	if (user_mode(regs)) {
		struct thread_struct *t = &current->thread;
		struct io_bitmap *iobm = t->io_bitmap;
		size_t idx;

		if (!iobm)
			goto fault;

		for (idx = port; idx < port + size; ++idx) {
			if (test_bit(idx, iobm->bitmap))
				goto fault;
		}
	}

	return ES_OK;

fault:
	return ES_EXCEPTION;
}

#define IOIO_TYPE_STR  BIT(2)
#define IOIO_TYPE_IN   1
#define IOIO_TYPE_INS  (IOIO_TYPE_IN | IOIO_TYPE_STR)
#define IOIO_TYPE_OUT  0
#define IOIO_TYPE_OUTS (IOIO_TYPE_OUT | IOIO_TYPE_STR)

#define IOIO_REP       BIT(3)

#define IOIO_ADDR_64   BIT(9)
#define IOIO_ADDR_32   BIT(8)
#define IOIO_ADDR_16   BIT(7)

#define IOIO_DATA_32   BIT(6)
#define IOIO_DATA_16   BIT(5)
#define IOIO_DATA_8    BIT(4)

#define IOIO_SEG_ES    (0 << 10)
#define IOIO_SEG_DS    (3 << 10)

static enum es_result vc_ioio_exitinfo(struct es_em_ctxt *ctxt, u64 *exitinfo)
{
	struct insn *insn = &ctxt->insn;
	size_t size;
	u64 port;

	*exitinfo = 0;

	switch (insn->opcode.bytes[0]) {
	/* INS opcodes */
	case 0x6c:
	case 0x6d:
		*exitinfo |= IOIO_TYPE_INS;
		*exitinfo |= IOIO_SEG_ES;
		port = ctxt->regs->dx & 0xffff;
		break;

	/* OUTS opcodes */
	case 0x6e:
	case 0x6f:
		*exitinfo |= IOIO_TYPE_OUTS;
		*exitinfo |= IOIO_SEG_DS;
		port = ctxt->regs->dx & 0xffff;
		break;

	/* IN immediate opcodes */
	case 0xe4:
	case 0xe5:
		*exitinfo |= IOIO_TYPE_IN;
		port = (u8)insn->immediate.value & 0xffff;
		break;

	/* OUT immediate opcodes */
	case 0xe6:
	case 0xe7:
		*exitinfo |= IOIO_TYPE_OUT;
		port = (u8)insn->immediate.value & 0xffff;
		break;

	/* IN immediate opcodes */
	case 0xec:
	case 0xed:
		*exitinfo |= IOIO_TYPE_IN;
		port = ctxt->regs->dx & 0xffff;
		break;

	/* OUT register opcodes */
	case 0xee:
	case 0xef:
		*exitinfo |= IOIO_TYPE_OUT;
		port = ctxt->regs->dx & 0xffff;
		break;
	default:
		return ES_DECODE_FAILED;
	}

	*exitinfo |= port << 16;

	switch (insn->opcode.bytes[0]) {
	case 0x6c:
	case 0x6e:
	case 0xe4:
	case 0xe6:
	case 0xec:
	case 0xee:
		/* Single byte opcodes */
		*exitinfo |= IOIO_DATA_8;
		size = 1;
		break;
	default:
		/* Length determined by instruction parsing */
		*exitinfo |= (insn->opnd_bytes == 2) ? IOIO_DATA_16
						     : IOIO_DATA_32;
		size = (insn->opnd_bytes == 2) ? 2 : 4;
	}

	switch (insn->addr_bytes) {
	case 2:
		*exitinfo |= IOIO_ADDR_16;
		break;
	case 4:
		*exitinfo |= IOIO_ADDR_32;
		break;
	case 8:
		*exitinfo |= IOIO_ADDR_64;
		break;
	}

	if ((*klpe_insn_has_rep_prefix)(insn))
		*exitinfo |= IOIO_REP;

	return vc_ioio_check(ctxt->regs, port, size);
}

int klpp_insn_fetch_from_user_inatomic(struct pt_regs *regs, unsigned char buf[MAX_INSN_SIZE],
					unsigned long caller_rdx)
{
	unsigned long ip;
	int not_copied;
	int ret;
	struct es_em_ctxt local_ctxt = { 0 };
	u64 exit_info_1;
	unsigned long es_base, addr;

	unsigned long exit_code = caller_rdx + 0x40;

	/*
	 * In the original fix, it checked if the exit_code is MMIO
	 * (SVM_EXIT_NPF) and if it's uesr_mode(regs). At this point we don't
	 * need to check for user_mode, since insn_fetch_from_user_inatomic is
	 * only called when on user_mode.
	 */
	if (exit_code == SVM_EXIT_NPF) {
		return -EINVAL;
	}

	if ((*klpe_insn_get_effective_ip)(regs, &ip))
		return -EINVAL;

	not_copied = __copy_from_user_inatomic(buf, (void __user *)ip, MAX_INSN_SIZE);

	ret = MAX_INSN_SIZE - not_copied;
	if (ret <= 0)
		return ret;

	if (exit_code == SVM_EXIT_IOIO) {
		local_ctxt.regs = regs;
		if (!(*klpe_insn_decode_from_regs)(&local_ctxt.insn, local_ctxt.regs, buf, ret))
			return -EINVAL;

		if (vc_ioio_exitinfo(&local_ctxt, &exit_info_1) != ES_OK)
			return -EINVAL;

		es_base = (*klpe_insn_get_seg_base)(regs, INAT_SEG_REG_ES);

		/*
		 * At this point, in the original fix, user_mode(regs) will be
		 * checked. But as stated above, we are already on user_mode.
		 */
		if (exit_info_1 & IOIO_TYPE_STR) {
			if (!(exit_info_1 & IOIO_TYPE_IN))
				addr = es_base + regs->si;
			else
				addr = es_base + regs->di;

			if ((*klpe_fault_in_kernel_space)(addr))
				return -EINVAL;
		}
	}

	return ret;
}



#include "livepatch_bsc1216898.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fault_in_kernel_space", (void *)&klpe_fault_in_kernel_space },
	{ "insn_decode_from_regs", (void *)&klpe_insn_decode_from_regs },
	{ "insn_get_effective_ip", (void *)&klpe_insn_get_effective_ip },
	{ "insn_get_seg_base", (void *)&klpe_insn_get_seg_base },
	{ "insn_has_rep_prefix", (void *)&klpe_insn_has_rep_prefix },
};

int livepatch_bsc1216898_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_AMD_MEM_ENCRYPT) */
