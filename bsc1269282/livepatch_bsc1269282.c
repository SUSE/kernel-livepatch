/*
 * livepatch_bsc1269282
 *
 * Fix for CVE-2026-43109, bsc#1269282
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

#if IS_ENABLED(CONFIG_X86_USER_SHADOW_STACK)

#include "livepatch_bsc1269282.h"

/* klp-ccp: from arch/x86/kernel/shstk.c */
#include <linux/sched.h>

int klpp_restore_signal_shadow_stack(void);

/* klp-ccp: from arch/x86/kernel/shstk.c */
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/compat.h>
#include <linux/sizes.h>
#include <linux/user.h>
#include <linux/syscalls.h>
#include <asm/msr.h>
#include <asm/fpu/xstate.h>
#include <asm/fpu/types.h>
#include <asm/shstk.h>
#include <asm/special_insns.h>
#include <asm/fpu/api.h>
#include <asm/prctl.h>

static bool features_enabled(unsigned long features)
{
	return current->thread.features & features;
}

static unsigned long get_user_shstk_addr(void)
{
	unsigned long long ssp;

	fpregs_lock_and_load();

	rdmsrl(MSR_IA32_PL3_SSP, ssp);

	fpregs_unlock();

	return ssp;
}

#define SHSTK_DATA_BIT BIT(63)

static int get_shstk_data(unsigned long *data, unsigned long __user *addr)
{
	unsigned long ldata;

	if (unlikely(get_user(ldata, addr)))
		return -EFAULT;

	if (!(ldata & SHSTK_DATA_BIT))
		return -EINVAL;

	*data = ldata & ~SHSTK_DATA_BIT;

	return 0;
}

static int shstk_pop_sigframe(unsigned long *ssp)
{
	struct vm_area_struct *vma;
	unsigned long token_addr;
	bool need_to_check_vma;
	int err = 1;

	/*
	 * It is possible for the SSP to be off the end of a shadow stack by 4
	 * or 8 bytes. If the shadow stack is at the start of a page or 4 bytes
	 * before it, it might be this case, so check that the address being
	 * read is actually shadow stack.
	 */
	if (!IS_ALIGNED(*ssp, 8))
		return -EINVAL;

	need_to_check_vma = PAGE_ALIGN(*ssp) == *ssp;

	if (need_to_check_vma)
		if (mmap_read_lock_killable(current->mm))
			return -EINTR;

	err = get_shstk_data(&token_addr, (unsigned long __user *)*ssp);
	if (unlikely(err))
		goto out_err;

	if (need_to_check_vma) {
		vma = find_vma(current->mm, *ssp);
		if (!vma || !(vma->vm_flags & VM_SHADOW_STACK)) {
			err = -EFAULT;
			goto out_err;
		}

		mmap_read_unlock(current->mm);
	}

	/* Restore SSP aligned? */
	if (unlikely(!IS_ALIGNED(token_addr, 8)))
		return -EINVAL;

	/* SSP in userspace? */
	if (unlikely(token_addr >= TASK_SIZE_MAX))
		return -EINVAL;

	*ssp = token_addr;

	return 0;
out_err:
	if (need_to_check_vma)
		mmap_read_unlock(current->mm);
	return err;
}

int klpp_restore_signal_shadow_stack(void)
{
	unsigned long ssp;
	int err;

	if (!cpu_feature_enabled(X86_FEATURE_USER_SHSTK) ||
	    !features_enabled(ARCH_SHSTK_SHSTK))
		return 0;

	ssp = get_user_shstk_addr();
	if (unlikely(!ssp))
		return -EINVAL;

	err = shstk_pop_sigframe(&ssp);
	if (unlikely(err))
		return err;

	fpregs_lock_and_load();
	wrmsrl(MSR_IA32_PL3_SSP, ssp);
	fpregs_unlock();

	return 0;
}


#include <linux/livepatch.h>

extern typeof(fpregs_lock_and_load) fpregs_lock_and_load
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, fpregs_lock_and_load);

#endif /* IS_ENABLED(CONFIG_X86_USER_SHADOW_STACK) */
