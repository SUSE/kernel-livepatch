/*
 * livepatch_bsc1229504
 *
 * Fix for CVE-2024-43882, bsc#1229504
 *
 *  Upstream commit:
 *  f50733b45d86 ("exec: Fix ToCToU between perm check and set-uid/gid usage")
 *
 *  SLE12-SP5 commit:
 *  236a83a2cf3e63feb330395fe7e94a0b27870ac0
 *
 *  SLE15-SP3 commit:
 *  ce6fb0c780628c336745ccb286ff418a4ed2c281
 *
 *  SLE15-SP4 and -SP5 commit:
 *  83a7456632866f91bb766a5d6914bb9025c71caa
 *
 *  SLE15-SP6 commit:
 *  7a21b9de3359142bdd8c9587ff4f063d5cd2ef2b
 *
 *  SLE MICRO-6-0 commit:
 *  7a21b9de3359142bdd8c9587ff4f063d5cd2ef2b
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


/* klp-ccp: from fs/exec.c */
#include <linux/slab.h>
#include <linux/fdtable.h>
#include <linux/mm.h>
#include <linux/vmacache.h>
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/swap.h>
#include <linux/string.h>
#include <linux/init.h>

#include <linux/sched/coredump.h>

/* klp-ccp: from include/linux/sched/task.h */
#define _LINUX_SCHED_TASK_H

/* klp-ccp: from fs/exec.c */
#include <linux/sched/task.h>

/* klp-ccp: from include/linux/pid_namespace.h */
#define _LINUX_PID_NS_H

/* klp-ccp: from fs/exec.c */
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <linux/key.h>
#include <linux/personality.h>
#include <linux/binfmts.h>

/* klp-ccp: from include/linux/binfmts.h */
int klpp_prepare_binprm(struct linux_binprm *);

/* klp-ccp: from fs/exec.c */
#include <linux/pid_namespace.h>

/* klp-ccp: from include/linux/kmod.h */
#define __LINUX_KMOD_H__

/* klp-ccp: from include/linux/mount.h */
static bool (*klpe_mnt_may_suid)(struct vfsmount *mnt);

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_SECURITY

static int (*klpe_security_bprm_set_creds)(struct linux_binprm *bprm);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */

/* klp-ccp: from fs/exec.c */
#include <linux/kmod.h>

#include <linux/vmalloc.h>

#include <linux/uaccess.h>

int kernel_read(struct file *file, loff_t offset,
		char *addr, unsigned long count);

extern typeof(kernel_read) kernel_read;

static void klpp_bprm_fill_uid(struct linux_binprm *bprm)
{
	struct inode *inode;
	unsigned int mode;
	kuid_t uid;
	kgid_t gid;
	int err;

	/*
	 * Since this can be called multiple times (via prepare_binprm),
	 * we must clear any previous work done when setting set[ug]id
	 * bits from any earlier bprm->file uses (for example when run
	 * first for a setuid script then again for its interpreter).
	 */
	bprm->cred->euid = current_euid();
	bprm->cred->egid = current_egid();

	if (!(*klpe_mnt_may_suid)(bprm->file->f_path.mnt))
		return;

	if (task_no_new_privs(current))
		return;

	inode = bprm->file->f_path.dentry->d_inode;
	mode = READ_ONCE(inode->i_mode);
	if (!(mode & (S_ISUID|S_ISGID)))
		return;

	/* Be careful if suid/sgid is set */
	inode_lock(inode);

	/* Atomically reload and check mode/uid/gid now that lock held. */
	mode = inode->i_mode;
	uid = inode->i_uid;
	gid = inode->i_gid;
	err = inode_permission(inode, MAY_EXEC);
	inode_unlock(inode);

	/* Did the exec bit vanish out from under us? Give up. */
	if (err)
		return;

	/* We ignore suid/sgid if there are no mappings for them in the ns */
	if (!kuid_has_mapping(bprm->cred->user_ns, uid) ||
		 !kgid_has_mapping(bprm->cred->user_ns, gid))
		return;

	if (mode & S_ISUID) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->euid = uid;
	}

	if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
		bprm->per_clear |= PER_CLEAR_ON_SETID;
		bprm->cred->egid = gid;
	}
}

int klpp_prepare_binprm(struct linux_binprm *bprm)
{
	int retval;

	klpp_bprm_fill_uid(bprm);

	/* fill in binprm security blob */
	retval = (*klpe_security_bprm_set_creds)(bprm);
	if (retval)
		return retval;
	bprm->cred_prepared = 1;

	memset(bprm->buf, 0, BINPRM_BUF_SIZE);
	return kernel_read(bprm->file, 0, bprm->buf, BINPRM_BUF_SIZE);
}

typeof(klpp_prepare_binprm) klpp_prepare_binprm;


#include "livepatch_bsc1229504.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "mnt_may_suid", (void *)&klpe_mnt_may_suid },
	{ "security_bprm_set_creds", (void *)&klpe_security_bprm_set_creds },
};

int livepatch_bsc1229504_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

