/*
 * livepatch_bsc1207190
 *
 * Fix for CVE-2023-0266, bsc#1207190 (fs/compat_ioctl.c part)
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_SND)

#if !IS_ENABLED(CONFIG_COMPAT)
#error "Live patch supports only CONFIG_COMPAT=y"
#endif

#include "bsc1207190_common.h"
#include <linux/syscalls.h>

/* klp-ccp: from fs/compat_ioctl.c */
#include <linux/joystick.h>

/* klp-ccp: from include/linux/pinctrl/devinfo.h */
#ifdef CONFIG_PINCTRL

/* klp-ccp: from include/linux/fs.h */
static int (*klpe_ioctl_preallocate)(struct file *filp, void __user *argp);

/* klp-ccp: from include/linux/pinctrl/devinfo.h */
#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PINCTRL */

/* klp-ccp: from fs/compat_ioctl.c */
#include <linux/types.h>
#include <linux/compat.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/ioctl.h>
#include <linux/if.h>

/* klp-ccp: from include/linux/security.h */
#ifdef CONFIG_SECURITY

static int (*klpe_security_file_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);

#else /* CONFIG_SECURITY */
#error "klp-ccp: non-taken branch"
#endif	/* CONFIG_SECURITY */

/* klp-ccp: from fs/compat_ioctl.c */
#include <linux/in6.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/falloc.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <uapi/asm/ioctls.h>
#include <linux/netdevice.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/i2c.h>
#include <linux/gfp.h>

/* klp-ccp: from fs/internal.h */
static int (*klpe_do_vfs_ioctl)(struct file *file, unsigned int fd, unsigned int cmd,
		    unsigned long arg);

/* klp-ccp: from fs/compat_ioctl.c */
#include <linux/gigaset_dev.h>
#include <linux/uaccess.h>
#include <linux/ethtool.h>
#include <linux/if_bonding.h>
#include <linux/atmclip.h>
#include <linux/atmioc.h>
#include <linux/atm_suni.h>
#include <linux/random.h>
#include <linux/filter.h>

#if defined(CONFIG_IA64) || defined(CONFIG_X86_64)
struct space_resv_32 {
	__s16		l_type;
	__s16		l_whence;
	__s64		l_start	__attribute__((packed));
			/* len == 0 means until end of file */
	__s64		l_len __attribute__((packed));
	__s32		l_sysid;
	__u32		l_pid;
	__s32		l_pad[4];	/* reserve area */
};

#define FS_IOC_RESVSP_32		_IOW ('X', 40, struct space_resv_32)
#define FS_IOC_RESVSP64_32	_IOW ('X', 42, struct space_resv_32)

static int klpr_compat_ioctl_preallocate(struct file *file,
			struct space_resv_32    __user *p32)
{
	struct space_resv	__user *p = compat_alloc_user_space(sizeof(*p));

	if (copy_in_user(&p->l_type,	&p32->l_type,	sizeof(s16)) ||
	    copy_in_user(&p->l_whence,	&p32->l_whence, sizeof(s16)) ||
	    copy_in_user(&p->l_start,	&p32->l_start,	sizeof(s64)) ||
	    copy_in_user(&p->l_len,	&p32->l_len,	sizeof(s64)) ||
	    copy_in_user(&p->l_sysid,	&p32->l_sysid,	sizeof(s32)) ||
	    copy_in_user(&p->l_pid,	&p32->l_pid,	sizeof(u32)) ||
	    copy_in_user(&p->l_pad,	&p32->l_pad,	4*sizeof(u32)))
		return -EFAULT;

	return (*klpe_ioctl_preallocate)(file, p);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define XFORM(i) (((i) ^ ((i) << 27) ^ ((i) << 17)) & 0xffffffff)

static unsigned int (*klpe_ioctl_pointer)[489]

#ifdef TIOCSRS485

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef TIOCGRS485

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
#ifdef TCGETS2

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_BLOCK

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef CONFIG_BLOCK

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#ifdef TIOCGLTC
#error "klp-ccp: non-taken branch"
#endif
#ifdef TIOCSTART
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_SPARC
#error "klp-ccp: non-taken branch"
#endif
;

static long (*klpe_do_ioctl_trans)(unsigned int cmd,
		 unsigned long arg, struct file *file);

static int klpr_compat_ioctl_check_table(unsigned int xcmd)
{
	int i;
	const int max = ARRAY_SIZE((*klpe_ioctl_pointer)) - 1;

	BUILD_BUG_ON(max >= (1 << 16));

	/* guess initial offset into table, assuming a
	   normalized distribution */
	i = ((xcmd >> 16) * max) >> 16;

	/* do linear search up first, until greater or equal */
	while ((*klpe_ioctl_pointer)[i] < xcmd && i < max)
		i++;

	/* then do linear search down */
	while ((*klpe_ioctl_pointer)[i] > xcmd && i > 0)
		i--;

	return (*klpe_ioctl_pointer)[i] == xcmd;
}

COMPAT_SYSCALL_DEFINEx(3, _klpp_ioctl, unsigned int, fd, unsigned int, cmd,
		       compat_ulong_t, arg32)
{
	unsigned long arg = arg32;
	struct fd f = fdget(fd);
	int error = -EBADF;
	if (!f.file)
		goto out;

	/* RED-PEN how should LSM module know it's handling 32bit? */
	error = (*klpe_security_file_ioctl)(f.file, cmd, arg);
	if (error)
		goto out_fput;

	/*
	 * To allow the compat_ioctl handlers to be self contained
	 * we need to check the common ioctls here first.
	 * Just handle them with the standard handlers below.
	 */
	switch (cmd) {
	case FIOCLEX:
	case FIONCLEX:
	case FIONBIO:
	case FIOASYNC:
	case FIOQSIZE:
		break;

#if defined(CONFIG_IA64) || defined(CONFIG_X86_64)
	case FS_IOC_RESVSP_32:
	case FS_IOC_RESVSP64_32:
		error = klpr_compat_ioctl_preallocate(f.file, compat_ptr(arg));
		goto out_fput;
#else
#error "klp-ccp: non-taken branch"
#endif
	case FICLONE:
	case FICLONERANGE:
	case FIDEDUPERANGE:
		goto do_ioctl;

	case FIBMAP:
	case FIGETBSZ:
	case FIONREAD:
		if (S_ISREG(file_inode(f.file)->i_mode))
			break;
		/*FALL THROUGH*/

	default:
		/*
		 * Fix CVE-2023-0266
		 *  -1 line, +6 lines
		 */
		if (f.file->f_op->compat_ioctl &&
		    f.file->f_op->compat_ioctl == READ_ONCE(klpe_snd_ctl_ioctl_compat)) {
			error = klpp_snd_ctl_ioctl_compat(f.file, cmd, arg);
			if (error != -ENOIOCTLCMD)
				goto out_fput;
		} else if (f.file->f_op->compat_ioctl) {
			error = f.file->f_op->compat_ioctl(f.file, cmd, arg);
			if (error != -ENOIOCTLCMD)
				goto out_fput;
		}

		if (!f.file->f_op->unlocked_ioctl)
			goto do_ioctl;
		break;
	}

	if (klpr_compat_ioctl_check_table(XFORM(cmd)))
		goto found_handler;

	error = (*klpe_do_ioctl_trans)(cmd, arg, f.file);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;

	goto out_fput;

 found_handler:
	arg = (unsigned long)compat_ptr(arg);
 do_ioctl:
	error = (*klpe_do_vfs_ioctl)(f.file, fd, cmd, arg);
 out_fput:
	fdput(f);
 out:
	return error;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1207190.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "do_ioctl_trans", (void *)&klpe_do_ioctl_trans },
	{ "do_vfs_ioctl", (void *)&klpe_do_vfs_ioctl },
	{ "ioctl_pointer", (void *)&klpe_ioctl_pointer },
	{ "ioctl_preallocate", (void *)&klpe_ioctl_preallocate },
	{ "security_file_ioctl", (void *)&klpe_security_file_ioctl },
};

int livepatch_bsc1207190_fs_compat_ioctl_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

#endif /* IS_ENABLED(CONFIG_SND) */
