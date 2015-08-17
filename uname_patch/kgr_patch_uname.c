/*
 * kgraft_patch -- initial SLE Live Patching patch
 *
 * Patch uname to show kGraft in version string
 *
 *  Copyright (c) 2014 SUSE
 *  Author: Libor Pechacek
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

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/personality.h>
#include <linux/utsname.h>
#include <generated/utsrelease.h>
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <asm/uaccess.h>

#ifdef COMPAT_UTS_MACHINE
#define override_architecture(name) \
	(personality(current->personality) == PER_LINUX32 && \
	 copy_to_user(name->machine, COMPAT_UTS_MACHINE, \
		      sizeof(COMPAT_UTS_MACHINE)))
#else
#define override_architecture(name)	0
#endif

/*
 * Work around broken programs that cannot handle "Linux 3.0".
 * Instead we map 3.x to 2.6.40+x, so e.g. 3.0 would be 2.6.40
 */
static int override_release(char __user *release, size_t len)
{
	int ret = 0;

	if (current->personality & UNAME26) {
		const char *rest = UTS_RELEASE;
		char buf[65] = { 0 };
		int ndots = 0;
		unsigned v;
		size_t copy;

		while (*rest) {
			if (*rest == '.' && ++ndots >= 3)
				break;
			if (!isdigit(*rest) && *rest != '.')
				break;
			rest++;
		}
		v = ((LINUX_VERSION_CODE >> 8) & 0xff) + 40;
		copy = clamp_t(size_t, len, 1, sizeof(buf));
		copy = scnprintf(buf, copy, "2.6.%u%s", v, rest);
		ret = copy_to_user(release, buf, copy + 1);
	}
	return ret;
}

char *kgr_tag="/kGraft-@@GITREV@@";

static struct rw_semaphore *kgr_uts_sem;

static int override_version(char __user *version, size_t len, char *kgr_version)
{
	int ret = 0;
	char *right_brace;
	size_t newlen;

	newlen = strlen(kgr_version) + strlen(kgr_tag);
	if (newlen >= len) {
		WARN_ONCE(1, "kgraft-patch: not enough space for utsname.version extension");
		goto out;
	}

	right_brace = strchr(kgr_version, ')');
	if (!right_brace) {
		WARN_ONCE(1, "kgraft-patch: did not find the commit id");
		goto out;
	}

	memmove(right_brace + strlen(kgr_tag), right_brace,
		strlen(right_brace) + 1);
	memcpy(right_brace, kgr_tag, strlen(kgr_tag));

	ret = copy_to_user(version, kgr_version, newlen + 1);

out:
	return ret;
}

asmlinkage long kgr_sys_newuname(struct new_utsname __user *name)
{
	int errno = 0;
	char kgr_version[65] = { 0 };

	down_read(kgr_uts_sem);
	if (copy_to_user(name, utsname(), sizeof *name))
		errno = -EFAULT;
	memcpy(kgr_version, utsname()->version, sizeof(utsname()->version));
	up_read(kgr_uts_sem);

	if (!errno && override_release(name->release, sizeof(name->release)))
		errno = -EFAULT;
	if (!errno && override_architecture(name))
		errno = -EFAULT;
	if (!errno && override_version(name->version, sizeof(name->version),
		kgr_version))
		errno = -EFAULT;
	return errno;
}

int kgr_patch_uname_init(void)
{
	unsigned long addr;

	addr = kallsyms_lookup_name("uts_sem");
	if (!addr) {
		pr_err("kgraft-patch: symbol uts_sem not resolved\n");
		return -EFAULT;
	}
	kgr_uts_sem = (struct rw_semaphore *) addr;

	return 0;
}
