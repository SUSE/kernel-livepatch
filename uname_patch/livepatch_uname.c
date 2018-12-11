/*
 * livepatch -- initial SLE Live Patching patch
 *
 * Patch uname to show Kernel Live Patching in version string
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
 * And we map 4.x to 2.6.60+x, so 4.0 would be 2.6.60.
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
		v = ((LINUX_VERSION_CODE >> 8) & 0xff) + 60;
		copy = clamp_t(size_t, len, 1, sizeof(buf));
		copy = scnprintf(buf, copy, "2.6.%u%s", v, rest);
		ret = copy_to_user(release, buf, copy + 1);
	}
	return ret;
}

char *klp_tag="/lp-@@GITREV@@";


static struct rw_semaphore *klp_uts_sem;

static int override_version(char __user *version, size_t len, char *klp_version)
{
	int ret = 0;
	char *right_brace;
	size_t newlen;

	newlen = strlen(klp_version) + strlen(klp_tag);
	if (newlen >= len) {
		WARN_ONCE(1, "livepatch: not enough space for utsname.version extension");
		goto out;
	}

	right_brace = strchr(klp_version, ')');
	if (!right_brace) {
		WARN_ONCE(1, "livepatch: did not find the commit id");
		goto out;
	}

	memmove(right_brace + strlen(klp_tag), right_brace,
		strlen(right_brace) + 1);
	memcpy(right_brace, klp_tag, strlen(klp_tag));

	ret = copy_to_user(version, klp_version, newlen + 1);

out:
	return ret;
}

asmlinkage long klp_sys_newuname(struct new_utsname __user *name)
{
	struct new_utsname tmp;
	char klp_version[65] = { 0 };

	down_read(klp_uts_sem);
	memcpy(&tmp, utsname(), sizeof(tmp));
	memcpy(klp_version, utsname()->version, sizeof(utsname()->version));
	up_read(klp_uts_sem);
	if (copy_to_user(name, &tmp, sizeof(tmp)))
		return -EFAULT;

	if (override_release(name->release, sizeof(name->release)))
		return -EFAULT;
	if (override_architecture(name))
		return -EFAULT;
	if (override_version(name->version, sizeof(name->version), klp_version))
		return -EFAULT;
	return 0;
}

int klp_patch_uname_init(void)
{
	unsigned long addr;

	addr = kallsyms_lookup_name("uts_sem");
	if (!addr) {
		pr_err("livepatch: symbol uts_sem not resolved\n");
		return -EFAULT;
	}
	klp_uts_sem = (struct rw_semaphore *) addr;

	return 0;
}
