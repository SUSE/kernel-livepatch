/*
 * livepatch_bsc1203993
 *
 * Fix for CVE-2022-2991, bsc#1203993
 *
 *  Upstream commit:
 *  9ea9b9c48387 ("remove the lightnvm subsystem")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  30cd9beef530d83213eccc5131e5d23d78df32af
 *
 *  SLE15-SP2 and -SP3 commit:
 *  1b534dbe64700c32de5511b3234e881bda66bfb6
 *
 *  SLE15-SP4 commit:
 *  769f8dbc8a8923084724b32b46af519d8b00fb2f
 *
 *  Copyright (c) 2023 SUSE
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

#include <linux/errno.h>
#include <linux/printk.h>

struct nvme_ns;

int klpp_nvme_nvm_register(struct nvme_ns *ns, char *disk_name, int node)
{
	pr_warn("lightnvm has been rejected by livepatch (CVE-2022-2991)");
	return -ENOSYS;
}
