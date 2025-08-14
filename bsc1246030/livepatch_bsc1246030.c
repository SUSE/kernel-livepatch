/*
 * livepatch_bsc1246030
 *
 * Fix for CVE-2025-38212, bsc#1246030
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

/* klp-ccp: from ipc/shm.c */
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/shm.h>
#include <linux/init.h>

/* klp-ccp: from include/linux/security.h */
#define __LINUX_SECURITY_H

/* klp-ccp: from ipc/shm.c */
#include <linux/security.h>

/* klp-ccp: from include/linux/ptrace.h */
#define _LINUX_PTRACE_H

/* klp-ccp: from ipc/shm.c */
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <linux/rwsem.h>
#include <linux/nsproxy.h>
#include <linux/mount.h>
#include <linux/ipc_namespace.h>


/* klp-ccp: from ipc/shm.c */
#include <linux/uaccess.h>

/* klp-ccp: from ipc/util.h */
#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/ipc_namespace.h>

#define IPC_SHM_IDS	2

/* klp-ccp: from ipc/shm.c */
#define shm_ids(ns)	((ns)->ids[IPC_SHM_IDS])

extern int shm_try_destroy_orphaned(int id, void *p, void *data);

void klpp_shm_destroy_orphaned(struct ipc_namespace *ns)
{
	down_write(&shm_ids(ns).rwsem);
	if (shm_ids(ns).in_use) {
		rcu_read_lock();
		idr_for_each(&shm_ids(ns).ipcs_idr, &shm_try_destroy_orphaned, ns);
		rcu_read_unlock();
	}
	up_write(&shm_ids(ns).rwsem);
}


#include "livepatch_bsc1246030.h"

#include <linux/livepatch.h>

extern typeof(shm_try_destroy_orphaned) shm_try_destroy_orphaned
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, shm_try_destroy_orphaned);
