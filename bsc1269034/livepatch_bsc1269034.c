/*
 * livepatch_bsc1269034
 *
 * Fix for CVE-2026-52923, bsc#1269034
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


#include "livepatch_bsc1269034.h"


/* klp-ccp: from ipc/util.c */
#include <linux/mm.h>
#include <linux/shm.h>
#include <linux/init.h>
#include <linux/msg.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/notifier.h>
#include <linux/capability.h>
#include <linux/highuid.h>
#include <linux/security.h>
#include <linux/rcupdate.h>
#include <linux/workqueue.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/audit.h>
#include <linux/nsproxy.h>
#include <linux/rwsem.h>
#include <linux/memory.h>
#include <linux/ipc_namespace.h>

#include <asm/unistd.h>

/* klp-ccp: from ipc/util.h */
#include <linux/unistd.h>
#include <linux/err.h>

#define SEQ_MULTIPLIER	(IPCMNI)

#define ipcid_to_idx(id) ((id) % SEQ_MULTIPLIER)
#define ipcid_to_seqx(id) ((id) / SEQ_MULTIPLIER)
#define IPCID_SEQ_MAX min_t(int, INT_MAX/SEQ_MULTIPLIER, USHRT_MAX)

int klpp_ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int);

static inline int ipc_buildid(int id, int seq)
{
	return SEQ_MULTIPLIER * seq + id;
}

/* klp-ccp: from ipc/util.c */
int klpp_ipc_addid(struct ipc_ids *ids, struct kern_ipc_perm *new, int size)
{
	kuid_t euid;
	kgid_t egid;
	int id;
	int next_id = ids->next_id;

	if (size > IPCMNI)
		size = IPCMNI;

	if (ids->in_use >= size)
		return -ENOSPC;

	idr_preload(GFP_KERNEL);

	atomic_set(&new->refcount, 1);
	spin_lock_init(&new->lock);
	new->deleted = false;
	rcu_read_lock();
	spin_lock(&new->lock);

	current_euid_egid(&euid, &egid);
	new->cuid = new->uid = euid;
	new->gid = new->cgid = egid;

	id = idr_alloc(&ids->ipcs_idr, new,
		       (next_id < 0) ? 0 : ipcid_to_idx(next_id), IPCMNI,
		       GFP_NOWAIT);
	idr_preload_end();
	if (id < 0) {
		spin_unlock(&new->lock);
		rcu_read_unlock();
		return id;
	}

	ids->in_use++;

	if (next_id < 0) {
		new->seq = ids->seq++;
		if (ids->seq > IPCID_SEQ_MAX)
			ids->seq = 0;
	} else {
		new->seq = ipcid_to_seqx(next_id);
		ids->next_id = -1;
	}

	new->id = ipc_buildid(id, new->seq);
	return id;
}


