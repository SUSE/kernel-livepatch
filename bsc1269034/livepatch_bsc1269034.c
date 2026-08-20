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
#include <linux/rhashtable.h>
#include <linux/log2.h>

#include <asm/unistd.h>

/* klp-ccp: from ipc/util.h */
#include <linux/unistd.h>
#include <linux/err.h>
#include <linux/ipc_namespace.h>

#ifdef CONFIG_SYSVIPC_SYSCTL
extern int ipc_mni;
extern int ipc_mni_shift;
extern int ipc_min_cycle;

#define ipcmni_seq_shift()	ipc_mni_shift
#define IPCMNI_IDX_MASK		((1 << ipc_mni_shift) - 1)

#else /* CONFIG_SYSVIPC_SYSCTL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SYSVIPC_SYSCTL */

#define ipcid_to_idx(id)  ((id) & IPCMNI_IDX_MASK)
#define ipcid_to_seqx(id) ((id) >> ipcmni_seq_shift())
#define ipcid_seq_max()	  (INT_MAX >> ipcmni_seq_shift())

int klpp_ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int);

#ifdef CONFIG_COMPAT
#include <linux/compat.h>
#endif

/* klp-ccp: from ipc/util.c */
extern const struct rhashtable_params ipc_kht_params;

static inline int klpp_ipc_idr_alloc(struct ipc_ids *ids, struct kern_ipc_perm *new)
{
	int idx, next_id = -1;

#ifdef CONFIG_CHECKPOINT_RESTORE
	next_id = ids->next_id;
	ids->next_id = -1;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (next_id < 0) { /* !CHECKPOINT_RESTORE or next_id is unset */
		int max_idx;

		max_idx = max(ids->in_use*3/2, ipc_min_cycle);
		max_idx = min(max_idx, ipc_mni);

		/* allocate the idx, with a NULL struct kern_ipc_perm */
		idx = idr_alloc_cyclic(&ids->ipcs_idr, NULL, 0, max_idx,
					GFP_NOWAIT);

		if (idx >= 0) {
			/*
			 * idx got allocated successfully.
			 * Now calculate the sequence number and set the
			 * pointer for real.
			 */
			if (idx <= ids->last_idx) {
				ids->seq++;
				if (ids->seq >= ipcid_seq_max())
					ids->seq = 0;
			}
			ids->last_idx = idx;

			new->seq = ids->seq;
			/* no need for smp_wmb(), this is done
			 * inside idr_replace, as part of
			 * rcu_assign_pointer
			 */
			idr_replace(&ids->ipcs_idr, new, idx);
		}
	} else {
		new->seq = ipcid_to_seqx(next_id);
		idx = idr_alloc(&ids->ipcs_idr, new, ipcid_to_idx(next_id),
				ipc_mni, GFP_NOWAIT);
	}
	if (idx >= 0)
		new->id = (new->seq << ipcmni_seq_shift()) + idx;
	return idx;
}

int klpp_ipc_addid(struct ipc_ids *ids, struct kern_ipc_perm *new, int limit)
{
	kuid_t euid;
	kgid_t egid;
	int idx, err;

	/* 1) Initialize the refcount so that ipc_rcu_putref works */
	refcount_set(&new->refcount, 1);

	if (limit > ipc_mni)
		limit = ipc_mni;

	if (ids->in_use >= limit)
		return -ENOSPC;

	idr_preload(GFP_KERNEL);

	spin_lock_init(&new->lock);
	rcu_read_lock();
	spin_lock(&new->lock);

	current_euid_egid(&euid, &egid);
	new->cuid = new->uid = euid;
	new->gid = new->cgid = egid;

	new->deleted = false;

	idx = klpp_ipc_idr_alloc(ids, new);
	idr_preload_end();

	if (idx >= 0 && new->key != IPC_PRIVATE) {
		err = rhashtable_insert_fast(&ids->key_ht, &new->khtnode,
					     ipc_kht_params);
		if (err < 0) {
			idr_remove(&ids->ipcs_idr, idx);
			idx = err;
		}
	}
	if (idx < 0) {
		new->deleted = true;
		spin_unlock(&new->lock);
		rcu_read_unlock();
		return idx;
	}

	ids->in_use++;
	if (idx > ids->max_idx)
		ids->max_idx = idx;
	return idx;
}


#include <linux/livepatch.h>

extern typeof(ipc_kht_params) ipc_kht_params
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipc_kht_params);
extern typeof(ipc_min_cycle) ipc_min_cycle
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipc_min_cycle);
extern typeof(ipc_mni) ipc_mni KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipc_mni);
extern typeof(ipc_mni_shift) ipc_mni_shift
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipc_mni_shift);
