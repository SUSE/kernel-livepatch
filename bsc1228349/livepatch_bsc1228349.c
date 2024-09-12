/*
 * livepatch_bsc1228349
 *
 * Fix for CVE-2024-40909, bsc#1228349
 *
 *  Upstream commit:
 *  2884dc7d08d9 ("bpf: Fix a potential use-after-free in bpf_link_free()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  377837fd53dbd7a6c35cff41d5c42ab1224512b0
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

/* klp-ccp: from kernel/bpf/syscall.c */
#include <linux/bpf.h>

/* klp-ccp: from include/linux/vmalloc.h */
#define _LINUX_VMALLOC_H

/* klp-ccp: from include/linux/poll.h */
#define _LINUX_POLL_H

/* klp-ccp: from include/linux/filter.h */
#define __LINUX_FILTER_H__

/* klp-ccp: from kernel/bpf/syscall.c */
#include <linux/bsearch.h>
#include <linux/btf.h>

/* klp-ccp: from include/linux/trace_events.h */
#define _LINUX_TRACE_EVENT_H

#define TRACE_CUSTOM_EVENT(name, proto, args, struct, assign, print)

/* klp-ccp: from kernel/bpf/syscall.c */
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/vmalloc.h>
#include <linux/mmzone.h>

/* klp-ccp: from include/linux/nospec.h */
#define _LINUX_NOSPEC_H

/* klp-ccp: from kernel/bpf/syscall.c */
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/cred.h>
#include <linux/timekeeping.h>
#include <linux/ctype.h>
#include <linux/nospec.h>
#include <uapi/linux/btf.h>
#include <linux/pgtable.h>
#include <linux/poll.h>
#include <linux/rcupdate_trace.h>
#include <linux/memcontrol.h>
#include <linux/trace_events.h>

extern struct idr link_idr;
extern spinlock_t link_idr_lock;

void bpf_prog_put(struct bpf_prog *prog);

extern typeof(bpf_prog_put) bpf_prog_put;

static void bpf_link_free_id(int id)
{
	if (!id)
		return;

	spin_lock_bh(&link_idr_lock);
	idr_remove(&link_idr, id);
	spin_unlock_bh(&link_idr_lock);
}

extern void bpf_link_defer_dealloc_rcu_gp(struct rcu_head *rcu);

extern void bpf_link_defer_dealloc_mult_rcu_gp(struct rcu_head *rcu);

void klpp_bpf_link_free(struct bpf_link *link)
{
	const struct bpf_link_ops *ops = link->ops;
	bool sleepable = false;

	bpf_link_free_id(link->id);
	if (link->prog) {
		sleepable = link->prog->aux->sleepable;
		/* detach BPF program, clean up used resources */
		ops->release(link);
		bpf_prog_put(link->prog);
	}
	if (ops->dealloc_deferred) {
		/* schedule BPF link deallocation; if underlying BPF program
		 * is sleepable, we need to first wait for RCU tasks trace
		 * sync, then go through "classic" RCU grace period
		 */
		if (sleepable)
			call_rcu_tasks_trace(&link->rcu, bpf_link_defer_dealloc_mult_rcu_gp);
		else
			call_rcu(&link->rcu, bpf_link_defer_dealloc_rcu_gp);
	} else if (ops->dealloc)
		ops->dealloc(link);
}


#include "livepatch_bsc1228349.h"

#include <linux/livepatch.h>

extern typeof(bpf_link_defer_dealloc_mult_rcu_gp)
	 bpf_link_defer_dealloc_mult_rcu_gp
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_defer_dealloc_mult_rcu_gp);
extern typeof(bpf_link_defer_dealloc_rcu_gp) bpf_link_defer_dealloc_rcu_gp
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, bpf_link_defer_dealloc_rcu_gp);
extern typeof(link_idr) link_idr KLP_RELOC_SYMBOL(vmlinux, vmlinux, link_idr);
extern typeof(link_idr_lock) link_idr_lock
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, link_idr_lock);
