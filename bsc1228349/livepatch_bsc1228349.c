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
#include <linux/bpf-cgroup.h>
#include <linux/bpf_trace.h>
#include <linux/btf.h>

/* klp-ccp: from include/linux/trace_events.h */
#define _LINUX_TRACE_EVENT_H

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
#include <linux/nospec.h>
#include <uapi/linux/btf.h>
#include <linux/pgtable.h>
#include <linux/poll.h>
#include <linux/rcupdate_trace.h>
#include <linux/memcontrol.h>
#include <linux/trace_events.h>

static struct idr (*klpe_link_idr);
static spinlock_t (*klpe_link_idr_lock);

void bpf_prog_put(struct bpf_prog *prog);

extern typeof(bpf_prog_put) bpf_prog_put;

static void klpr_bpf_link_free_id(int id)
{
	if (!id)
		return;

	spin_lock_bh(&(*klpe_link_idr_lock));
	idr_remove(&(*klpe_link_idr), id);
	spin_unlock_bh(&(*klpe_link_idr_lock));
}

static void (*klpe_bpf_link_defer_dealloc_rcu_gp)(struct rcu_head *rcu);

static void (*klpe_bpf_link_defer_dealloc_mult_rcu_gp)(struct rcu_head *rcu);

void klpp_bpf_link_free(struct bpf_link *link)
{
	const struct bpf_link_ops *ops = link->ops;
	bool sleepable = false;

	klpr_bpf_link_free_id(link->id);
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
			call_rcu_tasks_trace(&link->rcu, (*klpe_bpf_link_defer_dealloc_mult_rcu_gp));
		else
			call_rcu(&link->rcu, (*klpe_bpf_link_defer_dealloc_rcu_gp));
	} else if (ops->dealloc)
		ops->dealloc(link);
}


#include "livepatch_bsc1228349.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "bpf_link_defer_dealloc_mult_rcu_gp",
	  (void *)&klpe_bpf_link_defer_dealloc_mult_rcu_gp },
	{ "bpf_link_defer_dealloc_rcu_gp",
	  (void *)&klpe_bpf_link_defer_dealloc_rcu_gp },
	{ "link_idr", (void *)&klpe_link_idr },
	{ "link_idr_lock", (void *)&klpe_link_idr_lock },
};

int livepatch_bsc1228349_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
