/*
 * livepatch_bsc1191318
 *
 * Fix for CVE-2021-41864, bsc#1191318
 *
 *  Upstream commit:
 *  30e29a9a2bc6 ("bpf: Fix integer overflow in prealloc_elems_and_freelist()")
 *
 *  SLE12-SP3 commit:
 *  not affected
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d0cde4191f6c6d987945a00fdcb36e53024c2c3f
 *
 *  SLE15-SP2 and -SP3 commit:
 *  d4466f5d6b578abd6649a580f438c960cd6ef7a6
 *
 *
 *  Copyright (c) 2021 SUSE
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

/* klp-ccp: from kernel/bpf/stackmap.c */
#include <linux/bpf.h>

/* klp-ccp: from include/linux/bpf.h */
#ifdef CONFIG_BPF_SYSCALL

static int (*klpe_bpf_map_precharge_memlock)(u32 pages);

static void *(*klpe_bpf_map_area_alloc)(size_t size, int numa_node);
static void (*klpe_bpf_map_area_free)(void *base);
static void (*klpe_bpf_map_init_from_attr)(struct bpf_map *map, union bpf_attr *attr);

#else /* !CONFIG_BPF_SYSCALL */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_BPF_SYSCALL */

/* klp-ccp: from kernel/bpf/stackmap.c */
#include <linux/jhash.h>
#include <linux/filter.h>
#include <linux/stacktrace.h>

/* klp-ccp: from include/linux/perf_event.h */
#ifdef CONFIG_PERF_EVENTS

static int (*klpe_get_callchain_buffers)(int max_stack);
static void (*klpe_put_callchain_buffers)(void);

static int (*klpe_sysctl_perf_event_max_stack);

#else /* !CONFIG_PERF_EVENTS: */
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from kernel/bpf/stackmap.c */
#include <linux/irq_work.h>
/* klp-ccp: from kernel/bpf/percpu_freelist.h */
#include <linux/spinlock.h>
#include <linux/percpu.h>

struct pcpu_freelist {
	struct pcpu_freelist_head __percpu *freelist;
};

struct pcpu_freelist_node {
	struct pcpu_freelist_node *next;
};

static void (*klpe_pcpu_freelist_populate)(struct pcpu_freelist *s, void *buf, u32 elem_size,
			    u32 nr_elems);
static int (*klpe_pcpu_freelist_init)(struct pcpu_freelist *);

/* klp-ccp: from kernel/bpf/stackmap.c */
#define STACK_CREATE_FLAG_MASK					\
	(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY |	\
	 BPF_F_STACK_BUILD_ID)

struct stack_map_bucket {
	struct pcpu_freelist_node fnode;
	u32 hash;
	u32 nr;
	u64 data[];
};

struct bpf_stack_map {
	struct bpf_map map;
	void *elems;
	struct pcpu_freelist freelist;
	u32 n_buckets;
	struct stack_map_bucket *buckets[];
};

static int klpp_prealloc_elems_and_freelist(struct bpf_stack_map *smap)
{
	/*
	 * Fix CVE-2021-41864
	 *  -1 line, +2 lines
	 */
	u64 elem_size = sizeof(struct stack_map_bucket) +
			(u64)smap->map.value_size;
	int err;

	smap->elems = (*klpe_bpf_map_area_alloc)(elem_size * smap->map.max_entries,
					 smap->map.numa_node);
	if (!smap->elems)
		return -ENOMEM;

	err = (*klpe_pcpu_freelist_init)(&smap->freelist);
	if (err)
		goto free_elems;

	(*klpe_pcpu_freelist_populate)(&smap->freelist, smap->elems, elem_size,
			       smap->map.max_entries);
	return 0;

free_elems:
	(*klpe_bpf_map_area_free)(smap->elems);
	return err;
}

struct bpf_map *klpp_stack_map_alloc(union bpf_attr *attr)
{
	u32 value_size = attr->value_size;
	struct bpf_stack_map *smap;
	u64 cost, n_buckets;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return ERR_PTR(-EPERM);

	if (attr->map_flags & ~STACK_CREATE_FLAG_MASK)
		return ERR_PTR(-EINVAL);

	/* check sanity of attributes */
	if (attr->max_entries == 0 || attr->key_size != 4 ||
	    value_size < 8 || value_size % 8)
		return ERR_PTR(-EINVAL);

	BUILD_BUG_ON(sizeof(struct bpf_stack_build_id) % sizeof(u64));
	if (attr->map_flags & BPF_F_STACK_BUILD_ID) {
		if (value_size % sizeof(struct bpf_stack_build_id) ||
		    value_size / sizeof(struct bpf_stack_build_id)
		    > (*klpe_sysctl_perf_event_max_stack))
			return ERR_PTR(-EINVAL);
	} else if (value_size / 8 > (*klpe_sysctl_perf_event_max_stack))
		return ERR_PTR(-EINVAL);

	/* hash table size must be power of 2 */
	n_buckets = roundup_pow_of_two(attr->max_entries);

	cost = n_buckets * sizeof(struct stack_map_bucket *) + sizeof(*smap);
	if (cost >= U32_MAX - PAGE_SIZE)
		return ERR_PTR(-E2BIG);

	smap = (*klpe_bpf_map_area_alloc)(cost, bpf_map_attr_numa_node(attr));
	if (!smap)
		return ERR_PTR(-ENOMEM);

	err = -E2BIG;
	cost += n_buckets * (value_size + sizeof(struct stack_map_bucket));
	if (cost >= U32_MAX - PAGE_SIZE)
		goto free_smap;

	(*klpe_bpf_map_init_from_attr)(&smap->map, attr);
	smap->map.value_size = value_size;
	smap->n_buckets = n_buckets;
	smap->map.pages = round_up(cost, PAGE_SIZE) >> PAGE_SHIFT;

	err = (*klpe_bpf_map_precharge_memlock)(smap->map.pages);
	if (err)
		goto free_smap;

	err = (*klpe_get_callchain_buffers)((*klpe_sysctl_perf_event_max_stack));
	if (err)
		goto free_smap;

	err = klpp_prealloc_elems_and_freelist(smap);
	if (err)
		goto put_buffers;

	return &smap->map;

put_buffers:
	(*klpe_put_callchain_buffers)();
free_smap:
	(*klpe_bpf_map_area_free)(smap);
	return ERR_PTR(err);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1191318.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sysctl_perf_event_max_stack",
	  (void *)&klpe_sysctl_perf_event_max_stack },
	{ "bpf_map_precharge_memlock",
	  (void *)&klpe_bpf_map_precharge_memlock },
	{ "bpf_map_area_alloc", (void *)&klpe_bpf_map_area_alloc },
	{ "bpf_map_area_free", (void *)&klpe_bpf_map_area_free },
	{ "bpf_map_init_from_attr", (void *)&klpe_bpf_map_init_from_attr },
	{ "get_callchain_buffers", (void *)&klpe_get_callchain_buffers },
	{ "put_callchain_buffers", (void *)&klpe_put_callchain_buffers },
	{ "pcpu_freelist_populate", (void *)&klpe_pcpu_freelist_populate },
	{ "pcpu_freelist_init", (void *)&klpe_pcpu_freelist_init },
};

int livepatch_bsc1191318_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}
