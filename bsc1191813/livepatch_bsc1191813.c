/*
 * livepatch_bsc1191813
 *
 * Fix for CVE-2021-20322, bsc#1191813
 *
 *  Upstream commits:
 *  6457378fe796 ("ipv4: use siphash instead of Jenkins in fnhe_hashfun()")
 *  67d6d681e15b ("ipv4: make exception cache less predictible")
 *  4785305c05b2 ("ipv6: use siphash in rt6_exception_hash()")
 *  a00df2caffed ("ipv6: make exception cache less predictible")
 *
 *  SLE12-SP3 commits:
 *  c0cf71aeaaf9fca047fde14397a8e1b2dcfa5a5e
 *  3410ffcc51dd858fa6a4757e341e8ac165fea26f
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commits:
 *  238505e894d4ec80993fc49d3ec0c26ad34e52f0
 *  74af5bd03ad58489836a6a8269e219c34550fece
 *
 *  SLE15-SP2 and -SP3 commits:
 *  46555dae97faf328234ef9fd68d729281a896bd2
 *  191e9b31d6a1ee3303ac147e85c97ca3cb4ad596
 *  a7a1a7f8384d8b28875e21b6dfb64ef7984b4d93
 *  23f16ab0d5248479194556b343f7fd99686e14ab
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

/* klp-ccp: from net/ipv4/route.c */
#define pr_fmt(fmt) "IPv4: " fmt

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/pkt_sched.h>
#include <linux/mroute.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <net/dst.h>
#include <net/dst_metadata.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <net/inetpeer.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <net/lwtunnel.h>
#include <net/rtnetlink.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#include <linux/kmemleak.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#include <net/ip_tunnels.h>
#include <net/l3mdev.h>


/*
 * Live patching specific approach to mitigate against collision group
 * discovery: we cannot safely change the hash function on a running
 * system, but we can make finding collision groups harder. A vital
 * part of finding collision groups is to correlate evictions with
 * insertions: an attacker would reinsert some recently evicted entry
 * to see what falls out next and would have found a collision. The
 * livepatch mitigation is to break this chain by simply detect
 * reinsertions and have nothing new (or something unrelated) evicted
 * in this case. In order to implement this, maintain one ringbuffer
 * of recently evicted entries' addresses for each exception hash
 * bucket.
 */
#define KLPP_EVICTION_HISTORY_SIZE 32

/*
 * Ringbuffer for recording the history of recent evections for each
 * exception hash bucket.
 */
struct klpp_eviction_history
{
	struct klpp_history_entry {
		unsigned long expires;
		__be32 daddr;
	} entries[KLPP_EVICTION_HISTORY_SIZE];
	unsigned int head, tail;
};

struct klp_bsc1191813_shared_state
{
	unsigned long refcount;

	struct klpp_eviction_history (*eviction_history)[FNHE_HASH_SIZE];
};

static struct klp_bsc1191813_shared_state *klp_bsc1191813_shared_state;

/* New. */
static void __klpp_eviction_history_expire(struct klpp_eviction_history *h)
{
	unsigned int i;

	for (i = h->head; i != h->tail;
	     i = (i + 1) % ARRAY_SIZE(h->entries)) {
		if (!time_after(jiffies, h->entries[i].expires))
			break;
	}

	h->head = i;
}

/* New. */
static bool __klpp_eviction_history_lookup(struct klpp_eviction_history *h,
					   __be32 daddr)
{
	unsigned int i;

	__klpp_eviction_history_expire(h);
	for (i = h->head; i != h->tail;
	     i = (i + 1) % ARRAY_SIZE(h->entries)) {
		if (h->entries[i].daddr == daddr)
			return true;
	}

	return false;
}

/* New. */
static void __klpp_eviction_history_record(struct klpp_eviction_history *h,
					   __be32 daddr)
{
	unsigned int i;

	__klpp_eviction_history_expire(h);

	i = h->tail;
	h->tail = (i + 1) % ARRAY_SIZE(h->entries);
	if (h->tail == h->head) {
		/* Ring buffer overrun. */
		h->head = (h->head + 1) % ARRAY_SIZE(h->entries);
	}

	h->entries[i].daddr = daddr;
	h->entries[i].expires = jiffies + 300 * HZ;
}

/* New. */
static bool klpp_eviction_history_lookup(u32 hval, __be32 daddr)
{
	struct klpp_eviction_history *h;

	h = &(*klp_bsc1191813_shared_state->eviction_history)[hval];
	return __klpp_eviction_history_lookup(h, daddr);
}

/* New. */
static void klpp_eviction_history_record(u32 hval, __be32 daddr)
{
	struct klpp_eviction_history *h;

	h = &(*klp_bsc1191813_shared_state->eviction_history)[hval];
	return __klpp_eviction_history_record(h, daddr);
}


static spinlock_t (*klpe_fnhe_lock);

static void (*klpe_fnhe_flush_routes)(struct fib_nh_exception *fnhe);

/* New. */
static void klpp_fnhe_remove_oldest(struct fnhe_hash_bucket *nh_exceptions,
				    u32 hval)
{
	struct fnhe_hash_bucket *hash = nh_exceptions + hval;
	struct fib_nh_exception __rcu **fnhe_p, **oldest_p;
	struct fib_nh_exception *fnhe, *oldest = NULL;

	for (fnhe_p = &hash->chain; ; fnhe_p = &fnhe->fnhe_next) {
		fnhe = rcu_dereference_protected(*fnhe_p,
						 lockdep_is_held(&fnhe_lock));
		if (!fnhe)
			break;
		if (!oldest ||
		    time_before(fnhe->fnhe_stamp, oldest->fnhe_stamp)) {
			oldest = fnhe;
			oldest_p = fnhe_p;
		}
	}
	if (!oldest)
		return;

	klpp_eviction_history_record(hval, oldest->fnhe_daddr);
	(*klpe_fnhe_flush_routes)(oldest);
	*oldest_p = oldest->fnhe_next;
	kfree_rcu(oldest, rcu);
}

static u32 (*klpe_fnhe_hashfun_local_fnhe_hashrnd);
static bool (*klpe_fnhe_hashfun_local____done);

static void klp_fnhe_hashfun_fnhe_hashrnd_init_once(void)
{
	/*
	 * Livepatch adjustment: simulate the DO_ONCE() from
	 * fnhe_hashfun()'s net_get_random_once() invocation. The
	 * function here would get called only from DO_ONCE() itself,
	 * and thus the global once_lock is held.
	 */
	if (!(*klpe_fnhe_hashfun_local____done)) {
		get_random_bytes(&(*klpe_fnhe_hashfun_local_fnhe_hashrnd),
				 sizeof(*klpe_fnhe_hashfun_local_fnhe_hashrnd));
		*klpe_fnhe_hashfun_local____done = true;
	}
}

static u32 klpp_fnhe_hashfun(__be32 daddr)
{
	u32 hval;

	DO_ONCE(klp_fnhe_hashfun_fnhe_hashrnd_init_once);
	hval = jhash_1word((__force u32) daddr, (*klpe_fnhe_hashfun_local_fnhe_hashrnd));
	return hash_32(hval, FNHE_HASH_SHIFT);
}

static void (*klpe_fill_route_from_fnhe)(struct rtable *rt, struct fib_nh_exception *fnhe);

void klpp_update_or_create_fnhe(struct fib_nh *nh, __be32 daddr, __be32 gw,
				  u32 pmtu, bool lock, unsigned long expires)
{
	/*
	 * Fix CVE-2021-20322
	 *  +1 line
	 */
	struct fnhe_hash_bucket *nh_exceptions;
	struct fnhe_hash_bucket *hash;
	struct fib_nh_exception *fnhe;
	struct rtable *rt;
	u32 genid, hval;
	unsigned int i;
	int depth;

	genid = fnhe_genid(dev_net(nh->nh_dev));
	hval = klpp_fnhe_hashfun(daddr);

	spin_lock_bh(&(*klpe_fnhe_lock));

	/*
	 * Fix CVE-2021-20322
	 *  -7 lines, +8 lines
	 */
	nh_exceptions = rcu_dereference(nh->nh_exceptions);
	if (!nh_exceptions) {
		nh_exceptions = kzalloc(FNHE_HASH_SIZE * sizeof(*nh_exceptions), GFP_ATOMIC);
		if (!nh_exceptions)
			goto out_unlock;
		rcu_assign_pointer(nh->nh_exceptions, nh_exceptions);
	}
	hash = nh_exceptions;

	hash += hval;

	depth = 0;
	for (fnhe = rcu_dereference(hash->chain); fnhe;
	     fnhe = rcu_dereference(fnhe->fnhe_next)) {
		if (fnhe->fnhe_daddr == daddr)
			break;
		depth++;
	}

	if (fnhe) {
		if (fnhe->fnhe_genid != genid)
			fnhe->fnhe_genid = genid;
		if (gw)
			fnhe->fnhe_gw = gw;
		if (pmtu) {
			fnhe->fnhe_pmtu = pmtu;
			fnhe->fnhe_mtu_locked = lock;
		}
		fnhe->fnhe_expires = max(1UL, expires);
		/* Update all cached dsts too */
		rt = rcu_dereference(fnhe->fnhe_rth_input);
		if (rt)
			(*klpe_fill_route_from_fnhe)(rt, fnhe);
		rt = rcu_dereference(fnhe->fnhe_rth_output);
		if (rt)
			(*klpe_fill_route_from_fnhe)(rt, fnhe);
	} else {
		/*
		 * Fix CVE-2021-20322
		 *  -10 line, +33 lines
		 */
		/* Randomize max depth to avoid some side channels attacks. */
		int max_depth = FNHE_RECLAIM_DEPTH +
				prandom_u32_max(FNHE_RECLAIM_DEPTH);

		if (depth > max_depth) {
			if (!klpp_eviction_history_lookup(hval, daddr)) {
				while (depth > max_depth) {
					klpp_fnhe_remove_oldest(nh_exceptions, hval);
					depth--;
				}
			} else {
				/*
				 * The entry for this destination
				 * address has been evicted recently,
				 * which is suspicious. Chances are
				 * an attacker is trying to reinsert
				 * it to find new collisions falling
				 * out from the bucket below. Pick
				 * some random bucket to evict from in
				 * order to not reveal any information
				 * on which pairs of entries collided.
				 */
				klpp_fnhe_remove_oldest(nh_exceptions,
							prandom_u32_max(FNHE_HASH_SIZE));
			}
		}

		fnhe = kzalloc(sizeof(*fnhe), GFP_ATOMIC);
		if (!fnhe)
			goto out_unlock;

		fnhe->fnhe_next = hash->chain;

		fnhe->fnhe_genid = genid;
		fnhe->fnhe_daddr = daddr;
		fnhe->fnhe_gw = gw;
		fnhe->fnhe_pmtu = pmtu;
		fnhe->fnhe_mtu_locked = lock;
		fnhe->fnhe_expires = max(1UL, expires);

		/*
		 * Fix CVE-2021-20322
		 *  +1 line
		 */
		rcu_assign_pointer(hash->chain, fnhe);

		/* Exception created; mark the cached routes for the nexthop
		 * stale, so anyone caching it rechecks if this exception
		 * applies to them.
		 */
		rt = rcu_dereference(nh->nh_rth_input);
		if (rt)
			rt->dst.obsolete = DST_OBSOLETE_KILL;

		for_each_possible_cpu(i) {
			struct rtable __rcu **prt;
			prt = per_cpu_ptr(nh->nh_pcpu_rth_output, i);
			rt = rcu_dereference(*prt);
			if (rt)
				rt->dst.obsolete = DST_OBSOLETE_KILL;
		}
	}

	fnhe->fnhe_stamp = jiffies;

out_unlock:
	spin_unlock_bh(&(*klpe_fnhe_lock));
}



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/livepatch.h>
#include <linux/vmalloc.h>
#include "livepatch_bsc1191813.h"
#include "../kallsyms_relocs.h"
#include "../shadow.h"

static int klp_resolve_fnhe_hashfun_locals(void)
{
	struct klp_kallsyms_reloc locals[] = {
		{ .addr = (void *)&klpe_fnhe_hashfun_local_fnhe_hashrnd },
		{ .addr = (void *)&klpe_fnhe_hashfun_local____done },
	};

#if IS_ENABLED(CONFIG_X86_64)
	if(!strcmp(UTS_RELEASE, "4.12.14-95.65-default")) { /* SLE12-SP4_Update_17 */
		locals[0].symname = "fnhe_hashrnd.67588";
		locals[1].symname = "___done.67591";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.68-default")) { /* SLE12-SP4_Update_18 */
		locals[0].symname = "fnhe_hashrnd.67600";
		locals[1].symname = "___done.67603";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.71-default")) { /* SLE12-SP4_Update_19 */
		locals[0].symname = "fnhe_hashrnd.67600";
		locals[1].symname = "___done.67603";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.74-default")) { /* SLE12-SP4_Update_20 */
		locals[0].symname = "fnhe_hashrnd.67600";
		locals[1].symname = "___done.67603";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.77-default")) { /* SLE12-SP4_Update_21 */
		locals[0].symname = "fnhe_hashrnd.67609";
		locals[1].symname = "___done.67612";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.80-default")) { /* SLE12-SP4_Update_22 */
		locals[0].symname = "fnhe_hashrnd.67609";
		locals[1].symname = "___done.67612";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.54-default")) { /* SLE12-SP5_Update_13 */
		locals[0].symname = "fnhe_hashrnd.70511";
		locals[1].symname = "___done.70514";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.57-default")) { /* SLE12-SP5_Update_14 */
		locals[0].symname = "fnhe_hashrnd.70517";
		locals[1].symname = "___done.70520";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.60-default")) { /* SLE12-SP5_Update_15 */
		locals[0].symname = "fnhe_hashrnd.70524";
		locals[1].symname = "___done.70527";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.63-default")) { /* SLE12-SP5_Update_16 */
		locals[0].symname = "fnhe_hashrnd.70525";
		locals[1].symname = "___done.70528";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.66-default")) { /* SLE12-SP5_Update_17 */
		locals[0].symname = "fnhe_hashrnd.70526";
		locals[1].symname = "___done.70529";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.71-default")) { /* SLE12-SP5_Update_18 */
		locals[0].symname = "fnhe_hashrnd.70533";
		locals[1].symname = "___done.70536";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.74-default")) { /* SLE12-SP5_Update_19 */
		locals[0].symname = "fnhe_hashrnd.70542";
		locals[1].symname = "___done.70545";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.77-default")) { /* SLE12-SP5_Update_20 */
		locals[0].symname = "fnhe_hashrnd.70546";
		locals[1].symname = "___done.70549";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.80-default")) { /* SLE12-SP5_Update_21 */
		locals[0].symname = "fnhe_hashrnd.70546";
		locals[1].symname = "___done.70549";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.83-default")) { /* SLE12-SP5_Update_22 */
		locals[0].symname = "fnhe_hashrnd.70562";
		locals[1].symname = "___done.70565";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.88-default")) { /* SLE12-SP5_Update_23 */
		locals[0].symname = "fnhe_hashrnd.70568";
		locals[1].symname = "___done.70571";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.91-default")) { /* SLE12-SP5_Update_24 */
		locals[0].symname = "fnhe_hashrnd.70586";
		locals[1].symname = "___done.70589";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.98-default")) { /* SLE12-SP5_Update_25 */
		locals[0].symname = "fnhe_hashrnd.70590";
		locals[1].symname = "___done.70593";

	}
#elif IS_ENABLED(CONFIG_PPC64)
	if(!strcmp(UTS_RELEASE, "4.12.14-95.65-default")) { /* SLE12-SP4_Update_17 */
		locals[0].symname = "fnhe_hashrnd.66668";
		locals[1].symname = "___done.66671";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.68-default")) { /* SLE12-SP4_Update_18 */
		locals[0].symname = "fnhe_hashrnd.66723";
		locals[1].symname = "___done.66726";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.71-default")) { /* SLE12-SP4_Update_19 */
		locals[0].symname = "fnhe_hashrnd.66723";
		locals[1].symname = "___done.66726";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.74-default")) { /* SLE12-SP4_Update_20 */
		locals[0].symname = "fnhe_hashrnd.66723";
		locals[1].symname = "___done.66726";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.77-default")) { /* SLE12-SP4_Update_21 */
		locals[0].symname = "fnhe_hashrnd.66732";
		locals[1].symname = "___done.66735";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.80-default")) { /* SLE12-SP4_Update_22 */
		locals[0].symname = "fnhe_hashrnd.66732";
		locals[1].symname = "___done.66735";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.54-default")) { /* SLE12-SP5_Update_13 */
		locals[0].symname = "fnhe_hashrnd.70328";
		locals[1].symname = "___done.70331";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.57-default")) { /* SLE12-SP5_Update_14 */
		locals[0].symname = "fnhe_hashrnd.70389";
		locals[1].symname = "___done.70392";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.60-default")) { /* SLE12-SP5_Update_15 */
		locals[0].symname = "fnhe_hashrnd.70390";
		locals[1].symname = "___done.70393";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.63-default")) { /* SLE12-SP5_Update_16 */
		locals[0].symname = "fnhe_hashrnd.70391";
		locals[1].symname = "___done.70394";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.66-default")) { /* SLE12-SP5_Update_17 */
		locals[0].symname = "fnhe_hashrnd.70381";
		locals[1].symname = "___done.70384";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.71-default")) { /* SLE12-SP5_Update_18 */
		locals[0].symname = "fnhe_hashrnd.70384";
		locals[1].symname = "___done.70387";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.74-default")) { /* SLE12-SP5_Update_19 */
		locals[0].symname = "fnhe_hashrnd.70388";
		locals[1].symname = "___done.70391";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.77-default")) { /* SLE12-SP5_Update_20 */
		locals[0].symname = "fnhe_hashrnd.70392";
		locals[1].symname = "___done.70395";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.80-default")) { /* SLE12-SP5_Update_21 */
		locals[0].symname = "fnhe_hashrnd.70392";
		locals[1].symname = "___done.70395";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.83-default")) { /* SLE12-SP5_Update_22 */
		locals[0].symname = "fnhe_hashrnd.70408";
		locals[1].symname = "___done.70411";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.88-default")) { /* SLE12-SP5_Update_23 */
		locals[0].symname = "fnhe_hashrnd.70414";
		locals[1].symname = "___done.70417";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.91-default")) { /* SLE12-SP5_Update_24 */
		locals[0].symname = "fnhe_hashrnd.70433";
		locals[1].symname = "___done.70436";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.98-default")) { /* SLE12-SP5_Update_25 */
		locals[0].symname = "fnhe_hashrnd.70437";
		locals[1].symname = "___done.70440";

	}
#elif IS_ENABLED(CONFIG_S390)
	if(!strcmp(UTS_RELEASE, "4.12.14-95.65-default")) { /* SLE12-SP4_Update_17 */
		locals[0].symname = "fnhe_hashrnd.61715";
		locals[1].symname = "___done.61718";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.68-default")) { /* SLE12-SP4_Update_18 */
		locals[0].symname = "fnhe_hashrnd.61715";
		locals[1].symname = "___done.61718";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.71-default")) { /* SLE12-SP4_Update_19 */
		locals[0].symname = "fnhe_hashrnd.61715";
		locals[1].symname = "___done.61718";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.74-default")) { /* SLE12-SP4_Update_20 */
		locals[0].symname = "fnhe_hashrnd.61715";
		locals[1].symname = "___done.61718";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.77-default")) { /* SLE12-SP4_Update_21 */
		locals[0].symname = "fnhe_hashrnd.61724";
		locals[1].symname = "___done.61727";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-95.80-default")) { /* SLE12-SP4_Update_22 */
		locals[0].symname = "fnhe_hashrnd.61724";
		locals[1].symname = "___done.61727";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.54-default")) { /* SLE12-SP5_Update_13 */
		locals[0].symname = "fnhe_hashrnd.65125";
		locals[1].symname = "___done.65128";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.57-default")) { /* SLE12-SP5_Update_14 */
		locals[0].symname = "fnhe_hashrnd.65127";
		locals[1].symname = "___done.65130";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.60-default")) { /* SLE12-SP5_Update_15 */
		locals[0].symname = "fnhe_hashrnd.65128";
		locals[1].symname = "___done.65131";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.63-default")) { /* SLE12-SP5_Update_16 */
		locals[0].symname = "fnhe_hashrnd.65129";
		locals[1].symname = "___done.65132";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.66-default")) { /* SLE12-SP5_Update_17 */
		locals[0].symname = "fnhe_hashrnd.65130";
		locals[1].symname = "___done.65133";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.71-default")) { /* SLE12-SP5_Update_18 */
		locals[0].symname = "fnhe_hashrnd.65134";
		locals[1].symname = "___done.65137";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.74-default")) { /* SLE12-SP5_Update_19 */
		locals[0].symname = "fnhe_hashrnd.65143";
		locals[1].symname = "___done.65146";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.77-default")) { /* SLE12-SP5_Update_20 */
		locals[0].symname = "fnhe_hashrnd.65147";
		locals[1].symname = "___done.65150";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.80-default")) { /* SLE12-SP5_Update_21 */
		locals[0].symname = "fnhe_hashrnd.65147";
		locals[1].symname = "___done.65150";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.83-default")) { /* SLE12-SP5_Update_22 */
		locals[0].symname = "fnhe_hashrnd.65163";
		locals[1].symname = "___done.65166";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.88-default")) { /* SLE12-SP5_Update_23 */
		locals[0].symname = "fnhe_hashrnd.65169";
		locals[1].symname = "___done.65172";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.91-default")) { /* SLE12-SP5_Update_24 */
		locals[0].symname = "fnhe_hashrnd.65173";
		locals[1].symname = "___done.65176";

	} else if(!strcmp(UTS_RELEASE, "4.12.14-122.98-default")) { /* SLE12-SP5_Update_25 */
		locals[0].symname = "fnhe_hashrnd.65177";
		locals[1].symname = "___done.65180";

	}
#else
#error "Architecture not supported by livepatch."
#endif
	else {
		WARN(1, "kernel version not supported by livepatch\n");
		return -ENOTSUPP;

	}

	return __klp_resolve_kallsyms_relocs(locals, ARRAY_SIZE(locals));
}

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "fill_route_from_fnhe", (void *)&klpe_fill_route_from_fnhe },
	{ "fnhe_flush_routes", (void *)&klpe_fnhe_flush_routes },
	{ "fnhe_lock", (void *)&klpe_fnhe_lock },
};


#define KLP_BSC1191813_SHARED_STATE_ID KLP_SHADOW_ID(1191813, 0)

static int klp_bsc1191813_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	struct klp_bsc1191813_shared_state *s = shadow_data;

	memset(s, 0, sizeof(*s));

	return 0;
}

static void __klp_bsc1191813_put_shared_state(void);

/* Must be called with module_mutex held. */
static int __klp_bsc1191813_get_shared_state(void)
{
	klp_bsc1191813_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1191813_SHARED_STATE_ID,
					sizeof(*klp_bsc1191813_shared_state),
					GFP_KERNEL,
					klp_bsc1191813_init_shared_state, NULL);
	if (!klp_bsc1191813_shared_state)
		return -ENOMEM;

	++klp_bsc1191813_shared_state->refcount;

	if (!klp_bsc1191813_shared_state->eviction_history) {
		struct klp_bsc1191813_shared_state *s;

		s = klp_bsc1191813_shared_state;
		s->eviction_history = vzalloc(sizeof(*s->eviction_history));
		if (!s->eviction_history) {
			__klp_bsc1191813_put_shared_state();
			return -ENOMEM;
		}
	}

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1191813_put_shared_state(void)
{
	--klp_bsc1191813_shared_state->refcount;

	if (!klp_bsc1191813_shared_state->refcount) {
		vfree(klp_bsc1191813_shared_state->eviction_history);
		klp_shadow_free(NULL, KLP_BSC1191813_SHARED_STATE_ID, NULL);
	}

	klp_bsc1191813_shared_state = NULL;
}


int livepatch_bsc1191813_init(void)
{
	int ret;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	if (ret)
		return ret;

	ret = klp_resolve_fnhe_hashfun_locals();
	if (ret)
		return ret;

	mutex_lock(&module_mutex);
	ret = __klp_bsc1191813_get_shared_state();
	mutex_unlock(&module_mutex);

	return ret;
}

void livepatch_bsc1191813_cleanup(void)
{
	mutex_lock(&module_mutex);
	__klp_bsc1191813_put_shared_state();
	mutex_unlock(&module_mutex);
}
