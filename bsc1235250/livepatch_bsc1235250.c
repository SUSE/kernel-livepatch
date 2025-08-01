/*
 * livepatch_bsc1235250
 *
 * Fix for CVE-2024-56664, bsc#1235250
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


/* klp-ccp: from net/core/sock_map.c */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/workqueue.h>
#include <linux/skmsg.h>
#include <linux/list.h>
#include <linux/jhash.h>

struct bpf_stab {
	struct bpf_map map;
	struct sock **sks;
	struct sk_psock_progs progs;
	spinlock_t lock;
};

static void (*klpe_sock_map_unref)(struct sock *sk, void *link_raw);

int klpp___sock_map_delete(struct bpf_stab *stab, struct sock *sk_test,
			     struct sock **psk)
{
	struct sock *sk = NULL;
	int err = 0;

	if (irqs_disabled())
		return -EOPNOTSUPP; /* locks here are hardirq-unsafe */

	spin_lock_bh(&stab->lock);
	if (!sk_test || sk_test == *psk)
		sk = xchg(psk, NULL);

	if (likely(sk))
		(*klpe_sock_map_unref)(sk, psk);
	else
		err = -EINVAL;

	spin_unlock_bh(&stab->lock);
	return err;
}


#include "livepatch_bsc1235250.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sock_map_unref", (void *)&klpe_sock_map_unref },
};

int livepatch_bsc1235250_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

