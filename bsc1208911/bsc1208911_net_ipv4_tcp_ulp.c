/*
 * bsc1208911_net_ipv4_tcp_ulp
 *
 * Fix for CVE-2023-0461, bsc#1208911
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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


/* klp-ccp: from net/ipv4/tcp_ulp.c */
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <net/tcp.h>

/* klp-ccp: from include/net/tcp.h */
int klpp_tcp_set_ulp(struct sock *sk, const char *name);

/* klp-ccp: from net/ipv4/tcp_ulp.c */
static struct list_head (*klpe_tcp_ulp_list);

static struct tcp_ulp_ops *klpr_tcp_ulp_find(const char *name)
{
	struct tcp_ulp_ops *e;

	list_for_each_entry_rcu(e, &(*klpe_tcp_ulp_list), list,
				lockdep_is_held(&tcp_ulp_list_lock)) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

static const struct tcp_ulp_ops *klpr___tcp_ulp_find_autoload(const char *name)
{
	const struct tcp_ulp_ops *ulp = NULL;

	rcu_read_lock();
	ulp = klpr_tcp_ulp_find(name);

#ifdef CONFIG_MODULES
	if (!ulp && capable(CAP_NET_ADMIN)) {
		rcu_read_unlock();
		request_module("tcp-ulp-%s", name);
		rcu_read_lock();
		ulp = klpr_tcp_ulp_find(name);
	}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	if (!ulp || !try_module_get(ulp->owner))
		ulp = NULL;

	rcu_read_unlock();
	return ulp;
}

static int klpp___tcp_set_ulp(struct sock *sk, const struct tcp_ulp_ops *ulp_ops)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	int err;

	err = -EEXIST;
	if (icsk->icsk_ulp_ops)
		goto out_err;

	err = -EINVAL;
	if (!ulp_ops->clone && sk->sk_state == TCP_LISTEN)
		goto out_err;

	err = ulp_ops->init(sk);
	if (err)
		goto out_err;

	icsk->icsk_ulp_ops = ulp_ops;
	return 0;
out_err:
	module_put(ulp_ops->owner);
	return err;
}

int klpp_tcp_set_ulp(struct sock *sk, const char *name)
{
	const struct tcp_ulp_ops *ulp_ops;

	sock_owned_by_me(sk);

	ulp_ops = klpr___tcp_ulp_find_autoload(name);
	if (!ulp_ops)
		return -ENOENT;

	return klpp___tcp_set_ulp(sk, ulp_ops);
}




#include <linux/kernel.h>
#include "livepatch_bsc1208911.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tcp_ulp_list", (void *)&klpe_tcp_ulp_list },
};

int bsc1208911_net_ipv4_tcp_ulp_init(void)
{
	return klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

