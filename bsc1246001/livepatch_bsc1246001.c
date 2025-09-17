/*
 * livepatch_bsc1246001
 *
 * Fix for CVE-2025-38181, bsc#1246001
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


/* klp-ccp: from net/ipv6/calipso.c */
#include <linux/init.h>
#include <linux/types.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/jhash.h>
#include <linux/audit.h>
#include <linux/slab.h>
#include <net/ip.h>

/* klp-ccp: from include/net/ipv6.h */
static struct ipv6_txoptions *
(*klpe_ipv6_renew_options_kern)(struct sock *sk,
			struct ipv6_txoptions *opt,
			int newtype,
			struct ipv6_opt_hdr *newopt,
			int newoptlen);

/* klp-ccp: from include/net/netlabel.h */
struct calipso_doi;

struct netlbl_lsm_secattr;

/* klp-ccp: from net/ipv6/calipso.c */
#include <linux/atomic.h>
#include <linux/bug.h>
#include <asm/unaligned.h>

static struct ipv6_opt_hdr *
(*klpe_calipso_opt_insert)(struct ipv6_opt_hdr *hop,
		   const struct calipso_doi *doi_def,
		   const struct netlbl_lsm_secattr *secattr);

static int (*klpe_calipso_opt_del)(struct ipv6_opt_hdr *hop,
			   struct ipv6_opt_hdr **new);

int klpp_calipso_req_setattr(struct request_sock *req,
			       const struct calipso_doi *doi_def,
			       const struct netlbl_lsm_secattr *secattr)
{
	struct ipv6_txoptions *txopts;
	struct inet_request_sock *req_inet = inet_rsk(req);
	struct ipv6_opt_hdr *old, *new;
	struct sock *sk = sk_to_full_sk(req_to_sk(req));

	/* sk is NULL for SYN+ACK w/ SYN Cookie */
	if (!sk)
		return -ENOMEM;

	if (req_inet->ipv6_opt && req_inet->ipv6_opt->hopopt)
		old = req_inet->ipv6_opt->hopopt;
	else
		old = NULL;

	new = (*klpe_calipso_opt_insert)(old, doi_def, secattr);
	if (IS_ERR(new))
		return PTR_ERR(new);

	txopts = (*klpe_ipv6_renew_options_kern)(sk, req_inet->ipv6_opt, IPV6_HOPOPTS,
					 new, new ? ipv6_optlen(new) : 0);

	kfree(new);

	if (IS_ERR(txopts))
		return PTR_ERR(txopts);

	txopts = xchg(&req_inet->ipv6_opt, txopts);
	if (txopts) {
		atomic_sub(txopts->tot_len, &sk->sk_omem_alloc);
		txopt_put(txopts);
	}

	return 0;
}

void klpp_calipso_req_delattr(struct request_sock *req)
{
	struct inet_request_sock *req_inet = inet_rsk(req);
	struct ipv6_opt_hdr *new;
	struct ipv6_txoptions *txopts;
	struct sock *sk = sk_to_full_sk(req_to_sk(req));

	/* sk is NULL for SYN+ACK w/ SYN Cookie */
	if (!sk)
		return;

	if (!req_inet->ipv6_opt || !req_inet->ipv6_opt->hopopt)
		return;

	if ((*klpe_calipso_opt_del)(req_inet->ipv6_opt->hopopt, &new))
		return; /* Nothing to do */

	txopts = (*klpe_ipv6_renew_options_kern)(sk, req_inet->ipv6_opt, IPV6_HOPOPTS,
					 new, new ? ipv6_optlen(new) : 0);

	if (!IS_ERR(txopts)) {
		txopts = xchg(&req_inet->ipv6_opt, txopts);
		if (txopts) {
			atomic_sub(txopts->tot_len, &sk->sk_omem_alloc);
			txopt_put(txopts);
		}
	}
	kfree(new);
}


#include "livepatch_bsc1246001.h"

#include <linux/kernel.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "calipso_opt_del", (void *)&klpe_calipso_opt_del },
	{ "calipso_opt_insert", (void *)&klpe_calipso_opt_insert },
	{ "ipv6_renew_options_kern", (void *)&klpe_ipv6_renew_options_kern },
};

int livepatch_bsc1246001_init(void)
{
	return __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
}

