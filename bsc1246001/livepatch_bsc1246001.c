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

/* klp-ccp: from include/asm-generic/unaligned.h */
#define __ASM_GENERIC_UNALIGNED_H

/* klp-ccp: from include/net/netlabel.h */
struct calipso_doi;

struct netlbl_lsm_secattr;

/* klp-ccp: from net/ipv6/calipso.c */
#include <linux/atomic.h>
#include <linux/bug.h>
#include <asm/unaligned.h>

extern struct ipv6_opt_hdr *
calipso_opt_insert(struct ipv6_opt_hdr *hop,
		   const struct calipso_doi *doi_def,
		   const struct netlbl_lsm_secattr *secattr);

extern int calipso_opt_del(struct ipv6_opt_hdr *hop,
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

	new = calipso_opt_insert(old, doi_def, secattr);
	if (IS_ERR(new))
		return PTR_ERR(new);

	txopts = ipv6_renew_options(sk, req_inet->ipv6_opt, IPV6_HOPOPTS, new);

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

	if (calipso_opt_del(req_inet->ipv6_opt->hopopt, &new))
		return; /* Nothing to do */

	txopts = ipv6_renew_options(sk, req_inet->ipv6_opt, IPV6_HOPOPTS, new);

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

#include <linux/livepatch.h>

extern typeof(calipso_opt_del) calipso_opt_del
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, calipso_opt_del);
extern typeof(calipso_opt_insert) calipso_opt_insert
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, calipso_opt_insert);
extern typeof(ipv6_renew_options) ipv6_renew_options
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipv6_renew_options);
