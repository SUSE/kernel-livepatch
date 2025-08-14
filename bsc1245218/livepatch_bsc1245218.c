/*
 * livepatch_bsc1245218
 *
 * Fix for CVE-2025-38079, bsc#1245218
 *
 *  Upstream commit:
 *  b2df03ed4052 ("crypto: algif_hash - fix double free in hash_accept")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  891cb3de33301928360544d71e5bd3abf6abc477
 *
 *  SLE MICRO-6-0 commit:
 *  891cb3de33301928360544d71e5bd3abf6abc477
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Marco Crivellari <marco.crivellari@suse.com>
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

/* klp-ccp: from crypto/algif_hash.c */
#include <crypto/hash.h>
#include <crypto/if_alg.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/net.h>
#include <net/sock.h>

struct hash_ctx {
	struct af_alg_sgl sgl;

	u8 *result;

	struct crypto_wait wait;

	unsigned int len;
	bool more;

	struct ahash_request req;
};

int klpp_hash_accept(struct socket *sock, struct socket *newsock, int flags,
		       bool kern)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct hash_ctx *ctx = ask->private;
	struct ahash_request *req = &ctx->req;
	struct crypto_ahash *tfm;
	struct sock *sk2;
	struct alg_sock *ask2;
	struct hash_ctx *ctx2;
	char *state;
	bool more;
	int err;

	tfm = crypto_ahash_reqtfm(req);
	state = kmalloc(crypto_ahash_statesize(tfm), GFP_KERNEL);
	err = -ENOMEM;
	if (!state)
		goto out;

	lock_sock(sk);
	more = ctx->more;
	err = more ? crypto_ahash_export(req, state) : 0;
	release_sock(sk);

	if (err)
		goto out_free_state;

	err = af_alg_accept(ask->parent, newsock, kern);
	if (err)
		goto out_free_state;

	sk2 = newsock->sk;
	ask2 = alg_sk(sk2);
	ctx2 = ask2->private;
	ctx2->more = more;

	if (!more)
		goto out_free_state;

	err = crypto_ahash_import(&ctx2->req, state);

out_free_state:
	kfree_sensitive(state);

out:
	return err;
}


#include "livepatch_bsc1245218.h"

#include <linux/livepatch.h>

extern typeof(af_alg_accept) af_alg_accept
	 KLP_RELOC_SYMBOL(algif_hash, af_alg, af_alg_accept);
