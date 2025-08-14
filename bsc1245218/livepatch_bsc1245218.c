/*
 * livepatch_bsc1245218
 *
 * Fix for CVE-2025-38079, bsc#1245218
 *
 *  Upstream commit:
 *  b2df03ed4052 ("crypto: algif_hash - fix double free in hash_accept")
 *
 *  SLE12-SP5 commit:
 *  288b933025a59630217981873704f27132e872e0
 *
 *  SLE15-SP3 commit:
 *  7f960baa68227ae380598c0b066622b821552b9b
 *
 *  SLE15-SP4 and -SP5 commit:
 *  6c6cb3dfd3a512f2c4fe95f5b522e165e3d26c06
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

/* klp-ccp: from include/crypto/if_alg.h */
static int (*klpe_af_alg_accept)(struct sock *sk, struct socket *newsock, bool kern);

/* klp-ccp: from crypto/algif_hash.c */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <linux/net.h>
#include <net/sock.h>

struct hash_ctx {
	struct af_alg_sgl sgl;

	u8 *result;

	struct af_alg_completion completion;

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
	char state[crypto_ahash_statesize(crypto_ahash_reqtfm(req)) ? : 1];
	struct sock *sk2;
	struct alg_sock *ask2;
	struct hash_ctx *ctx2;
	bool more;
	int err;

	lock_sock(sk);
	more = ctx->more;
	err = more ? crypto_ahash_export(req, state) : 0;
	release_sock(sk);

	if (err)
		return err;

	err = (*klpe_af_alg_accept)(ask->parent, newsock, kern);
	if (err)
		return err;

	sk2 = newsock->sk;
	ask2 = alg_sk(sk2);
	ctx2 = ask2->private;
	ctx2->more = more;

	if (!more)
		return err;

	err = crypto_ahash_import(&ctx2->req, state);

	return err;
}


#include "livepatch_bsc1245218.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "algif_hash"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "af_alg_accept", (void *)&klpe_af_alg_accept, "af_alg" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1245218_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1245218_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
