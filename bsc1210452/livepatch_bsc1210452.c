/*
 * livepatch_bsc1210452
 *
 * Fix for CVE-2023-28466, bsc#1210452
 *
 *  Upstream commit:
 *  49c47cc21b5b ("net: tls: fix possible race condition between
 *                 do_tls_getsockopt_conf() and do_tls_setsockopt_conf()")
 *
 *  SLE12-SP5 commit:
 *  6a60b3048a6ba7e1ea7a2890ae0d941e2a66ef1d
 *
 *  SLE15-SP1 commit:
 *  cbbbf9951c31851ea0d003fd1be35d268eeefc4f
 *
 *  SLE15-SP2 and -SP3 commit:
 *  5f7c4a63f1d6b4a7c670c8144e656fe113baf628
 *
 *  SLE15-SP4 commit:
 *  3dab1fe8f7198493e869aa2328e740f7c9994399
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

#if !IS_MODULE(CONFIG_TLS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/tls/tls_main.c */
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/highmem.h>
#include <linux/netdevice.h>
#include <net/tls.h>

static int klpp_do_tls_getsockopt_tx(struct sock *sk, char __user *optval,
				int __user *optlen)
{
	int rc = 0;
	struct tls_context *ctx = tls_get_ctx(sk);
	struct tls_crypto_info *crypto_info;
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	if (!optval || (len < sizeof(*crypto_info))) {
		rc = -EINVAL;
		goto out;
	}

	if (!ctx) {
		rc = -EBUSY;
		goto out;
	}

	/* get user crypto info */
	crypto_info = &ctx->crypto_send.info;

	if (!TLS_CRYPTO_INFO_READY(crypto_info)) {
		rc = -EBUSY;
		goto out;
	}

	if (len == sizeof(*crypto_info)) {
		if (copy_to_user(optval, crypto_info, sizeof(*crypto_info)))
			rc = -EFAULT;
		goto out;
	}

	switch (crypto_info->cipher_type) {
	case TLS_CIPHER_AES_GCM_128: {
		struct tls12_crypto_info_aes_gcm_128 *
		  crypto_info_aes_gcm_128 =
		  container_of(crypto_info,
			       struct tls12_crypto_info_aes_gcm_128,
			       info);

		if (len != sizeof(*crypto_info_aes_gcm_128)) {
			rc = -EINVAL;
			goto out;
		}
		memcpy(crypto_info_aes_gcm_128->iv,
		       ctx->tx.iv + TLS_CIPHER_AES_GCM_128_SALT_SIZE,
		       TLS_CIPHER_AES_GCM_128_IV_SIZE);
		memcpy(crypto_info_aes_gcm_128->rec_seq, ctx->tx.rec_seq,
		       TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
		if (copy_to_user(optval,
				 crypto_info_aes_gcm_128,
				 sizeof(*crypto_info_aes_gcm_128)))
			rc = -EFAULT;
		break;
	}
	default:
		rc = -EINVAL;
	}

out:
	return rc;
}

static int klpp_do_tls_getsockopt(struct sock *sk, int optname,
			     char __user *optval, int __user *optlen)
{
	int rc = 0;

	lock_sock(sk);

	switch (optname) {
	case TLS_TX:
		rc = klpp_do_tls_getsockopt_tx(sk, optval, optlen);
		break;
	default:
		rc = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);

	return rc;
}

int klpp_tls_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct tls_context *ctx = tls_get_ctx(sk);

	if (level != SOL_TLS)
		return ctx->getsockopt(sk, level, optname, optval, optlen);

	return klpp_do_tls_getsockopt(sk, optname, optval, optlen);
}
