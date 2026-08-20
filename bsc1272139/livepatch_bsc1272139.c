/*
 * livepatch_bsc1272139
 *
 * Fix for CVE-2026-52956, bsc#1272139
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1272139.h"


/* klp-ccp: from net/ceph/auth_x.c */
#include <linux/ceph/ceph_debug.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/ceph/decode.h>
#include <linux/ceph/auth.h>
#include <linux/ceph/ceph_features.h>
#include <linux/ceph/libceph.h>
#include <linux/ceph/messenger.h>
/* klp-ccp: from net/ceph/crypto.h */
#include <linux/ceph/types.h>
#include <linux/ceph/buffer.h>

int ceph_crypt(const struct ceph_crypto_key *key, bool encrypt,
	       void *buf, int buf_len, int in_len, int *pout_len);

/* klp-ccp: from net/ceph/auth_x.h */
#include <linux/rbtree.h>
#include <linux/ceph/auth.h>

/* klp-ccp: from net/ceph/auth_x_protocol.h */
#define CEPHX_ENC_MAGIC 0xff009cad8826aa55ull

struct ceph_x_encrypt_header {
	__u8 struct_v;
	__le64 magic;
} __attribute__ ((packed));

/* klp-ccp: from net/ceph/auth_x.c */
int klpp___ceph_x_decrypt(struct ceph_crypto_key *secret, void *p,
			    int ciphertext_len)
{
	struct ceph_x_encrypt_header *hdr = p;
	int plaintext_len;
	int ret;

	ret = ceph_crypt(secret, false, p, ciphertext_len, ciphertext_len,
			 &plaintext_len);
	if (ret)
		return ret;

	if (plaintext_len < sizeof(*hdr)) {
		pr_err("%s plaintext too small %d\n", __func__, plaintext_len);
		return -EINVAL;
	}

	if (le64_to_cpu(hdr->magic) != CEPHX_ENC_MAGIC) {
		pr_err("%s bad magic\n", __func__);
		return -EINVAL;
	}

	return plaintext_len - sizeof(*hdr);
}


#include <linux/livepatch.h>

extern typeof(ceph_crypt) ceph_crypt
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_crypt);
