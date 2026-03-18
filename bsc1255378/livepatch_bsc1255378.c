/*
 * livepatch_bsc1255378
 *
 * Fix for CVE-2025-68284, bsc#1255378
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

/* klp-ccp: from net/ceph/auth_x.c */
#include <linux/ceph/ceph_debug.h>

#include <linux/err.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>

#include <linux/ceph/decode.h>
#include <linux/ceph/auth.h>

/* klp-ccp: from net/ceph/auth_x.c */
#include <linux/ceph/messenger.h>

/* klp-ccp: from net/ceph/crypto.h */
#include <linux/ceph/types.h>
#include <linux/ceph/buffer.h>

struct ceph_crypto_key {
	int type;
	struct ceph_timespec created;
	int len;
	void *key;
	struct crypto_sync_skcipher *tfm;
};

/* klp-ccp: from net/ceph/auth_x.h */
#include <linux/rbtree.h>

#include <linux/ceph/auth.h>

/* klp-ccp: from net/ceph/auth_x_protocol.h */
#define CEPHX_GET_AUTH_SESSION_KEY      0x0100
#define CEPHX_GET_PRINCIPAL_SESSION_KEY 0x0200

struct ceph_x_server_challenge {
	__u8 struct_v;
	__le64 server_challenge;
} __attribute__ ((packed));

struct ceph_x_encrypt_header {
	__u8 struct_v;
	__le64 magic;
} __attribute__ ((packed));

/* klp-ccp: from net/ceph/auth_x.h */
struct ceph_x_ticket_handler {
	struct rb_node node;
	unsigned int service;

	struct ceph_crypto_key session_key;
	bool have_key;

	u64 secret_id;
	struct ceph_buffer *ticket_blob;

	time64_t renew_after, expires;
};

#define CEPHX_AU_ENC_BUF_LEN	128  /* big enough for encrypted blob */

struct ceph_x_authorizer {
	struct ceph_authorizer base;
	struct ceph_crypto_key session_key;
	struct ceph_buffer *buf;
	unsigned int service;
	u64 nonce;
	u64 secret_id;
	char enc_buf[CEPHX_AU_ENC_BUF_LEN] __aligned(8);
};

struct ceph_x_info {
	struct ceph_crypto_key secret;

	bool starting;
	u64 server_challenge;

	unsigned int have_keys;
	struct rb_root ticket_handlers;

	struct ceph_x_authorizer auth_authorizer;
};


int klpp_ceph_x_handle_reply(struct ceph_auth_client *ac, u64 global_id,
			     void *buf, void *end,
			     u8 *session_key, int *session_key_len,
			     u8 *con_secret, int *con_secret_len);

/* klp-ccp: from net/ceph/auth_x.c */
static int ceph_x_encrypt_offset(void)
{
	return sizeof(u32) + sizeof(struct ceph_x_encrypt_header);
}

extern int ceph_x_decrypt(struct ceph_crypto_key *secret, void **p, void *end);

static struct ceph_x_ticket_handler *
get_ticket_handler(struct ceph_auth_client *ac, int service)
{
	struct ceph_x_ticket_handler *th;
	struct ceph_x_info *xi = ac->private;
	struct rb_node *parent = NULL, **p = &xi->ticket_handlers.rb_node;

	while (*p) {
		parent = *p;
		th = rb_entry(parent, struct ceph_x_ticket_handler, node);
		if (service < th->service)
			p = &(*p)->rb_left;
		else if (service > th->service)
			p = &(*p)->rb_right;
		else
			return th;
	}

	/* add it */
	th = kzalloc(sizeof(*th), GFP_NOFS);
	if (!th)
		return ERR_PTR(-ENOMEM);
	th->service = service;
	rb_link_node(&th->node, parent, p);
	rb_insert_color(&th->node, &xi->ticket_handlers);
	return th;
}

extern int ceph_x_proc_ticket_reply(struct ceph_auth_client *ac,
				    struct ceph_crypto_key *secret,
				    void **p, void *end);

extern int decode_con_secret(void **p, void *end, u8 *con_secret,
			     int *con_secret_len);

static int handle_auth_session_key(struct ceph_auth_client *ac, u64 global_id,
				   void **p, void *end,
				   u8 *session_key, int *session_key_len,
				   u8 *con_secret, int *con_secret_len)
{
	struct ceph_x_info *xi = ac->private;
	struct ceph_x_ticket_handler *th;
	void *dp, *dend;
	int len;
	int ret;

	/* AUTH ticket */
	ret = ceph_x_proc_ticket_reply(ac, &xi->secret, p, end);
	if (ret)
		return ret;

	ceph_auth_set_global_id(ac, global_id);
	if (*p == end) {
		/* pre-nautilus (or didn't request service tickets!) */
		WARN_ON(session_key || con_secret);
		return 0;
	}

	th = get_ticket_handler(ac, CEPH_ENTITY_TYPE_AUTH);
	if (IS_ERR(th))
		return PTR_ERR(th);

	if (session_key) {
		memcpy(session_key, th->session_key.key, th->session_key.len);
		*session_key_len = th->session_key.len;
	}

	/* connection secret */
	ceph_decode_32_safe(p, end, len, e_inval);
	ceph_decode_need(p, end, len, e_inval);
	dout("%s connection secret blob len %d\n", __func__, len);
	if (len > 0) {
		dp = *p + ceph_x_encrypt_offset();
		ret = ceph_x_decrypt(&th->session_key, p, *p + len);
		if (ret < 0)
			return ret;

		dout("%s decrypted %d bytes\n", __func__, ret);
		dend = dp + ret;

		ret = decode_con_secret(&dp, dend, con_secret, con_secret_len);
		if (ret)
			return ret;
	}

	/* service tickets */
	ceph_decode_32_safe(p, end, len, e_inval);
	ceph_decode_need(p, end, len, e_inval);
	dout("%s service tickets blob len %d\n", __func__, len);
	if (len > 0) {
		ret = ceph_x_proc_ticket_reply(ac, &th->session_key,
					       p, *p + len);
		if (ret)
			return ret;
	}

	return 0;

e_inval:
	return -EINVAL;
}

int klpp_ceph_x_handle_reply(struct ceph_auth_client *ac, u64 global_id,
			     void *buf, void *end,
			     u8 *session_key, int *session_key_len,
			     u8 *con_secret, int *con_secret_len)
{
	struct ceph_x_info *xi = ac->private;
	struct ceph_x_ticket_handler *th;
	int len = end - buf;
	int result;
	void *p;
	int op;
	int ret;

	if (xi->starting) {
		/* it's a hello */
		struct ceph_x_server_challenge *sc = buf;

		if (len != sizeof(*sc))
			return -EINVAL;
		xi->server_challenge = le64_to_cpu(sc->server_challenge);
		dout("handle_reply got server challenge %llx\n",
		     xi->server_challenge);
		xi->starting = false;
		xi->have_keys &= ~CEPH_ENTITY_TYPE_AUTH;
		return -EAGAIN;
	}

	p = buf;
	ceph_decode_16_safe(&p, end, op, e_inval);
	ceph_decode_32_safe(&p, end, result, e_inval);
	dout("handle_reply op %d result %d\n", op, result);
	switch (op) {
	case CEPHX_GET_AUTH_SESSION_KEY:
		/* AUTH ticket + [connection secret] + service tickets */
		ret = handle_auth_session_key(ac, global_id, &p, end,
					      session_key, session_key_len,
					      con_secret, con_secret_len);
		break;

	case CEPHX_GET_PRINCIPAL_SESSION_KEY:
		th = get_ticket_handler(ac, CEPH_ENTITY_TYPE_AUTH);
		if (IS_ERR(th))
			return PTR_ERR(th);

		/* service tickets */
		ret = ceph_x_proc_ticket_reply(ac, &th->session_key, &p, end);
		break;

	default:
		return -EINVAL;
	}
	if (ret)
		return ret;
	if (ac->want_keys == xi->have_keys)
		return 0;
	return -EAGAIN;

e_inval:
	return -EINVAL;
}


#include "livepatch_bsc1255378.h"

#include <linux/livepatch.h>

extern typeof(ceph_auth_set_global_id) ceph_auth_set_global_id
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_auth_set_global_id);
extern typeof(ceph_x_decrypt) ceph_x_decrypt
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_x_decrypt);
extern typeof(ceph_x_proc_ticket_reply) ceph_x_proc_ticket_reply
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_x_proc_ticket_reply);
extern typeof(decode_con_secret) decode_con_secret
	 KLP_RELOC_SYMBOL(libceph, libceph, decode_con_secret);
