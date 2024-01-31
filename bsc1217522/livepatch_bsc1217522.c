/*
 * livepatch_bsc1217522
 *
 * Fix for CVE-2023-6176, bsc#1217522
 *
 *  Upstream commit:
 *  cfaa80c91f6f ("net/tls: do not free tls_rec on async operation in bpf_exec_tx_verdict()")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  20678d90592bea5413c5a76baf52691c95a349b7
 *
 *  SLE15-SP4 and -SP5 commit:
 *  4d4ef94e1f2d92ff4f31fce13cecf381ddd9f263
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

/* klp-ccp: from net/tls/tls_sw.c */
#include <linux/sched/signal.h>
#include <linux/module.h>

/* klp-ccp: from net/tls/tls_sw.c */
#include <crypto/aead.h>
#include <net/strparser.h>
#include <net/tls.h>

static void (*klpe_tls_free_rec)(struct sock *sk, struct tls_rec *rec);

static void klpr_tls_free_open_rec(struct sock *sk)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct tls_rec *rec = ctx->open_rec;

	if (rec) {
		(*klpe_tls_free_rec)(sk, rec);
		ctx->open_rec = NULL;
	}
}

static int (*klpe_tls_push_record)(struct sock *sk, int flags,
			   unsigned char record_type);

int klpp_bpf_exec_tx_verdict(struct sk_msg *msg, struct sock *sk,
			       bool full_record, u8 record_type,
			       ssize_t *copied, int flags)
{
	struct tls_context *tls_ctx = tls_get_ctx(sk);
	struct tls_sw_context_tx *ctx = tls_sw_ctx_tx(tls_ctx);
	struct sk_msg msg_redir = { };
	struct sk_psock *psock;
	struct sock *sk_redir;
	struct tls_rec *rec;
	bool enospc, policy;
	int err = 0, send;
	u32 delta = 0;

	policy = !(flags & MSG_SENDPAGE_NOPOLICY);
	psock = sk_psock_get(sk);
	if (!psock || !policy) {
		err = (*klpe_tls_push_record)(sk, flags, record_type);
		if (err && err != -EINPROGRESS && sk->sk_err == EBADMSG) {
			*copied -= sk_msg_free(sk, msg);
			klpr_tls_free_open_rec(sk);
			err = -sk->sk_err;
		}
		if (psock)
			sk_psock_put(sk, psock);
		return err;
	}
more_data:
	enospc = sk_msg_full(msg);
	if (psock->eval == __SK_NONE) {
		delta = msg->sg.size;
		psock->eval = sk_psock_msg_verdict(sk, psock, msg);
		delta -= msg->sg.size;
	}
	if (msg->cork_bytes && msg->cork_bytes > msg->sg.size &&
	    !enospc && !full_record) {
		err = -ENOSPC;
		goto out_err;
	}
	msg->cork_bytes = 0;
	send = msg->sg.size;
	if (msg->apply_bytes && msg->apply_bytes < send)
		send = msg->apply_bytes;

	switch (psock->eval) {
	case __SK_PASS:
		err = (*klpe_tls_push_record)(sk, flags, record_type);
		if (err && err != -EINPROGRESS && sk->sk_err == EBADMSG) {
			*copied -= sk_msg_free(sk, msg);
			klpr_tls_free_open_rec(sk);
			err = -sk->sk_err;
			goto out_err;
		}
		break;
	case __SK_REDIRECT:
		sk_redir = psock->sk_redir;
		memcpy(&msg_redir, msg, sizeof(*msg));
		if (msg->apply_bytes < send)
			msg->apply_bytes = 0;
		else
			msg->apply_bytes -= send;
		sk_msg_return_zero(sk, msg, send);
		msg->sg.size -= send;
		release_sock(sk);
		err = tcp_bpf_sendmsg_redir(sk_redir, &msg_redir, send, flags);
		lock_sock(sk);
		if (err < 0) {
			*copied -= sk_msg_free_nocharge(sk, &msg_redir);
			msg->sg.size = 0;
		}
		if (msg->sg.size == 0)
			klpr_tls_free_open_rec(sk);
		break;
	case __SK_DROP:
	default:
		sk_msg_free_partial(sk, msg, send);
		if (msg->apply_bytes < send)
			msg->apply_bytes = 0;
		else
			msg->apply_bytes -= send;
		if (msg->sg.size == 0)
			klpr_tls_free_open_rec(sk);
		*copied -= (send + delta);
		err = -EACCES;
	}

	if (likely(!err)) {
		bool reset_eval = !ctx->open_rec;

		rec = ctx->open_rec;
		if (rec) {
			msg = &rec->msg_plaintext;
			if (!msg->apply_bytes)
				reset_eval = true;
		}
		if (reset_eval) {
			psock->eval = __SK_NONE;
			if (psock->sk_redir) {
				sock_put(psock->sk_redir);
				psock->sk_redir = NULL;
			}
		}
		if (rec)
			goto more_data;
	}
 out_err:
	sk_psock_put(sk, psock);
	return err;
}



#include "livepatch_bsc1217522.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "tls"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "tls_free_rec", (void *)&klpe_tls_free_rec, "tls" },
	{ "tls_push_record", (void *)&klpe_tls_push_record, "tls" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1217522_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1217522_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
