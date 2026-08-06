/*
 * livepatch_bsc1269196
 *
 * Fix for CVE-2026-52972, bsc#1269196
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


#include "livepatch_bsc1269196.h"


/* klp-ccp: from crypto/af_alg.c */
#include <linux/atomic.h>
#include <crypto/if_alg.h>

/* klp-ccp: from include/crypto/if_alg.h */
int klpp_af_alg_sendmsg(struct socket *sock, struct msghdr *msg, size_t size,
		   unsigned int ivsize);

/* klp-ccp: from crypto/af_alg.c */
#include <linux/crypto.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/rwsem.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/string.h>
#include <keys/user-type.h>
#include <keys/trusted-type.h>
#include <keys/encrypted-type.h>

static int klpp_af_alg_cmsg_send(struct msghdr *msg, struct af_alg_control *con)
{
	struct cmsghdr *cmsg;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;
		if (cmsg->cmsg_level != SOL_ALG)
			continue;

		switch (cmsg->cmsg_type) {
		case ALG_SET_IV:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(*con->iv)))
				return -EINVAL;
			con->iv = (void *)CMSG_DATA(cmsg);
			if (cmsg->cmsg_len < CMSG_LEN(con->iv->ivlen +
						      sizeof(*con->iv)))
				return -EINVAL;
			break;

		case ALG_SET_OP:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(u32)))
				return -EINVAL;
			con->op = *(u32 *)CMSG_DATA(cmsg);
			break;

		case ALG_SET_AEAD_ASSOCLEN:
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(u32)))
				return -EINVAL;
			con->aead_assoclen = *(u32 *)CMSG_DATA(cmsg);
			if (con->aead_assoclen >= 0x80000000u)
				return -EINVAL;
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

static int af_alg_alloc_tsgl(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct af_alg_ctx *ctx = ask->private;
	struct af_alg_tsgl *sgl;
	struct scatterlist *sg = NULL;

	sgl = list_entry(ctx->tsgl_list.prev, struct af_alg_tsgl, list);
	if (!list_empty(&ctx->tsgl_list))
		sg = sgl->sg;

	if (!sg || sgl->cur >= MAX_SGL_ENTS) {
		sgl = sock_kmalloc(sk,
				   struct_size(sgl, sg, (MAX_SGL_ENTS + 1)),
				   GFP_KERNEL);
		if (!sgl)
			return -ENOMEM;

		sg_init_table(sgl->sg, MAX_SGL_ENTS + 1);
		sgl->cur = 0;

		if (sg)
			sg_chain(sg, MAX_SGL_ENTS + 1, sgl->sg);

		list_add_tail(&sgl->list, &ctx->tsgl_list);
	}

	return 0;
}

static int af_alg_wait_for_wmem(struct sock *sk, unsigned int flags)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	int err = -ERESTARTSYS;
	long timeout;

	if (flags & MSG_DONTWAIT)
		return -EAGAIN;

	sk_set_bit(SOCKWQ_ASYNC_NOSPACE, sk);

	add_wait_queue(sk_sleep(sk), &wait);
	for (;;) {
		if (signal_pending(current))
			break;
		timeout = MAX_SCHEDULE_TIMEOUT;
		if (sk_wait_event(sk, &timeout, af_alg_writable(sk), &wait)) {
			err = 0;
			break;
		}
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	return err;
}

static void af_alg_data_wakeup(struct sock *sk)
{
	struct alg_sock *ask = alg_sk(sk);
	struct af_alg_ctx *ctx = ask->private;
	struct socket_wq *wq;

	if (!ctx->used)
		return;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait, EPOLLOUT |
							   EPOLLRDNORM |
							   EPOLLRDBAND);
	sk_wake_async(sk, SOCK_WAKE_SPACE, POLL_OUT);
	rcu_read_unlock();
}

int klpp_af_alg_sendmsg(struct socket *sock, struct msghdr *msg, size_t size,
		   unsigned int ivsize)
{
	struct sock *sk = sock->sk;
	struct alg_sock *ask = alg_sk(sk);
	struct af_alg_ctx *ctx = ask->private;
	struct af_alg_tsgl *sgl;
	struct af_alg_control con = {};
	long copied = 0;
	bool enc = false;
	bool init = false;
	int err = 0;

	if (msg->msg_controllen) {
		err = klpp_af_alg_cmsg_send(msg, &con);
		if (err)
			return err;

		init = true;
		switch (con.op) {
		case ALG_OP_ENCRYPT:
			enc = true;
			break;
		case ALG_OP_DECRYPT:
			enc = false;
			break;
		default:
			return -EINVAL;
		}

		if (con.iv && con.iv->ivlen != ivsize)
			return -EINVAL;
	}

	lock_sock(sk);
	if (ctx->write) {
		release_sock(sk);
		return -EBUSY;
	}
	ctx->write = true;

	if (ctx->init && !ctx->more) {
		if (ctx->used) {
			err = -EINVAL;
			goto unlock;
		}

		pr_info_once(
			"%s sent an empty control message without MSG_MORE.\n",
			current->comm);
	}
	ctx->init = true;

	if (init) {
		ctx->enc = enc;
		if (con.iv)
			memcpy(ctx->iv, con.iv->iv, ivsize);

		ctx->aead_assoclen = con.aead_assoclen;
	}

	while (size) {
		struct scatterlist *sg;
		size_t len = size;
		ssize_t plen;

		/* use the existing memory in an allocated page */
		if (ctx->merge && !(msg->msg_flags & MSG_SPLICE_PAGES)) {
			sgl = list_entry(ctx->tsgl_list.prev,
					 struct af_alg_tsgl, list);
			sg = sgl->sg + sgl->cur - 1;
			len = min_t(size_t, len,
				    PAGE_SIZE - sg->offset - sg->length);

			err = memcpy_from_msg(page_address(sg_page(sg)) +
					      sg->offset + sg->length,
					      msg, len);
			if (err)
				goto unlock;

			sg->length += len;
			ctx->merge = (sg->offset + sg->length) &
				     (PAGE_SIZE - 1);

			ctx->used += len;
			copied += len;
			size -= len;
			continue;
		}

		ctx->merge = 0;

		if (!af_alg_writable(sk)) {
			err = af_alg_wait_for_wmem(sk, msg->msg_flags);
			if (err)
				goto unlock;
		}

		/* allocate a new page */
		len = min_t(unsigned long, len, af_alg_sndbuf(sk));

		err = af_alg_alloc_tsgl(sk);
		if (err)
			goto unlock;

		sgl = list_entry(ctx->tsgl_list.prev, struct af_alg_tsgl,
				 list);
		sg = sgl->sg;
		if (sgl->cur)
			sg_unmark_end(sg + sgl->cur - 1);

		if (msg->msg_flags & MSG_SPLICE_PAGES) {
			struct sg_table sgtable = {
				.sgl		= sg,
				.nents		= sgl->cur,
				.orig_nents	= sgl->cur,
			};

			plen = extract_iter_to_sg(&msg->msg_iter, len, &sgtable,
						  MAX_SGL_ENTS - sgl->cur, 0);
			if (plen < 0) {
				err = plen;
				goto unlock;
			}

			for (; sgl->cur < sgtable.nents; sgl->cur++)
				get_page(sg_page(&sg[sgl->cur]));
			len -= plen;
			ctx->used += plen;
			copied += plen;
			size -= plen;
		} else {
			do {
				struct page *pg;
				unsigned int i = sgl->cur;

				plen = min_t(size_t, len, PAGE_SIZE);

				pg = alloc_page(GFP_KERNEL);
				if (!pg) {
					err = -ENOMEM;
					goto unlock;
				}

				sg_assign_page(sg + i, pg);

				err = memcpy_from_msg(
					page_address(sg_page(sg + i)),
					msg, plen);
				if (err) {
					__free_page(sg_page(sg + i));
					sg_assign_page(sg + i, NULL);
					goto unlock;
				}

				sg[i].length = plen;
				len -= plen;
				ctx->used += plen;
				copied += plen;
				size -= plen;
				sgl->cur++;
			} while (len && sgl->cur < MAX_SGL_ENTS);

			ctx->merge = plen & (PAGE_SIZE - 1);
		}

		if (!size)
			sg_mark_end(sg + sgl->cur - 1);
	}

	err = 0;

	ctx->more = msg->msg_flags & MSG_MORE;

unlock:
	af_alg_data_wakeup(sk);
	ctx->write = false;
	release_sock(sk);

	return copied ?: err;
}

typeof(klpp_af_alg_sendmsg) klpp_af_alg_sendmsg;


