/*
 * livepatch_bsc1248376
 *
 * Fix for CVE-2025-38566, bsc#1248376
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

/* klp-ccp: from net/sunrpc/svcsock.c */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/file.h>

#include <net/sock.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/tls_prot.h>
#include <net/handshake.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>
#include <asm/ioctls.h>
#include <linux/key.h>

/* klp-ccp: from include/linux/sunrpc/types.h */
#define _LINUX_SUNRPC_TYPES_H_

/* klp-ccp: from net/sunrpc/svcsock.c */
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/msg_prot.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/xprt.h>

#include <trace/events/sock.h>
#include <trace/events/sunrpc.h>

/* manually added tracing macros */
#include "../klp_trace.h"

KLPR_TRACE_EVENT(sunrpc, svcsock_marker,
	TP_PROTO(
		const struct svc_xprt *xprt,
		__be32 marker
	),
	TP_ARGS(xprt, marker))


KLPR_TRACE_EVENT(sunrpc, svcsock_tcp_recv,
	TP_PROTO( \
		const struct svc_xprt *xprt, \
		ssize_t result \
	), \
	TP_ARGS(xprt, result))


KLPR_TRACE_EVENT(sunrpc, svcsock_tcp_recv_eagain,
	TP_PROTO( \
		const struct svc_xprt *xprt, \
		ssize_t result \
	), \
	TP_ARGS(xprt, result))

KLPR_TRACE_EVENT(sunrpc, svcsock_tcp_recv_err,
	TP_PROTO( \
		const struct svc_xprt *xprt, \
		ssize_t result \
	), \
	TP_ARGS(xprt, result))


KLPR_TRACE_EVENT(sunrpc, svcsock_tcp_recv_short,
	TP_PROTO(
		const struct svc_xprt *xprt,
		u32 expected,
		u32 received
	),
	TP_ARGS(xprt, expected, received))



/* klp-ccp: from net/sunrpc/sunrpc.h */
#include <linux/net.h>

/* klp-ccp: from net/sunrpc/svcsock.c */
static int
svc_tcp_sock_process_cmsg(struct socket *sock, struct msghdr *msg,
			  struct cmsghdr *cmsg, int ret)
{
	u8 content_type = tls_get_record_type(sock->sk, cmsg);
	u8 level, description;

	switch (content_type) {
	case 0:
		break;
	case TLS_RECORD_TYPE_DATA:
		/* TLS sets EOR at the end of each application data
		 * record, even though there might be more frames
		 * waiting to be decrypted.
		 */
		msg->msg_flags &= ~MSG_EOR;
		break;
	case TLS_RECORD_TYPE_ALERT:
		tls_alert_recv(sock->sk, msg, &level, &description);
		ret = (level == TLS_ALERT_LEVEL_FATAL) ?
			-ENOTCONN : -EAGAIN;
		break;
	default:
		/* discard this record type */
		ret = -EAGAIN;
	}
	return ret;
}

static int
klpp_svc_tcp_sock_recv_cmsg(struct socket *sock, unsigned int *msg_flags)
{
	union {
		struct cmsghdr	cmsg;
		u8		buf[CMSG_SPACE(sizeof(u8))];
	} u;
	u8 alert[2];
	struct kvec alert_kvec = {
		.iov_base = alert,
		.iov_len = sizeof(alert),
	};
	struct msghdr msg = {
		.msg_flags = *msg_flags,
		.msg_control = &u,
		.msg_controllen = sizeof(u),
	};
	int ret;

	iov_iter_kvec(&msg.msg_iter, ITER_DEST, &alert_kvec, 1,
		      alert_kvec.iov_len);
	ret = sock_recvmsg(sock, &msg, MSG_DONTWAIT);
	if (ret > 0 &&
	    tls_get_record_type(sock->sk, &u.cmsg) == TLS_RECORD_TYPE_ALERT) {
		iov_iter_revert(&msg.msg_iter, ret);
		ret = svc_tcp_sock_process_cmsg(sock, &msg, &u.cmsg, -EAGAIN);
	}
	return ret;
}

static int
klpp_svc_tcp_sock_recvmsg(struct svc_sock *svsk, struct msghdr *msg)
{
	int ret;
	struct socket *sock = svsk->sk_sock;

	ret = sock_recvmsg(sock, msg, MSG_DONTWAIT);
	if (msg->msg_flags & MSG_CTRUNC) {
		msg->msg_flags &= ~(MSG_CTRUNC | MSG_EOR);
		if (ret == 0 || ret == -EIO)
			ret = klpp_svc_tcp_sock_recv_cmsg(sock, &msg->msg_flags);
	}
	return ret;
}

#if ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE
static void svc_flush_bvec(const struct bio_vec *bvec, size_t size, size_t seek)
{
	struct bvec_iter bi = {
		.bi_size	= size + seek,
	};
	struct bio_vec bv;

	bvec_iter_advance(bvec, &bi, seek & PAGE_MASK);
	for_each_bvec(bv, bvec, bi, bi)
		flush_dcache_page(bv.bv_page);
}
#else
static inline void svc_flush_bvec(const struct bio_vec *bvec, size_t size,
				  size_t seek)
{
}
#endif

ssize_t klpp_svc_tcp_read_msg(struct svc_rqst *rqstp, size_t buflen,
				size_t seek)
{
	struct svc_sock *svsk =
		container_of(rqstp->rq_xprt, struct svc_sock, sk_xprt);
	struct bio_vec *bvec = rqstp->rq_bvec;
	struct msghdr msg = { NULL };
	unsigned int i;
	ssize_t len;
	size_t t;

	clear_bit(XPT_DATA, &svsk->sk_xprt.xpt_flags);

	for (i = 0, t = 0; t < buflen; i++, t += PAGE_SIZE)
		bvec_set_page(&bvec[i], rqstp->rq_pages[i], PAGE_SIZE, 0);
	rqstp->rq_respages = &rqstp->rq_pages[i];
	rqstp->rq_next_page = rqstp->rq_respages + 1;

	iov_iter_bvec(&msg.msg_iter, ITER_DEST, bvec, i, buflen);
	if (seek) {
		iov_iter_advance(&msg.msg_iter, seek);
		buflen -= seek;
	}
	len = klpp_svc_tcp_sock_recvmsg(svsk, &msg);
	if (len > 0)
		svc_flush_bvec(bvec, len, seek);

	/* If we read a full record, then assume there may be more
	 * data to read (stream based sockets only!)
	 */
	if (len == buflen)
		set_bit(XPT_DATA, &svsk->sk_xprt.xpt_flags);

	return len;
}

static void svc_sock_secure_port(struct svc_rqst *rqstp)
{
	if (svc_port_is_privileged(svc_addr(rqstp)))
		set_bit(RQ_SECURE, &rqstp->rq_flags);
	else
		clear_bit(RQ_SECURE, &rqstp->rq_flags);
}

static size_t svc_tcp_restore_pages(struct svc_sock *svsk,
				    struct svc_rqst *rqstp)
{
	size_t len = svsk->sk_datalen;
	unsigned int i, npages;

	if (!len)
		return 0;
	npages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	for (i = 0; i < npages; i++) {
		if (rqstp->rq_pages[i] != NULL)
			put_page(rqstp->rq_pages[i]);
		BUG_ON(svsk->sk_pages[i] == NULL);
		rqstp->rq_pages[i] = svsk->sk_pages[i];
		svsk->sk_pages[i] = NULL;
	}
	rqstp->rq_arg.head[0].iov_base = page_address(rqstp->rq_pages[0]);
	return len;
}

static void svc_tcp_save_pages(struct svc_sock *svsk, struct svc_rqst *rqstp)
{
	unsigned int i, len, npages;

	if (svsk->sk_datalen == 0)
		return;
	len = svsk->sk_datalen;
	npages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	for (i = 0; i < npages; i++) {
		svsk->sk_pages[i] = rqstp->rq_pages[i];
		rqstp->rq_pages[i] = NULL;
	}
}

static ssize_t klpp_svc_tcp_read_marker(struct svc_sock *svsk,
				   struct svc_rqst *rqstp)
{
	ssize_t want, len;

	/* If we haven't gotten the record length yet,
	 * get the next four bytes.
	 */
	if (svsk->sk_tcplen < sizeof(rpc_fraghdr)) {
		struct msghdr	msg = { NULL };
		struct kvec	iov;

		want = sizeof(rpc_fraghdr) - svsk->sk_tcplen;
		iov.iov_base = ((char *)&svsk->sk_marker) + svsk->sk_tcplen;
		iov.iov_len  = want;
		iov_iter_kvec(&msg.msg_iter, ITER_DEST, &iov, 1, want);
		len = klpp_svc_tcp_sock_recvmsg(svsk, &msg);
		if (len < 0)
			return len;
		svsk->sk_tcplen += len;
		if (len < want) {
			/* call again to read the remaining bytes */
			goto err_short;
		}
		klpr_trace_svcsock_marker(&svsk->sk_xprt, svsk->sk_marker);
		if (svc_sock_reclen(svsk) + svsk->sk_datalen >
		    svsk->sk_xprt.xpt_server->sv_max_mesg)
			goto err_too_large;
	}
	return svc_sock_reclen(svsk);

err_too_large:
	net_notice_ratelimited("svc: %s %s RPC fragment too large: %d\n",
			       __func__, svsk->sk_xprt.xpt_server->sv_name,
			       svc_sock_reclen(svsk));
	svc_xprt_deferred_close(&svsk->sk_xprt);
err_short:
	return -EAGAIN;
}

static int receive_cb_reply(struct svc_sock *svsk, struct svc_rqst *rqstp)
{
	struct rpc_xprt *bc_xprt = svsk->sk_xprt.xpt_bc_xprt;
	struct rpc_rqst *req = NULL;
	struct kvec *src, *dst;
	__be32 *p = (__be32 *)rqstp->rq_arg.head[0].iov_base;
	__be32 xid;
	__be32 calldir;

	xid = *p++;
	calldir = *p;

	if (!bc_xprt)
		return -EAGAIN;
	spin_lock(&bc_xprt->queue_lock);
	req = xprt_lookup_rqst(bc_xprt, xid);
	if (!req)
		goto unlock_notfound;

	memcpy(&req->rq_private_buf, &req->rq_rcv_buf, sizeof(struct xdr_buf));
	/*
	 * XXX!: cheating for now!  Only copying HEAD.
	 * But we know this is good enough for now (in fact, for any
	 * callback reply in the forseeable future).
	 */
	dst = &req->rq_private_buf.head[0];
	src = &rqstp->rq_arg.head[0];
	if (dst->iov_len < src->iov_len)
		goto unlock_eagain; /* whatever; just giving up. */
	memcpy(dst->iov_base, src->iov_base, src->iov_len);
	xprt_complete_rqst(req->rq_task, rqstp->rq_arg.len);
	rqstp->rq_arg.len = 0;
	spin_unlock(&bc_xprt->queue_lock);
	return 0;
unlock_notfound:
	printk(KERN_NOTICE
		"%s: Got unrecognized reply: "
		"calldir 0x%x xpt_bc_xprt %p xid %08x\n",
		__func__, ntohl(calldir),
		bc_xprt, ntohl(xid));
unlock_eagain:
	spin_unlock(&bc_xprt->queue_lock);
	return -EAGAIN;
}

static void svc_tcp_fragment_received(struct svc_sock *svsk)
{
	/* If we have more data, signal svc_xprt_enqueue() to try again */
	svsk->sk_tcplen = 0;
	svsk->sk_marker = xdr_zero;
}

int klpp_svc_tcp_recvfrom(struct svc_rqst *rqstp)
{
	struct svc_sock	*svsk =
		container_of(rqstp->rq_xprt, struct svc_sock, sk_xprt);
	struct svc_serv	*serv = svsk->sk_xprt.xpt_server;
	size_t want, base;
	ssize_t len;
	__be32 *p;
	__be32 calldir;

	clear_bit(XPT_DATA, &svsk->sk_xprt.xpt_flags);
	len = klpp_svc_tcp_read_marker(svsk, rqstp);
	if (len < 0)
		goto error;

	base = svc_tcp_restore_pages(svsk, rqstp);
	want = len - (svsk->sk_tcplen - sizeof(rpc_fraghdr));
	len = klpp_svc_tcp_read_msg(rqstp, base + want, base);
	if (len >= 0) {
		klpr_trace_svcsock_tcp_recv(&svsk->sk_xprt, len);
		svsk->sk_tcplen += len;
		svsk->sk_datalen += len;
	}
	if (len != want || !svc_sock_final_rec(svsk))
		goto err_incomplete;
	if (svsk->sk_datalen < 8)
		goto err_nuts;

	rqstp->rq_arg.len = svsk->sk_datalen;
	rqstp->rq_arg.page_base = 0;
	if (rqstp->rq_arg.len <= rqstp->rq_arg.head[0].iov_len) {
		rqstp->rq_arg.head[0].iov_len = rqstp->rq_arg.len;
		rqstp->rq_arg.page_len = 0;
	} else
		rqstp->rq_arg.page_len = rqstp->rq_arg.len - rqstp->rq_arg.head[0].iov_len;

	rqstp->rq_xprt_ctxt   = NULL;
	rqstp->rq_prot	      = IPPROTO_TCP;
	if (test_bit(XPT_LOCAL, &svsk->sk_xprt.xpt_flags))
		set_bit(RQ_LOCAL, &rqstp->rq_flags);
	else
		clear_bit(RQ_LOCAL, &rqstp->rq_flags);

	p = (__be32 *)rqstp->rq_arg.head[0].iov_base;
	calldir = p[1];
	if (calldir)
		len = receive_cb_reply(svsk, rqstp);

	/* Reset TCP read info */
	svsk->sk_datalen = 0;
	svc_tcp_fragment_received(svsk);

	if (len < 0)
		goto error;

	svc_xprt_copy_addrs(rqstp, &svsk->sk_xprt);
	if (serv->sv_stats)
		serv->sv_stats->nettcpcnt++;

	svc_sock_secure_port(rqstp);
	svc_xprt_received(rqstp->rq_xprt);
	return rqstp->rq_arg.len;

err_incomplete:
	svc_tcp_save_pages(svsk, rqstp);
	if (len < 0 && len != -EAGAIN)
		goto err_delete;
	if (len == want)
		svc_tcp_fragment_received(svsk);
	else
		klpr_trace_svcsock_tcp_recv_short(&svsk->sk_xprt,
				svc_sock_reclen(svsk),
				svsk->sk_tcplen - sizeof(rpc_fraghdr));
	goto err_noclose;
error:
	if (len != -EAGAIN)
		goto err_delete;
	klpr_trace_svcsock_tcp_recv_eagain(&svsk->sk_xprt, 0);
	goto err_noclose;
err_nuts:
	svsk->sk_datalen = 0;
err_delete:
	klpr_trace_svcsock_tcp_recv_err(&svsk->sk_xprt, len);
	svc_xprt_deferred_close(&svsk->sk_xprt);
err_noclose:
	svc_xprt_received(rqstp->rq_xprt);
	return 0;	/* record not complete */
}


#include "livepatch_bsc1248376.h"

#include <linux/livepatch.h>

extern typeof(svc_port_is_privileged) svc_port_is_privileged
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_port_is_privileged);
extern typeof(svc_xprt_copy_addrs) svc_xprt_copy_addrs
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_xprt_copy_addrs);
extern typeof(svc_xprt_deferred_close) svc_xprt_deferred_close
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_xprt_deferred_close);
extern typeof(svc_xprt_received) svc_xprt_received
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, svc_xprt_received);
extern typeof(xprt_complete_rqst) xprt_complete_rqst
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, xprt_complete_rqst);
extern typeof(xprt_lookup_rqst) xprt_lookup_rqst
	 KLP_RELOC_SYMBOL(sunrpc, sunrpc, xprt_lookup_rqst);
