/*
 * bsc1243650_net_sunrpc_xprtsock
 *
 * Fix for CVE-2024-53168, bsc#1243650
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


/* klp-ccp: from net/sunrpc/xprtsock.c */
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/capability.h>
#include <linux/pagemap.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/mm.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/sunrpc/clnt.h>

/* klp-ccp: from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
static unsigned int		(*klpe_rpc_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/linux/sunrpc/xprt.h */
#ifdef __KERNEL__

static void			(*klpe_xprt_wake_pending_tasks)(struct rpc_xprt *xprt, int status);

static void			(*klpe_xprt_force_disconnect)(struct rpc_xprt *xprt);

static void			(*klpe_xprt_unlock_connect)(struct rpc_xprt *, void *);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* __KERNEL__*/

/* klp-ccp: from net/sunrpc/xprtsock.c */
#include <linux/sunrpc/sched.h>

#include <linux/sunrpc/xprtsock.h>

#include <net/sock.h>
#include <net/checksum.h>

/* klp-ccp: from include/net/tcp.h */
#define TCP_NAGLE_OFF		1	/* Nagle's algo is disabled */

/* klp-ccp: from include/trace/events/sunrpc.h */
#if !defined(_TRACE_SUNRPC_H) || defined(TRACE_HEADER_MULTI_READ)

static struct tracepoint (*klpe___tracepoint_rpc_socket_connect);

/* klp-ccp: not from file */
#undef inline

/* klp-ccp: from include/trace/events/sunrpc.h */

#include "../klp_trace.h"
KLPR_TRACE_EVENT(rpc_socket_connect,
		TP_PROTO( \
			struct rpc_xprt *xprt, \
			struct socket *socket, \
			int error \
		), \
		TP_ARGS(xprt, socket, error))

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* _TRACE_SUNRPC_H */

/* klp-ccp: from net/sunrpc/sunrpc.h */
#include <linux/net.h>

/* klp-ccp: from net/sunrpc/xprtsock.c */
static void (*klpe_xs_tcp_set_socket_timeouts)(struct rpc_xprt *xprt,
		struct socket *sock);

/* klp-ccp: from include/linux/compiler-gcc.h */
#define inline inline		__attribute__((unused)) notrace __gnu_inline

/* klp-ccp: from net/sunrpc/xprtsock.c */
#define XS_TCP_INIT_REEST_TO	(3U * HZ)

static inline struct sockaddr *xs_addr(struct rpc_xprt *xprt)
{
	return (struct sockaddr *) &xprt->addr;
}

static void xs_save_old_callbacks(struct sock_xprt *transport, struct sock *sk)
{
	transport->old_data_ready = sk->sk_data_ready;
	transport->old_state_change = sk->sk_state_change;
	transport->old_write_space = sk->sk_write_space;
	transport->old_error_report = sk->sk_error_report;
}

static void (*klpe_xs_error_report)(struct sock *sk);

static void (*klpe_xs_data_ready)(struct sock *sk);

static void klpr_xs_tcp_force_close(struct rpc_xprt *xprt)
{
	(*klpe_xprt_force_disconnect)(xprt);
}

static void (*klpe_xs_tcp_state_change)(struct sock *sk);

static void (*klpe_xs_udp_write_space)(struct sock *sk);

static void (*klpe_xs_tcp_write_space)(struct sock *sk);

static void (*klpe_xs_udp_do_set_buffer_size)(struct rpc_xprt *xprt);

static void xs_sock_set_reuseport(struct socket *sock)
{
	int opt = 1;

	kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
			(char *)&opt, sizeof(opt));
}

static unsigned short (*klpe_xs_sock_getport)(struct socket *sock);

static void klpr_xs_set_srcport(struct sock_xprt *transport, struct socket *sock)
{
	if (transport->srcport == 0 && transport->xprt.reuseport)
		transport->srcport = (*klpe_xs_sock_getport)(sock);
}

static int (*klpe_xs_bind)(struct sock_xprt *transport, struct socket *sock);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#error "klp-ccp: non-taken branch"
#else
static inline void xs_reclassify_socket(int family, struct socket *sock)
{
}
#endif

static struct socket *klpp_xs_create_sock(struct rpc_xprt *xprt,
		struct sock_xprt *transport, int family, int type,
		int protocol, bool reuseport)
{
	struct socket *sock;
	int err;

	err = __sock_create(xprt->xprt_net, family, type, protocol, &sock, 1);
	if (err < 0) {
		do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0080), 0)) printk("\001" "d" "RPC:       can't create %d transport socket (%d).\n",protocol, -err); } while (0);
		goto out;
	}
	xs_reclassify_socket(family, sock);

	if (protocol == IPPROTO_TCP) {
		sock->sk->sk_net_refcnt = 1;
		get_net(xprt->xprt_net);
	}

	if (reuseport)
		xs_sock_set_reuseport(sock);

	err = (*klpe_xs_bind)(transport, sock);
	if (err) {
		sock_release(sock);
		goto out;
	}

	return sock;
out:
	return ERR_PTR(err);
}

#if IS_ENABLED(CONFIG_SUNRPC_SWAP)

static void xs_set_memalloc(struct rpc_xprt *xprt)
{
	struct sock_xprt *transport = container_of(xprt, struct sock_xprt,
			xprt);

	/*
	 * If there's no sock, then we have nothing to set. The
	 * reconnecting process will get it for us.
	 */
	if (!transport->inet)
		return;
	if (atomic_read(&xprt->swapper))
		sk_set_memalloc(transport->inet);
}

#else
#error "klp-ccp: non-taken branch"
#endif

static void klpr_xs_udp_finish_connecting(struct rpc_xprt *xprt, struct socket *sock)
{
	struct sock_xprt *transport = container_of(xprt, struct sock_xprt, xprt);

	if (!transport->inet) {
		struct sock *sk = sock->sk;

		write_lock_bh(&sk->sk_callback_lock);

		xs_save_old_callbacks(transport, sk);

		sk->sk_user_data = xprt;
		sk->sk_data_ready = (*klpe_xs_data_ready);
		sk->sk_write_space = (*klpe_xs_udp_write_space);
		sock_set_flag(sk, SOCK_FASYNC);
		sk->sk_allocation = GFP_NOIO;

		xprt_set_connected(xprt);

		/* Reset to new socket */
		transport->sock = sock;
		transport->inet = sk;

		xs_set_memalloc(xprt);

		write_unlock_bh(&sk->sk_callback_lock);
	}
	(*klpe_xs_udp_do_set_buffer_size)(xprt);

	xprt->stat.connect_start = jiffies;
}

void klpp_xs_udp_setup_socket(struct work_struct *work)
{
	struct sock_xprt *transport =
		container_of(work, struct sock_xprt, connect_worker.work);
	struct rpc_xprt *xprt = &transport->xprt;
	struct socket *sock = transport->sock;
	int status = -EIO;
	unsigned int pflags = current->flags;

	if (atomic_read(&xprt->swapper))
		current->flags |= PF_MEMALLOC;
	sock = klpp_xs_create_sock(xprt, transport,
			xs_addr(xprt)->sa_family, SOCK_DGRAM,
			IPPROTO_UDP, false);
	if (IS_ERR(sock))
		goto out;

	do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0080), 0)) printk("\001" "d" "RPC:       worker connecting xprt %p via %s to " "%s (port %s)\n",xprt, xprt->address_strings[RPC_DISPLAY_PROTO], xprt->address_strings[RPC_DISPLAY_ADDR], xprt->address_strings[RPC_DISPLAY_PORT]); } while (0);

	klpr_xs_udp_finish_connecting(xprt, sock);
	klpr_trace_rpc_socket_connect(xprt, sock, 0);
	status = 0;
out:
	xprt_clear_connecting(xprt);
	(*klpe_xprt_unlock_connect)(xprt, transport);
	(*klpe_xprt_wake_pending_tasks)(xprt, status);
	current_restore_flags(pflags, PF_MEMALLOC);
}

static void (*klpe_xs_tcp_set_socket_timeouts)(struct rpc_xprt *xprt,
		struct socket *sock);

static int klpr_xs_tcp_finish_connecting(struct rpc_xprt *xprt, struct socket *sock)
{
	struct sock_xprt *transport = container_of(xprt, struct sock_xprt, xprt);
	int ret = -ENOTCONN;

	if (!transport->inet) {
		struct sock *sk = sock->sk;
		unsigned int addr_pref = IPV6_PREFER_SRC_PUBLIC;

		/* Avoid temporary address, they are bad for long-lived
		 * connections such as NFS mounts.
		 * RFC4941, section 3.6 suggests that:
		 *    Individual applications, which have specific
		 *    knowledge about the normal duration of connections,
		 *    MAY override this as appropriate.
		 */
		kernel_setsockopt(sock, SOL_IPV6, IPV6_ADDR_PREFERENCES,
				(char *)&addr_pref, sizeof(addr_pref));

		(*klpe_xs_tcp_set_socket_timeouts)(xprt, sock);

		write_lock_bh(&sk->sk_callback_lock);

		xs_save_old_callbacks(transport, sk);

		sk->sk_user_data = xprt;
		sk->sk_data_ready = (*klpe_xs_data_ready);
		sk->sk_state_change = (*klpe_xs_tcp_state_change);
		sk->sk_write_space = (*klpe_xs_tcp_write_space);
		sock_set_flag(sk, SOCK_FASYNC);
		sk->sk_error_report = (*klpe_xs_error_report);
		sk->sk_allocation = GFP_NOIO;

		/* socket options */
		sock_reset_flag(sk, SOCK_LINGER);
		tcp_sk(sk)->nonagle |= TCP_NAGLE_OFF;

		xprt_clear_connected(xprt);

		/* Reset to new socket */
		transport->sock = sock;
		transport->inet = sk;

		write_unlock_bh(&sk->sk_callback_lock);
	}

	if (!xprt_bound(xprt))
		goto out;

	xs_set_memalloc(xprt);

	/* Tell the socket layer to start connecting... */
	set_bit(XPRT_SOCK_CONNECTING, &transport->sock_state);
	ret = kernel_connect(sock, xs_addr(xprt), xprt->addrlen, O_NONBLOCK);
	switch (ret) {
	case 0:
		klpr_xs_set_srcport(transport, sock);
	case -EINPROGRESS:
		/* SYN_SENT! */
		if (xprt->reestablish_timeout < XS_TCP_INIT_REEST_TO)
			xprt->reestablish_timeout = XS_TCP_INIT_REEST_TO;
		break;
	case -EADDRNOTAVAIL:
		/* Source port number is unavailable. Try a new one! */
		transport->srcport = 0;
	}
out:
	return ret;
}

void klpp_xs_tcp_setup_socket(struct work_struct *work)
{
	struct sock_xprt *transport =
		container_of(work, struct sock_xprt, connect_worker.work);
	struct socket *sock = transport->sock;
	struct rpc_xprt *xprt = &transport->xprt;
	int status = -EIO;
	unsigned int pflags = current->flags;

	if (atomic_read(&xprt->swapper))
		current->flags |= PF_MEMALLOC;
	if (!sock) {
		sock = klpp_xs_create_sock(xprt, transport,
				xs_addr(xprt)->sa_family, SOCK_STREAM,
				IPPROTO_TCP, true);
		if (IS_ERR(sock)) {
			status = PTR_ERR(sock);
			goto out;
		}
	}

	do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0080), 0)) printk("\001" "d" "RPC:       worker connecting xprt %p via %s to " "%s (port %s)\n",xprt, xprt->address_strings[RPC_DISPLAY_PROTO], xprt->address_strings[RPC_DISPLAY_ADDR], xprt->address_strings[RPC_DISPLAY_PORT]); } while (0);

	status = klpr_xs_tcp_finish_connecting(xprt, sock);
	klpr_trace_rpc_socket_connect(xprt, sock, status);
	do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0080), 0)) printk("\001" "d" "RPC:       %p connect status %d connected %d sock state %d\n",xprt, -status, xprt_connected(xprt), sock->sk->__sk_common.skc_state); } while (0);
	switch (status) {
	default:
		printk("%s: connect returned unhandled error %d\n",
			__func__, status);
	case -EADDRNOTAVAIL:
		/* We're probably in TIME_WAIT. Get rid of existing socket,
		 * and retry
		 */
		klpr_xs_tcp_force_close(xprt);
		break;
	case 0:
	case -EINPROGRESS:
	case -EALREADY:
		(*klpe_xprt_unlock_connect)(xprt, transport);
		goto out_restore;
	case -EPERM:
		/* Happens, for instance, if a BPF program is preventing
		 * the connect. Remap the error so upper layers can better
		 * deal with it.
		 */
		status = -ECONNREFUSED;
		/* fallthrough */
	case -EINVAL:
		/* Happens, for instance, if the user specified a link
		 * local IPv6 address without a scope-id.
		 */
	case -ECONNREFUSED:
	case -ECONNRESET:
	case -ENETUNREACH:
	case -EHOSTUNREACH:
	case -EADDRINUSE:
	case -ENOBUFS:
		/* xs_tcp_force_close() wakes tasks with a fixed error code.
		 * We need to wake them first to ensure the correct error code.
		 */
		(*klpe_xprt_wake_pending_tasks)(xprt, status);
		klpr_xs_tcp_force_close(xprt);
		clear_bit(XPRT_SOCK_CONNECTING, &transport->sock_state);
		goto out;
	}
	clear_bit(XPRT_SOCK_CONNECTING, &transport->sock_state);
	status = -EAGAIN;
out:
	xprt_clear_connecting(xprt);
	(*klpe_xprt_unlock_connect)(xprt, transport);
	(*klpe_xprt_wake_pending_tasks)(xprt, status);
out_restore:
	current_restore_flags(pflags, PF_MEMALLOC);
}


#include "livepatch_bsc1243650.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sunrpc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__tracepoint_rpc_socket_connect",
	  (void *)&klpe___tracepoint_rpc_socket_connect, "sunrpc" },
	{ "rpc_debug", (void *)&klpe_rpc_debug, "sunrpc" },
	{ "xprt_force_disconnect", (void *)&klpe_xprt_force_disconnect,
	  "sunrpc" },
	{ "xprt_unlock_connect", (void *)&klpe_xprt_unlock_connect, "sunrpc" },
	{ "xprt_wake_pending_tasks", (void *)&klpe_xprt_wake_pending_tasks,
	  "sunrpc" },
	{ "xs_bind", (void *)&klpe_xs_bind, "sunrpc" },
	{ "xs_data_ready", (void *)&klpe_xs_data_ready, "sunrpc" },
	{ "xs_error_report", (void *)&klpe_xs_error_report, "sunrpc" },
	{ "xs_sock_getport", (void *)&klpe_xs_sock_getport, "sunrpc" },
	{ "xs_tcp_set_socket_timeouts",
	  (void *)&klpe_xs_tcp_set_socket_timeouts, "sunrpc" },
	{ "xs_tcp_state_change", (void *)&klpe_xs_tcp_state_change, "sunrpc" },
	{ "xs_tcp_write_space", (void *)&klpe_xs_tcp_write_space, "sunrpc" },
	{ "xs_udp_do_set_buffer_size", (void *)&klpe_xs_udp_do_set_buffer_size,
	  "sunrpc" },
	{ "xs_udp_write_space", (void *)&klpe_xs_udp_write_space, "sunrpc" },
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

int bsc1243650_net_sunrpc_xprtsock_init(void)
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

void bsc1243650_net_sunrpc_xprtsock_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
