/*
 * bsc1243650_net_sunrpc_svcsock
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


/* klp-ccp: from net/sunrpc/svcsock.c */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/errno.h>

/* klp-ccp: from include/linux/fcntl.h */
#define _LINUX_FCNTL_H

/* klp-ccp: from include/uapi/asm-generic/fcntl.h */
#define O_WRONLY	00000001

#define O_APPEND	00002000

#define O_NONBLOCK	00004000

#define O_DSYNC		00010000	/* used to be O_SYNC, see below */

#define O_DIRECT	00040000	/* direct disk access hint */

#define O_NOATIME	01000000

#define __O_SYNC	04000000

#ifndef HAVE_ARCH_STRUCT_FLOCK

struct flock;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

/* klp-ccp: from include/uapi/linux/fcntl.h */
#define RWH_WRITE_LIFE_NONE	1
#define RWH_WRITE_LIFE_SHORT	2
#define RWH_WRITE_LIFE_MEDIUM	3
#define RWH_WRITE_LIFE_LONG	4
#define RWH_WRITE_LIFE_EXTREME	5

#define AT_FDCWD		-100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */
#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */

#define AT_NO_AUTOMOUNT		0x800	/* Suppress terminal automount traversal */

/* klp-ccp: from net/sunrpc/svcsock.c */
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/udp.h>

#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#include <net/sock.h>
#include <net/checksum.h>

/* klp-ccp: from include/net/ipv6.h */
#define _NET_IPV6_H

/* klp-ccp: from net/sunrpc/svcsock.c */
#include <net/ipv6.h>

#include <net/tcp_states.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>

/* klp-ccp: from include/linux/sunrpc/types.h */
#define _LINUX_SUNRPC_TYPES_H_

/* klp-ccp: from include/linux/sunrpc/debug.h */
#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
static unsigned int		(*klpe_rpc_debug);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

# define RPC_IFDEBUG(x)		x

/* klp-ccp: from net/sunrpc/svcsock.c */
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/xdr.h>
#include <linux/sunrpc/msg_prot.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/xprt.h>

/* klp-ccp: from net/sunrpc/sunrpc.h */
#include <linux/net.h>

/* klp-ccp: from net/sunrpc/svcsock.c */
static struct svc_sock *(*klpe_svc_setup_socket)(struct svc_serv *, struct socket *,
					 int flags);

#ifdef CONFIG_DEBUG_LOCK_ALLOC
#error "klp-ccp: non-taken branch"
#else
static void svc_reclassify_socket(struct socket *sock)
{
}
#endif

static struct svc_sock *(*klpe_svc_setup_socket)(struct svc_serv *serv,
						struct socket *sock,
						int flags);

struct svc_xprt *klpp_svc_create_socket(struct svc_serv *serv,
					  int protocol,
					  struct net *net,
					  struct sockaddr *sin, int len,
					  int flags)
{
	struct svc_sock	*svsk;
	struct socket	*sock;
	int		error;
	int		type;
	struct sockaddr_storage addr;
	struct sockaddr *newsin = (struct sockaddr *)&addr;
	int		newlen;
	int		family;
	int		val;
	RPC_IFDEBUG(char buf[RPC_MAX_ADDRBUFLEN]);

	do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0100), 0)) printk("\001" "d" "svc: svc_create_socket(%s, %d, %s)\n",serv->sv_program->pg_name, protocol, __svc_print_addr(sin, buf, sizeof(buf))); } while (0);

	if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
		printk(KERN_WARNING "svc: only UDP and TCP "
				"sockets supported\n");
		return ERR_PTR(-EINVAL);
	}

	type = (protocol == IPPROTO_UDP)? SOCK_DGRAM : SOCK_STREAM;
	switch (sin->sa_family) {
	case AF_INET6:
		family = PF_INET6;
		break;
	case AF_INET:
		family = PF_INET;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	error = __sock_create(net, family, type, protocol, &sock, 1);
	if (error < 0)
		return ERR_PTR(error);

	svc_reclassify_socket(sock);

	/*
	 * If this is an PF_INET6 listener, we want to avoid
	 * getting requests from IPv4 remotes.  Those should
	 * be shunted to a PF_INET listener via rpcbind.
	 */
	val = 1;
	if (family == PF_INET6)
		kernel_setsockopt(sock, SOL_IPV6, IPV6_V6ONLY,
					(char *)&val, sizeof(val));

	if (type == SOCK_STREAM)
		sock->sk->sk_reuse = SK_CAN_REUSE; /* allow address reuse */
	error = kernel_bind(sock, sin, len);
	if (error < 0)
		goto bummer;

	newlen = len;
	error = kernel_getsockname(sock, newsin, &newlen);
	if (error < 0)
		goto bummer;

	if (protocol == IPPROTO_TCP) {
		sock->sk->sk_net_refcnt = 1;
		get_net(net);
		if ((error = kernel_listen(sock, 64)) < 0)
			goto bummer;
	}

	svsk = (*klpe_svc_setup_socket)(serv, sock, flags);
	if (IS_ERR(svsk)) {
		error = PTR_ERR(svsk);
		goto bummer;
	}
	svc_xprt_set_local(&svsk->sk_xprt, newsin, newlen);
	return (struct svc_xprt *)svsk;
bummer:
	do { if (__builtin_expect(!!((*klpe_rpc_debug) & 0x0100), 0)) printk("\001" "d" "svc: svc_create_socket error = %d\n",-error); } while (0);
	sock_release(sock);
	return ERR_PTR(error);
}


#include "livepatch_bsc1243650.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sunrpc"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "rpc_debug", (void *)&klpe_rpc_debug, "sunrpc" },
	{ "svc_setup_socket", (void *)&klpe_svc_setup_socket, "sunrpc" },
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

int bsc1243650_net_sunrpc_svcsock_init(void)
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

void bsc1243650_net_sunrpc_svcsock_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
