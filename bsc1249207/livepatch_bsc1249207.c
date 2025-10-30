/*
 * livepatch_bsc1249207
 *
 * Fix for CVE-2025-38618, bsc#1249207
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/vmw_vsock/af_vsock.c */
#include <linux/compat.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/errqueue.h>
#include <linux/init.h>

#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/kmod.h>
#include <linux/list.h>

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#include <linux/socket.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/af_vsock.h>
#include <uapi/linux/vm_sockets.h>
#include <uapi/asm-generic/ioctls.h>

#define MAX_PORT_RETRIES        24

#define VSOCK_HASH(addr)        ((addr)->svm_port % VSOCK_HASH_SIZE)
#define vsock_bound_sockets(addr) (&vsock_bind_table[VSOCK_HASH(addr)])

extern struct list_head vsock_bind_table[VSOCK_HASH_SIZE + 1];

extern typeof(vsock_bind_table) vsock_bind_table;

extern spinlock_t vsock_table_lock;

extern typeof(vsock_table_lock) vsock_table_lock;

static void __vsock_insert_bound(struct list_head *list,
				 struct vsock_sock *vsk)
{
	sock_hold(&vsk->sk);
	list_add(&vsk->bound_table, list);
}

static void __vsock_remove_bound(struct vsock_sock *vsk)
{
	list_del_init(&vsk->bound_table);
	sock_put(&vsk->sk);
}

extern struct sock *__vsock_find_bound_socket(struct sockaddr_vm *addr);

bool vsock_find_cid(unsigned int cid);

extern typeof(vsock_find_cid) vsock_find_cid;

static int klpp___vsock_bind_connectible(struct vsock_sock *vsk,
				    struct sockaddr_vm *addr)
{
	static u32 port;
	struct sockaddr_vm new_addr;

	if (!port)
		port = get_random_u32_above(LAST_RESERVED_PORT);

	vsock_addr_init(&new_addr, addr->svm_cid, addr->svm_port);

	if (addr->svm_port == VMADDR_PORT_ANY) {
		bool found = false;
		unsigned int i;

		for (i = 0; i < MAX_PORT_RETRIES; i++) {
			if (port == VMADDR_PORT_ANY ||
			    port <= LAST_RESERVED_PORT)
				port = LAST_RESERVED_PORT + 1;

			new_addr.svm_port = port++;

			if (!__vsock_find_bound_socket(&new_addr)) {
				found = true;
				break;
			}
		}

		if (!found)
			return -EADDRNOTAVAIL;
	} else {
		/* If port is in reserved range, ensure caller
		 * has necessary privileges.
		 */
		if (addr->svm_port <= LAST_RESERVED_PORT &&
		    !capable(CAP_NET_BIND_SERVICE)) {
			return -EACCES;
		}

		if (__vsock_find_bound_socket(&new_addr))
			return -EADDRINUSE;
	}

	vsock_addr_init(&vsk->local_addr, new_addr.svm_cid, new_addr.svm_port);

	/* Remove connection oriented sockets from the unbound list and add them
	 * to the hash table for easy lookup by its address.  The unbound list
	 * is simply an extra entry at the end of the hash table, a trick used
	 * by AF_UNIX.
	 */
	__vsock_remove_bound(vsk);
	__vsock_insert_bound(vsock_bound_sockets(&vsk->local_addr), vsk);

	return 0;
}

static int __vsock_bind_dgram(struct vsock_sock *vsk,
			      struct sockaddr_vm *addr)
{
	return vsk->transport->dgram_bind(vsk, addr);
}

int klpp___vsock_bind(struct sock *sk, struct sockaddr_vm *addr)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	int retval;

	/* First ensure this socket isn't already bound. */
	if (vsock_addr_bound(&vsk->local_addr))
		return -EINVAL;

	/* Now bind to the provided address or select appropriate values if
	 * none are provided (VMADDR_CID_ANY and VMADDR_PORT_ANY).  Note that
	 * like AF_INET prevents binding to a non-local IP address (in most
	 * cases), we only allow binding to a local CID.
	 */
	if (addr->svm_cid != VMADDR_CID_ANY && !vsock_find_cid(addr->svm_cid))
		return -EADDRNOTAVAIL;

	switch (sk->sk_socket->type) {
	case SOCK_STREAM:
	case SOCK_SEQPACKET:
		spin_lock_bh(&vsock_table_lock);
		retval = klpp___vsock_bind_connectible(vsk, addr);
		spin_unlock_bh(&vsock_table_lock);
		break;

	case SOCK_DGRAM:
		retval = __vsock_bind_dgram(vsk, addr);
		break;

	default:
		retval = -EINVAL;
		break;
	}

	return retval;
}


#include "livepatch_bsc1249207.h"

#include <linux/livepatch.h>

extern typeof(__vsock_find_bound_socket) __vsock_find_bound_socket
	 KLP_RELOC_SYMBOL(vsock, vsock, __vsock_find_bound_socket);
extern typeof(vsock_addr_bound) vsock_addr_bound
	 KLP_RELOC_SYMBOL(vsock, vsock, vsock_addr_bound);
extern typeof(vsock_addr_init) vsock_addr_init
	 KLP_RELOC_SYMBOL(vsock, vsock, vsock_addr_init);
extern typeof(vsock_bind_table) vsock_bind_table
	 KLP_RELOC_SYMBOL(vsock, vsock, vsock_bind_table);
extern typeof(vsock_find_cid) vsock_find_cid
	 KLP_RELOC_SYMBOL(vsock, vsock, vsock_find_cid);
extern typeof(vsock_table_lock) vsock_table_lock
	 KLP_RELOC_SYMBOL(vsock, vsock, vsock_table_lock);
