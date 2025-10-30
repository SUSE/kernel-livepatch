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
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/cred.h>
#include <linux/init.h>

/* klp-ccp: from include/linux/io.h */
#define _LINUX_IO_H

/* klp-ccp: from net/vmw_vsock/af_vsock.c */
#include <linux/kernel.h>

#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#include <linux/socket.h>
#include <linux/stddef.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/af_vsock.h>

/* klp-ccp: from include/net/vsock_addr.h */
static void (*klpe_vsock_addr_init)(struct sockaddr_vm *addr, u32 cid, u32 port);

static bool (*klpe_vsock_addr_bound)(const struct sockaddr_vm *addr);

static const struct vsock_transport *(*klpe_transport);

#define VSOCK_HASH_SIZE         251
#define MAX_PORT_RETRIES        24

static struct list_head (*klpe_vsock_bind_table)[VSOCK_HASH_SIZE + 1];

static spinlock_t (*klpe_vsock_table_lock);

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

static struct sock *klpr___vsock_find_bound_socket(struct sockaddr_vm *addr)
{
	struct vsock_sock *vsk;

	for (vsk = ({ void *__mptr = (void *)(((&(*klpe_vsock_bind_table)[((addr)->svm_port % 251)]))->next); do { bool __cond = !(!(!__builtin_types_compatible_p(typeof(*(((&(*klpe_vsock_bind_table)[((addr)->svm_port % 251)]))->next)), typeof(((typeof(*vsk) *)0)->bound_table)) && !__builtin_types_compatible_p(typeof(*(((&(*klpe_vsock_bind_table)[((addr)->svm_port % 251)]))->next)), typeof(void)))); extern void __compiletime_assert_228(void) __attribute__((error("pointer type mismatch in container_of()"))); if (__cond) __compiletime_assert_228(); do { } while (0); } while (0); ((typeof(*vsk) *)(__mptr - __builtin_offsetof(typeof(*vsk), bound_table))); }); &vsk->bound_table != ((&(*klpe_vsock_bind_table)[((addr)->svm_port % 251)])); vsk = ({ void *__mptr = (void *)((vsk)->bound_table.next); do { bool __cond = !(!(!__builtin_types_compatible_p(typeof(*((vsk)->bound_table.next)), typeof(((typeof(*(vsk)) *)0)->bound_table)) && !__builtin_types_compatible_p(typeof(*((vsk)->bound_table.next)), typeof(void)))); extern void __compiletime_assert_228(void) __attribute__((error("pointer type mismatch in container_of()"))); if (__cond) __compiletime_assert_228(); do { } while (0); } while (0); ((typeof(*(vsk)) *)(__mptr - __builtin_offsetof(typeof(*(vsk)), bound_table))); }))
		if (addr->svm_port == vsk->local_addr.svm_port)
			return sk_vsock(vsk);

	return NULL;
}

static int klpp___vsock_bind_stream(struct vsock_sock *vsk,
			       struct sockaddr_vm *addr)
{
	static u32 port = LAST_RESERVED_PORT + 1;
	struct sockaddr_vm new_addr;

	(*klpe_vsock_addr_init)(&new_addr, addr->svm_cid, addr->svm_port);

	if (addr->svm_port == VMADDR_PORT_ANY) {
		bool found = false;
		unsigned int i;

		for (i = 0; i < MAX_PORT_RETRIES; i++) {
			if (port == VMADDR_PORT_ANY ||
			    port <= LAST_RESERVED_PORT)
				port = LAST_RESERVED_PORT + 1;

			new_addr.svm_port = port++;

			if (!klpr___vsock_find_bound_socket(&new_addr)) {
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

		if (klpr___vsock_find_bound_socket(&new_addr))
			return -EADDRINUSE;
	}

	(*klpe_vsock_addr_init)(&vsk->local_addr, new_addr.svm_cid, new_addr.svm_port);

	/* Remove stream sockets from the unbound list and add them to the hash
	 * table for easy lookup by its address.  The unbound list is simply an
	 * extra entry at the end of the hash table, a trick used by AF_UNIX.
	 */
	__vsock_remove_bound(vsk);
	__vsock_insert_bound((&(*klpe_vsock_bind_table)[((&vsk->local_addr)->svm_port % 251)]), vsk);

	return 0;
}

static int klpr___vsock_bind_dgram(struct vsock_sock *vsk,
			      struct sockaddr_vm *addr)
{
	return (*klpe_transport)->dgram_bind(vsk, addr);
}

int klpp___vsock_bind(struct sock *sk, struct sockaddr_vm *addr)
{
	struct vsock_sock *vsk = vsock_sk(sk);
	u32 cid;
	int retval;

	/* First ensure this socket isn't already bound. */
	if ((*klpe_vsock_addr_bound)(&vsk->local_addr))
		return -EINVAL;

	/* Now bind to the provided address or select appropriate values if
	 * none are provided (VMADDR_CID_ANY and VMADDR_PORT_ANY).  Note that
	 * like AF_INET prevents binding to a non-local IP address (in most
	 * cases), we only allow binding to the local CID.
	 */
	cid = (*klpe_transport)->get_local_cid();
	if (addr->svm_cid != cid && addr->svm_cid != VMADDR_CID_ANY)
		return -EADDRNOTAVAIL;

	switch (sk->sk_socket->type) {
	case SOCK_STREAM:
		spin_lock_bh(&(*klpe_vsock_table_lock));
		retval = klpp___vsock_bind_stream(vsk, addr);
		spin_unlock_bh(&(*klpe_vsock_table_lock));
		break;

	case SOCK_DGRAM:
		retval = klpr___vsock_bind_dgram(vsk, addr);
		break;

	default:
		retval = -EINVAL;
		break;
	}

	return retval;
}


#include "livepatch_bsc1249207.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "vsock"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "transport", (void *)&klpe_transport, "vsock" },
	{ "vsock_addr_bound", (void *)&klpe_vsock_addr_bound, "vsock" },
	{ "vsock_addr_init", (void *)&klpe_vsock_addr_init, "vsock" },
	{ "vsock_bind_table", (void *)&klpe_vsock_bind_table, "vsock" },
	{ "vsock_table_lock", (void *)&klpe_vsock_table_lock, "vsock" },
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

int livepatch_bsc1249207_init(void)
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

void livepatch_bsc1249207_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
