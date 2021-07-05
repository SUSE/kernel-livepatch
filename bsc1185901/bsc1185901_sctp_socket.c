/*
 * bsc1185901_sctp_socket
 *
 * Fix for CVE-2021-23133, bsc#1185901 (net/sctp/socket.c part)
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_IP_SCTP)
#error "Live patch supports only CONFIG_IP_SCTP=m"
#endif

#include "bsc1185901_common.h"

/* klp-ccp: from net/sctp/socket.c */
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/socket.h> /* for sa_family_t */
#include <net/sock.h>
#include <net/sctp/sctp.h>

static void (*klpe_sctp_destroy_sock)(struct sock *sk);

/* New. */
bool klpp_is_sctp_sock(struct sock *sk)
{
	void (* const destroy)(struct sock *) = sk->sk_prot->destroy;

	return destroy && destroy == READ_ONCE(klpe_sctp_destroy_sock);
}

/* New. */
void klpp_sctp_disable_asconf(struct sock *sk)
{
	struct net *net = sock_net(sk);
	struct sctp_sock *sp = sctp_sk(sk);

	spin_lock_bh(&net->sctp.addr_wq_lock);
	if (sp->do_auto_asconf) {
		sp->do_auto_asconf = 0;
		list_del(&sp->auto_asconf_list);
	}
	spin_unlock_bh(&net->sctp.addr_wq_lock);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1185901.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_destroy_sock", (void *)&klpe_sctp_destroy_sock, "sctp" },
};

static int livepatch_bsc1185901_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action == MODULE_STATE_GOING &&
	    !strcmp(mod->name, LIVEPATCHED_MODULE)) {
		/*
		 * Clear out klpe_sctp_destroy_sock still used for
		 * comparisons in livepatched inet_create()
		 * resp. inet6_create().
		 */
		WRITE_ONCE(klpe_sctp_destroy_sock, NULL);
	}

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1185901_module_nb = {
	.notifier_call = livepatch_bsc1185901_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1185901_sctp_socket_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1185901_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1185901_sctp_socket_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1185901_module_nb);
}
