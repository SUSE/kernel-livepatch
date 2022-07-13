/*
 * bsc1200068_sctp_socket
 *
 * Fix for CVE-2022-20154, bsc#1200608 (net/sctp/socket.c part)
 *
 *  Copyright (c) 2022 SUSE
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

/* klp-ccp: from net/sctp/socket.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/sched/signal.h>
#include <linux/ip.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <linux/socket.h> /* for sa_family_t */
#include <linux/export.h>
#include <net/sock.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/structs.h */
static void (*klpe_sctp_transport_put)(struct sctp_transport *);

/* klp-ccp: from include/net/sctp/sctp.h */
static int (*klpe_sctp_transport_walk_start)(struct rhashtable_iter *iter);
static void (*klpe_sctp_transport_walk_stop)(struct rhashtable_iter *iter);
static struct sctp_transport *(*klpe_sctp_transport_get_next)(struct net *net,
			struct rhashtable_iter *iter);
static struct sctp_transport *(*klpe_sctp_transport_get_idx)(struct net *net,
			struct rhashtable_iter *iter, int pos);

/* klp-ccp: from net/sctp/socket.c */
/*
 * Fix CVE-2022-20154
 *  +1 line
 */
#include "bsc1200608_common.h"

/*
 * Fix CVE-2022-20154
 *  -3 lines, +2 lines
 */
int klpp_sctp_transport_traverse_process(sctp_callback_t cb, sctp_callback_t cb_done,
					 struct net *net, int *pos, void *p)
{
	struct rhashtable_iter hti;
	struct sctp_transport *tsp;
	/*
	 * Fix CVE-2022-20154
	 *  +1 line
	 */
	struct sctp_endpoint *ep;
	int ret;

again:
	ret = (*klpe_sctp_transport_walk_start)(&hti);
	if (ret)
		return ret;

	tsp = (*klpe_sctp_transport_get_idx)(net, &hti, *pos + 1);
	for (; !IS_ERR_OR_NULL(tsp); tsp = (*klpe_sctp_transport_get_next)(net, &hti)) {
		/*
		 * Fix CVE-2022-20154
		 *  -3 lines, +7 lines
		 */
		ep = tsp->asoc->ep;
		if (klpp_sctp_endpoint_hold(ep)) { /* asoc can be peeled off */
			ret = cb(ep, tsp, p);
			if (ret)
				break;
			klpp_sctp_endpoint_put(ep);
		}
		(*pos)++;
		(*klpe_sctp_transport_put)(tsp);
	}
	(*klpe_sctp_transport_walk_stop)(&hti);

	if (ret) {
		/*
		 * Fix CVE-2022-20154
		 *  -1 line, +1 line
		 */
		if (cb_done && !cb_done(ep, tsp, p)) {
			(*pos)++;
			/*
			 * Fix CVE-2022-20154
			 *  +1 line
			 */
			klpp_sctp_endpoint_put(ep);
			(*klpe_sctp_transport_put)(tsp);
			goto again;
		}
		/*
		 * Fix CVE-2022-20154
		 *  +1 line
		 */
		klpp_sctp_endpoint_put(ep);
		(*klpe_sctp_transport_put)(tsp);
	}

	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1200608.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_transport_get_idx", (void *)&klpe_sctp_transport_get_idx,
	  "sctp" },
	{ "sctp_transport_get_next", (void *)&klpe_sctp_transport_get_next,
	  "sctp" },
	{ "sctp_transport_put", (void *)&klpe_sctp_transport_put, "sctp" },
	{ "sctp_transport_walk_start", (void *)&klpe_sctp_transport_walk_start,
	  "sctp" },
	{ "sctp_transport_walk_stop", (void *)&klpe_sctp_transport_walk_stop,
	  "sctp" },
};

static int livepatch_bsc1200608_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1200608_module_nb = {
	.notifier_call = livepatch_bsc1200608_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1200608_sctp_socket_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1200608_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1200608_sctp_socket_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1200608_module_nb);
}
