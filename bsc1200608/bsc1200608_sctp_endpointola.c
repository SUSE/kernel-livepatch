/*
 * bsc1200068_sctp_endpointola
 *
 * Fix for CVE-2022-20154, bsc#1200608 (net/sctp/endpointola.c part)
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

/* klp-ccp: from net/sctp/endpointola.c */
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/random.h>	/* get_random_bytes() */
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/auth.h */
static void (*klpe_sctp_auth_destroy_keys)(struct list_head *keys);

static void (*klpe_sctp_auth_destroy_hmacs)(struct crypto_shash *auth_hmacs[]);

/* klp-ccp: from include/net/sctp/structs.h */
static void (*klpe_sctp_inq_free)(struct sctp_inq *);

static void (*klpe_sctp_bind_addr_free)(struct sctp_bind_addr *);

/* klp-ccp: from include/net/sctp/sctp.h */
static void (*klpe_sctp_put_port)(struct sock *sk);

/* New. */
struct klpp_sctp_endpoint_rcu_head
{
	struct rcu_head rcu;
	struct sctp_endpoint *ep;
};

/* New. */
static void __klpp_sctp_endpoint_destroy_rcu(struct sctp_endpoint *ep)
{
	struct sock *sk = ep->base.sk;

	if (sk) {
		sctp_sk(sk)->ep = NULL;
		sock_put(sk);
	}

	kfree(ep);
	SCTP_DBG_OBJCNT_DEC(ep);
}

/* New. */
static void klpp_sctp_endpoint_destroy_rcu(struct rcu_head *rcu)
{
	struct klpp_sctp_endpoint_rcu_head *head =
		container_of(rcu, struct klpp_sctp_endpoint_rcu_head, rcu);

	__klpp_sctp_endpoint_destroy_rcu(head->ep);
	kfree(head);
}

/* klp-ccp: from net/sctp/endpointola.c */
static void klpp_sctp_endpoint_destroy(struct sctp_endpoint *ep)
{
	struct sock *sk;
	/*
	 * Fix CVE-2022-20154
	 *  +1 line
	 */
	struct klpp_sctp_endpoint_rcu_head *head;

	if (unlikely(!ep->base.dead)) {
		WARN(1, "Attempt to destroy undead endpoint %p!\n", ep);
		return;
	}

	/* Free the digest buffer */
	kfree(ep->digest);

	/* SCTP-AUTH: Free up AUTH releated data such as shared keys
	 * chunks and hmacs arrays that were allocated
	 */
	(*klpe_sctp_auth_destroy_keys)(&ep->endpoint_shared_keys);
	kfree(ep->auth_hmacs_list);
	kfree(ep->auth_chunk_list);

	/* AUTH - Free any allocated HMAC transform containers */
	(*klpe_sctp_auth_destroy_hmacs)(ep->auth_hmacs);

	/* Cleanup. */
	(*klpe_sctp_inq_free)(&ep->base.inqueue);
	(*klpe_sctp_bind_addr_free)(&ep->base.bind_addr);

	memset(ep->secret_key, 0, sizeof(ep->secret_key));

	/* Give up our hold on the sock. */
	sk = ep->base.sk;
	if (sk != NULL) {
		/* Remove and free the port */
		if (sctp_sk(sk)->bind_hash)
			(*klpe_sctp_put_port)(sk);

		/*
		 * Fix CVE-2022-20154
		 *  -2 lines
		 */
	}

	/*
	 * Fix CVE-2022-20154
	 *  -2 lines, +8 lines
	 */
	head = kzalloc(sizeof(*head), GFP_ATOMIC);
	if (!head) {
		__klpp_sctp_endpoint_destroy_rcu(ep);
		return;
	}

	head->ep = ep;
	call_rcu(&head->rcu, klpp_sctp_endpoint_destroy_rcu);
}

/*
 * Fix CVE-2022-20154
 *  -1 line, +1 line
 */
int klpp_sctp_endpoint_hold(struct sctp_endpoint *ep)
{
	/*
	 * Fix CVE-2022-20154
	 *  -1 line, +1 line
	 */
	return atomic_inc_not_zero(&ep->base.refcnt);
}

void klpp_sctp_endpoint_put(struct sctp_endpoint *ep)
{
	if (atomic_dec_and_test(&ep->base.refcnt))
		klpp_sctp_endpoint_destroy(ep);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1200608.h"
#include "bsc1200608_common.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_auth_destroy_hmacs", (void *)&klpe_sctp_auth_destroy_hmacs,
	  "sctp" },
	{ "sctp_auth_destroy_keys", (void *)&klpe_sctp_auth_destroy_keys,
	  "sctp" },
	{ "sctp_bind_addr_free", (void *)&klpe_sctp_bind_addr_free, "sctp" },
	{ "sctp_inq_free", (void *)&klpe_sctp_inq_free, "sctp" },
	{ "sctp_put_port", (void *)&klpe_sctp_put_port, "sctp" },
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

int livepatch_bsc1200608_sctp_endpointola_init(void)
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

void livepatch_bsc1200608_sctp_endpointola_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1200608_module_nb);
	rcu_barrier();
}
