/*
 * bsc1253437_net_sctp_bind_addr
 *
 * Fix for CVE-2025-40204, bsc#1253437
 * Fix for CVE-2026-53224, bsc#1270023
 * Fix for CVE-2026-53246, bsc#1270024
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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


#include "livepatch_bsc1253437.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/sctp/bind_addr.c */
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/ipv6.h>
#include <net/if_inet6.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/structs.h */
static struct sctp_af *(*klpe_sctp_get_af_specific)(sa_family_t);

static int (*klpe_sctp_add_bind_addr)(struct sctp_bind_addr *, union sctp_addr *,
		       int new_size, __u8 addr_state, gfp_t gfp);

static int (*klpe_sctp_bind_addr_state)(const struct sctp_bind_addr *bp,
			 const union sctp_addr *addr);

int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw, int len,
			   __u16 port, gfp_t gfp);

/* klp-ccp: from net/sctp/bind_addr.c */
#include <net/sctp/sm.h>

static void sctp_bind_addr_clean(struct sctp_bind_addr *);

static void sctp_bind_addr_clean(struct sctp_bind_addr *bp)
{
	struct sctp_sockaddr_entry *addr, *temp;

	/* Empty the bind address list. */
	list_for_each_entry_safe(addr, temp, &bp->address_list, list) {
		list_del_rcu(&addr->list);
		kfree_rcu(addr, rcu);
		SCTP_DBG_OBJCNT_DEC(addr);
	}
}
int klpp_sctp_raw_to_bind_addrs(struct sctp_bind_addr *bp, __u8 *raw_addr_list,
			   int addrs_len, __u16 port, gfp_t gfp)
{
	union sctp_addr_param *rawaddr;
	struct sctp_paramhdr *param;
	union sctp_addr addr;
	int retval = 0;
	int len;
	struct sctp_af *af;

	/* Convert the raw address to standard address format */
	while (addrs_len) {
		param = (struct sctp_paramhdr *)raw_addr_list;
		rawaddr = (union sctp_addr_param *)raw_addr_list;

		if (addrs_len < sizeof(*param)) {
			retval = -EINVAL;
			goto out_err;
		}
		len = ntohs(param->length);
		if (addrs_len < len) {
			retval = -EINVAL;
			goto out_err;
		}

		af = (*klpe_sctp_get_af_specific)(param_type2af(param->type));
		if (unlikely(!af) ||
		    !af->from_addr_param(&addr, rawaddr, htons(port), 0)) {
			retval = -EINVAL;
			goto out_err;
		}

		if ((*klpe_sctp_bind_addr_state)(bp, &addr) != -1)
			goto next;
		retval = (*klpe_sctp_add_bind_addr)(bp, &addr, sizeof(addr),
					    SCTP_ADDR_SRC, gfp);
		if (retval)
			/* Can't finish building the list, clean up. */
			goto out_err;

next:
		addrs_len -= len;
		raw_addr_list += len;
	}

	return retval;

out_err:
	if (retval)
		sctp_bind_addr_clean(bp);

	return retval;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "sctp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sctp_add_bind_addr", (void *)&klpe_sctp_add_bind_addr, "sctp" },
	{ "sctp_bind_addr_state", (void *)&klpe_sctp_bind_addr_state, "sctp" },
	{ "sctp_get_af_specific", (void *)&klpe_sctp_get_af_specific, "sctp" },
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

int bsc1253437_net_sctp_bind_addr_init(void)
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

void bsc1253437_net_sctp_bind_addr_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
