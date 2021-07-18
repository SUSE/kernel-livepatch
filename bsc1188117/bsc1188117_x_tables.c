/*
 * bsc1188117_x_tables
 *
 * Fix for CVE-2021-22555, bsc#1188117 (x_tables.c part)
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

#if !IS_MODULE(CONFIG_NETFILTER_XTABLES)
#error "Live patch supports only CONFIG_NETFILTER_XTABLES=m"
#endif

#include "bsc1188117_common.h"

/* klp-ccp: from net/netfilter/x_tables.c */
#define pr_fmt(fmt) "x_tables" ": " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/audit.h>
#include <net/net_namespace.h>
#include <linux/netfilter/x_tables.h>

/* klp-ccp: from include/linux/netfilter/x_tables.h */
static int (*klpe_xt_compat_match_offset)(const struct xt_match *match);
void klpp_xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			      unsigned int *size);

static int (*klpe_xt_compat_target_offset)(const struct xt_target *target);
void klpp_xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size);

/* klp-ccp: from net/netfilter/x_tables.c */
#include <linux/netfilter_arp.h>

void klpp_xt_compat_match_from_user(struct xt_entry_match *m, void **dstptr,
			       unsigned int *size)
{
	const struct xt_match *match = m->u.kernel.match;
	struct compat_xt_entry_match *cm = (struct compat_xt_entry_match *)m;
	/*
	 * Fix CVE-2021-22555
	 *  -1 line, +1 line
	 */
	int off = (*klpe_xt_compat_match_offset)(match);
	u_int16_t msize = cm->u.user.match_size;
	char name[sizeof(m->u.user.name)];

	m = *dstptr;
	memcpy(m, cm, sizeof(*cm));
	if (match->compat_from_user)
		match->compat_from_user(m->data, cm->data);
	else
		memcpy(m->data, cm->data, msize - sizeof(*cm));
	/*
	 * Fix CVE-2021-22555
	 *  -3 lines
	 */

	msize += off;
	m->u.user.match_size = msize;
	strlcpy(name, match->name, sizeof(name));
	module_put(match->me);
	strncpy(m->u.user.name, name, sizeof(m->u.user.name));

	*size += off;
	*dstptr += msize;
}

void klpp_xt_compat_target_from_user(struct xt_entry_target *t, void **dstptr,
				unsigned int *size)
{
	const struct xt_target *target = t->u.kernel.target;
	struct compat_xt_entry_target *ct = (struct compat_xt_entry_target *)t;
	/*
	 * Fix CVE-2021-22555
	 *  -1 line, +1 line
	 */
	int off = (*klpe_xt_compat_target_offset)(target);
	u_int16_t tsize = ct->u.user.target_size;
	char name[sizeof(t->u.user.name)];

	t = *dstptr;
	memcpy(t, ct, sizeof(*ct));
	if (target->compat_from_user)
		target->compat_from_user(t->data, ct->data);
	else
		memcpy(t->data, ct->data, tsize - sizeof(*ct));
	/*
	 * Fix CVE-2021-22555
	 *  -3 lines
	 */

	tsize += off;
	t->u.user.target_size = tsize;
	strlcpy(name, target->name, sizeof(name));
	module_put(target->me);
	strncpy(t->u.user.name, name, sizeof(t->u.user.name));

	*size += off;
	*dstptr += tsize;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1188117.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "x_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xt_compat_match_offset", (void *)&klpe_xt_compat_match_offset,
	  "x_tables" },
	{ "xt_compat_target_offset", (void *)&klpe_xt_compat_target_offset,
	  "x_tables" },
};

static int livepatch_bsc1188117_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1188117_module_nb = {
	.notifier_call = livepatch_bsc1188117_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1188117_x_tables_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1188117_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1188117_x_tables_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1188117_module_nb);
}
