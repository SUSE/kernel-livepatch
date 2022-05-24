/*
 * bsc1188117_ip_tables
 *
 * Fix for CVE-2021-22555, bsc#1188117 (ip_tables.c part)
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

#if !IS_MODULE(CONFIG_IP_NF_IPTABLES)
#error "Live patch supports only CONFIG_IP_NF_IPTABLES=m"
#endif

#include "bsc1188117_common.h"

/* klp-ccp: from net/ipv4/netfilter/ip_tables.c */
#define pr_fmt(fmt) "ip_tables" ": " fmt
#include <linux/cache.h>
#include <linux/capability.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/cpumask.h>
#include <linux/netfilter/x_tables.h>

/* klp-ccp: from include/linux/netfilter/x_tables.h */
static struct xt_match *(*klpe_xt_request_find_match)(u8 af, const char *name, u8 revision);
static struct xt_target *(*klpe_xt_request_find_target)(u8 af, const char *name, u8 revision);

static struct xt_table_info *(*klpe_xt_alloc_table_info)(unsigned int size);
static void (*klpe_xt_free_table_info)(struct xt_table_info *info);

static void (*klpe_xt_compat_lock)(u_int8_t af);
static void (*klpe_xt_compat_unlock)(u_int8_t af);

static int (*klpe_xt_compat_add_offset)(u_int8_t af, unsigned int offset, int delta);
static void (*klpe_xt_compat_flush_offsets)(u_int8_t af);
static void (*klpe_xt_compat_init_offsets)(u_int8_t af, unsigned int number);

static int (*klpe_xt_compat_match_offset)(const struct xt_match *match);

static int (*klpe_xt_compat_target_offset)(const struct xt_target *target);

static int (*klpe_xt_compat_check_entry_offsets)(const void *base, const char *elems,
				  unsigned int target_offset,
				  unsigned int next_offset);

/* klp-ccp: from net/ipv4/netfilter/ip_tables.c */
#include <linux/netfilter_ipv4/ip_tables.h>

static bool
ip_checkentry(const struct ipt_ip *ip)
{
	if (ip->flags & ~IPT_F_MASK)
		return false;
	if (ip->invflags & ~IPT_INV_MASK)
		return false;
	return true;
}

static int
(*klpe_translate_table)(struct net *net, struct xt_table_info *newinfo, void *entry0,
		const struct ipt_replace *repl);

struct compat_ipt_replace {
	char			name[XT_TABLE_MAXNAMELEN];
	u32			valid_hooks;
	u32			num_entries;
	u32			size;
	u32			hook_entry[NF_INET_NUMHOOKS];
	u32			underflow[NF_INET_NUMHOOKS];
	u32			num_counters;
	compat_uptr_t		counters;	/* struct xt_counters * */
	struct compat_ipt_entry	entries[0];
};

static int
klpr_compat_find_calc_match(struct xt_entry_match *m,
		       const struct ipt_ip *ip,
		       int *size)
{
	struct xt_match *match;

	match = (*klpe_xt_request_find_match)(NFPROTO_IPV4, m->u.user.name,
				      m->u.user.revision);
	if (IS_ERR(match))
		return PTR_ERR(match);

	m->u.kernel.match = match;
	*size += (*klpe_xt_compat_match_offset)(match);
	return 0;
}

static void compat_release_entry(struct compat_ipt_entry *e)
{
	struct xt_entry_target *t;
	struct xt_entry_match *ematch;

	/* Cleanup all matches */
	xt_ematch_foreach(ematch, e)
		module_put(ematch->u.kernel.match->me);
	t = compat_ipt_get_target(e);
	module_put(t->u.kernel.target->me);
}

static int
klpr_check_compat_entry_size_and_hooks(struct compat_ipt_entry *e,
				  struct xt_table_info *newinfo,
				  unsigned int *size,
				  const unsigned char *base,
				  const unsigned char *limit)
{
	struct xt_entry_match *ematch;
	struct xt_entry_target *t;
	struct xt_target *target;
	unsigned int entry_offset;
	unsigned int j;
	int ret, off;

	if ((unsigned long)e % __alignof__(struct compat_ipt_entry) != 0 ||
	    (unsigned char *)e + sizeof(struct compat_ipt_entry) >= limit ||
	    (unsigned char *)e + e->next_offset > limit)
		return -EINVAL;

	if (e->next_offset < sizeof(struct compat_ipt_entry) +
			     sizeof(struct compat_xt_entry_target))
		return -EINVAL;

	if (!ip_checkentry(&e->ip))
		return -EINVAL;

	ret = (*klpe_xt_compat_check_entry_offsets)(e, e->elems,
					    e->target_offset, e->next_offset);
	if (ret)
		return ret;

	off = sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);
	entry_offset = (void *)e - (void *)base;
	j = 0;
	xt_ematch_foreach(ematch, e) {
		ret = klpr_compat_find_calc_match(ematch, &e->ip, &off);
		if (ret != 0)
			goto release_matches;
		++j;
	}

	t = compat_ipt_get_target(e);
	target = (*klpe_xt_request_find_target)(NFPROTO_IPV4, t->u.user.name,
					t->u.user.revision);
	if (IS_ERR(target)) {
		ret = PTR_ERR(target);
		goto release_matches;
	}
	t->u.kernel.target = target;

	off += (*klpe_xt_compat_target_offset)(target);
	*size += off;
	ret = (*klpe_xt_compat_add_offset)(AF_INET, entry_offset, off);
	if (ret)
		goto out;

	return 0;

out:
	module_put(t->u.kernel.target->me);
release_matches:
	xt_ematch_foreach(ematch, e) {
		if (j-- == 0)
			break;
		module_put(ematch->u.kernel.match->me);
	}
	return ret;
}

static void
klpp_compat_copy_entry_from_user(struct compat_ipt_entry *e, void **dstptr,
			    unsigned int *size,
			    struct xt_table_info *newinfo, unsigned char *base)
{
	struct xt_entry_target *t;
	struct xt_target *target;
	struct ipt_entry *de;
	unsigned int origsize;
	int h;
	struct xt_entry_match *ematch;

	origsize = *size;
	de = *dstptr;
	memcpy(de, e, sizeof(struct ipt_entry));
	memcpy(&de->counters, &e->counters, sizeof(e->counters));

	*dstptr += sizeof(struct ipt_entry);
	*size += sizeof(struct ipt_entry) - sizeof(struct compat_ipt_entry);

	xt_ematch_foreach(ematch, e)
		klpp_xt_compat_match_from_user(ematch, dstptr, size);

	de->target_offset = e->target_offset - (origsize - *size);
	t = compat_ipt_get_target(e);
	target = t->u.kernel.target;
	klpp_xt_compat_target_from_user(t, dstptr, size);

	de->next_offset = e->next_offset - (origsize - *size);

	for (h = 0; h < NF_INET_NUMHOOKS; h++) {
		if ((unsigned char *)de - base < newinfo->hook_entry[h])
			newinfo->hook_entry[h] -= origsize - *size;
		if ((unsigned char *)de - base < newinfo->underflow[h])
			newinfo->underflow[h] -= origsize - *size;
	}
}

int
klpp_ip_tables_translate_compat_table(struct net *net,
		       struct xt_table_info **pinfo,
		       void **pentry0,
		       const struct compat_ipt_replace *compatr)
{
	unsigned int i, j;
	struct xt_table_info *newinfo, *info;
	void *pos, *entry0, *entry1;
	struct compat_ipt_entry *iter0;
	struct ipt_replace repl;
	unsigned int size;
	int ret;

	info = *pinfo;
	entry0 = *pentry0;
	size = compatr->size;
	info->number = compatr->num_entries;

	j = 0;
	(*klpe_xt_compat_lock)(AF_INET);
	(*klpe_xt_compat_init_offsets)(AF_INET, compatr->num_entries);
	/* Walk through entries, checking offsets. */
	xt_entry_foreach(iter0, entry0, compatr->size) {
		ret = klpr_check_compat_entry_size_and_hooks(iter0, info, &size,
							entry0,
							entry0 + compatr->size);
		if (ret != 0)
			goto out_unlock;
		++j;
	}

	ret = -EINVAL;
	if (j != compatr->num_entries)
		goto out_unlock;

	ret = -ENOMEM;
	newinfo = (*klpe_xt_alloc_table_info)(size);
	if (!newinfo)
		goto out_unlock;

	/*
	 * Fix CVE-2021-22555
	 *  +1 line
	 */
	memset(newinfo->entries, 0, size);

	newinfo->number = compatr->num_entries;
	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		newinfo->hook_entry[i] = compatr->hook_entry[i];
		newinfo->underflow[i] = compatr->underflow[i];
	}
	entry1 = newinfo->entries;
	pos = entry1;
	size = compatr->size;
	xt_entry_foreach(iter0, entry0, compatr->size)
		klpp_compat_copy_entry_from_user(iter0, &pos, &size,
					    newinfo, entry1);

	/* all module references in entry0 are now gone.
	 * entry1/newinfo contains a 64bit ruleset that looks exactly as
	 * generated by 64bit userspace.
	 *
	 * Call standard translate_table() to validate all hook_entrys,
	 * underflows, check for loops, etc.
	 */
	(*klpe_xt_compat_flush_offsets)(AF_INET);
	(*klpe_xt_compat_unlock)(AF_INET);

	memcpy(&repl, compatr, sizeof(*compatr));

	for (i = 0; i < NF_INET_NUMHOOKS; i++) {
		repl.hook_entry[i] = newinfo->hook_entry[i];
		repl.underflow[i] = newinfo->underflow[i];
	}

	repl.num_counters = 0;
	repl.counters = NULL;
	repl.size = newinfo->size;
	ret = (*klpe_translate_table)(net, newinfo, entry1, &repl);
	if (ret)
		goto free_newinfo;

	*pinfo = newinfo;
	*pentry0 = entry1;
	(*klpe_xt_free_table_info)(info);
	return 0;

free_newinfo:
	(*klpe_xt_free_table_info)(newinfo);
	return ret;
out_unlock:
	(*klpe_xt_compat_flush_offsets)(AF_INET);
	(*klpe_xt_compat_unlock)(AF_INET);
	xt_entry_foreach(iter0, entry0, compatr->size) {
		if (j-- == 0)
			break;
		compat_release_entry(iter0);
	}
	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1188117.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "ip_tables"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "xt_request_find_match", (void *)&klpe_xt_request_find_match,
	  "x_tables" },
	{ "xt_request_find_target", (void *)&klpe_xt_request_find_target,
	  "x_tables" },
	{ "xt_alloc_table_info", (void *)&klpe_xt_alloc_table_info,
	  "x_tables" },
	{ "xt_free_table_info", (void *)&klpe_xt_free_table_info, "x_tables" },
	{ "xt_compat_lock", (void *)&klpe_xt_compat_lock, "x_tables" },
	{ "xt_compat_unlock", (void *)&klpe_xt_compat_unlock, "x_tables" },
	{ "xt_compat_add_offset", (void *)&klpe_xt_compat_add_offset,
	  "x_tables" },
	{ "xt_compat_flush_offsets", (void *)&klpe_xt_compat_flush_offsets,
	  "x_tables" },
	{ "xt_compat_init_offsets", (void *)&klpe_xt_compat_init_offsets,
	  "x_tables" },
	{ "xt_compat_match_offset", (void *)&klpe_xt_compat_match_offset,
	  "x_tables" },
	{ "xt_compat_target_offset", (void *)&klpe_xt_compat_target_offset,
	  "x_tables" },
	{ "xt_compat_check_entry_offsets",
	  (void *)&klpe_xt_compat_check_entry_offsets, "x_tables" },
	{ "translate_table", (void *)&klpe_translate_table, "ip_tables" },
};

static int livepatch_bsc1188117_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1188117_module_nb = {
	.notifier_call = livepatch_bsc1188117_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1188117_ip_tables_init(void)
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

void livepatch_bsc1188117_ip_tables_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1188117_module_nb);
}
