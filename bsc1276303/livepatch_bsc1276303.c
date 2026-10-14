/*
 * livepatch_bsc1276303
 *
 * Fix for CVE-2026-68158, bsc#1276303
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Fernando Gonzalez <fernando.gonzalez@suse.com>
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


#include "livepatch_bsc1276303.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/ceph/osdmap.c */
#include <linux/ceph/ceph_debug.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/div64.h>
#include <linux/ceph/libceph.h>

/* klp-ccp: from include/linux/ceph/decode.h */
static int (*klpe_ceph_decode_entity_addr)(void **p, void *end,
				   struct ceph_entity_addr *addr);

/* klp-ccp: from net/ceph/osdmap.c */
#include <linux/ceph/osdmap.h>
#include <linux/ceph/decode.h>
#include <linux/crush/hash.h>
#include <linux/crush/mapper.h>

static int set_primary_affinity(struct ceph_osdmap *map, int osd, u32 aff)
{
	if (!map->osd_primary_affinity) {
		int i;

		map->osd_primary_affinity = kmalloc(map->max_osd*sizeof(u32),
						    GFP_NOFS);
		if (!map->osd_primary_affinity)
			return -ENOMEM;

		for (i = 0; i < map->max_osd; i++)
			map->osd_primary_affinity[i] =
			    CEPH_OSD_DEFAULT_PRIMARY_AFFINITY;
	}

	map->osd_primary_affinity[osd] = aff;

	return 0;
}

int klpp_decode_new_up_state_weight(void **p, void *end, u8 struct_v, struct ceph_osdmap *map)
{
	void *new_up_client;
	void *new_state;
	void *new_weight_end;
	const u32 new_state_item_size =
	    sizeof(u32) + (struct_v >= 5 ? sizeof(u32) : sizeof(u8));
	u32 len;
	int i;

	new_up_client = *p;
	ceph_decode_32_safe(p, end, len, e_inval);
	for (i = 0; i < len; ++i) {
		struct ceph_entity_addr addr;

		ceph_decode_skip_32(p, end, e_inval);
		if ((*klpe_ceph_decode_entity_addr)(p, end, &addr))
			goto e_inval;
	}

	new_state = *p;
	ceph_decode_32_safe(p, end, len, e_inval);
	if (check_mul_overflow(len, new_state_item_size, &len))
		goto e_inval;
	ceph_decode_need(p, end, len, e_inval);
	*p += len;

	/* new_weight */
	ceph_decode_32_safe(p, end, len, e_inval);
	while (len--) {
		s32 osd;
		u32 w;

		ceph_decode_need(p, end, 2*sizeof(u32), e_inval);
		osd = ceph_decode_32(p);
		w = ceph_decode_32(p);
		if (osd >= map->max_osd)
			goto e_inval;

		pr_info("osd%d weight 0x%x %s\n", osd, w,
		     w == CEPH_OSD_IN ? "(in)" :
		     (w == CEPH_OSD_OUT ? "(out)" : ""));
		map->osd_weight[osd] = w;

		/*
		 * If we are marking in, set the EXISTS, and clear the
		 * AUTOOUT and NEW bits.
		 */
		if (w) {
			map->osd_state[osd] |= CEPH_OSD_EXISTS;
			map->osd_state[osd] &= ~(CEPH_OSD_AUTOOUT |
						 CEPH_OSD_NEW);
		}
	}
	new_weight_end = *p;

	/* new_state (up/down) */
	*p = new_state;
	len = ceph_decode_32(p);
	while (len--) {
		s32 osd;
		u32 xorstate;
		int ret;

		osd = ceph_decode_32(p);
		if (osd >= map->max_osd)
			goto e_inval;

		if (struct_v >= 5)
			xorstate = ceph_decode_32(p);
		else
			xorstate = ceph_decode_8(p);
		if (xorstate == 0)
			xorstate = CEPH_OSD_UP;
		if ((map->osd_state[osd] & CEPH_OSD_UP) &&
		    (xorstate & CEPH_OSD_UP))
			pr_info("osd%d down\n", osd);
		if ((map->osd_state[osd] & CEPH_OSD_EXISTS) &&
		    (xorstate & CEPH_OSD_EXISTS)) {
			pr_info("osd%d does not exist\n", osd);
			ret = set_primary_affinity(map, osd,
						   CEPH_OSD_DEFAULT_PRIMARY_AFFINITY);
			if (ret)
				return ret;
			memset(map->osd_addr + osd, 0, sizeof(*map->osd_addr));
			map->osd_state[osd] = 0;
		} else {
			map->osd_state[osd] ^= xorstate;
		}
	}

	/* new_up_client */
	*p = new_up_client;
	len = ceph_decode_32(p);
	while (len--) {
		s32 osd;
		struct ceph_entity_addr addr;

		osd = ceph_decode_32(p);
		if (osd >= map->max_osd)
			goto e_inval;
		if ((*klpe_ceph_decode_entity_addr)(p, end, &addr))
			goto e_inval;
		pr_info("osd%d up\n", osd);
		map->osd_state[osd] |= CEPH_OSD_EXISTS | CEPH_OSD_UP;
		map->osd_addr[osd] = addr;
	}

	*p = new_weight_end;
	return 0;

e_inval:
	return -EINVAL;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "libceph"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ceph_decode_entity_addr", (void *)&klpe_ceph_decode_entity_addr,
	  "libceph" },
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

int livepatch_bsc1276303_init(void)
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

void livepatch_bsc1276303_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
