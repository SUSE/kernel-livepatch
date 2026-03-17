/*
 * bsc1255402_net_ceph_debugfs
 *
 * Fix for CVE-2025-68285, bsc#1255402
 *
 *  Copyright (c) 2026 SUSE
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

/* klp-ccp: from net/ceph/debugfs.c */
#include <linux/ceph/ceph_debug.h>

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <linux/ceph/libceph.h>
#include <linux/ceph/mon_client.h>
#include <linux/ceph/auth.h>

#ifdef CONFIG_DEBUG_FS

int klpp_monmap_show(struct seq_file *s, void *p);
int klpp_osdmap_show(struct seq_file *s, void *p);

int klpp_monmap_show(struct seq_file *s, void *p)
{
	int i;
	struct ceph_client *client = s->private;

	mutex_lock(&client->monc.mutex);
	if (client->monc.monmap == NULL)
		goto out_unlock;

	seq_printf(s, "epoch %d\n", client->monc.monmap->epoch);
	for (i = 0; i < client->monc.monmap->num_mon; i++) {
		struct ceph_entity_inst *inst =
			&client->monc.monmap->mon_inst[i];

		seq_printf(s, "\t%s%lld\t%s\n",
			   ENTITY_NAME(inst->name),
			   ceph_pr_addr(&inst->addr));
	}

out_unlock:
	mutex_unlock(&client->monc.mutex);
	return 0;
}

int klpp_osdmap_show(struct seq_file *s, void *p)
{
	int i;
	struct ceph_client *client = s->private;
	struct ceph_osd_client *osdc = &client->osdc;
	struct ceph_osdmap *map;
	struct rb_node *n;

	down_read(&osdc->lock);
	map = osdc->osdmap;
	if (map == NULL)
		goto out_unlock;

	seq_printf(s, "epoch %u barrier %u flags 0x%x\n", map->epoch,
			osdc->epoch_barrier, map->flags);

	for (n = rb_first(&map->pg_pools); n; n = rb_next(n)) {
		struct ceph_pg_pool_info *pi =
			rb_entry(n, struct ceph_pg_pool_info, node);

		seq_printf(s, "pool %lld '%s' type %d size %d min_size %d pg_num %u pg_num_mask %d flags 0x%llx lfor %u read_tier %lld write_tier %lld\n",
			   pi->id, pi->name, pi->type, pi->size, pi->min_size,
			   pi->pg_num, pi->pg_num_mask, pi->flags,
			   pi->last_force_request_resend, pi->read_tier,
			   pi->write_tier);
	}
	for (i = 0; i < map->max_osd; i++) {
		struct ceph_entity_addr *addr = &map->osd_addr[i];
		u32 state = map->osd_state[i];
		char sb[64];

		seq_printf(s, "osd%d\t%s\t%3d%%\t(%s)\t%3d%%\t%2d\n",
			   i, ceph_pr_addr(addr),
			   ((map->osd_weight[i]*100) >> 16),
			   ceph_osdmap_state_str(sb, sizeof(sb), state),
			   ((ceph_get_primary_affinity(map, i)*100) >> 16),
			   ceph_get_crush_locality(map, i,
					   &client->options->crush_locs));
	}
	for (n = rb_first(&map->pg_temp); n; n = rb_next(n)) {
		struct ceph_pg_mapping *pg =
			rb_entry(n, struct ceph_pg_mapping, node);

		seq_printf(s, "pg_temp %llu.%x [", pg->pgid.pool,
			   pg->pgid.seed);
		for (i = 0; i < pg->pg_temp.len; i++)
			seq_printf(s, "%s%d", (i == 0 ? "" : ","),
				   pg->pg_temp.osds[i]);
		seq_printf(s, "]\n");
	}
	for (n = rb_first(&map->primary_temp); n; n = rb_next(n)) {
		struct ceph_pg_mapping *pg =
			rb_entry(n, struct ceph_pg_mapping, node);

		seq_printf(s, "primary_temp %llu.%x %d\n", pg->pgid.pool,
			   pg->pgid.seed, pg->primary_temp.osd);
	}
	for (n = rb_first(&map->pg_upmap); n; n = rb_next(n)) {
		struct ceph_pg_mapping *pg =
			rb_entry(n, struct ceph_pg_mapping, node);

		seq_printf(s, "pg_upmap %llu.%x [", pg->pgid.pool,
			   pg->pgid.seed);
		for (i = 0; i < pg->pg_upmap.len; i++)
			seq_printf(s, "%s%d", (i == 0 ? "" : ","),
				   pg->pg_upmap.osds[i]);
		seq_printf(s, "]\n");
	}
	for (n = rb_first(&map->pg_upmap_items); n; n = rb_next(n)) {
		struct ceph_pg_mapping *pg =
			rb_entry(n, struct ceph_pg_mapping, node);

		seq_printf(s, "pg_upmap_items %llu.%x [", pg->pgid.pool,
			   pg->pgid.seed);
		for (i = 0; i < pg->pg_upmap_items.len; i++)
			seq_printf(s, "%s%d->%d", (i == 0 ? "" : ","),
				   pg->pg_upmap_items.from_to[i][0],
				   pg->pg_upmap_items.from_to[i][1]);
		seq_printf(s, "]\n");
	}

out_unlock:
	up_read(&osdc->lock);
	return 0;
}

#else  /* CONFIG_DEBUG_FS */
#error "klp-ccp: non-taken branch"
#endif  /* CONFIG_DEBUG_FS */


#include "livepatch_bsc1255402.h"

#include <linux/livepatch.h>

extern typeof(ceph_entity_type_name) ceph_entity_type_name
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_entity_type_name);
extern typeof(ceph_get_crush_locality) ceph_get_crush_locality
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_get_crush_locality);
extern typeof(ceph_get_primary_affinity) ceph_get_primary_affinity
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_get_primary_affinity);
extern typeof(ceph_osdmap_state_str) ceph_osdmap_state_str
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_osdmap_state_str);
extern typeof(ceph_pr_addr) ceph_pr_addr
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_pr_addr);
