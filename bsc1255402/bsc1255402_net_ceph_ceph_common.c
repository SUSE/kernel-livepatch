/*
 * bsc1255402_net_ceph_ceph_common
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


/* klp-ccp: from net/ceph/ceph_common.c */
#include <linux/ceph/ceph_debug.h>
#include <linux/backing-dev.h>

#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/key.h>

#include <linux/nsproxy.h>

#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include <linux/string.h>
#include <linux/vmalloc.h>

#include <linux/ceph/libceph.h>

/* klp-ccp: from include/linux/ceph/mon_client.h */
static int (*klpe_ceph_monc_open_session)(struct ceph_mon_client *monc);

/* klp-ccp: from include/linux/ceph/libceph.h */
static u64 (*klpe_ceph_client_gid)(struct ceph_client *client);

int klpp___ceph_open_session(struct ceph_client *client,
			     unsigned long started);

/* klp-ccp: from include/linux/ceph/debugfs.h */
static int (*klpe_ceph_debugfs_client_init)(struct ceph_client *client);

/* klp-ccp: from net/ceph/ceph_common.c */
#include <linux/ceph/decode.h>
#include <linux/ceph/mon_client.h>
#include <linux/ceph/auth.h>

/* klp-ccp: from net/ceph/crypto.h */
#include <linux/ceph/types.h>
#include <linux/ceph/buffer.h>

int klpp___ceph_open_session(struct ceph_client *client, unsigned long started)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	long timeout = ceph_timeout_jiffies(client->options->mount_timeout);
	bool have_monmap, have_osdmap;
	int err;

	/* open session, and wait for mon and osd maps */
	err = (*klpe_ceph_monc_open_session)(&client->monc);
	if (err < 0)
		return err;

	add_wait_queue(&client->auth_wq, &wait);
	for (;;) {
		mutex_lock(&client->monc.mutex);
		err = client->auth_err;
		have_monmap = client->monc.monmap && client->monc.monmap->epoch;
		mutex_unlock(&client->monc.mutex);

		down_read(&client->osdc.lock);
		have_osdmap = client->osdc.osdmap && client->osdc.osdmap->epoch;
		up_read(&client->osdc.lock);

		if (err || (have_monmap && have_osdmap))
			break;

		if (signal_pending(current)) {
			err = -ERESTARTSYS;
			break;
		}

		if (!timeout) {
			err = -ETIMEDOUT;
			break;
		}

		/* wait */
		dout("mount waiting for mon_map\n");
		timeout = wait_woken(&wait, TASK_INTERRUPTIBLE, timeout);
	}
	remove_wait_queue(&client->auth_wq, &wait);

	if (err)
		return err;

	pr_info("client%llu fsid %pU\n", (*klpe_ceph_client_gid)(client),
		&client->fsid);
	(*klpe_ceph_debugfs_client_init)(client);

	return 0;
}

#include "livepatch_bsc1255402.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "libceph"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ceph_client_gid", (void *)&klpe_ceph_client_gid, "libceph" },
	{ "ceph_debugfs_client_init", (void *)&klpe_ceph_debugfs_client_init,
	  "libceph" },
	{ "ceph_monc_open_session", (void *)&klpe_ceph_monc_open_session,
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

int bsc1255402_net_ceph_ceph_common_init(void)
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

void bsc1255402_net_ceph_ceph_common_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
