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
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/key.h>

#include <linux/module.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/fs_parser.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include <linux/string.h>

/* klp-ccp: from net/ceph/ceph_common.c */
#include <linux/ceph/libceph.h>

/* klp-ccp: from net/ceph/ceph_common.c */
#include <linux/ceph/debugfs.h>
#include <linux/ceph/decode.h>
#include <linux/ceph/mon_client.h>
#include <linux/ceph/auth.h>

/* klp-ccp: from net/ceph/crypto.h */
#include <linux/ceph/types.h>
#include <linux/ceph/buffer.h>

/* klp-ccp: from net/ceph/ceph_common.c */
u64 ceph_client_gid(struct ceph_client *client);

extern typeof(ceph_client_gid) ceph_client_gid;

int klpp___ceph_open_session(struct ceph_client *client, unsigned long started);

int klpp___ceph_open_session(struct ceph_client *client, unsigned long started)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);
	long timeout = ceph_timeout_jiffies(client->options->mount_timeout);
	bool have_monmap, have_osdmap;
	int err;

	/* open session, and wait for mon and osd maps */
	err = ceph_monc_open_session(&client->monc);
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

	pr_info("client%llu fsid %pU\n", ceph_client_gid(client),
		&client->fsid);
	ceph_debugfs_client_init(client);

	return 0;
}


#include "livepatch_bsc1255402.h"

#include <linux/livepatch.h>

extern typeof(ceph_client_gid) ceph_client_gid
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_client_gid);
extern typeof(ceph_debugfs_client_init) ceph_debugfs_client_init
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_debugfs_client_init);
extern typeof(ceph_monc_open_session) ceph_monc_open_session
	 KLP_RELOC_SYMBOL(libceph, libceph, ceph_monc_open_session);
