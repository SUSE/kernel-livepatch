/*
 * livepatch_bsc1229458
 *
 * Fix for CVE-2024-42232, bsc#1229458
 *
 *  Upstream commit:
 *  69c7b2fe4c9c ("libceph: fix race between delayed_work() and ceph_monc_stop()")
 *
 *  SLE12-SP5 commit:
 *  498ef723ef3d1d5ed06c6eaf52f841b40b6f4247
 *
 *  SLE15-SP3 commit:
 *  8bcc4def3cb9c2f8aff49f4540fd11a83944ff39
 *
 *  SLE15-SP4 and -SP5 commit:
 *  27160c2ec92c90ff474b7523df89c8d95f4d9adc
 *
 *  SLE15-SP6 commit:
 *  e69b61a4afddf1626358bde997dcfece4d756280
 *
 *  SLE MICRO-6-0 commit:
 *  e69b61a4afddf1626358bde997dcfece4d756280
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Marco Crivellari <marco.crivellari@suse.com>
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

/* klp-ccp: from net/ceph/mon_client.c */
#include <linux/ceph/ceph_debug.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/sched.h>

#include <linux/ceph/ceph_features.h>
#include <linux/ceph/mon_client.h>

/* klp-ccp: from include/linux/ceph/messenger.h */
static void (*klpe_ceph_msgr_flush)(void);

static void (*klpe_ceph_con_keepalive)(struct ceph_connection *con);
static bool (*klpe_ceph_con_keepalive_expired)(struct ceph_connection *con,
				       unsigned long interval);

static void (*klpe_ceph_msg_put)(struct ceph_msg *msg);

/* klp-ccp: from include/linux/ceph/mon_client.h */
void klpp_ceph_monc_stop(struct ceph_mon_client *monc);

/* klp-ccp: from include/linux/ceph/decode.h */
#define __CEPH_DECODE_H

/* klp-ccp: from include/linux/ceph/auth.h */
#define _FS_CEPH_AUTH_H

static void (*klpe_ceph_auth_destroy)(struct ceph_auth_client *ac);

static int (*klpe_ceph_build_auth)(struct ceph_auth_client *ac,
		    void *msg_buf, size_t msg_len);

static int (*klpe_ceph_auth_is_authenticated)(struct ceph_auth_client *ac);

/* klp-ccp: from include/linux/ceph/libceph.h */
#define CEPH_MONC_PING_TIMEOUT		msecs_to_jiffies(30 * 1000)

/* klp-ccp: from net/ceph/mon_client.c */
#include <linux/ceph/decode.h>
#include <linux/ceph/auth.h>

static  int klpr___validate_auth(struct ceph_mon_client *monc);

static void (*klpe___send_prepared_auth_request)(struct ceph_mon_client *monc, int len);

static void (*klpe___close_session)(struct ceph_mon_client *monc);

static void (*klpe_reopen_session)(struct ceph_mon_client *monc);

static void un_backoff(struct ceph_mon_client *monc)
{
	monc->hunt_mult /= 2; /* reduce by 50% */
	if (monc->hunt_mult < 1)
		monc->hunt_mult = 1;
	dout("%s hunt_mult now %d\n", __func__, monc->hunt_mult);
}

static void (*klpe___schedule_delayed)(struct ceph_mon_client *monc);

static void (*klpe___send_subscribe)(struct ceph_mon_client *monc);

void klpp_delayed_work(struct work_struct *work)
{
	struct ceph_mon_client *monc =
		container_of(work, struct ceph_mon_client, delayed_work.work);

	mutex_lock(&monc->mutex);
	dout("%s mon%d\n", __func__, monc->cur_mon);
	if (monc->cur_mon < 0) {
		goto out;
	}

	if (monc->hunting) {
		dout("%s continuing hunt\n", __func__);
		(*klpe_reopen_session)(monc);
	} else {
		int is_auth = (*klpe_ceph_auth_is_authenticated)(monc->auth);

		dout("%s is_authed %d\n", __func__, is_auth);
		if ((*klpe_ceph_con_keepalive_expired)(&monc->con,
					       CEPH_MONC_PING_TIMEOUT)) {
			dout("monc keepalive timeout\n");
			is_auth = 0;
			(*klpe_reopen_session)(monc);
		}

		if (!monc->hunting) {
			(*klpe_ceph_con_keepalive)(&monc->con);
			klpr___validate_auth(monc);
			un_backoff(monc);
		}

		if (is_auth &&
		    !(monc->con.peer_features & CEPH_FEATURE_MON_STATEFUL_SUB)) {
			unsigned long now = jiffies;

			dout("%s renew subs? now %lu renew after %lu\n",
			     __func__, now, monc->sub_renew_after);
			if (time_after_eq(now, monc->sub_renew_after))
				(*klpe___send_subscribe)(monc);
		}
	}
	(*klpe___schedule_delayed)(monc);

out:
	mutex_unlock(&monc->mutex);
}

void klpp_ceph_monc_stop(struct ceph_mon_client *monc)
{
	dout("stop\n");

	mutex_lock(&monc->mutex);
	(*klpe___close_session)(monc);
	monc->hunting = false;
	monc->cur_mon = -1;
	mutex_unlock(&monc->mutex);

	cancel_delayed_work_sync(&monc->delayed_work);

	/*
	 * flush msgr queue before we destroy ourselves to ensure that:
	 *  - any work that references our embedded con is finished.
	 *  - any osd_client or other work that may reference an authorizer
	 *    finishes before we shut down the auth subsystem.
	 */
	(*klpe_ceph_msgr_flush)();

	(*klpe_ceph_auth_destroy)(monc->auth);

	WARN_ON(!RB_EMPTY_ROOT(&monc->generic_request_tree));

	(*klpe_ceph_msg_put)(monc->m_auth);
	(*klpe_ceph_msg_put)(monc->m_auth_reply);
	(*klpe_ceph_msg_put)(monc->m_subscribe);
	(*klpe_ceph_msg_put)(monc->m_subscribe_ack);

	kfree(monc->monmap);
}

typeof(klpp_ceph_monc_stop) klpp_ceph_monc_stop;

int klpr___validate_auth(struct ceph_mon_client *monc)
{
	int ret;

	if (monc->pending_auth)
		return 0;

	ret = (*klpe_ceph_build_auth)(monc->auth, monc->m_auth->front.iov_base,
			      monc->m_auth->front_alloc_len);
	if (ret <= 0)
		return ret; /* either an error, or no need to authenticate */
	(*klpe___send_prepared_auth_request)(monc, ret);
	return 0;
}


#include "livepatch_bsc1229458.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "libceph"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__close_session", (void *)&klpe___close_session, "libceph" },
	{ "__schedule_delayed", (void *)&klpe___schedule_delayed, "libceph" },
	{ "__send_prepared_auth_request",
	  (void *)&klpe___send_prepared_auth_request, "libceph" },
	{ "__send_subscribe", (void *)&klpe___send_subscribe, "libceph" },
	{ "ceph_auth_destroy", (void *)&klpe_ceph_auth_destroy, "libceph" },
	{ "ceph_auth_is_authenticated",
	  (void *)&klpe_ceph_auth_is_authenticated, "libceph" },
	{ "ceph_build_auth", (void *)&klpe_ceph_build_auth, "libceph" },
	{ "ceph_con_keepalive", (void *)&klpe_ceph_con_keepalive, "libceph" },
	{ "ceph_con_keepalive_expired",
	  (void *)&klpe_ceph_con_keepalive_expired, "libceph" },
	{ "ceph_msg_put", (void *)&klpe_ceph_msg_put, "libceph" },
	{ "ceph_msgr_flush", (void *)&klpe_ceph_msgr_flush, "libceph" },
	{ "reopen_session", (void *)&klpe_reopen_session, "libceph" },
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

int livepatch_bsc1229458_init(void)
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

void livepatch_bsc1229458_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
