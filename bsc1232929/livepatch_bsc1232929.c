/*
 * livepatch_bsc1232929
 *
 * Fix for CVE-2024-50125, bsc#1232929
 *
 *  Upstream commit:
 *  f4712fa993f6 ("Bluetooth: call sock_hold earlier in sco_conn_del")
 *  1bf4470a3939 ("Bluetooth: SCO: Fix UAF on sco_sock_timeout")
 *
 *  SLE12-SP5 commit:
 *  37a97f60e80684300dcec80b35720e080d3ce94b
 *  4838e6deb1934cf4992983474ad49061b4a40158
 *
 *  SLE15-SP3 commit:
 *  1a6524e16491bea9afbe1e7a1a8bf98ca5b7dcf8
 *  b82cf2a13f3f064295c7dab589907231d5acf46d
 *
 *  SLE15-SP4 and -SP5 commit:
 *  f9d799e0a6c2815d3127a84f32985b6de13d0d50
 *
 *  SLE15-SP6 commit:
 *  5725fe50b27a5366552923710e9ba61ec2bbf431
 *
 *  SLE MICRO-6-0 commit:
 *  5725fe50b27a5366552923710e9ba61ec2bbf431
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Marcos Paulo de Souza <mpdesouza@suse.com>
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/bluetooth/sco.c */
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

struct sco_conn {
	struct hci_conn	*hcon;

	spinlock_t	lock;
	struct sock	*sk;

	struct delayed_work	timeout_work;

	unsigned int    mtu;
};

#define sco_conn_lock(c)	spin_lock(&c->lock);
#define sco_conn_unlock(c)	spin_unlock(&c->lock);

static bool bt_sock_linked(struct bt_sock_list *l, struct sock *s)
{
	struct sock *sk;

	if (!l || !s)
		return false;

	read_lock(&l->lock);

	sk_for_each(sk, &l->head) {
		if (s == sk) {
			read_unlock(&l->lock);
			return true;
		}
	}

	read_unlock(&l->lock);

	return false;
}

static struct bt_sock_list *klpe_sco_sk_list;

struct sock *sco_sock_hold(struct sco_conn *conn)
{
	if (!conn || !bt_sock_linked(&(*klpe_sco_sk_list), conn->sk))
		return NULL;

	sock_hold(conn->sk);

	return conn->sk;
}

static void (*klpe_sco_sock_clear_timer)(struct sock *sk);

static void (*klpe_sco_chan_del)(struct sock *sk, int err);

void klpp_sco_conn_del(struct hci_conn *hcon, int err)
{
	struct sco_conn *conn = hcon->sco_data;
	struct sock *sk;

	if (!conn)
		return;

	BT_DBG("hcon %p conn %p, err %d", hcon, conn, err);

	/* Kill socket */
	sco_conn_lock(conn);
	sk = sco_sock_hold(conn);
	sco_conn_unlock(conn);

	if (sk) {
		lock_sock(sk);
		(*klpe_sco_sock_clear_timer)(sk);
		(*klpe_sco_chan_del)(sk, err);
		release_sock(sk);
		sock_put(sk);

		/* Ensure no more work items will run before freeing conn. */
		cancel_delayed_work_sync(&conn->timeout_work);
	}

	hcon->sco_data = NULL;
	kfree(conn);
}


#include "livepatch_bsc1232929.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "bluetooth"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "sco_chan_del", (void *)&klpe_sco_chan_del, "bluetooth" },
	{ "sco_sk_list", (void *)&klpe_sco_sk_list, "bluetooth" },
	{ "sco_sock_clear_timer", (void *)&klpe_sco_sock_clear_timer,
	  "bluetooth" },
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

int livepatch_bsc1232929_init(void)
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

void livepatch_bsc1232929_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
