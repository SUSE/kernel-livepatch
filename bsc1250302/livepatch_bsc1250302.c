/*
 * livepatch_bsc1250302
 *
 * Fix for CVE-2022-50386, bsc#1250302
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <linux/module.h>
#include <linux/debugfs.h>

#include <linux/filter.h>

#include <net/bluetooth/bluetooth.h>

#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static void (*klpe_l2cap_chan_put)(struct l2cap_chan *c);

static void (*klpe_l2cap_chan_del)(struct l2cap_chan *chan, int err);

/* klp-ccp: from net/bluetooth/a2mp.h */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from net/bluetooth/l2cap_core.c */
static void (*klpe_l2cap_send_cmd)(struct l2cap_conn *conn, u8 ident, u8 code, u16 len,
			   void *data);
static int (*klpe_l2cap_build_conf_req)(struct l2cap_chan *chan, void *data, size_t data_size);

static struct l2cap_chan *l2cap_chan_hold_unless_zero(struct l2cap_chan *c)
{
	BT_DBG("chan %p orig refcnt %u", c, kref_read(&c->kref));

	if (!kref_get_unless_zero(&c->kref))
		return NULL;

	return c;
}

static struct l2cap_chan *__l2cap_get_chan_by_scid(struct l2cap_conn *conn,
						   u16 cid)
{
	struct l2cap_chan *c;

	list_for_each_entry(c, &conn->chan_l, list) {
		if (c->scid == cid)
			return c;
	}
	return NULL;
}

static struct l2cap_chan *__l2cap_get_chan_by_ident(struct l2cap_conn *conn,
						    u8 ident)
{
	struct l2cap_chan *c;

	list_for_each_entry(c, &conn->chan_l, list) {
		if (c->ident == ident)
			return c;
	}
	return NULL;
}

static void (*klpe_l2cap_state_change)(struct l2cap_chan *chan, int state);

static u8 (*klpe_l2cap_get_ident)(struct l2cap_conn *conn);

static void (*klpe_l2cap_send_cmd)(struct l2cap_conn *conn, u8 ident, u8 code, u16 len,
			   void *data);

static int (*klpe_l2cap_build_conf_req)(struct l2cap_chan *chan, void *data, size_t data_size);

int klpp_l2cap_connect_create_rsp(struct l2cap_conn *conn,
				    struct l2cap_cmd_hdr *cmd, u16 cmd_len,
				    u8 *data)
{
	struct l2cap_conn_rsp *rsp = (struct l2cap_conn_rsp *) data;
	u16 scid, dcid, result, status;
	struct l2cap_chan *chan;
	u8 req[128];
	int err;

	if (cmd_len < sizeof(*rsp))
		return -EPROTO;

	scid   = __le16_to_cpu(rsp->scid);
	dcid   = __le16_to_cpu(rsp->dcid);
	result = __le16_to_cpu(rsp->result);
	status = __le16_to_cpu(rsp->status);

	BT_DBG("dcid 0x%4.4x scid 0x%4.4x result 0x%2.2x status 0x%2.2x",
	       dcid, scid, result, status);

	mutex_lock(&conn->chan_lock);

	if (scid) {
		chan = __l2cap_get_chan_by_scid(conn, scid);
		if (!chan) {
			err = -EBADSLT;
			goto unlock;
		}
	} else {
		chan = __l2cap_get_chan_by_ident(conn, cmd->ident);
		if (!chan) {
			err = -EBADSLT;
			goto unlock;
		}
	}

	chan = l2cap_chan_hold_unless_zero(chan);
	if (!chan) {
		err = -EBADSLT;
		goto unlock;
	}

	err = 0;

	l2cap_chan_lock(chan);

	switch (result) {
	case L2CAP_CR_SUCCESS:
		(*klpe_l2cap_state_change)(chan, BT_CONFIG);
		chan->ident = 0;
		chan->dcid = dcid;
		clear_bit(CONF_CONNECT_PEND, &chan->conf_state);

		if (test_and_set_bit(CONF_REQ_SENT, &chan->conf_state))
			break;

		(*klpe_l2cap_send_cmd)(conn, (*klpe_l2cap_get_ident)(conn), L2CAP_CONF_REQ,
			       (*klpe_l2cap_build_conf_req)(chan, req, sizeof(req)), req);
		chan->num_conf_req++;
		break;

	case L2CAP_CR_PEND:
		set_bit(CONF_CONNECT_PEND, &chan->conf_state);
		break;

	default:
		(*klpe_l2cap_chan_del)(chan, ECONNREFUSED);
		break;
	}

	l2cap_chan_unlock(chan);
	(*klpe_l2cap_chan_put)(chan);

unlock:
	mutex_unlock(&conn->chan_lock);

	return err;
}


#include "livepatch_bsc1250302.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "bluetooth"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "l2cap_build_conf_req", (void *)&klpe_l2cap_build_conf_req,
	  "bluetooth" },
	{ "l2cap_chan_del", (void *)&klpe_l2cap_chan_del, "bluetooth" },
	{ "l2cap_chan_put", (void *)&klpe_l2cap_chan_put, "bluetooth" },
	{ "l2cap_get_ident", (void *)&klpe_l2cap_get_ident, "bluetooth" },
	{ "l2cap_send_cmd", (void *)&klpe_l2cap_send_cmd, "bluetooth" },
	{ "l2cap_state_change", (void *)&klpe_l2cap_state_change,
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

int livepatch_bsc1250302_init(void)
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

void livepatch_bsc1250302_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
