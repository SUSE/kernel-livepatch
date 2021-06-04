/*
 * bsc1186285_hci_conn
 *
 * Fix for CVE-2021-33034, bsc#1186285 (net/bluetooth/hci_conn.c part)
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG_BT=m"
#endif

#include "bsc1186285_common.h"
#include "livepatch_bsc1186285.h"

/* klp-ccp: from net/bluetooth/hci_conn.c */
#include <linux/export.h>
#include <linux/debugfs.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
struct hci_chan *klpp_hci_chan_create(struct hci_conn *conn);

/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>
/* klp-ccp: from net/bluetooth/a2mp.h */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from net/bluetooth/hci_conn.c */
struct hci_chan *klpp_hci_chan_create(struct hci_conn *conn)
{
	struct hci_dev *hdev = conn->hdev;
	struct hci_chan *chan;

	BT_DBG("%s hcon %p", hdev->name, conn);

	if (test_bit(HCI_CONN_DROP, &conn->flags)) {
		BT_DBG("Refusing to create new hci_chan");
		return NULL;
	}

	chan = kzalloc(sizeof(*chan), GFP_KERNEL);
	if (!chan)
		return NULL;

	chan->conn = hci_conn_get(conn);
	skb_queue_head_init(&chan->data_q);
	chan->state = BT_CONNECTED;

	/*
	 * Fix CVE-2021-33034
	 *  +1 line
	 */
	klpp_hci_chan_clear_amp(chan);

	list_add_rcu(&chan->list, &conn->chan_list);

	return chan;
}

#endif /* IS_ENABLED(CONFIG_BT) */
