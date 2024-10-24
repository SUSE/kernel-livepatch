/*
 * livepatch_bsc1231419
 *
 * Fix for CVE-2024-42133, bsc#1231419
 *
 *  Upstream commit:
 *  015d79c96d62 ("Bluetooth: Ignore too large handle values in BIG")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  2cf10dc10a7b1403daf8f2f8cc17c8bbba2a65be
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from net/bluetooth/hci_event.c */
#include <asm/unaligned.h>
#include <linux/crypto.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>

/* klp-ccp: from net/bluetooth/eir.h */
#include <asm/unaligned.h>

/* klp-ccp: from net/bluetooth/hci_event.c */
static void *hci_le_ev_skb_pull(struct hci_dev *hdev, struct sk_buff *skb,
				u8 ev, size_t len)
{
	void *data;

	data = skb_pull_data(skb, len);
	if (!data)
		bt_dev_err(hdev, "Malformed LE Event: 0x%2.2x", ev);

	return data;
}

void klpp_hci_le_big_sync_established_evt(struct hci_dev *hdev, void *data,
					    struct sk_buff *skb)
{
	struct hci_evt_le_big_sync_estabilished *ev = data;
	struct hci_conn *bis;
	struct hci_conn *pa_sync;
	int i;

	bt_dev_dbg(hdev, "status 0x%2.2x", ev->status);

	if (!hci_le_ev_skb_pull(hdev, skb, HCI_EVT_LE_BIG_SYNC_ESTABILISHED,
				flex_array_size(ev, bis, ev->num_bis)))
		return;

	hci_dev_lock(hdev);

	if (!ev->status) {
		pa_sync = hci_conn_hash_lookup_pa_sync_big_handle(hdev, ev->handle);
		if (pa_sync)
			/* Also mark the BIG sync established event on the
			 * associated PA sync hcon
			 */
			set_bit(HCI_CONN_BIG_SYNC, &pa_sync->flags);
	}

	for (i = 0; i < ev->num_bis; i++) {
		u16 handle = le16_to_cpu(ev->bis[i]);
		__le32 interval;

		bis = hci_conn_hash_lookup_handle(hdev, handle);
		if (!bis) {
			if (handle > HCI_CONN_HANDLE_MAX) {
				bt_dev_dbg(hdev, "ignore too large handle %u", handle);
				continue;
			}
			bis = hci_conn_add(hdev, ISO_LINK, BDADDR_ANY,
					   HCI_ROLE_SLAVE, handle);
			if (!bis)
				continue;
		}

		if (ev->status != 0x42)
			/* Mark PA sync as established */
			set_bit(HCI_CONN_PA_SYNC, &bis->flags);

		bis->iso_qos.bcast.big = ev->handle;
		memset(&interval, 0, sizeof(interval));
		memcpy(&interval, ev->latency, sizeof(ev->latency));
		bis->iso_qos.bcast.in.interval = le32_to_cpu(interval);
		/* Convert ISO Interval (1.25 ms slots) to latency (ms) */
		bis->iso_qos.bcast.in.latency = le16_to_cpu(ev->interval) * 125 / 100;
		bis->iso_qos.bcast.in.sdu = le16_to_cpu(ev->max_pdu);

		if (!ev->status) {
			set_bit(HCI_CONN_BIG_SYNC, &bis->flags);
			hci_iso_setup_path(bis);
		}
	}

	/* In case BIG sync failed, notify each failed connection to
	 * the user after all hci connections have been added
	 */
	if (ev->status)
		for (i = 0; i < ev->num_bis; i++) {
			u16 handle = le16_to_cpu(ev->bis[i]);

			bis = hci_conn_hash_lookup_handle(hdev, handle);
			if (!bis)
				continue;

			set_bit(HCI_CONN_BIG_SYNC_FAILED, &bis->flags);
			hci_connect_cfm(bis, ev->status);
		}

	hci_dev_unlock(hdev);
}


#include "livepatch_bsc1231419.h"

#include <linux/livepatch.h>

extern typeof(bt_err) bt_err KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_err);
extern typeof(hci_cb_list) hci_cb_list
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_cb_list);
extern typeof(hci_cb_list_lock) hci_cb_list_lock
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_cb_list_lock);
extern typeof(hci_conn_add) hci_conn_add
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_conn_add);
extern typeof(hci_iso_setup_path) hci_iso_setup_path
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_iso_setup_path);

#endif /* IS_ENABLED(CONFIG_BT) */
