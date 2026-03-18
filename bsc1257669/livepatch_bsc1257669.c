/*
 * livepatch_bsc1257669
 *
 * Fix for CVE-2025-40284, bsc#1257669
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


/* klp-ccp: from net/bluetooth/mgmt.c */
#include <linux/module.h>
#include <asm/unaligned.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
void klpp_mgmt_index_removed(struct hci_dev *hdev);

/* klp-ccp: from net/bluetooth/mgmt.c */
#include <net/bluetooth/hci_sock.h>
#include <net/bluetooth/l2cap.h>
#include <net/bluetooth/mgmt.h>

/* klp-ccp: from net/bluetooth/mgmt_util.h */
struct mgmt_pending_cmd;

int mgmt_send_event(u16 event, struct hci_dev *hdev, unsigned short channel,
		    void *data, u16 data_len, int flag, struct sock *skip_sk);

void mgmt_pending_foreach(u16 opcode, struct hci_dev *hdev,
			  void (*cb)(struct mgmt_pending_cmd *cmd, void *data),
			  void *data);

/* klp-ccp: from net/bluetooth/eir.h */
#include <asm/unaligned.h>

/* klp-ccp: from net/bluetooth/mgmt.c */
static int mgmt_index_event(u16 event, struct hci_dev *hdev, void *data,
			    u16 len, int flag)
{
	return mgmt_send_event(event, hdev, HCI_CHANNEL_CONTROL, data, len,
			       flag, NULL);
}

struct cmd_lookup {
	struct sock *sk;
	struct hci_dev *hdev;
	u8 mgmt_status;
};

extern void cmd_complete_rsp(struct mgmt_pending_cmd *cmd, void *data);

void klpp_mgmt_index_removed(struct hci_dev *hdev)
{
	struct mgmt_ev_ext_index ev;
	struct cmd_lookup match = { NULL, hdev, MGMT_STATUS_INVALID_INDEX };

	if (test_bit(HCI_QUIRK_RAW_DEVICE, &hdev->quirks))
		return;

	mgmt_pending_foreach(0, hdev, cmd_complete_rsp, &match);

	if (hci_dev_test_flag(hdev, HCI_UNCONFIGURED)) {
		mgmt_index_event(MGMT_EV_UNCONF_INDEX_REMOVED, hdev, NULL, 0,
				 HCI_MGMT_UNCONF_INDEX_EVENTS);
		ev.type = 0x01;
	} else {
		mgmt_index_event(MGMT_EV_INDEX_REMOVED, hdev, NULL, 0,
				 HCI_MGMT_INDEX_EVENTS);
		ev.type = 0x00;
	}

	ev.bus = hdev->bus;

	mgmt_index_event(MGMT_EV_EXT_INDEX_REMOVED, hdev, &ev, sizeof(ev),
			 HCI_MGMT_EXT_INDEX_EVENTS);

	/* Cancel any remaining timed work */
	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		return;
	cancel_delayed_work_sync(&hdev->discov_off);
	cancel_delayed_work_sync(&hdev->service_cache);
	cancel_delayed_work_sync(&hdev->rpa_expired);
	cancel_delayed_work_sync(&hdev->mesh_send_done);
}


#include "livepatch_bsc1257669.h"

#include <linux/livepatch.h>

extern typeof(cmd_complete_rsp) cmd_complete_rsp
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, cmd_complete_rsp);
extern typeof(mgmt_pending_foreach) mgmt_pending_foreach
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, mgmt_pending_foreach);
extern typeof(mgmt_send_event) mgmt_send_event
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, mgmt_send_event);

#endif /* IS_ENABLED(CONFIG_BT) */
