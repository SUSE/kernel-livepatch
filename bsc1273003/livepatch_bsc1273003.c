/*
 * livepatch_bsc1273003
 *
 * Fix for CVE-2026-63944, bsc#1273003
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


#include "livepatch_bsc1273003.h"


/* klp-ccp: from net/bluetooth/hci_sync.c */
#include <linux/property.h>
#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_sync.h */
/* klp-ccp: from net/bluetooth/hci_sync.c */
#include <net/bluetooth/mgmt.h>
/* klp-ccp: from net/bluetooth/eir.h */
#include <asm/unaligned.h>

/* klp-ccp: from net/bluetooth/hci_sync.c */
int __hci_cmd_sync_status_sk(struct hci_dev *hdev, u16 opcode, u32 plen,
			     const void *param, u8 event, u32 timeout,
			     struct sock *sk);

extern typeof(__hci_cmd_sync_status_sk) __hci_cmd_sync_status_sk;

int klpp_hci_le_create_cis_sync(struct hci_dev *hdev)
{
	DEFINE_FLEX(struct hci_cp_le_create_cis, cmd, cis, num_cis, 0x1f);
	size_t aux_num_cis = 0;
	struct hci_conn *conn;
	u16 timeout = 0;
	u8 cig = BT_ISO_QOS_CIG_UNSET;

	/* The spec allows only one pending LE Create CIS command at a time. If
	 * the command is pending now, don't do anything. We check for pending
	 * connections after each CIS Established event.
	 *
	 * BLUETOOTH CORE SPECIFICATION Version 5.3 | Vol 4, Part E
	 * page 2566:
	 *
	 * If the Host issues this command before all the
	 * HCI_LE_CIS_Established events from the previous use of the
	 * command have been generated, the Controller shall return the
	 * error code Command Disallowed (0x0C).
	 *
	 * BLUETOOTH CORE SPECIFICATION Version 5.3 | Vol 4, Part E
	 * page 2567:
	 *
	 * When the Controller receives the HCI_LE_Create_CIS command, the
	 * Controller sends the HCI_Command_Status event to the Host. An
	 * HCI_LE_CIS_Established event will be generated for each CIS when it
	 * is established or if it is disconnected or considered lost before
	 * being established; until all the events are generated, the command
	 * remains pending.
	 */

	hci_dev_lock(hdev);

	rcu_read_lock();

	/* Wait until previous Create CIS has completed */
	list_for_each_entry_rcu(conn, &hdev->conn_hash.list, list) {
		if (test_bit(HCI_CONN_CREATE_CIS, &conn->flags))
			goto done;
	}

	/* Find CIG with all CIS ready */
	list_for_each_entry_rcu(conn, &hdev->conn_hash.list, list) {
		struct hci_conn *link;

		if (hci_conn_check_create_cis(conn))
			continue;

		cig = conn->iso_qos.ucast.cig;

		list_for_each_entry_rcu(link, &hdev->conn_hash.list, list) {
			if (hci_conn_check_create_cis(link) > 0 &&
			    link->iso_qos.ucast.cig == cig &&
			    link->state != BT_CONNECTED) {
				cig = BT_ISO_QOS_CIG_UNSET;
				break;
			}
		}

		if (cig != BT_ISO_QOS_CIG_UNSET)
			break;
	}

	if (cig == BT_ISO_QOS_CIG_UNSET)
		goto done;

	list_for_each_entry_rcu(conn, &hdev->conn_hash.list, list) {
		struct hci_cis *cis = &cmd->cis[aux_num_cis];

		if (hci_conn_check_create_cis(conn) ||
		    conn->iso_qos.ucast.cig != cig)
			continue;

		set_bit(HCI_CONN_CREATE_CIS, &conn->flags);
		cis->acl_handle = cpu_to_le16(conn->parent->handle);
		cis->cis_handle = cpu_to_le16(conn->handle);
		timeout = conn->conn_timeout;
		aux_num_cis++;

		if (aux_num_cis >= cmd->num_cis)
			break;
	}
	cmd->num_cis = aux_num_cis;

done:
	rcu_read_unlock();

	hci_dev_unlock(hdev);

	if (!aux_num_cis)
		return 0;

	/* Wait for HCI_LE_CIS_Established */
	return __hci_cmd_sync_status_sk(hdev, HCI_OP_LE_CREATE_CIS,
					struct_size(cmd, cis, cmd->num_cis),
					cmd, HCI_EVT_LE_CIS_ESTABLISHED,
					timeout, NULL);
}


#include <linux/livepatch.h>

extern typeof(__hci_cmd_sync_status_sk) __hci_cmd_sync_status_sk
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, __hci_cmd_sync_status_sk);
extern typeof(hci_conn_check_create_cis) hci_conn_check_create_cis
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_conn_check_create_cis);
