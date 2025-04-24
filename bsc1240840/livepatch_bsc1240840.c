/*
 * livepatch_bsc1240840
 *
 * Fix for CVE-2024-8805, bsc#1240840
 *
 *  Upstream commit:
 *  b25e11f978b6 ("Bluetooth: hci_event: Align BR/EDR JUST_WORKS paring with LE")
 *
 *  SLE12-SP5 commit:
 *  af6048b022000ff5c2bf3ed881612fcf7f7b0ecf
 *
 *  SLE15-SP3 commit:
 *  da492aab649e9fed95dd30e414ba42f5b2a3c059
 *
 *  SLE15-SP4 and -SP5 commit:
 *  cddc976fdab25e50013c4bd6a53b61edd5b1c733
 *
 *  SLE15-SP6 commit:
 *  456d926a7b48b230a7314841d98a0b8b09159e9e
 *
 *  SLE MICRO-6-0 commit:
 *  456d926a7b48b230a7314841d98a0b8b09159e9e
 *
 *  Copyright (c) 2025 SUSE
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

/* klp-ccp: from net/bluetooth/hci_event.c */
#include <asm/unaligned.h>
#include <linux/crypto.h>

#include <net/bluetooth/bluetooth.h>
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
void klpp_hci_event_packet(struct hci_dev *hdev, struct sk_buff *skb);

/* klp-ccp: from include/net/bluetooth/mgmt.h */
#define MGMT_WAKE_REASON_UNEXPECTED		0x1
#define MGMT_WAKE_REASON_REMOTE_WAKE		0x2

/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>

void hci_req_cmd_complete(struct hci_dev *hdev, u16 opcode, u8 status,
			  hci_req_complete_t *req_complete,
			  hci_req_complete_skb_t *req_complete_skb);

/* klp-ccp: from net/bluetooth/msft.h */
#if IS_ENABLED(CONFIG_BT_MSFTEXT)

void msft_vendor_evt(struct hci_dev *hdev, void *data, struct sk_buff *skb);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/bluetooth/eir.h */
#include <asm/unaligned.h>

/* klp-ccp: from net/bluetooth/hci_event.c */
static void *hci_ev_skb_pull(struct hci_dev *hdev, struct sk_buff *skb,
			     u8 ev, size_t len)
{
	void *data;

	data = skb_pull_data(skb, len);
	if (!data)
		bt_dev_err(hdev, "Malformed Event: 0x%2.2x", ev);

	return data;
}

static void *hci_cc_skb_pull(struct hci_dev *hdev, struct sk_buff *skb,
			     u16 op, size_t len)
{
	void *data;

	data = skb_pull_data(skb, len);
	if (!data)
		bt_dev_err(hdev, "Malformed Command Complete: 0x%4.4x", op);

	return data;
}

extern void hci_inquiry_complete_evt(struct hci_dev *hdev, void *data,
				     struct sk_buff *skb);

extern void hci_inquiry_result_evt(struct hci_dev *hdev, void *edata,
				   struct sk_buff *skb);

extern void hci_conn_complete_evt(struct hci_dev *hdev, void *data,
				  struct sk_buff *skb);

extern void hci_conn_request_evt(struct hci_dev *hdev, void *data,
				 struct sk_buff *skb);

extern void hci_disconn_complete_evt(struct hci_dev *hdev, void *data,
				     struct sk_buff *skb);

extern void hci_auth_complete_evt(struct hci_dev *hdev, void *data,
				  struct sk_buff *skb);

extern void hci_remote_name_evt(struct hci_dev *hdev, void *data,
				struct sk_buff *skb);

extern void hci_encrypt_change_evt(struct hci_dev *hdev, void *data,
				   struct sk_buff *skb);

extern void hci_change_link_key_complete_evt(struct hci_dev *hdev, void *data,
					     struct sk_buff *skb);

extern void hci_remote_features_evt(struct hci_dev *hdev, void *data,
				    struct sk_buff *skb);

extern void hci_cmd_complete_evt(struct hci_dev *hdev, void *data,
				 struct sk_buff *skb, u16 *opcode, u8 *status,
				 hci_req_complete_t *req_complete,
				 hci_req_complete_skb_t *req_complete_skb);

extern void hci_cmd_status_evt(struct hci_dev *hdev, void *data,
			       struct sk_buff *skb, u16 *opcode, u8 *status,
			       hci_req_complete_t *req_complete,
			       hci_req_complete_skb_t *req_complete_skb);

extern void hci_hardware_error_evt(struct hci_dev *hdev, void *data,
				   struct sk_buff *skb);

extern void hci_role_change_evt(struct hci_dev *hdev, void *data,
				struct sk_buff *skb);

extern void hci_num_comp_pkts_evt(struct hci_dev *hdev, void *data,
				  struct sk_buff *skb);

extern void hci_num_comp_blocks_evt(struct hci_dev *hdev, void *data,
				    struct sk_buff *skb);

extern void hci_mode_change_evt(struct hci_dev *hdev, void *data,
				struct sk_buff *skb);

extern void hci_pin_code_request_evt(struct hci_dev *hdev, void *data,
				     struct sk_buff *skb);

extern void hci_link_key_request_evt(struct hci_dev *hdev, void *data,
				     struct sk_buff *skb);

extern void hci_link_key_notify_evt(struct hci_dev *hdev, void *data,
				    struct sk_buff *skb);

extern void hci_clock_offset_evt(struct hci_dev *hdev, void *data,
				 struct sk_buff *skb);

extern void hci_pkt_type_change_evt(struct hci_dev *hdev, void *data,
				    struct sk_buff *skb);

extern void hci_pscan_rep_mode_evt(struct hci_dev *hdev, void *data,
				   struct sk_buff *skb);

extern void hci_inquiry_result_with_rssi_evt(struct hci_dev *hdev, void *edata,
					     struct sk_buff *skb);

extern void hci_remote_ext_features_evt(struct hci_dev *hdev, void *data,
					struct sk_buff *skb);

extern void hci_sync_conn_complete_evt(struct hci_dev *hdev, void *data,
				       struct sk_buff *skb);

extern void hci_extended_inquiry_result_evt(struct hci_dev *hdev, void *edata,
					    struct sk_buff *skb);

extern void hci_key_refresh_complete_evt(struct hci_dev *hdev, void *data,
					 struct sk_buff *skb);

extern void hci_io_capa_request_evt(struct hci_dev *hdev, void *data,
				    struct sk_buff *skb);

extern void hci_io_capa_reply_evt(struct hci_dev *hdev, void *data,
				  struct sk_buff *skb);

extern void hci_user_confirm_request_evt(struct hci_dev *hdev, void *data,
					 struct sk_buff *skb);

static void klpp_hci_user_confirm_request_evt(struct hci_dev *hdev, void *data,
					 struct sk_buff *skb)
{
	struct hci_ev_user_confirm_req *ev = data;
	int loc_mitm, rem_mitm, confirm_hint = 0;
	struct hci_conn *conn;

	bt_dev_dbg(hdev, "");

	hci_dev_lock(hdev);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		goto unlock;

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		goto unlock;

	loc_mitm = (conn->auth_type & 0x01);
	rem_mitm = (conn->remote_auth & 0x01);

	/* If we require MITM but the remote device can't provide that
	 * (it has NoInputNoOutput) then reject the confirmation
	 * request. We check the security level here since it doesn't
	 * necessarily match conn->auth_type.
	 */
	if (conn->pending_sec_level > BT_SECURITY_MEDIUM &&
	    conn->remote_cap == HCI_IO_NO_INPUT_OUTPUT) {
		bt_dev_dbg(hdev, "Rejecting request: remote device can't provide MITM");
		hci_send_cmd(hdev, HCI_OP_USER_CONFIRM_NEG_REPLY,
			     sizeof(ev->bdaddr), &ev->bdaddr);
		goto unlock;
	}

	/* If no side requires MITM protection; use JUST_CFM method */
	if ((!loc_mitm || conn->remote_cap == HCI_IO_NO_INPUT_OUTPUT) &&
	    (!rem_mitm || conn->io_capability == HCI_IO_NO_INPUT_OUTPUT)) {

		/* If we're not the initiator of request authorization and the
		 * local IO capability is not NoInputNoOutput, use JUST_WORKS
		 * method (mgmt_user_confirm with confirm_hint set to 1).
		 */
		if (!test_bit(HCI_CONN_AUTH_PEND, &conn->flags) &&
		    conn->io_capability != HCI_IO_NO_INPUT_OUTPUT) {
			bt_dev_dbg(hdev, "Confirming auto-accept as acceptor");
			confirm_hint = 1;
			goto confirm;
		}

		/* If there already exists link key in local host, leave the
		 * decision to user space since the remote device could be
		 * legitimate or malicious.
		 */
		if (hci_find_link_key(hdev, &ev->bdaddr)) {
			bt_dev_dbg(hdev, "Local host already has link key");
			confirm_hint = 1;
			goto confirm;
		}

		BT_DBG("Auto-accept of user confirmation with %ums delay",
		       hdev->auto_accept_delay);

		if (hdev->auto_accept_delay > 0) {
			int delay = msecs_to_jiffies(hdev->auto_accept_delay);
			queue_delayed_work(conn->hdev->workqueue,
					   &conn->auto_accept_work, delay);
			goto unlock;
		}

		hci_send_cmd(hdev, HCI_OP_USER_CONFIRM_REPLY,
			     sizeof(ev->bdaddr), &ev->bdaddr);
		goto unlock;
	}

confirm:
	mgmt_user_confirm_request(hdev, &ev->bdaddr, ACL_LINK, 0,
				  le32_to_cpu(ev->passkey), confirm_hint);

unlock:
	hci_dev_unlock(hdev);
}

extern void hci_user_passkey_request_evt(struct hci_dev *hdev, void *data,
					 struct sk_buff *skb);

extern void hci_user_passkey_notify_evt(struct hci_dev *hdev, void *data,
					struct sk_buff *skb);

extern void hci_keypress_notify_evt(struct hci_dev *hdev, void *data,
				    struct sk_buff *skb);

extern void hci_simple_pair_complete_evt(struct hci_dev *hdev, void *data,
					 struct sk_buff *skb);

extern void hci_remote_host_features_evt(struct hci_dev *hdev, void *data,
					 struct sk_buff *skb);

extern void hci_remote_oob_data_request_evt(struct hci_dev *hdev, void *edata,
					    struct sk_buff *skb);

#if IS_ENABLED(CONFIG_BT_HS)
extern void hci_chan_selected_evt(struct hci_dev *hdev, void *data,
				  struct sk_buff *skb);

extern void hci_phy_link_complete_evt(struct hci_dev *hdev, void *data,
				      struct sk_buff *skb);

extern void hci_loglink_complete_evt(struct hci_dev *hdev, void *data,
				     struct sk_buff *skb);

extern void hci_disconn_loglink_complete_evt(struct hci_dev *hdev, void *data,
					     struct sk_buff *skb);

extern void hci_disconn_phylink_complete_evt(struct hci_dev *hdev, void *data,
					     struct sk_buff *skb);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

extern void hci_le_meta_evt(struct hci_dev *hdev, void *data,
			    struct sk_buff *skb, u16 *opcode, u8 *status,
			    hci_req_complete_t *req_complete,
			    hci_req_complete_skb_t *req_complete_skb);

static bool hci_get_cmd_complete(struct hci_dev *hdev, u16 opcode,
				 u8 event, struct sk_buff *skb)
{
	struct hci_ev_cmd_complete *ev;
	struct hci_event_hdr *hdr;

	if (!skb)
		return false;

	hdr = hci_ev_skb_pull(hdev, skb, event, sizeof(*hdr));
	if (!hdr)
		return false;

	if (event) {
		if (hdr->evt != event)
			return false;
		return true;
	}

	/* Check if request ended in Command Status - no way to retrieve
	 * any extra parameters in this case.
	 */
	if (hdr->evt == HCI_EV_CMD_STATUS)
		return false;

	if (hdr->evt != HCI_EV_CMD_COMPLETE) {
		bt_dev_err(hdev, "last event is not cmd complete (0x%2.2x)",
			   hdr->evt);
		return false;
	}

	ev = hci_cc_skb_pull(hdev, skb, opcode, sizeof(*ev));
	if (!ev)
		return false;

	if (opcode != __le16_to_cpu(ev->opcode)) {
		BT_DBG("opcode doesn't match (0x%2.2x != 0x%2.2x)", opcode,
		       __le16_to_cpu(ev->opcode));
		return false;
	}

	return true;
}

static void hci_store_wake_reason(struct hci_dev *hdev, u8 event,
				  struct sk_buff *skb)
{
	struct hci_ev_le_advertising_info *adv;
	struct hci_ev_le_direct_adv_info *direct_adv;
	struct hci_ev_le_ext_adv_info *ext_adv;
	const struct hci_ev_conn_complete *conn_complete = (void *)skb->data;
	const struct hci_ev_conn_request *conn_request = (void *)skb->data;

	hci_dev_lock(hdev);

	/* If we are currently suspended and this is the first BT event seen,
	 * save the wake reason associated with the event.
	 */
	if (!hdev->suspended || hdev->wake_reason)
		goto unlock;

	/* Default to remote wake. Values for wake_reason are documented in the
	 * Bluez mgmt api docs.
	 */
	hdev->wake_reason = MGMT_WAKE_REASON_REMOTE_WAKE;

	/* Once configured for remote wakeup, we should only wake up for
	 * reconnections. It's useful to see which device is waking us up so
	 * keep track of the bdaddr of the connection event that woke us up.
	 */
	if (event == HCI_EV_CONN_REQUEST) {
		bacpy(&hdev->wake_addr, &conn_request->bdaddr);
		hdev->wake_addr_type = BDADDR_BREDR;
	} else if (event == HCI_EV_CONN_COMPLETE) {
		bacpy(&hdev->wake_addr, &conn_complete->bdaddr);
		hdev->wake_addr_type = BDADDR_BREDR;
	} else if (event == HCI_EV_LE_META) {
		struct hci_ev_le_meta *le_ev = (void *)skb->data;
		u8 subevent = le_ev->subevent;
		u8 *ptr = &skb->data[sizeof(*le_ev)];
		u8 num_reports = *ptr;

		if ((subevent == HCI_EV_LE_ADVERTISING_REPORT ||
		     subevent == HCI_EV_LE_DIRECT_ADV_REPORT ||
		     subevent == HCI_EV_LE_EXT_ADV_REPORT) &&
		    num_reports) {
			adv = (void *)(ptr + 1);
			direct_adv = (void *)(ptr + 1);
			ext_adv = (void *)(ptr + 1);

			switch (subevent) {
			case HCI_EV_LE_ADVERTISING_REPORT:
				bacpy(&hdev->wake_addr, &adv->bdaddr);
				hdev->wake_addr_type = adv->bdaddr_type;
				break;
			case HCI_EV_LE_DIRECT_ADV_REPORT:
				bacpy(&hdev->wake_addr, &direct_adv->bdaddr);
				hdev->wake_addr_type = direct_adv->bdaddr_type;
				break;
			case HCI_EV_LE_EXT_ADV_REPORT:
				bacpy(&hdev->wake_addr, &ext_adv->bdaddr);
				hdev->wake_addr_type = ext_adv->bdaddr_type;
				break;
			}
		}
	} else {
		hdev->wake_reason = MGMT_WAKE_REASON_UNEXPECTED;
	}

unlock:
	hci_dev_unlock(hdev);
}

#define HCI_EV_VL(_op, _func, _min_len, _max_len) \
[_op] = { \
	.req = false, \
	.func = _func, \
	.min_len = _min_len, \
	.max_len = _max_len, \
}

#define HCI_EV(_op, _func, _len) \
	HCI_EV_VL(_op, _func, _len, _len)

#define HCI_EV_STATUS(_op, _func) \
	HCI_EV(_op, _func, sizeof(struct hci_ev_status))

#define HCI_EV_REQ_VL(_op, _func, _min_len, _max_len) \
[_op] = { \
	.req = true, \
	.func_req = _func, \
	.min_len = _min_len, \
	.max_len = _max_len, \
}

#define HCI_EV_REQ(_op, _func, _len) \
	HCI_EV_REQ_VL(_op, _func, _len, _len)

static const struct hci_ev {
	bool req;
	union {
		void (*func)(struct hci_dev *hdev, void *data,
			     struct sk_buff *skb);
		void (*func_req)(struct hci_dev *hdev, void *data,
				 struct sk_buff *skb, u16 *opcode, u8 *status,
				 hci_req_complete_t *req_complete,
				 hci_req_complete_skb_t *req_complete_skb);
	};
	u16  min_len;
	u16  max_len;
} hci_ev_table[U8_MAX + 1] = {
	/* [0x01 = HCI_EV_INQUIRY_COMPLETE] */
	HCI_EV_STATUS(HCI_EV_INQUIRY_COMPLETE, hci_inquiry_complete_evt),
	/* [0x02 = HCI_EV_INQUIRY_RESULT] */
	HCI_EV_VL(HCI_EV_INQUIRY_RESULT, hci_inquiry_result_evt,
		  sizeof(struct hci_ev_inquiry_result), HCI_MAX_EVENT_SIZE),
	/* [0x03 = HCI_EV_CONN_COMPLETE] */
	HCI_EV(HCI_EV_CONN_COMPLETE, hci_conn_complete_evt,
	       sizeof(struct hci_ev_conn_complete)),
	/* [0x04 = HCI_EV_CONN_REQUEST] */
	HCI_EV(HCI_EV_CONN_REQUEST, hci_conn_request_evt,
	       sizeof(struct hci_ev_conn_request)),
	/* [0x05 = HCI_EV_DISCONN_COMPLETE] */
	HCI_EV(HCI_EV_DISCONN_COMPLETE, hci_disconn_complete_evt,
	       sizeof(struct hci_ev_disconn_complete)),
	/* [0x06 = HCI_EV_AUTH_COMPLETE] */
	HCI_EV(HCI_EV_AUTH_COMPLETE, hci_auth_complete_evt,
	       sizeof(struct hci_ev_auth_complete)),
	/* [0x07 = HCI_EV_REMOTE_NAME] */
	HCI_EV(HCI_EV_REMOTE_NAME, hci_remote_name_evt,
	       sizeof(struct hci_ev_remote_name)),
	/* [0x08 = HCI_EV_ENCRYPT_CHANGE] */
	HCI_EV(HCI_EV_ENCRYPT_CHANGE, hci_encrypt_change_evt,
	       sizeof(struct hci_ev_encrypt_change)),
	/* [0x09 = HCI_EV_CHANGE_LINK_KEY_COMPLETE] */
	HCI_EV(HCI_EV_CHANGE_LINK_KEY_COMPLETE,
	       hci_change_link_key_complete_evt,
	       sizeof(struct hci_ev_change_link_key_complete)),
	/* [0x0b = HCI_EV_REMOTE_FEATURES] */
	HCI_EV(HCI_EV_REMOTE_FEATURES, hci_remote_features_evt,
	       sizeof(struct hci_ev_remote_features)),
	/* [0x0e = HCI_EV_CMD_COMPLETE] */
	HCI_EV_REQ_VL(HCI_EV_CMD_COMPLETE, hci_cmd_complete_evt,
		      sizeof(struct hci_ev_cmd_complete), HCI_MAX_EVENT_SIZE),
	/* [0x0f = HCI_EV_CMD_STATUS] */
	HCI_EV_REQ(HCI_EV_CMD_STATUS, hci_cmd_status_evt,
		   sizeof(struct hci_ev_cmd_status)),
	/* [0x10 = HCI_EV_CMD_STATUS] */
	HCI_EV(HCI_EV_HARDWARE_ERROR, hci_hardware_error_evt,
	       sizeof(struct hci_ev_hardware_error)),
	/* [0x12 = HCI_EV_ROLE_CHANGE] */
	HCI_EV(HCI_EV_ROLE_CHANGE, hci_role_change_evt,
	       sizeof(struct hci_ev_role_change)),
	/* [0x13 = HCI_EV_NUM_COMP_PKTS] */
	HCI_EV_VL(HCI_EV_NUM_COMP_PKTS, hci_num_comp_pkts_evt,
		  sizeof(struct hci_ev_num_comp_pkts), HCI_MAX_EVENT_SIZE),
	/* [0x14 = HCI_EV_MODE_CHANGE] */
	HCI_EV(HCI_EV_MODE_CHANGE, hci_mode_change_evt,
	       sizeof(struct hci_ev_mode_change)),
	/* [0x16 = HCI_EV_PIN_CODE_REQ] */
	HCI_EV(HCI_EV_PIN_CODE_REQ, hci_pin_code_request_evt,
	       sizeof(struct hci_ev_pin_code_req)),
	/* [0x17 = HCI_EV_LINK_KEY_REQ] */
	HCI_EV(HCI_EV_LINK_KEY_REQ, hci_link_key_request_evt,
	       sizeof(struct hci_ev_link_key_req)),
	/* [0x18 = HCI_EV_LINK_KEY_NOTIFY] */
	HCI_EV(HCI_EV_LINK_KEY_NOTIFY, hci_link_key_notify_evt,
	       sizeof(struct hci_ev_link_key_notify)),
	/* [0x1c = HCI_EV_CLOCK_OFFSET] */
	HCI_EV(HCI_EV_CLOCK_OFFSET, hci_clock_offset_evt,
	       sizeof(struct hci_ev_clock_offset)),
	/* [0x1d = HCI_EV_PKT_TYPE_CHANGE] */
	HCI_EV(HCI_EV_PKT_TYPE_CHANGE, hci_pkt_type_change_evt,
	       sizeof(struct hci_ev_pkt_type_change)),
	/* [0x20 = HCI_EV_PSCAN_REP_MODE] */
	HCI_EV(HCI_EV_PSCAN_REP_MODE, hci_pscan_rep_mode_evt,
	       sizeof(struct hci_ev_pscan_rep_mode)),
	/* [0x22 = HCI_EV_INQUIRY_RESULT_WITH_RSSI] */
	HCI_EV_VL(HCI_EV_INQUIRY_RESULT_WITH_RSSI,
		  hci_inquiry_result_with_rssi_evt,
		  sizeof(struct hci_ev_inquiry_result_rssi),
		  HCI_MAX_EVENT_SIZE),
	/* [0x23 = HCI_EV_REMOTE_EXT_FEATURES] */
	HCI_EV(HCI_EV_REMOTE_EXT_FEATURES, hci_remote_ext_features_evt,
	       sizeof(struct hci_ev_remote_ext_features)),
	/* [0x2c = HCI_EV_SYNC_CONN_COMPLETE] */
	HCI_EV(HCI_EV_SYNC_CONN_COMPLETE, hci_sync_conn_complete_evt,
	       sizeof(struct hci_ev_sync_conn_complete)),
	/* [0x2d = HCI_EV_EXTENDED_INQUIRY_RESULT] */
	HCI_EV_VL(HCI_EV_EXTENDED_INQUIRY_RESULT,
		  hci_extended_inquiry_result_evt,
		  sizeof(struct hci_ev_ext_inquiry_result), HCI_MAX_EVENT_SIZE),
	/* [0x30 = HCI_EV_KEY_REFRESH_COMPLETE] */
	HCI_EV(HCI_EV_KEY_REFRESH_COMPLETE, hci_key_refresh_complete_evt,
	       sizeof(struct hci_ev_key_refresh_complete)),
	/* [0x31 = HCI_EV_IO_CAPA_REQUEST] */
	HCI_EV(HCI_EV_IO_CAPA_REQUEST, hci_io_capa_request_evt,
	       sizeof(struct hci_ev_io_capa_request)),
	/* [0x32 = HCI_EV_IO_CAPA_REPLY] */
	HCI_EV(HCI_EV_IO_CAPA_REPLY, hci_io_capa_reply_evt,
	       sizeof(struct hci_ev_io_capa_reply)),
	/* [0x33 = HCI_EV_USER_CONFIRM_REQUEST] */
	HCI_EV(HCI_EV_USER_CONFIRM_REQUEST, klpp_hci_user_confirm_request_evt,
	       sizeof(struct hci_ev_user_confirm_req)),
	/* [0x34 = HCI_EV_USER_PASSKEY_REQUEST] */
	HCI_EV(HCI_EV_USER_PASSKEY_REQUEST, hci_user_passkey_request_evt,
	       sizeof(struct hci_ev_user_passkey_req)),
	/* [0x35 = HCI_EV_REMOTE_OOB_DATA_REQUEST] */
	HCI_EV(HCI_EV_REMOTE_OOB_DATA_REQUEST, hci_remote_oob_data_request_evt,
	       sizeof(struct hci_ev_remote_oob_data_request)),
	/* [0x36 = HCI_EV_SIMPLE_PAIR_COMPLETE] */
	HCI_EV(HCI_EV_SIMPLE_PAIR_COMPLETE, hci_simple_pair_complete_evt,
	       sizeof(struct hci_ev_simple_pair_complete)),
	/* [0x3b = HCI_EV_USER_PASSKEY_NOTIFY] */
	HCI_EV(HCI_EV_USER_PASSKEY_NOTIFY, hci_user_passkey_notify_evt,
	       sizeof(struct hci_ev_user_passkey_notify)),
	/* [0x3c = HCI_EV_KEYPRESS_NOTIFY] */
	HCI_EV(HCI_EV_KEYPRESS_NOTIFY, hci_keypress_notify_evt,
	       sizeof(struct hci_ev_keypress_notify)),
	/* [0x3d = HCI_EV_REMOTE_HOST_FEATURES] */
	HCI_EV(HCI_EV_REMOTE_HOST_FEATURES, hci_remote_host_features_evt,
	       sizeof(struct hci_ev_remote_host_features)),
	/* [0x3e = HCI_EV_LE_META] */
	HCI_EV_REQ_VL(HCI_EV_LE_META, hci_le_meta_evt,
		      sizeof(struct hci_ev_le_meta), HCI_MAX_EVENT_SIZE),
#if IS_ENABLED(CONFIG_BT_HS)
	HCI_EV(HCI_EV_PHY_LINK_COMPLETE, hci_phy_link_complete_evt,
	       sizeof(struct hci_ev_phy_link_complete)),
	/* [0x41 = HCI_EV_CHANNEL_SELECTED] */
	HCI_EV(HCI_EV_CHANNEL_SELECTED, hci_chan_selected_evt,
	       sizeof(struct hci_ev_channel_selected)),
	/* [0x42 = HCI_EV_DISCONN_PHY_LINK_COMPLETE] */
	HCI_EV(HCI_EV_DISCONN_LOGICAL_LINK_COMPLETE,
	       hci_disconn_loglink_complete_evt,
	       sizeof(struct hci_ev_disconn_logical_link_complete)),
	/* [0x45 = HCI_EV_LOGICAL_LINK_COMPLETE] */
	HCI_EV(HCI_EV_LOGICAL_LINK_COMPLETE, hci_loglink_complete_evt,
	       sizeof(struct hci_ev_logical_link_complete)),
	/* [0x46 = HCI_EV_DISCONN_LOGICAL_LINK_COMPLETE] */
	HCI_EV(HCI_EV_DISCONN_PHY_LINK_COMPLETE,
	       hci_disconn_phylink_complete_evt,
	       sizeof(struct hci_ev_disconn_phy_link_complete)),
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	HCI_EV(HCI_EV_NUM_COMP_BLOCKS, hci_num_comp_blocks_evt,
	       sizeof(struct hci_ev_num_comp_blocks)),
	/* [0xff = HCI_EV_VENDOR] */
	HCI_EV_VL(HCI_EV_VENDOR, msft_vendor_evt, 0, HCI_MAX_EVENT_SIZE),
};

static void klpp_hci_event_func(struct hci_dev *hdev, u8 event, struct sk_buff *skb,
			   u16 *opcode, u8 *status,
			   hci_req_complete_t *req_complete,
			   hci_req_complete_skb_t *req_complete_skb)
{
	const struct hci_ev *ev = &hci_ev_table[event];
	void *data;

	if (!ev->func)
		return;

	if (skb->len < ev->min_len) {
		bt_dev_err(hdev, "unexpected event 0x%2.2x length: %u < %u",
			   event, skb->len, ev->min_len);
		return;
	}

	/* Just warn if the length is over max_len size it still be
	 * possible to partially parse the event so leave to callback to
	 * decide if that is acceptable.
	 */
	if (skb->len > ev->max_len)
		bt_dev_warn_ratelimited(hdev,
					"unexpected event 0x%2.2x length: %u > %u",
					event, skb->len, ev->max_len);

	data = hci_ev_skb_pull(hdev, skb, event, ev->min_len);
	if (!data)
		return;

	if (ev->req)
		ev->func_req(hdev, data, skb, opcode, status, req_complete,
			     req_complete_skb);
	else
		ev->func(hdev, data, skb);
}

void klpp_hci_event_packet(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_event_hdr *hdr = (void *) skb->data;
	hci_req_complete_t req_complete = NULL;
	hci_req_complete_skb_t req_complete_skb = NULL;
	struct sk_buff *orig_skb = NULL;
	u8 status = 0, event, req_evt = 0;
	u16 opcode = HCI_OP_NOP;

	if (skb->len < sizeof(*hdr)) {
		bt_dev_err(hdev, "Malformed HCI Event");
		goto done;
	}

	kfree_skb(hdev->recv_event);
	hdev->recv_event = skb_clone(skb, GFP_KERNEL);

	event = hdr->evt;
	if (!event) {
		bt_dev_warn(hdev, "Received unexpected HCI Event 0x%2.2x",
			    event);
		goto done;
	}

	/* Only match event if command OGF is not for LE */
	if (hdev->sent_cmd &&
	    hci_opcode_ogf(hci_skb_opcode(hdev->sent_cmd)) != 0x08 &&
	    hci_skb_event(hdev->sent_cmd) == event) {
		hci_req_cmd_complete(hdev, hci_skb_opcode(hdev->sent_cmd),
				     status, &req_complete, &req_complete_skb);
		req_evt = event;
	}

	/* If it looks like we might end up having to call
	 * req_complete_skb, store a pristine copy of the skb since the
	 * various handlers may modify the original one through
	 * skb_pull() calls, etc.
	 */
	if (req_complete_skb || event == HCI_EV_CMD_STATUS ||
	    event == HCI_EV_CMD_COMPLETE)
		orig_skb = skb_clone(skb, GFP_KERNEL);

	skb_pull(skb, HCI_EVENT_HDR_SIZE);

	/* Store wake reason if we're suspended */
	hci_store_wake_reason(hdev, event, skb);

	bt_dev_dbg(hdev, "event 0x%2.2x", event);

	klpp_hci_event_func(hdev, event, skb, &opcode, &status, &req_complete,
		       &req_complete_skb);

	if (req_complete) {
		req_complete(hdev, status, opcode);
	} else if (req_complete_skb) {
		if (!hci_get_cmd_complete(hdev, opcode, req_evt, orig_skb)) {
			kfree_skb(orig_skb);
			orig_skb = NULL;
		}
		req_complete_skb(hdev, status, opcode, orig_skb);
	}

done:
	kfree_skb(orig_skb);
	kfree_skb(skb);
	hdev->stat.evt_rx++;
}


#include "livepatch_bsc1240840.h"

#include <linux/livepatch.h>

extern typeof(bt_err) bt_err KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_err);
extern typeof(bt_warn) bt_warn KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_warn);
extern typeof(bt_warn_ratelimited) bt_warn_ratelimited
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, bt_warn_ratelimited);
extern typeof(hci_auth_complete_evt) hci_auth_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_auth_complete_evt);
extern typeof(hci_chan_selected_evt) hci_chan_selected_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_chan_selected_evt);
extern typeof(hci_change_link_key_complete_evt) hci_change_link_key_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_change_link_key_complete_evt);
extern typeof(hci_clock_offset_evt) hci_clock_offset_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_clock_offset_evt);
extern typeof(hci_cmd_complete_evt) hci_cmd_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_cmd_complete_evt);
extern typeof(hci_cmd_status_evt) hci_cmd_status_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_cmd_status_evt);
extern typeof(hci_conn_complete_evt) hci_conn_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_conn_complete_evt);
extern typeof(hci_conn_request_evt) hci_conn_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_conn_request_evt);
extern typeof(hci_disconn_complete_evt) hci_disconn_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_disconn_complete_evt);
extern typeof(hci_disconn_loglink_complete_evt) hci_disconn_loglink_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_disconn_loglink_complete_evt);
extern typeof(hci_disconn_phylink_complete_evt) hci_disconn_phylink_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_disconn_phylink_complete_evt);
extern typeof(hci_encrypt_change_evt) hci_encrypt_change_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_encrypt_change_evt);
extern typeof(hci_extended_inquiry_result_evt) hci_extended_inquiry_result_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_extended_inquiry_result_evt);
extern typeof(hci_find_link_key) hci_find_link_key
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_find_link_key);
extern typeof(hci_hardware_error_evt) hci_hardware_error_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_hardware_error_evt);
extern typeof(hci_inquiry_complete_evt) hci_inquiry_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_inquiry_complete_evt);
extern typeof(hci_inquiry_result_evt) hci_inquiry_result_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_inquiry_result_evt);
extern typeof(hci_inquiry_result_with_rssi_evt) hci_inquiry_result_with_rssi_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_inquiry_result_with_rssi_evt);
extern typeof(hci_io_capa_reply_evt) hci_io_capa_reply_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_io_capa_reply_evt);
extern typeof(hci_io_capa_request_evt) hci_io_capa_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_io_capa_request_evt);
extern typeof(hci_key_refresh_complete_evt) hci_key_refresh_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_key_refresh_complete_evt);
extern typeof(hci_keypress_notify_evt) hci_keypress_notify_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_keypress_notify_evt);
extern typeof(hci_le_meta_evt) hci_le_meta_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_le_meta_evt);
extern typeof(hci_link_key_notify_evt) hci_link_key_notify_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_link_key_notify_evt);
extern typeof(hci_link_key_request_evt) hci_link_key_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_link_key_request_evt);
extern typeof(hci_loglink_complete_evt) hci_loglink_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_loglink_complete_evt);
extern typeof(hci_mode_change_evt) hci_mode_change_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_mode_change_evt);
extern typeof(hci_num_comp_blocks_evt) hci_num_comp_blocks_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_num_comp_blocks_evt);
extern typeof(hci_num_comp_pkts_evt) hci_num_comp_pkts_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_num_comp_pkts_evt);
extern typeof(hci_phy_link_complete_evt) hci_phy_link_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_phy_link_complete_evt);
extern typeof(hci_pin_code_request_evt) hci_pin_code_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_pin_code_request_evt);
extern typeof(hci_pkt_type_change_evt) hci_pkt_type_change_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_pkt_type_change_evt);
extern typeof(hci_pscan_rep_mode_evt) hci_pscan_rep_mode_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_pscan_rep_mode_evt);
extern typeof(hci_remote_ext_features_evt) hci_remote_ext_features_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_remote_ext_features_evt);
extern typeof(hci_remote_features_evt) hci_remote_features_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_remote_features_evt);
extern typeof(hci_remote_host_features_evt) hci_remote_host_features_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_remote_host_features_evt);
extern typeof(hci_remote_name_evt) hci_remote_name_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_remote_name_evt);
extern typeof(hci_remote_oob_data_request_evt) hci_remote_oob_data_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_remote_oob_data_request_evt);
extern typeof(hci_req_cmd_complete) hci_req_cmd_complete
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_req_cmd_complete);
extern typeof(hci_role_change_evt) hci_role_change_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_role_change_evt);
extern typeof(hci_send_cmd) hci_send_cmd
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_send_cmd);
extern typeof(hci_simple_pair_complete_evt) hci_simple_pair_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_simple_pair_complete_evt);
extern typeof(hci_sync_conn_complete_evt) hci_sync_conn_complete_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_sync_conn_complete_evt);
extern typeof(hci_user_confirm_request_evt) hci_user_confirm_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_user_confirm_request_evt);
extern typeof(hci_user_passkey_notify_evt) hci_user_passkey_notify_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_user_passkey_notify_evt);
extern typeof(hci_user_passkey_request_evt) hci_user_passkey_request_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, hci_user_passkey_request_evt);
extern typeof(mgmt_user_confirm_request) mgmt_user_confirm_request
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, mgmt_user_confirm_request);
extern typeof(msft_vendor_evt) msft_vendor_evt
	 KLP_RELOC_SYMBOL(bluetooth, bluetooth, msft_vendor_evt);

#endif /* IS_ENABLED(CONFIG_BT) */
