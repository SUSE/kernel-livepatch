/*
 * bsc1186285_hci_event
 *
 * Fix for CVE-2021-33034, bsc#1186285 (net/bluetooth/hci_event.c part)
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

/* klp-ccp: from net/bluetooth/hci_event.c */
#include <asm/unaligned.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static __printf(1, 2)
void (*klpe_bt_info)(const char *fmt, ...);
static __printf(1, 2)
void (*klpe_bt_warn)(const char *fmt, ...);
static __printf(1, 2)
void (*klpe_bt_err)(const char *fmt, ...);

/* klp-ccp: from net/bluetooth/hci_event.c */
#include <net/bluetooth/hci_core.h>

/* klp-ccp: from include/net/bluetooth/hci_core.h */
static struct list_head (*klpe_hci_cb_list);

static struct mutex (*klpe_hci_cb_list_lock);

static int (*klpe_l2cap_connect_ind)(struct hci_dev *hdev, bdaddr_t *bdaddr);

#if IS_ENABLED(CONFIG_BT_BREDR)
static int (*klpe_sco_connect_ind)(struct hci_dev *hdev, bdaddr_t *bdaddr, __u8 *flags);

#else
#error "klp-ccp: non-taken branch"
#endif

static void (*klpe_hci_discovery_set_state)(struct hci_dev *hdev, int state);

static struct inquiry_entry *(*klpe_hci_inquiry_cache_lookup)(struct hci_dev *hdev,
					       bdaddr_t *bdaddr);

static struct inquiry_entry *(*klpe_hci_inquiry_cache_lookup_resolve)(struct hci_dev *hdev,
						       bdaddr_t *bdaddr,
						       int state);

static u32 (*klpe_hci_inquiry_cache_update)(struct hci_dev *hdev, struct inquiry_data *data,
			     bool name_known);

static int (*klpe_hci_disconnect)(struct hci_conn *conn, __u8 reason);
static bool (*klpe_hci_setup_sync)(struct hci_conn *conn, __u16 handle);
static void (*klpe_hci_sco_setup)(struct hci_conn *conn, __u8 status);

static struct hci_conn *(*klpe_hci_conn_add)(struct hci_dev *hdev, int type, bdaddr_t *dst,
			      u8 role);
static int (*klpe_hci_conn_del)(struct hci_conn *conn);

static void (*klpe_hci_conn_check_pending)(struct hci_dev *hdev);

static struct hci_chan *(*klpe_hci_chan_lookup_handle)(struct hci_dev *hdev, __u16 handle);

static int (*klpe_hci_conn_check_link_mode)(struct hci_conn *conn);

static struct bdaddr_list *(*klpe_hci_bdaddr_list_lookup)(struct list_head *list,
					   bdaddr_t *bdaddr, u8 type);

static struct hci_conn_params *(*klpe_hci_conn_params_lookup)(struct hci_dev *hdev,
					       bdaddr_t *addr, u8 addr_type);

static struct link_key *(*klpe_hci_find_link_key)(struct hci_dev *hdev, bdaddr_t *bdaddr);
static struct link_key *(*klpe_hci_add_link_key)(struct hci_dev *hdev, struct hci_conn *conn,
				  bdaddr_t *bdaddr, u8 *val, u8 type,
				  u8 pin_len, bool *persistent);

static int (*klpe_hci_remove_link_key)(struct hci_dev *hdev, bdaddr_t *bdaddr);

static struct oob_data *(*klpe_hci_find_remote_oob_data)(struct hci_dev *hdev,
					  bdaddr_t *bdaddr, u8 bdaddr_type);

void klpp_hci_event_packet(struct hci_dev *hdev, struct sk_buff *skb);

static void (*klpe_hci_conn_add_sysfs)(struct hci_conn *conn);

static inline int klpr_hci_proto_connect_ind(struct hci_dev *hdev, bdaddr_t *bdaddr,
					__u8 type, __u8 *flags)
{
	switch (type) {
	case ACL_LINK:
		return (*klpe_l2cap_connect_ind)(hdev, bdaddr);

	case SCO_LINK:
	case ESCO_LINK:
		return (*klpe_sco_connect_ind)(hdev, bdaddr, flags);

	default:
		(*klpe_bt_err)("unknown link type %d" "\n",type);
		return -EINVAL;
	}
}

static inline void klpr_hci_connect_cfm(struct hci_conn *conn, __u8 status)
{
	struct hci_cb *cb;

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->connect_cfm)
			cb->connect_cfm(conn, status);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));

	if (conn->connect_cfm_cb)
		conn->connect_cfm_cb(conn, status);
}

static inline void klpr_hci_disconn_cfm(struct hci_conn *conn, __u8 reason)
{
	struct hci_cb *cb;

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->disconn_cfm)
			cb->disconn_cfm(conn, reason);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));

	if (conn->disconn_cfm_cb)
		conn->disconn_cfm_cb(conn, reason);
}

static inline void klpr_hci_auth_cfm(struct hci_conn *conn, __u8 status)
{
	struct hci_cb *cb;
	__u8 encrypt;

	if (test_bit(HCI_CONN_ENCRYPT_PEND, &conn->flags))
		return;

	encrypt = test_bit(HCI_CONN_ENCRYPT, &conn->flags) ? 0x01 : 0x00;

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->security_cfm)
			cb->security_cfm(conn, status, encrypt);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));

	if (conn->security_cfm_cb)
		conn->security_cfm_cb(conn, status);
}

static inline void klpr_hci_encrypt_cfm(struct hci_conn *conn, __u8 status)
{
	struct hci_cb *cb;
	__u8 encrypt;

	if (conn->state == BT_CONFIG) {
		if (!status)
			conn->state = BT_CONNECTED;

		klpr_hci_connect_cfm(conn, status);
		hci_conn_drop(conn);
		return;
	}

	if (!test_bit(HCI_CONN_ENCRYPT, &conn->flags))
		encrypt = 0x00;
	else if (test_bit(HCI_CONN_AES_CCM, &conn->flags))
		encrypt = 0x02;
	else
		encrypt = 0x01;

	if (!status) {
		if (conn->sec_level == BT_SECURITY_SDP)
			conn->sec_level = BT_SECURITY_LOW;

		if (conn->pending_sec_level > conn->sec_level)
			conn->sec_level = conn->pending_sec_level;
	}

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->security_cfm)
			cb->security_cfm(conn, status, encrypt);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));

	if (conn->security_cfm_cb)
		conn->security_cfm_cb(conn, status);
}

static inline void klpr_hci_key_change_cfm(struct hci_conn *conn, __u8 status)
{
	struct hci_cb *cb;

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->key_change_cfm)
			cb->key_change_cfm(conn, status);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));
}

static inline void klpr_hci_role_switch_cfm(struct hci_conn *conn, __u8 status,
								__u8 role)
{
	struct hci_cb *cb;

	mutex_lock(&(*klpe_hci_cb_list_lock));
	list_for_each_entry(cb, &(*klpe_hci_cb_list), list) {
		if (cb->role_switch_cfm)
			cb->role_switch_cfm(conn, status, role);
	}
	mutex_unlock(&(*klpe_hci_cb_list_lock));
}

static int (*klpe_hci_send_cmd)(struct hci_dev *hdev, __u16 opcode, __u32 plen,
		 const void *param);

static void (*klpe_mgmt_new_link_key)(struct hci_dev *hdev, struct link_key *key,
		       bool persistent);
static void (*klpe_mgmt_device_connected)(struct hci_dev *hdev, struct hci_conn *conn,
			   u32 flags, u8 *name, u8 name_len);
static void (*klpe_mgmt_device_disconnected)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			      u8 link_type, u8 addr_type, u8 reason,
			      bool mgmt_connected);
static void (*klpe_mgmt_disconnect_failed)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			    u8 link_type, u8 addr_type, u8 status);
static void (*klpe_mgmt_connect_failed)(struct hci_dev *hdev, bdaddr_t *bdaddr, u8 link_type,
			 u8 addr_type, u8 status);
static void (*klpe_mgmt_pin_code_request)(struct hci_dev *hdev, bdaddr_t *bdaddr, u8 secure);

static int (*klpe_mgmt_user_confirm_request)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			      u8 link_type, u8 addr_type, u32 value,
			      u8 confirm_hint);

static int (*klpe_mgmt_user_passkey_request)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			      u8 link_type, u8 addr_type);

static int (*klpe_mgmt_user_passkey_notify)(struct hci_dev *hdev, bdaddr_t *bdaddr,
			     u8 link_type, u8 addr_type, u32 passkey,
			     u8 entered);
static void (*klpe_mgmt_auth_failed)(struct hci_conn *conn, u8 status);

static void (*klpe_mgmt_device_found)(struct hci_dev *hdev, bdaddr_t *bdaddr, u8 link_type,
		       u8 addr_type, u8 *dev_class, s8 rssi, u32 flags,
		       u8 *eir, u16 eir_len, u8 *scan_rsp, u8 scan_rsp_len);

/* klp-ccp: from include/net/bluetooth/mgmt.h */
#define MGMT_DEV_DISCONN_UNKNOWN	0x00
#define MGMT_DEV_DISCONN_TIMEOUT	0x01
#define MGMT_DEV_DISCONN_LOCAL_HOST	0x02
#define MGMT_DEV_DISCONN_REMOTE		0x03
#define MGMT_DEV_DISCONN_AUTH_FAILURE	0x04

/* klp-ccp: from net/bluetooth/hci_request.h */
#include <asm/unaligned.h>

struct hci_request {
	struct hci_dev		*hdev;
	struct sk_buff_head	cmd_q;

	/* If something goes wrong when building the HCI request, the error
	 * value is stored in this field.
	 */
	int			err;
};

static void (*klpe_hci_req_init)(struct hci_request *req, struct hci_dev *hdev);

static int (*klpe_hci_req_run_skb)(struct hci_request *req, hci_req_complete_skb_t complete);
static void (*klpe_hci_req_add)(struct hci_request *req, u16 opcode, u32 plen,
		 const void *param);

static void (*klpe_hci_req_cmd_complete)(struct hci_dev *hdev, u16 opcode, u8 status,
			  hci_req_complete_t *req_complete,
			  hci_req_complete_skb_t *req_complete_skb);

static void (*klpe_hci_req_reenable_advertising)(struct hci_dev *hdev);

static inline void hci_req_update_scan(struct hci_dev *hdev)
{
	queue_work(hdev->req_workqueue, &hdev->scan_update);
}

static inline void hci_update_background_scan(struct hci_dev *hdev)
{
	queue_work(hdev->req_workqueue, &hdev->bg_scan_update);
}

/* klp-ccp: from net/bluetooth/hci_debugfs.h */
#if IS_ENABLED(CONFIG_BT_DEBUGFS)
#error "klp-ccp: non-taken branch"
#else

static inline void hci_debugfs_create_conn(struct hci_conn *conn)
{
}

#endif

/* klp-ccp: from net/bluetooth/a2mp.h */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static void (*klpe_l2cap_logical_cfm)(struct l2cap_chan *chan, struct hci_chan *hchan,
		       u8 status);

/* klp-ccp: from net/bluetooth/a2mp.h */
struct amp_mgr {
	struct list_head	list;
	struct l2cap_conn	*l2cap_conn;
	struct l2cap_chan	*a2mp_chan;
	struct l2cap_chan	*bredr_chan;
	struct kref		kref;
	__u8			ident;
	__u8			handle;
	unsigned long		state;
	unsigned long		flags;

	struct list_head	amp_ctrls;
	struct mutex		amp_ctrls_lock;
};

/* klp-ccp: from net/bluetooth/amp.h */
static void (*klpe_amp_read_loc_assoc_final_data)(struct hci_dev *hdev,
				   struct hci_conn *hcon);

static void (*klpe_amp_physical_cfm)(struct hci_conn *bredr_hcon, struct hci_conn *hs_hcon);

static void (*klpe_amp_destroy_logical_link)(struct hci_chan *hchan, u8 reason);

/* klp-ccp: from net/bluetooth/hci_event.c */
#define ZERO_KEY "\x00\x00\x00\x00\x00\x00\x00\x00" \
		 "\x00\x00\x00\x00\x00\x00\x00\x00"

static int hci_outgoing_auth_needed(struct hci_dev *hdev,
				    struct hci_conn *conn)
{
	if (conn->state != BT_CONFIG || !conn->out)
		return 0;

	if (conn->pending_sec_level == BT_SECURITY_SDP)
		return 0;

	/* Only request authentication for SSP connections or non-SSP
	 * devices with sec_level MEDIUM or HIGH or if MITM protection
	 * is requested.
	 */
	if (!hci_conn_ssp_enabled(conn) && !(conn->auth_type & 0x01) &&
	    conn->pending_sec_level != BT_SECURITY_FIPS &&
	    conn->pending_sec_level != BT_SECURITY_HIGH &&
	    conn->pending_sec_level != BT_SECURITY_MEDIUM)
		return 0;

	return 1;
}

static int (*klpe_hci_resolve_name)(struct hci_dev *hdev,
				   struct inquiry_entry *e);

static void (*klpe_hci_check_pending_name)(struct hci_dev *hdev, struct hci_conn *conn,
				   bdaddr_t *bdaddr, u8 *name, u8 name_len);

static void klpr_hci_inquiry_complete_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	__u8 status = *((__u8 *) skb->data);
	struct discovery_state *discov = &hdev->discovery;
	struct inquiry_entry *e;

	BT_DBG("%s status 0x%2.2x", hdev->name, status);

	(*klpe_hci_conn_check_pending)(hdev);

	if (!test_and_clear_bit(HCI_INQUIRY, &hdev->flags))
		return;

	smp_mb__after_atomic(); /* wake_up_bit advises about this barrier */
	wake_up_bit(&hdev->flags, HCI_INQUIRY);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		return;

	hci_dev_lock(hdev);

	if (discov->state != DISCOVERY_FINDING)
		goto unlock;

	if (list_empty(&discov->resolve)) {
		/* When BR/EDR inquiry is active and no LE scanning is in
		 * progress, then change discovery state to indicate completion.
		 *
		 * When running LE scanning and BR/EDR inquiry simultaneously
		 * and the LE scan already finished, then change the discovery
		 * state to indicate completion.
		 */
		if (!hci_dev_test_flag(hdev, HCI_LE_SCAN) ||
		    !test_bit(HCI_QUIRK_SIMULTANEOUS_DISCOVERY, &hdev->quirks))
			(*klpe_hci_discovery_set_state)(hdev, DISCOVERY_STOPPED);
		goto unlock;
	}

	e = (*klpe_hci_inquiry_cache_lookup_resolve)(hdev, BDADDR_ANY, NAME_NEEDED);
	if (e && (*klpe_hci_resolve_name)(hdev, e) == 0) {
		e->name_state = NAME_PENDING;
		(*klpe_hci_discovery_set_state)(hdev, DISCOVERY_RESOLVING);
	} else {
		/* When BR/EDR inquiry is active and no LE scanning is in
		 * progress, then change discovery state to indicate completion.
		 *
		 * When running LE scanning and BR/EDR inquiry simultaneously
		 * and the LE scan already finished, then change the discovery
		 * state to indicate completion.
		 */
		if (!hci_dev_test_flag(hdev, HCI_LE_SCAN) ||
		    !test_bit(HCI_QUIRK_SIMULTANEOUS_DISCOVERY, &hdev->quirks))
			(*klpe_hci_discovery_set_state)(hdev, DISCOVERY_STOPPED);
	}

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_inquiry_result_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct inquiry_data data;
	struct inquiry_info *info = (void *) (skb->data + 1);
	int num_rsp = *((__u8 *) skb->data);

	BT_DBG("%s num_rsp %d", hdev->name, num_rsp);

	if (!num_rsp || skb->len < num_rsp * sizeof(*info) + 1)
		return;

	if (hci_dev_test_flag(hdev, HCI_PERIODIC_INQ))
		return;

	hci_dev_lock(hdev);

	for (; num_rsp; num_rsp--, info++) {
		u32 flags;

		bacpy(&data.bdaddr, &info->bdaddr);
		data.pscan_rep_mode	= info->pscan_rep_mode;
		data.pscan_period_mode	= info->pscan_period_mode;
		data.pscan_mode		= info->pscan_mode;
		memcpy(data.dev_class, info->dev_class, 3);
		data.clock_offset	= info->clock_offset;
		data.rssi		= HCI_RSSI_INVALID;
		data.ssp_mode		= 0x00;

		flags = (*klpe_hci_inquiry_cache_update)(hdev, &data, false);

		(*klpe_mgmt_device_found)(hdev, &info->bdaddr, ACL_LINK, 0x00,
				  info->dev_class, HCI_RSSI_INVALID,
				  flags, NULL, 0, NULL, 0);
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_conn_complete_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_conn_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ev->link_type, &ev->bdaddr);
	if (!conn) {
		if (ev->link_type != SCO_LINK)
			goto unlock;

		conn = hci_conn_hash_lookup_ba(hdev, ESCO_LINK, &ev->bdaddr);
		if (!conn)
			goto unlock;

		conn->type = SCO_LINK;
	}

	if (!ev->status) {
		conn->handle = __le16_to_cpu(ev->handle);

		if (conn->type == ACL_LINK) {
			conn->state = BT_CONFIG;
			hci_conn_hold(conn);

			if (!conn->out && !hci_conn_ssp_enabled(conn) &&
			    !(*klpe_hci_find_link_key)(hdev, &ev->bdaddr))
				conn->disc_timeout = HCI_PAIRING_TIMEOUT;
			else
				conn->disc_timeout = HCI_DISCONN_TIMEOUT;
		} else
			conn->state = BT_CONNECTED;

		hci_debugfs_create_conn(conn);
		(*klpe_hci_conn_add_sysfs)(conn);

		if (test_bit(HCI_AUTH, &hdev->flags))
			set_bit(HCI_CONN_AUTH, &conn->flags);

		if (test_bit(HCI_ENCRYPT, &hdev->flags))
			set_bit(HCI_CONN_ENCRYPT, &conn->flags);

		/* Get remote features */
		if (conn->type == ACL_LINK) {
			struct hci_cp_read_remote_features cp;
			cp.handle = ev->handle;
			(*klpe_hci_send_cmd)(hdev, HCI_OP_READ_REMOTE_FEATURES,
				     sizeof(cp), &cp);

			hci_req_update_scan(hdev);
		}

		/* Set packet type for incoming connection */
		if (!conn->out && hdev->hci_ver < BLUETOOTH_VER_2_0) {
			struct hci_cp_change_conn_ptype cp;
			cp.handle = ev->handle;
			cp.pkt_type = cpu_to_le16(conn->pkt_type);
			(*klpe_hci_send_cmd)(hdev, HCI_OP_CHANGE_CONN_PTYPE, sizeof(cp),
				     &cp);
		}
	} else {
		conn->state = BT_CLOSED;
		if (conn->type == ACL_LINK)
			(*klpe_mgmt_connect_failed)(hdev, &conn->dst, conn->type,
					    conn->dst_type, ev->status);
	}

	if (conn->type == ACL_LINK)
		(*klpe_hci_sco_setup)(conn, ev->status);

	if (ev->status) {
		klpr_hci_connect_cfm(conn, ev->status);
		(*klpe_hci_conn_del)(conn);
	} else if (ev->link_type != ACL_LINK)
		klpr_hci_connect_cfm(conn, ev->status);

unlock:
	hci_dev_unlock(hdev);

	(*klpe_hci_conn_check_pending)(hdev);
}

static void klpr_hci_reject_conn(struct hci_dev *hdev, bdaddr_t *bdaddr)
{
	struct hci_cp_reject_conn_req cp;

	bacpy(&cp.bdaddr, bdaddr);
	cp.reason = HCI_ERROR_REJ_BAD_ADDR;
	(*klpe_hci_send_cmd)(hdev, HCI_OP_REJECT_CONN_REQ, sizeof(cp), &cp);
}

static void klpr_hci_conn_request_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_conn_request *ev = (void *) skb->data;
	int mask = hdev->link_mode;
	struct inquiry_entry *ie;
	struct hci_conn *conn;
	__u8 flags = 0;

	BT_DBG("%s bdaddr %pMR type 0x%x", hdev->name, &ev->bdaddr,
	       ev->link_type);

	mask |= klpr_hci_proto_connect_ind(hdev, &ev->bdaddr, ev->link_type,
				      &flags);

	if (!(mask & HCI_LM_ACCEPT)) {
		klpr_hci_reject_conn(hdev, &ev->bdaddr);
		return;
	}

	if ((*klpe_hci_bdaddr_list_lookup)(&hdev->blacklist, &ev->bdaddr,
				   BDADDR_BREDR)) {
		klpr_hci_reject_conn(hdev, &ev->bdaddr);
		return;
	}

	/* Require HCI_CONNECTABLE or a whitelist entry to accept the
	 * connection. These features are only touched through mgmt so
	 * only do the checks if HCI_MGMT is set.
	 */
	if (hci_dev_test_flag(hdev, HCI_MGMT) &&
	    !hci_dev_test_flag(hdev, HCI_CONNECTABLE) &&
	    !(*klpe_hci_bdaddr_list_lookup)(&hdev->whitelist, &ev->bdaddr,
				    BDADDR_BREDR)) {
		    klpr_hci_reject_conn(hdev, &ev->bdaddr);
		    return;
	}

	/* Connection accepted */

	hci_dev_lock(hdev);

	ie = (*klpe_hci_inquiry_cache_lookup)(hdev, &ev->bdaddr);
	if (ie)
		memcpy(ie->data.dev_class, ev->dev_class, 3);

	conn = hci_conn_hash_lookup_ba(hdev, ev->link_type,
			&ev->bdaddr);
	if (!conn) {
		conn = (*klpe_hci_conn_add)(hdev, ev->link_type, &ev->bdaddr,
				    HCI_ROLE_SLAVE);
		if (!conn) {
			(*klpe_bt_err)("%s: " "no memory for new connection" "\n",(hdev)->name);
			hci_dev_unlock(hdev);
			return;
		}
	}

	memcpy(conn->dev_class, ev->dev_class, 3);

	hci_dev_unlock(hdev);

	if (ev->link_type == ACL_LINK ||
	    (!(flags & HCI_PROTO_DEFER) && !lmp_esco_capable(hdev))) {
		struct hci_cp_accept_conn_req cp;
		conn->state = BT_CONNECT;

		bacpy(&cp.bdaddr, &ev->bdaddr);

		if (lmp_rswitch_capable(hdev) && (mask & HCI_LM_MASTER))
			cp.role = 0x00; /* Become master */
		else
			cp.role = 0x01; /* Remain slave */

		(*klpe_hci_send_cmd)(hdev, HCI_OP_ACCEPT_CONN_REQ, sizeof(cp), &cp);
	} else if (!(flags & HCI_PROTO_DEFER)) {
		struct hci_cp_accept_sync_conn_req cp;
		conn->state = BT_CONNECT;

		bacpy(&cp.bdaddr, &ev->bdaddr);
		cp.pkt_type = cpu_to_le16(conn->pkt_type);

		cp.tx_bandwidth   = cpu_to_le32(0x00001f40);
		cp.rx_bandwidth   = cpu_to_le32(0x00001f40);
		cp.max_latency    = cpu_to_le16(0xffff);
		cp.content_format = cpu_to_le16(hdev->voice_setting);
		cp.retrans_effort = 0xff;

		(*klpe_hci_send_cmd)(hdev, HCI_OP_ACCEPT_SYNC_CONN_REQ, sizeof(cp),
			     &cp);
	} else {
		conn->state = BT_CONNECT2;
		klpr_hci_connect_cfm(conn, 0);
	}
}

static u8 hci_to_mgmt_reason(u8 err)
{
	switch (err) {
	case HCI_ERROR_CONNECTION_TIMEOUT:
		return MGMT_DEV_DISCONN_TIMEOUT;
	case HCI_ERROR_REMOTE_USER_TERM:
	case HCI_ERROR_REMOTE_LOW_RESOURCES:
	case HCI_ERROR_REMOTE_POWER_OFF:
		return MGMT_DEV_DISCONN_REMOTE;
	case HCI_ERROR_LOCAL_HOST_TERM:
		return MGMT_DEV_DISCONN_LOCAL_HOST;
	default:
		return MGMT_DEV_DISCONN_UNKNOWN;
	}
}

static void klpr_hci_disconn_complete_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_disconn_complete *ev = (void *) skb->data;
	u8 reason;
	struct hci_conn_params *params;
	struct hci_conn *conn;
	bool mgmt_connected;
	u8 type;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (!conn)
		goto unlock;

	if (ev->status) {
		(*klpe_mgmt_disconnect_failed)(hdev, &conn->dst, conn->type,
				       conn->dst_type, ev->status);
		goto unlock;
	}

	conn->state = BT_CLOSED;

	mgmt_connected = test_and_clear_bit(HCI_CONN_MGMT_CONNECTED, &conn->flags);

	if (test_bit(HCI_CONN_AUTH_FAILURE, &conn->flags))
		reason = MGMT_DEV_DISCONN_AUTH_FAILURE;
	else
		reason = hci_to_mgmt_reason(ev->reason);

	(*klpe_mgmt_device_disconnected)(hdev, &conn->dst, conn->type, conn->dst_type,
				reason, mgmt_connected);

	if (conn->type == ACL_LINK) {
		if (test_bit(HCI_CONN_FLUSH_KEY, &conn->flags))
			(*klpe_hci_remove_link_key)(hdev, &conn->dst);

		hci_req_update_scan(hdev);
	}

	params = (*klpe_hci_conn_params_lookup)(hdev, &conn->dst, conn->dst_type);
	if (params) {
		switch (params->auto_connect) {
		case HCI_AUTO_CONN_LINK_LOSS:
			if (ev->reason != HCI_ERROR_CONNECTION_TIMEOUT)
				break;
			/* Fall through */

		case HCI_AUTO_CONN_DIRECT:
		case HCI_AUTO_CONN_ALWAYS:
			list_del_init(&params->action);
			list_add(&params->action, &hdev->pend_le_conns);
			hci_update_background_scan(hdev);
			break;

		default:
			break;
		}
	}

	type = conn->type;

	klpr_hci_disconn_cfm(conn, ev->reason);
	(*klpe_hci_conn_del)(conn);

	/* Re-enable advertising if necessary, since it might
	 * have been disabled by the connection. From the
	 * HCI_LE_Set_Advertise_Enable command description in
	 * the core specification (v4.0):
	 * "The Controller shall continue advertising until the Host
	 * issues an LE_Set_Advertise_Enable command with
	 * Advertising_Enable set to 0x00 (Advertising is disabled)
	 * or until a connection is created or until the Advertising
	 * is timed out due to Directed Advertising."
	 */
	if (type == LE_LINK)
		(*klpe_hci_req_reenable_advertising)(hdev);

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_auth_complete_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_auth_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (!conn)
		goto unlock;

	if (!ev->status) {
		clear_bit(HCI_CONN_AUTH_FAILURE, &conn->flags);

		if (!hci_conn_ssp_enabled(conn) &&
		    test_bit(HCI_CONN_REAUTH_PEND, &conn->flags)) {
			(*klpe_bt_info)("%s: " "re-auth of legacy device is not possible." "\n",(hdev)->name);
		} else {
			set_bit(HCI_CONN_AUTH, &conn->flags);
			conn->sec_level = conn->pending_sec_level;
		}
	} else {
		if (ev->status == HCI_ERROR_PIN_OR_KEY_MISSING)
			set_bit(HCI_CONN_AUTH_FAILURE, &conn->flags);

		(*klpe_mgmt_auth_failed)(conn, ev->status);
	}

	clear_bit(HCI_CONN_AUTH_PEND, &conn->flags);
	clear_bit(HCI_CONN_REAUTH_PEND, &conn->flags);

	if (conn->state == BT_CONFIG) {
		if (!ev->status && hci_conn_ssp_enabled(conn)) {
			struct hci_cp_set_conn_encrypt cp;
			cp.handle  = ev->handle;
			cp.encrypt = 0x01;
			(*klpe_hci_send_cmd)(hdev, HCI_OP_SET_CONN_ENCRYPT, sizeof(cp),
				     &cp);
		} else {
			conn->state = BT_CONNECTED;
			klpr_hci_connect_cfm(conn, ev->status);
			hci_conn_drop(conn);
		}
	} else {
		klpr_hci_auth_cfm(conn, ev->status);

		hci_conn_hold(conn);
		conn->disc_timeout = HCI_DISCONN_TIMEOUT;
		hci_conn_drop(conn);
	}

	if (test_bit(HCI_CONN_ENCRYPT_PEND, &conn->flags)) {
		if (!ev->status) {
			struct hci_cp_set_conn_encrypt cp;
			cp.handle  = ev->handle;
			cp.encrypt = 0x01;
			(*klpe_hci_send_cmd)(hdev, HCI_OP_SET_CONN_ENCRYPT, sizeof(cp),
				     &cp);
		} else {
			clear_bit(HCI_CONN_ENCRYPT_PEND, &conn->flags);
			klpr_hci_encrypt_cfm(conn, ev->status);
		}
	}

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_remote_name_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_remote_name *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	(*klpe_hci_conn_check_pending)(hdev);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		goto check_auth;

	if (ev->status == 0)
		(*klpe_hci_check_pending_name)(hdev, conn, &ev->bdaddr, ev->name,
				       strnlen(ev->name, HCI_MAX_NAME_LENGTH));
	else
		(*klpe_hci_check_pending_name)(hdev, conn, &ev->bdaddr, NULL, 0);

check_auth:
	if (!conn)
		goto unlock;

	if (!hci_outgoing_auth_needed(hdev, conn))
		goto unlock;

	if (!test_and_set_bit(HCI_CONN_AUTH_PEND, &conn->flags)) {
		struct hci_cp_auth_requested cp;

		set_bit(HCI_CONN_AUTH_INITIATOR, &conn->flags);

		cp.handle = __cpu_to_le16(conn->handle);
		(*klpe_hci_send_cmd)(hdev, HCI_OP_AUTH_REQUESTED, sizeof(cp), &cp);
	}

unlock:
	hci_dev_unlock(hdev);
}

static void (*klpe_read_enc_key_size_complete)(struct hci_dev *hdev, u8 status,
				       u16 opcode, struct sk_buff *skb);

static void klpr_hci_encrypt_change_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_encrypt_change *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (!conn)
		goto unlock;

	if (!ev->status) {
		if (ev->encrypt) {
			/* Encryption implies authentication */
			set_bit(HCI_CONN_AUTH, &conn->flags);
			set_bit(HCI_CONN_ENCRYPT, &conn->flags);
			conn->sec_level = conn->pending_sec_level;

			/* P-256 authentication key implies FIPS */
			if (conn->key_type == HCI_LK_AUTH_COMBINATION_P256)
				set_bit(HCI_CONN_FIPS, &conn->flags);

			if ((conn->type == ACL_LINK && ev->encrypt == 0x02) ||
			    conn->type == LE_LINK)
				set_bit(HCI_CONN_AES_CCM, &conn->flags);
		} else {
			clear_bit(HCI_CONN_ENCRYPT, &conn->flags);
			clear_bit(HCI_CONN_AES_CCM, &conn->flags);
		}
	}

	/* We should disregard the current RPA and generate a new one
	 * whenever the encryption procedure fails.
	 */
	if (ev->status && conn->type == LE_LINK)
		hci_dev_set_flag(hdev, HCI_RPA_EXPIRED);

	clear_bit(HCI_CONN_ENCRYPT_PEND, &conn->flags);

	/* Check link security requirements are met */
	if (!(*klpe_hci_conn_check_link_mode)(conn))
		ev->status = HCI_ERROR_AUTH_FAILURE;

	if (ev->status && conn->state == BT_CONNECTED) {
		if (ev->status == HCI_ERROR_PIN_OR_KEY_MISSING)
			set_bit(HCI_CONN_AUTH_FAILURE, &conn->flags);

		/* Notify upper layers so they can cleanup before
		 * disconnecting.
		 */
		klpr_hci_encrypt_cfm(conn, ev->status);
		(*klpe_hci_disconnect)(conn, HCI_ERROR_AUTH_FAILURE);
		hci_conn_drop(conn);
		goto unlock;
	}

	/* Try reading the encryption key size for encrypted ACL links */
	if (!ev->status && ev->encrypt && conn->type == ACL_LINK) {
		struct hci_cp_read_enc_key_size cp;
		struct hci_request req;

		/* Only send HCI_Read_Encryption_Key_Size if the
		 * controller really supports it. If it doesn't, assume
		 * the default size (16).
		 */
		if (!(hdev->commands[20] & 0x10)) {
			conn->enc_key_size = HCI_LINK_KEY_SIZE;
			goto notify;
		}

		(*klpe_hci_req_init)(&req, hdev);

		cp.handle = cpu_to_le16(conn->handle);
		(*klpe_hci_req_add)(&req, HCI_OP_READ_ENC_KEY_SIZE, sizeof(cp), &cp);

		if ((*klpe_hci_req_run_skb)(&req, (*klpe_read_enc_key_size_complete))) {
			(*klpe_bt_err)("%s: " "sending read key size failed" "\n",(hdev)->name);
			conn->enc_key_size = HCI_LINK_KEY_SIZE;
			goto notify;
		}

		goto unlock;
	}

notify:
	klpr_hci_encrypt_cfm(conn, ev->status);

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_change_link_key_complete_evt(struct hci_dev *hdev,
					     struct sk_buff *skb)
{
	struct hci_ev_change_link_key_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn) {
		if (!ev->status)
			set_bit(HCI_CONN_SECURE, &conn->flags);

		clear_bit(HCI_CONN_AUTH_PEND, &conn->flags);

		klpr_hci_key_change_cfm(conn, ev->status);
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_remote_features_evt(struct hci_dev *hdev,
				    struct sk_buff *skb)
{
	struct hci_ev_remote_features *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (!conn)
		goto unlock;

	if (!ev->status)
		memcpy(conn->features[0], ev->features, 8);

	if (conn->state != BT_CONFIG)
		goto unlock;

	if (!ev->status && lmp_ext_feat_capable(hdev) &&
	    lmp_ext_feat_capable(conn)) {
		struct hci_cp_read_remote_ext_features cp;
		cp.handle = ev->handle;
		cp.page = 0x01;
		(*klpe_hci_send_cmd)(hdev, HCI_OP_READ_REMOTE_EXT_FEATURES,
			     sizeof(cp), &cp);
		goto unlock;
	}

	if (!ev->status && !test_bit(HCI_CONN_MGMT_CONNECTED, &conn->flags)) {
		struct hci_cp_remote_name_req cp;
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, &conn->dst);
		cp.pscan_rep_mode = 0x02;
		(*klpe_hci_send_cmd)(hdev, HCI_OP_REMOTE_NAME_REQ, sizeof(cp), &cp);
	} else if (!test_and_set_bit(HCI_CONN_MGMT_CONNECTED, &conn->flags))
		(*klpe_mgmt_device_connected)(hdev, conn, 0, NULL, 0);

	if (!hci_outgoing_auth_needed(hdev, conn)) {
		conn->state = BT_CONNECTED;
		klpr_hci_connect_cfm(conn, ev->status);
		hci_conn_drop(conn);
	}

unlock:
	hci_dev_unlock(hdev);
}

static void (*klpe_hci_cmd_complete_evt)(struct hci_dev *hdev, struct sk_buff *skb,
				 u16 *opcode, u8 *status,
				 hci_req_complete_t *req_complete,
				 hci_req_complete_skb_t *req_complete_skb);

static void (*klpe_hci_cmd_status_evt)(struct hci_dev *hdev, struct sk_buff *skb,
			       u16 *opcode, u8 *status,
			       hci_req_complete_t *req_complete,
			       hci_req_complete_skb_t *req_complete_skb);

static void hci_hardware_error_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_hardware_error *ev = (void *) skb->data;

	hdev->hw_error_code = ev->code;

	queue_work(hdev->req_workqueue, &hdev->error_reset);
}

static void klpr_hci_role_change_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_role_change *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (conn) {
		if (!ev->status)
			conn->role = ev->role;

		clear_bit(HCI_CONN_RSWITCH_PEND, &conn->flags);

		klpr_hci_role_switch_cfm(conn, ev->status, ev->role);
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_num_comp_pkts_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_num_comp_pkts *ev = (void *) skb->data;
	int i;

	if (hdev->flow_ctl_mode != HCI_FLOW_CTL_MODE_PACKET_BASED) {
		(*klpe_bt_err)("%s: " "wrong event for mode %d" "\n",(hdev)->name,hdev->flow_ctl_mode);
		return;
	}

	if (skb->len < sizeof(*ev) || skb->len < sizeof(*ev) +
	    ev->num_hndl * sizeof(struct hci_comp_pkts_info)) {
		BT_DBG("%s bad parameters", hdev->name);
		return;
	}

	BT_DBG("%s num_hndl %d", hdev->name, ev->num_hndl);

	for (i = 0; i < ev->num_hndl; i++) {
		struct hci_comp_pkts_info *info = &ev->handles[i];
		struct hci_conn *conn;
		__u16  handle, count;

		handle = __le16_to_cpu(info->handle);
		count  = __le16_to_cpu(info->count);

		conn = hci_conn_hash_lookup_handle(hdev, handle);
		if (!conn)
			continue;

		conn->sent -= count;

		switch (conn->type) {
		case ACL_LINK:
			hdev->acl_cnt += count;
			if (hdev->acl_cnt > hdev->acl_pkts)
				hdev->acl_cnt = hdev->acl_pkts;
			break;

		case LE_LINK:
			if (hdev->le_pkts) {
				hdev->le_cnt += count;
				if (hdev->le_cnt > hdev->le_pkts)
					hdev->le_cnt = hdev->le_pkts;
			} else {
				hdev->acl_cnt += count;
				if (hdev->acl_cnt > hdev->acl_pkts)
					hdev->acl_cnt = hdev->acl_pkts;
			}
			break;

		case SCO_LINK:
			hdev->sco_cnt += count;
			if (hdev->sco_cnt > hdev->sco_pkts)
				hdev->sco_cnt = hdev->sco_pkts;
			break;

		default:
			(*klpe_bt_err)("%s: " "unknown type %d conn %p" "\n",(hdev)->name,conn->type, conn);
			break;
		}
	}

	queue_work(hdev->workqueue, &hdev->tx_work);
}

static struct hci_conn *klpr___hci_conn_lookup_handle(struct hci_dev *hdev,
						 __u16 handle)
{
	struct hci_chan *chan;

	switch (hdev->dev_type) {
	case HCI_PRIMARY:
		return hci_conn_hash_lookup_handle(hdev, handle);
	case HCI_AMP:
		chan = (*klpe_hci_chan_lookup_handle)(hdev, handle);
		if (chan)
			return chan->conn;
		break;
	default:
		(*klpe_bt_err)("%s: " "unknown dev_type %d" "\n",(hdev)->name,hdev->dev_type);
		break;
	}

	return NULL;
}

static void klpr_hci_num_comp_blocks_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_num_comp_blocks *ev = (void *) skb->data;
	int i;

	if (hdev->flow_ctl_mode != HCI_FLOW_CTL_MODE_BLOCK_BASED) {
		(*klpe_bt_err)("%s: " "wrong event for mode %d" "\n",(hdev)->name,hdev->flow_ctl_mode);
		return;
	}

	if (skb->len < sizeof(*ev) || skb->len < sizeof(*ev) +
	    ev->num_hndl * sizeof(struct hci_comp_blocks_info)) {
		BT_DBG("%s bad parameters", hdev->name);
		return;
	}

	BT_DBG("%s num_blocks %d num_hndl %d", hdev->name, ev->num_blocks,
	       ev->num_hndl);

	for (i = 0; i < ev->num_hndl; i++) {
		struct hci_comp_blocks_info *info = &ev->handles[i];
		struct hci_conn *conn = NULL;
		__u16  handle, block_count;

		handle = __le16_to_cpu(info->handle);
		block_count = __le16_to_cpu(info->blocks);

		conn = klpr___hci_conn_lookup_handle(hdev, handle);
		if (!conn)
			continue;

		conn->sent -= block_count;

		switch (conn->type) {
		case ACL_LINK:
		case AMP_LINK:
			hdev->block_cnt += block_count;
			if (hdev->block_cnt > hdev->num_blocks)
				hdev->block_cnt = hdev->num_blocks;
			break;

		default:
			(*klpe_bt_err)("%s: " "unknown type %d conn %p" "\n",(hdev)->name,conn->type, conn);
			break;
		}
	}

	queue_work(hdev->workqueue, &hdev->tx_work);
}

static void klpr_hci_mode_change_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_mode_change *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn) {
		conn->mode = ev->mode;

		if (!test_and_clear_bit(HCI_CONN_MODE_CHANGE_PEND,
					&conn->flags)) {
			if (conn->mode == HCI_CM_ACTIVE)
				set_bit(HCI_CONN_POWER_SAVE, &conn->flags);
			else
				clear_bit(HCI_CONN_POWER_SAVE, &conn->flags);
		}

		if (test_and_clear_bit(HCI_CONN_SCO_SETUP_PEND, &conn->flags))
			(*klpe_hci_sco_setup)(conn, ev->status);
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_pin_code_request_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_pin_code_req *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		goto unlock;

	if (conn->state == BT_CONNECTED) {
		hci_conn_hold(conn);
		conn->disc_timeout = HCI_PAIRING_TIMEOUT;
		hci_conn_drop(conn);
	}

	if (!hci_dev_test_flag(hdev, HCI_BONDABLE) &&
	    !test_bit(HCI_CONN_AUTH_INITIATOR, &conn->flags)) {
		(*klpe_hci_send_cmd)(hdev, HCI_OP_PIN_CODE_NEG_REPLY,
			     sizeof(ev->bdaddr), &ev->bdaddr);
	} else if (hci_dev_test_flag(hdev, HCI_MGMT)) {
		u8 secure;

		if (conn->pending_sec_level == BT_SECURITY_HIGH)
			secure = 1;
		else
			secure = 0;

		(*klpe_mgmt_pin_code_request)(hdev, &ev->bdaddr, secure);
	}

unlock:
	hci_dev_unlock(hdev);
}

static void (*klpe_conn_set_key)(struct hci_conn *conn, u8 key_type, u8 pin_len);

static void klpr_hci_link_key_request_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_link_key_req *ev = (void *) skb->data;
	struct hci_cp_link_key_reply cp;
	struct hci_conn *conn;
	struct link_key *key;

	BT_DBG("%s", hdev->name);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		return;

	hci_dev_lock(hdev);

	key = (*klpe_hci_find_link_key)(hdev, &ev->bdaddr);
	if (!key) {
		BT_DBG("%s link key not found for %pMR", hdev->name,
		       &ev->bdaddr);
		goto not_found;
	}

	BT_DBG("%s found key type %u for %pMR", hdev->name, key->type,
	       &ev->bdaddr);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (conn) {
		clear_bit(HCI_CONN_NEW_LINK_KEY, &conn->flags);

		if ((key->type == HCI_LK_UNAUTH_COMBINATION_P192 ||
		     key->type == HCI_LK_UNAUTH_COMBINATION_P256) &&
		    conn->auth_type != 0xff && (conn->auth_type & 0x01)) {
			BT_DBG("%s ignoring unauthenticated key", hdev->name);
			goto not_found;
		}

		if (key->type == HCI_LK_COMBINATION && key->pin_len < 16 &&
		    (conn->pending_sec_level == BT_SECURITY_HIGH ||
		     conn->pending_sec_level == BT_SECURITY_FIPS)) {
			BT_DBG("%s ignoring key unauthenticated for high security",
			       hdev->name);
			goto not_found;
		}

		(*klpe_conn_set_key)(conn, key->type, key->pin_len);
	}

	bacpy(&cp.bdaddr, &ev->bdaddr);
	memcpy(cp.link_key, key->val, HCI_LINK_KEY_SIZE);

	(*klpe_hci_send_cmd)(hdev, HCI_OP_LINK_KEY_REPLY, sizeof(cp), &cp);

	hci_dev_unlock(hdev);

	return;

not_found:
	(*klpe_hci_send_cmd)(hdev, HCI_OP_LINK_KEY_NEG_REPLY, 6, &ev->bdaddr);
	hci_dev_unlock(hdev);
}

static void klpr_hci_link_key_notify_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_link_key_notify *ev = (void *) skb->data;
	struct hci_conn *conn;
	struct link_key *key;
	bool persistent;
	u8 pin_len = 0;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		goto unlock;

	hci_conn_hold(conn);
	conn->disc_timeout = HCI_DISCONN_TIMEOUT;
	hci_conn_drop(conn);

	set_bit(HCI_CONN_NEW_LINK_KEY, &conn->flags);
	(*klpe_conn_set_key)(conn, ev->key_type, conn->pin_length);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		goto unlock;

	key = (*klpe_hci_add_link_key)(hdev, conn, &ev->bdaddr, ev->link_key,
			        ev->key_type, pin_len, &persistent);
	if (!key)
		goto unlock;

	/* Update connection information since adding the key will have
	 * fixed up the type in the case of changed combination keys.
	 */
	if (ev->key_type == HCI_LK_CHANGED_COMBINATION)
		(*klpe_conn_set_key)(conn, key->type, key->pin_len);

	(*klpe_mgmt_new_link_key)(hdev, key, persistent);

	/* Keep debug keys around only if the HCI_KEEP_DEBUG_KEYS flag
	 * is set. If it's not set simply remove the key from the kernel
	 * list (we've still notified user space about it but with
	 * store_hint being 0).
	 */
	if (key->type == HCI_LK_DEBUG_COMBINATION &&
	    !hci_dev_test_flag(hdev, HCI_KEEP_DEBUG_KEYS)) {
		list_del_rcu(&key->list);
		kfree_rcu(key, rcu);
		goto unlock;
	}

	if (persistent)
		clear_bit(HCI_CONN_FLUSH_KEY, &conn->flags);
	else
		set_bit(HCI_CONN_FLUSH_KEY, &conn->flags);

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_clock_offset_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_clock_offset *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn && !ev->status) {
		struct inquiry_entry *ie;

		ie = (*klpe_hci_inquiry_cache_lookup)(hdev, &conn->dst);
		if (ie) {
			ie->data.clock_offset = ev->clock_offset;
			ie->timestamp = jiffies;
		}
	}

	hci_dev_unlock(hdev);
}

static void hci_pkt_type_change_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_pkt_type_change *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (conn && !ev->status)
		conn->pkt_type = __le16_to_cpu(ev->pkt_type);

	hci_dev_unlock(hdev);
}

static void klpr_hci_pscan_rep_mode_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_pscan_rep_mode *ev = (void *) skb->data;
	struct inquiry_entry *ie;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	ie = (*klpe_hci_inquiry_cache_lookup)(hdev, &ev->bdaddr);
	if (ie) {
		ie->data.pscan_rep_mode = ev->pscan_rep_mode;
		ie->timestamp = jiffies;
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_inquiry_result_with_rssi_evt(struct hci_dev *hdev,
					     struct sk_buff *skb)
{
	struct inquiry_data data;
	int num_rsp = *((__u8 *) skb->data);

	BT_DBG("%s num_rsp %d", hdev->name, num_rsp);

	if (!num_rsp)
		return;

	if (hci_dev_test_flag(hdev, HCI_PERIODIC_INQ))
		return;

	hci_dev_lock(hdev);

	if ((skb->len - 1) / num_rsp != sizeof(struct inquiry_info_with_rssi)) {
		struct inquiry_info_with_rssi_and_pscan_mode *info;
		info = (void *) (skb->data + 1);

		if (skb->len < num_rsp * sizeof(*info) + 1)
			goto unlock;

		for (; num_rsp; num_rsp--, info++) {
			u32 flags;

			bacpy(&data.bdaddr, &info->bdaddr);
			data.pscan_rep_mode	= info->pscan_rep_mode;
			data.pscan_period_mode	= info->pscan_period_mode;
			data.pscan_mode		= info->pscan_mode;
			memcpy(data.dev_class, info->dev_class, 3);
			data.clock_offset	= info->clock_offset;
			data.rssi		= info->rssi;
			data.ssp_mode		= 0x00;

			flags = (*klpe_hci_inquiry_cache_update)(hdev, &data, false);

			(*klpe_mgmt_device_found)(hdev, &info->bdaddr, ACL_LINK, 0x00,
					  info->dev_class, info->rssi,
					  flags, NULL, 0, NULL, 0);
		}
	} else {
		struct inquiry_info_with_rssi *info = (void *) (skb->data + 1);

		if (skb->len < num_rsp * sizeof(*info) + 1)
			goto unlock;

		for (; num_rsp; num_rsp--, info++) {
			u32 flags;

			bacpy(&data.bdaddr, &info->bdaddr);
			data.pscan_rep_mode	= info->pscan_rep_mode;
			data.pscan_period_mode	= info->pscan_period_mode;
			data.pscan_mode		= 0x00;
			memcpy(data.dev_class, info->dev_class, 3);
			data.clock_offset	= info->clock_offset;
			data.rssi		= info->rssi;
			data.ssp_mode		= 0x00;

			flags = (*klpe_hci_inquiry_cache_update)(hdev, &data, false);

			(*klpe_mgmt_device_found)(hdev, &info->bdaddr, ACL_LINK, 0x00,
					  info->dev_class, info->rssi,
					  flags, NULL, 0, NULL, 0);
		}
	}

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_remote_ext_features_evt(struct hci_dev *hdev,
					struct sk_buff *skb)
{
	struct hci_ev_remote_ext_features *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (!conn)
		goto unlock;

	if (ev->page < HCI_MAX_PAGES)
		memcpy(conn->features[ev->page], ev->features, 8);

	if (!ev->status && ev->page == 0x01) {
		struct inquiry_entry *ie;

		ie = (*klpe_hci_inquiry_cache_lookup)(hdev, &conn->dst);
		if (ie)
			ie->data.ssp_mode = (ev->features[0] & LMP_HOST_SSP);

		if (ev->features[0] & LMP_HOST_SSP) {
			set_bit(HCI_CONN_SSP_ENABLED, &conn->flags);
		} else {
			/* It is mandatory by the Bluetooth specification that
			 * Extended Inquiry Results are only used when Secure
			 * Simple Pairing is enabled, but some devices violate
			 * this.
			 *
			 * To make these devices work, the internal SSP
			 * enabled flag needs to be cleared if the remote host
			 * features do not indicate SSP support */
			clear_bit(HCI_CONN_SSP_ENABLED, &conn->flags);
		}

		if (ev->features[0] & LMP_HOST_SC)
			set_bit(HCI_CONN_SC_ENABLED, &conn->flags);
	}

	if (conn->state != BT_CONFIG)
		goto unlock;

	if (!ev->status && !test_bit(HCI_CONN_MGMT_CONNECTED, &conn->flags)) {
		struct hci_cp_remote_name_req cp;
		memset(&cp, 0, sizeof(cp));
		bacpy(&cp.bdaddr, &conn->dst);
		cp.pscan_rep_mode = 0x02;
		(*klpe_hci_send_cmd)(hdev, HCI_OP_REMOTE_NAME_REQ, sizeof(cp), &cp);
	} else if (!test_and_set_bit(HCI_CONN_MGMT_CONNECTED, &conn->flags))
		(*klpe_mgmt_device_connected)(hdev, conn, 0, NULL, 0);

	if (!hci_outgoing_auth_needed(hdev, conn)) {
		conn->state = BT_CONNECTED;
		klpr_hci_connect_cfm(conn, ev->status);
		hci_conn_drop(conn);
	}

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_sync_conn_complete_evt(struct hci_dev *hdev,
				       struct sk_buff *skb)
{
	struct hci_ev_sync_conn_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ev->link_type, &ev->bdaddr);
	if (!conn) {
		if (ev->link_type == ESCO_LINK)
			goto unlock;

		/* When the link type in the event indicates SCO connection
		 * and lookup of the connection object fails, then check
		 * if an eSCO connection object exists.
		 *
		 * The core limits the synchronous connections to either
		 * SCO or eSCO. The eSCO connection is preferred and tried
		 * to be setup first and until successfully established,
		 * the link type will be hinted as eSCO.
		 */
		conn = hci_conn_hash_lookup_ba(hdev, ESCO_LINK, &ev->bdaddr);
		if (!conn)
			goto unlock;
	}

	switch (ev->status) {
	case 0x00:
		conn->handle = __le16_to_cpu(ev->handle);
		conn->state  = BT_CONNECTED;
		conn->type   = ev->link_type;

		hci_debugfs_create_conn(conn);
		(*klpe_hci_conn_add_sysfs)(conn);
		break;

	case 0x10:	/* Connection Accept Timeout */
	case 0x0d:	/* Connection Rejected due to Limited Resources */
	case 0x11:	/* Unsupported Feature or Parameter Value */
	case 0x1c:	/* SCO interval rejected */
	case 0x1a:	/* Unsupported Remote Feature */
	case 0x1e:	/* Invalid LMP Parameters */
	case 0x1f:	/* Unspecified error */
	case 0x20:	/* Unsupported LMP Parameter value */
		if (conn->out) {
			conn->pkt_type = (hdev->esco_type & SCO_ESCO_MASK) |
					(hdev->esco_type & EDR_ESCO_MASK);
			if ((*klpe_hci_setup_sync)(conn, conn->link->handle))
				goto unlock;
		}
		/* fall through */

	default:
		conn->state = BT_CLOSED;
		break;
	}

	klpr_hci_connect_cfm(conn, ev->status);
	if (ev->status)
		(*klpe_hci_conn_del)(conn);

unlock:
	hci_dev_unlock(hdev);
}

static inline size_t eir_get_length(u8 *eir, size_t eir_len)
{
	size_t parsed = 0;

	while (parsed < eir_len) {
		u8 field_len = eir[0];

		if (field_len == 0)
			return parsed;

		parsed += field_len + 1;
		eir += field_len + 1;
	}

	return eir_len;
}

static void klpr_hci_extended_inquiry_result_evt(struct hci_dev *hdev,
					    struct sk_buff *skb)
{
	struct inquiry_data data;
	struct extended_inquiry_info *info = (void *) (skb->data + 1);
	int num_rsp = *((__u8 *) skb->data);
	size_t eir_len;

	BT_DBG("%s num_rsp %d", hdev->name, num_rsp);

	if (!num_rsp || skb->len < num_rsp * sizeof(*info) + 1)
		return;

	if (hci_dev_test_flag(hdev, HCI_PERIODIC_INQ))
		return;

	hci_dev_lock(hdev);

	for (; num_rsp; num_rsp--, info++) {
		u32 flags;
		bool name_known;

		bacpy(&data.bdaddr, &info->bdaddr);
		data.pscan_rep_mode	= info->pscan_rep_mode;
		data.pscan_period_mode	= info->pscan_period_mode;
		data.pscan_mode		= 0x00;
		memcpy(data.dev_class, info->dev_class, 3);
		data.clock_offset	= info->clock_offset;
		data.rssi		= info->rssi;
		data.ssp_mode		= 0x01;

		if (hci_dev_test_flag(hdev, HCI_MGMT))
			name_known = eir_get_data(info->data,
						  sizeof(info->data),
						  EIR_NAME_COMPLETE, NULL);
		else
			name_known = true;

		flags = (*klpe_hci_inquiry_cache_update)(hdev, &data, name_known);

		eir_len = eir_get_length(info->data, sizeof(info->data));

		(*klpe_mgmt_device_found)(hdev, &info->bdaddr, ACL_LINK, 0x00,
				  info->dev_class, info->rssi,
				  flags, info->data, eir_len, NULL, 0);
	}

	hci_dev_unlock(hdev);
}

static void klpr_hci_key_refresh_complete_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_ev_key_refresh_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s status 0x%2.2x handle 0x%4.4x", hdev->name, ev->status,
	       __le16_to_cpu(ev->handle));

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_handle(hdev, __le16_to_cpu(ev->handle));
	if (!conn)
		goto unlock;

	/* For BR/EDR the necessary steps are taken through the
	 * auth_complete event.
	 */
	if (conn->type != LE_LINK)
		goto unlock;

	if (!ev->status)
		conn->sec_level = conn->pending_sec_level;

	clear_bit(HCI_CONN_ENCRYPT_PEND, &conn->flags);

	if (ev->status && conn->state == BT_CONNECTED) {
		(*klpe_hci_disconnect)(conn, HCI_ERROR_AUTH_FAILURE);
		hci_conn_drop(conn);
		goto unlock;
	}

	if (conn->state == BT_CONFIG) {
		if (!ev->status)
			conn->state = BT_CONNECTED;

		klpr_hci_connect_cfm(conn, ev->status);
		hci_conn_drop(conn);
	} else {
		klpr_hci_auth_cfm(conn, ev->status);

		hci_conn_hold(conn);
		conn->disc_timeout = HCI_DISCONN_TIMEOUT;
		hci_conn_drop(conn);
	}

unlock:
	hci_dev_unlock(hdev);
}

static u8 hci_get_auth_req(struct hci_conn *conn)
{
	/* If remote requests no-bonding follow that lead */
	if (conn->remote_auth == HCI_AT_NO_BONDING ||
	    conn->remote_auth == HCI_AT_NO_BONDING_MITM)
		return conn->remote_auth | (conn->auth_type & 0x01);

	/* If both remote and local have enough IO capabilities, require
	 * MITM protection
	 */
	if (conn->remote_cap != HCI_IO_NO_INPUT_OUTPUT &&
	    conn->io_capability != HCI_IO_NO_INPUT_OUTPUT)
		return conn->remote_auth | 0x01;

	/* No MITM protection possible so ignore remote requirement */
	return (conn->remote_auth & ~0x01) | (conn->auth_type & 0x01);
}

static u8 klpr_bredr_oob_data_present(struct hci_conn *conn)
{
	struct hci_dev *hdev = conn->hdev;
	struct oob_data *data;

	data = (*klpe_hci_find_remote_oob_data)(hdev, &conn->dst, BDADDR_BREDR);
	if (!data)
		return 0x00;

	if (bredr_sc_enabled(hdev)) {
		/* When Secure Connections is enabled, then just
		 * return the present value stored with the OOB
		 * data. The stored value contains the right present
		 * information. However it can only be trusted when
		 * not in Secure Connection Only mode.
		 */
		if (!hci_dev_test_flag(hdev, HCI_SC_ONLY))
			return data->present;

		/* When Secure Connections Only mode is enabled, then
		 * the P-256 values are required. If they are not
		 * available, then do not declare that OOB data is
		 * present.
		 */
		if (!memcmp(data->rand256, ZERO_KEY, 16) ||
		    !memcmp(data->hash256, ZERO_KEY, 16))
			return 0x00;

		return 0x02;
	}

	/* When Secure Connections is not enabled or actually
	 * not supported by the hardware, then check that if
	 * P-192 data values are present.
	 */
	if (!memcmp(data->rand192, ZERO_KEY, 16) ||
	    !memcmp(data->hash192, ZERO_KEY, 16))
		return 0x00;

	return 0x01;
}

static void klpr_hci_io_capa_request_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_io_capa_request *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		goto unlock;

	hci_conn_hold(conn);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		goto unlock;

	/* Allow pairing if we're pairable, the initiators of the
	 * pairing or if the remote is not requesting bonding.
	 */
	if (hci_dev_test_flag(hdev, HCI_BONDABLE) ||
	    test_bit(HCI_CONN_AUTH_INITIATOR, &conn->flags) ||
	    (conn->remote_auth & ~0x01) == HCI_AT_NO_BONDING) {
		struct hci_cp_io_capability_reply cp;

		bacpy(&cp.bdaddr, &ev->bdaddr);
		/* Change the IO capability from KeyboardDisplay
		 * to DisplayYesNo as it is not supported by BT spec. */
		cp.capability = (conn->io_capability == 0x04) ?
				HCI_IO_DISPLAY_YESNO : conn->io_capability;

		/* If we are initiators, there is no remote information yet */
		if (conn->remote_auth == 0xff) {
			/* Request MITM protection if our IO caps allow it
			 * except for the no-bonding case.
			 */
			if (conn->io_capability != HCI_IO_NO_INPUT_OUTPUT &&
			    conn->auth_type != HCI_AT_NO_BONDING)
				conn->auth_type |= 0x01;
		} else {
			conn->auth_type = hci_get_auth_req(conn);
		}

		/* If we're not bondable, force one of the non-bondable
		 * authentication requirement values.
		 */
		if (!hci_dev_test_flag(hdev, HCI_BONDABLE))
			conn->auth_type &= HCI_AT_NO_BONDING_MITM;

		cp.authentication = conn->auth_type;
		cp.oob_data = klpr_bredr_oob_data_present(conn);

		(*klpe_hci_send_cmd)(hdev, HCI_OP_IO_CAPABILITY_REPLY,
			     sizeof(cp), &cp);
	} else {
		struct hci_cp_io_capability_neg_reply cp;

		bacpy(&cp.bdaddr, &ev->bdaddr);
		cp.reason = HCI_ERROR_PAIRING_NOT_ALLOWED;

		(*klpe_hci_send_cmd)(hdev, HCI_OP_IO_CAPABILITY_NEG_REPLY,
			     sizeof(cp), &cp);
	}

unlock:
	hci_dev_unlock(hdev);
}

static void hci_io_capa_reply_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_io_capa_reply *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		goto unlock;

	conn->remote_cap = ev->capability;
	conn->remote_auth = ev->authentication;

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_user_confirm_request_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_ev_user_confirm_req *ev = (void *) skb->data;
	int loc_mitm, rem_mitm, confirm_hint = 0;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

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
		BT_DBG("Rejecting request: remote device can't provide MITM");
		(*klpe_hci_send_cmd)(hdev, HCI_OP_USER_CONFIRM_NEG_REPLY,
			     sizeof(ev->bdaddr), &ev->bdaddr);
		goto unlock;
	}

	/* If no side requires MITM protection; auto-accept */
	if ((!loc_mitm || conn->remote_cap == HCI_IO_NO_INPUT_OUTPUT) &&
	    (!rem_mitm || conn->io_capability == HCI_IO_NO_INPUT_OUTPUT)) {

		/* If we're not the initiators request authorization to
		 * proceed from user space (mgmt_user_confirm with
		 * confirm_hint set to 1). The exception is if neither
		 * side had MITM or if the local IO capability is
		 * NoInputNoOutput, in which case we do auto-accept
		 */
		if (!test_bit(HCI_CONN_AUTH_PEND, &conn->flags) &&
		    conn->io_capability != HCI_IO_NO_INPUT_OUTPUT &&
		    (loc_mitm || rem_mitm)) {
			BT_DBG("Confirming auto-accept as acceptor");
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

		(*klpe_hci_send_cmd)(hdev, HCI_OP_USER_CONFIRM_REPLY,
			     sizeof(ev->bdaddr), &ev->bdaddr);
		goto unlock;
	}

confirm:
	(*klpe_mgmt_user_confirm_request)(hdev, &ev->bdaddr, ACL_LINK, 0,
				  le32_to_cpu(ev->passkey), confirm_hint);

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_user_passkey_request_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_ev_user_passkey_req *ev = (void *) skb->data;

	BT_DBG("%s", hdev->name);

	if (hci_dev_test_flag(hdev, HCI_MGMT))
		(*klpe_mgmt_user_passkey_request)(hdev, &ev->bdaddr, ACL_LINK, 0);
}

static void klpr_hci_user_passkey_notify_evt(struct hci_dev *hdev,
					struct sk_buff *skb)
{
	struct hci_ev_user_passkey_notify *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		return;

	conn->passkey_notify = __le32_to_cpu(ev->passkey);
	conn->passkey_entered = 0;

	if (hci_dev_test_flag(hdev, HCI_MGMT))
		(*klpe_mgmt_user_passkey_notify)(hdev, &conn->dst, conn->type,
					 conn->dst_type, conn->passkey_notify,
					 conn->passkey_entered);
}

static void klpr_hci_keypress_notify_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_keypress_notify *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		return;

	switch (ev->type) {
	case HCI_KEYPRESS_STARTED:
		conn->passkey_entered = 0;
		return;

	case HCI_KEYPRESS_ENTERED:
		conn->passkey_entered++;
		break;

	case HCI_KEYPRESS_ERASED:
		conn->passkey_entered--;
		break;

	case HCI_KEYPRESS_CLEARED:
		conn->passkey_entered = 0;
		break;

	case HCI_KEYPRESS_COMPLETED:
		return;
	}

	if (hci_dev_test_flag(hdev, HCI_MGMT))
		(*klpe_mgmt_user_passkey_notify)(hdev, &conn->dst, conn->type,
					 conn->dst_type, conn->passkey_notify,
					 conn->passkey_entered);
}

static void klpr_hci_simple_pair_complete_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_ev_simple_pair_complete *ev = (void *) skb->data;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (!conn)
		goto unlock;

	/* Reset the authentication requirement to unknown */
	conn->remote_auth = 0xff;

	/* To avoid duplicate auth_failed events to user space we check
	 * the HCI_CONN_AUTH_PEND flag which will be set if we
	 * initiated the authentication. A traditional auth_complete
	 * event gets always produced as initiator and is also mapped to
	 * the mgmt_auth_failed event */
	if (!test_bit(HCI_CONN_AUTH_PEND, &conn->flags) && ev->status)
		(*klpe_mgmt_auth_failed)(conn, ev->status);

	hci_conn_drop(conn);

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_remote_host_features_evt(struct hci_dev *hdev,
					 struct sk_buff *skb)
{
	struct hci_ev_remote_host_features *ev = (void *) skb->data;
	struct inquiry_entry *ie;
	struct hci_conn *conn;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	conn = hci_conn_hash_lookup_ba(hdev, ACL_LINK, &ev->bdaddr);
	if (conn)
		memcpy(conn->features[1], ev->features, 8);

	ie = (*klpe_hci_inquiry_cache_lookup)(hdev, &ev->bdaddr);
	if (ie)
		ie->data.ssp_mode = (ev->features[0] & LMP_HOST_SSP);

	hci_dev_unlock(hdev);
}

static void klpr_hci_remote_oob_data_request_evt(struct hci_dev *hdev,
					    struct sk_buff *skb)
{
	struct hci_ev_remote_oob_data_request *ev = (void *) skb->data;
	struct oob_data *data;

	BT_DBG("%s", hdev->name);

	hci_dev_lock(hdev);

	if (!hci_dev_test_flag(hdev, HCI_MGMT))
		goto unlock;

	data = (*klpe_hci_find_remote_oob_data)(hdev, &ev->bdaddr, BDADDR_BREDR);
	if (!data) {
		struct hci_cp_remote_oob_data_neg_reply cp;

		bacpy(&cp.bdaddr, &ev->bdaddr);
		(*klpe_hci_send_cmd)(hdev, HCI_OP_REMOTE_OOB_DATA_NEG_REPLY,
			     sizeof(cp), &cp);
		goto unlock;
	}

	if (bredr_sc_enabled(hdev)) {
		struct hci_cp_remote_oob_ext_data_reply cp;

		bacpy(&cp.bdaddr, &ev->bdaddr);
		if (hci_dev_test_flag(hdev, HCI_SC_ONLY)) {
			memset(cp.hash192, 0, sizeof(cp.hash192));
			memset(cp.rand192, 0, sizeof(cp.rand192));
		} else {
			memcpy(cp.hash192, data->hash192, sizeof(cp.hash192));
			memcpy(cp.rand192, data->rand192, sizeof(cp.rand192));
		}
		memcpy(cp.hash256, data->hash256, sizeof(cp.hash256));
		memcpy(cp.rand256, data->rand256, sizeof(cp.rand256));

		(*klpe_hci_send_cmd)(hdev, HCI_OP_REMOTE_OOB_EXT_DATA_REPLY,
			     sizeof(cp), &cp);
	} else {
		struct hci_cp_remote_oob_data_reply cp;

		bacpy(&cp.bdaddr, &ev->bdaddr);
		memcpy(cp.hash, data->hash192, sizeof(cp.hash));
		memcpy(cp.rand, data->rand192, sizeof(cp.rand));

		(*klpe_hci_send_cmd)(hdev, HCI_OP_REMOTE_OOB_DATA_REPLY,
			     sizeof(cp), &cp);
	}

unlock:
	hci_dev_unlock(hdev);
}

#if IS_ENABLED(CONFIG_BT_HS)
static void klpr_hci_chan_selected_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_channel_selected *ev = (void *)skb->data;
	struct hci_conn *hcon;

	BT_DBG("%s handle 0x%2.2x", hdev->name, ev->phy_handle);

	skb_pull(skb, sizeof(*ev));

	hcon = hci_conn_hash_lookup_handle(hdev, ev->phy_handle);
	if (!hcon)
		return;

	(*klpe_amp_read_loc_assoc_final_data)(hdev, hcon);
}

static void klpr_hci_phy_link_complete_evt(struct hci_dev *hdev,
				      struct sk_buff *skb)
{
	struct hci_ev_phy_link_complete *ev = (void *) skb->data;
	struct hci_conn *hcon, *bredr_hcon;

	BT_DBG("%s handle 0x%2.2x status 0x%2.2x", hdev->name, ev->phy_handle,
	       ev->status);

	hci_dev_lock(hdev);

	hcon = hci_conn_hash_lookup_handle(hdev, ev->phy_handle);
	if (!hcon) {
		hci_dev_unlock(hdev);
		return;
	}

	if (ev->status) {
		(*klpe_hci_conn_del)(hcon);
		hci_dev_unlock(hdev);
		return;
	}

	bredr_hcon = hcon->amp_mgr->l2cap_conn->hcon;

	hcon->state = BT_CONNECTED;
	bacpy(&hcon->dst, &bredr_hcon->dst);

	hci_conn_hold(hcon);
	hcon->disc_timeout = HCI_DISCONN_TIMEOUT;
	hci_conn_drop(hcon);

	hci_debugfs_create_conn(hcon);
	(*klpe_hci_conn_add_sysfs)(hcon);

	(*klpe_amp_physical_cfm)(bredr_hcon, hcon);

	hci_dev_unlock(hdev);
}

static void klpp_hci_loglink_complete_evt(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_ev_logical_link_complete *ev = (void *) skb->data;
	struct hci_conn *hcon;
	struct hci_chan *hchan;
	struct amp_mgr *mgr;

	BT_DBG("%s log_handle 0x%4.4x phy_handle 0x%2.2x status 0x%2.2x",
	       hdev->name, le16_to_cpu(ev->handle), ev->phy_handle,
	       ev->status);

	hcon = hci_conn_hash_lookup_handle(hdev, ev->phy_handle);
	if (!hcon)
		return;

	/* Create AMP hchan */
	hchan = klpp_hci_chan_create(hcon);
	if (!hchan)
		return;

	hchan->handle = le16_to_cpu(ev->handle);
	/*
	 * Fix CVE-2021-33034
	 *  +1 line
	 */
	klpp_hci_chan_set_amp(hchan);

	BT_DBG("hcon %p mgr %p hchan %p", hcon, hcon->amp_mgr, hchan);

	mgr = hcon->amp_mgr;
	if (mgr && mgr->bredr_chan) {
		struct l2cap_chan *bredr_chan = mgr->bredr_chan;

		l2cap_chan_lock(bredr_chan);

		bredr_chan->conn->mtu = hdev->block_mtu;
		(*klpe_l2cap_logical_cfm)(bredr_chan, hchan, 0);
		hci_conn_hold(hcon);

		l2cap_chan_unlock(bredr_chan);
	}
}

static void klpp_hci_disconn_loglink_complete_evt(struct hci_dev *hdev,
					     struct sk_buff *skb)
{
	struct hci_ev_disconn_logical_link_complete *ev = (void *) skb->data;
	struct hci_chan *hchan;

	BT_DBG("%s log handle 0x%4.4x status 0x%2.2x", hdev->name,
	       le16_to_cpu(ev->handle), ev->status);

	if (ev->status)
		return;

	hci_dev_lock(hdev);

	hchan = (*klpe_hci_chan_lookup_handle)(hdev, le16_to_cpu(ev->handle));
	/*
	 * Fix CVE-2021-33034
	 *  -1 line, +1 line
	 */
	if (!hchan || !klpp_hci_chan_is_amp(hchan))
		goto unlock;

	(*klpe_amp_destroy_logical_link)(hchan, ev->reason);

unlock:
	hci_dev_unlock(hdev);
}

static void klpr_hci_disconn_phylink_complete_evt(struct hci_dev *hdev,
					     struct sk_buff *skb)
{
	struct hci_ev_disconn_phy_link_complete *ev = (void *) skb->data;
	struct hci_conn *hcon;

	BT_DBG("%s status 0x%2.2x", hdev->name, ev->status);

	if (ev->status)
		return;

	hci_dev_lock(hdev);

	hcon = hci_conn_hash_lookup_handle(hdev, ev->phy_handle);
	if (hcon) {
		hcon->state = BT_CLOSED;
		(*klpe_hci_conn_del)(hcon);
	}

	hci_dev_unlock(hdev);
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static void (*klpe_hci_le_meta_evt)(struct hci_dev *hdev, struct sk_buff *skb);

static bool klpr_hci_get_cmd_complete(struct hci_dev *hdev, u16 opcode,
				 u8 event, struct sk_buff *skb)
{
	struct hci_ev_cmd_complete *ev;
	struct hci_event_hdr *hdr;

	if (!skb)
		return false;

	if (skb->len < sizeof(*hdr)) {
		(*klpe_bt_err)("%s: " "too short HCI event" "\n",(hdev)->name);
		return false;
	}

	hdr = (void *) skb->data;
	skb_pull(skb, HCI_EVENT_HDR_SIZE);

	if (event) {
		if (hdr->evt != event)
			return false;
		return true;
	}

	/* Check if request ended in Command Status - no way to retreive
	 * any extra parameters in this case.
	 */
	if (hdr->evt == HCI_EV_CMD_STATUS)
		return false;

	if (hdr->evt != HCI_EV_CMD_COMPLETE) {
		(*klpe_bt_err)("%s: " "last event is not cmd complete (0x%2.2x)" "\n",(hdev)->name,hdr->evt);
		return false;
	}

	if (skb->len < sizeof(*ev)) {
		(*klpe_bt_err)("%s: " "too short cmd_complete event" "\n",(hdev)->name);
		return false;
	}

	ev = (void *) skb->data;
	skb_pull(skb, sizeof(*ev));

	if (opcode != __le16_to_cpu(ev->opcode)) {
		BT_DBG("opcode doesn't match (0x%2.2x != 0x%2.2x)", opcode,
		       __le16_to_cpu(ev->opcode));
		return false;
	}

	return true;
}

void klpp_hci_event_packet(struct hci_dev *hdev, struct sk_buff *skb)
{
	struct hci_event_hdr *hdr = (void *) skb->data;
	hci_req_complete_t req_complete = NULL;
	hci_req_complete_skb_t req_complete_skb = NULL;
	struct sk_buff *orig_skb = NULL;
	u8 status = 0, event = hdr->evt, req_evt = 0;
	u16 opcode = HCI_OP_NOP;

	if (!event) {
		(*klpe_bt_warn)("%s: " "Received unexpected HCI Event 00000000" "\n",(hdev)->name);
		goto done;
	}

	if (hdev->sent_cmd && bt_cb(hdev->sent_cmd)->hci.req_event == event) {
		struct hci_command_hdr *cmd_hdr = (void *) hdev->sent_cmd->data;
		opcode = __le16_to_cpu(cmd_hdr->opcode);
		(*klpe_hci_req_cmd_complete)(hdev, opcode, status, &req_complete,
				     &req_complete_skb);
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

	switch (event) {
	case HCI_EV_INQUIRY_COMPLETE:
		klpr_hci_inquiry_complete_evt(hdev, skb);
		break;

	case HCI_EV_INQUIRY_RESULT:
		klpr_hci_inquiry_result_evt(hdev, skb);
		break;

	case HCI_EV_CONN_COMPLETE:
		klpr_hci_conn_complete_evt(hdev, skb);
		break;

	case HCI_EV_CONN_REQUEST:
		klpr_hci_conn_request_evt(hdev, skb);
		break;

	case HCI_EV_DISCONN_COMPLETE:
		klpr_hci_disconn_complete_evt(hdev, skb);
		break;

	case HCI_EV_AUTH_COMPLETE:
		klpr_hci_auth_complete_evt(hdev, skb);
		break;

	case HCI_EV_REMOTE_NAME:
		klpr_hci_remote_name_evt(hdev, skb);
		break;

	case HCI_EV_ENCRYPT_CHANGE:
		klpr_hci_encrypt_change_evt(hdev, skb);
		break;

	case HCI_EV_CHANGE_LINK_KEY_COMPLETE:
		klpr_hci_change_link_key_complete_evt(hdev, skb);
		break;

	case HCI_EV_REMOTE_FEATURES:
		klpr_hci_remote_features_evt(hdev, skb);
		break;

	case HCI_EV_CMD_COMPLETE:
		(*klpe_hci_cmd_complete_evt)(hdev, skb, &opcode, &status,
				     &req_complete, &req_complete_skb);
		break;

	case HCI_EV_CMD_STATUS:
		(*klpe_hci_cmd_status_evt)(hdev, skb, &opcode, &status, &req_complete,
				   &req_complete_skb);
		break;

	case HCI_EV_HARDWARE_ERROR:
		hci_hardware_error_evt(hdev, skb);
		break;

	case HCI_EV_ROLE_CHANGE:
		klpr_hci_role_change_evt(hdev, skb);
		break;

	case HCI_EV_NUM_COMP_PKTS:
		klpr_hci_num_comp_pkts_evt(hdev, skb);
		break;

	case HCI_EV_MODE_CHANGE:
		klpr_hci_mode_change_evt(hdev, skb);
		break;

	case HCI_EV_PIN_CODE_REQ:
		klpr_hci_pin_code_request_evt(hdev, skb);
		break;

	case HCI_EV_LINK_KEY_REQ:
		klpr_hci_link_key_request_evt(hdev, skb);
		break;

	case HCI_EV_LINK_KEY_NOTIFY:
		klpr_hci_link_key_notify_evt(hdev, skb);
		break;

	case HCI_EV_CLOCK_OFFSET:
		klpr_hci_clock_offset_evt(hdev, skb);
		break;

	case HCI_EV_PKT_TYPE_CHANGE:
		hci_pkt_type_change_evt(hdev, skb);
		break;

	case HCI_EV_PSCAN_REP_MODE:
		klpr_hci_pscan_rep_mode_evt(hdev, skb);
		break;

	case HCI_EV_INQUIRY_RESULT_WITH_RSSI:
		klpr_hci_inquiry_result_with_rssi_evt(hdev, skb);
		break;

	case HCI_EV_REMOTE_EXT_FEATURES:
		klpr_hci_remote_ext_features_evt(hdev, skb);
		break;

	case HCI_EV_SYNC_CONN_COMPLETE:
		klpr_hci_sync_conn_complete_evt(hdev, skb);
		break;

	case HCI_EV_EXTENDED_INQUIRY_RESULT:
		klpr_hci_extended_inquiry_result_evt(hdev, skb);
		break;

	case HCI_EV_KEY_REFRESH_COMPLETE:
		klpr_hci_key_refresh_complete_evt(hdev, skb);
		break;

	case HCI_EV_IO_CAPA_REQUEST:
		klpr_hci_io_capa_request_evt(hdev, skb);
		break;

	case HCI_EV_IO_CAPA_REPLY:
		hci_io_capa_reply_evt(hdev, skb);
		break;

	case HCI_EV_USER_CONFIRM_REQUEST:
		klpr_hci_user_confirm_request_evt(hdev, skb);
		break;

	case HCI_EV_USER_PASSKEY_REQUEST:
		klpr_hci_user_passkey_request_evt(hdev, skb);
		break;

	case HCI_EV_USER_PASSKEY_NOTIFY:
		klpr_hci_user_passkey_notify_evt(hdev, skb);
		break;

	case HCI_EV_KEYPRESS_NOTIFY:
		klpr_hci_keypress_notify_evt(hdev, skb);
		break;

	case HCI_EV_SIMPLE_PAIR_COMPLETE:
		klpr_hci_simple_pair_complete_evt(hdev, skb);
		break;

	case HCI_EV_REMOTE_HOST_FEATURES:
		klpr_hci_remote_host_features_evt(hdev, skb);
		break;

	case HCI_EV_LE_META:
		(*klpe_hci_le_meta_evt)(hdev, skb);
		break;

	case HCI_EV_REMOTE_OOB_DATA_REQUEST:
		klpr_hci_remote_oob_data_request_evt(hdev, skb);
		break;

#if IS_ENABLED(CONFIG_BT_HS)
	case HCI_EV_CHANNEL_SELECTED:
		klpr_hci_chan_selected_evt(hdev, skb);
		break;

	case HCI_EV_PHY_LINK_COMPLETE:
		klpr_hci_phy_link_complete_evt(hdev, skb);
		break;

	case HCI_EV_LOGICAL_LINK_COMPLETE:
		klpp_hci_loglink_complete_evt(hdev, skb);
		break;

	case HCI_EV_DISCONN_LOGICAL_LINK_COMPLETE:
		klpp_hci_disconn_loglink_complete_evt(hdev, skb);
		break;

	case HCI_EV_DISCONN_PHY_LINK_COMPLETE:
		klpr_hci_disconn_phylink_complete_evt(hdev, skb);
		break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	case HCI_EV_NUM_COMP_BLOCKS:
		klpr_hci_num_comp_blocks_evt(hdev, skb);
		break;

	default:
		BT_DBG("%s event 0x%2.2x", hdev->name, event);
		break;
	}

	if (req_complete) {
		req_complete(hdev, status, opcode);
	} else if (req_complete_skb) {
		if (!klpr_hci_get_cmd_complete(hdev, opcode, req_evt, orig_skb)) {
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



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1186285.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "bluetooth"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "hci_cb_list", (void *)&klpe_hci_cb_list, "bluetooth" },
	{ "hci_cb_list_lock", (void *)&klpe_hci_cb_list_lock, "bluetooth" },
	{ "bt_warn", (void *)&klpe_bt_warn, "bluetooth" },
	{ "bt_err", (void *)&klpe_bt_err, "bluetooth" },
	{ "bt_info", (void *)&klpe_bt_info, "bluetooth" },
	{ "l2cap_connect_ind", (void *)&klpe_l2cap_connect_ind, "bluetooth" },
	{ "sco_connect_ind", (void *)&klpe_sco_connect_ind, "bluetooth" },
	{ "hci_discovery_set_state", (void *)&klpe_hci_discovery_set_state,
	  "bluetooth" },
	{ "hci_inquiry_cache_lookup", (void *)&klpe_hci_inquiry_cache_lookup,
	  "bluetooth" },
	{ "hci_inquiry_cache_lookup_resolve",
	  (void *)&klpe_hci_inquiry_cache_lookup_resolve, "bluetooth" },
	{ "hci_inquiry_cache_update", (void *)&klpe_hci_inquiry_cache_update,
	  "bluetooth" },
	{ "hci_find_remote_oob_data", (void *)&klpe_hci_find_remote_oob_data,
	  "bluetooth" },
	{ "mgmt_disconnect_failed", (void *)&klpe_mgmt_disconnect_failed,
	  "bluetooth" },
	{ "mgmt_user_passkey_request", (void *)&klpe_mgmt_user_passkey_request,
	  "bluetooth" },
	{ "mgmt_user_passkey_notify", (void *)&klpe_mgmt_user_passkey_notify,
	  "bluetooth" },
	{ "mgmt_device_found", (void *)&klpe_mgmt_device_found, "bluetooth" },
	{ "hci_conn_check_link_mode", (void *)&klpe_hci_conn_check_link_mode,
	  "bluetooth" },
	{ "hci_conn_check_pending", (void *)&klpe_hci_conn_check_pending,
	  "bluetooth" },
	{ "mgmt_user_confirm_request", (void *)&klpe_mgmt_user_confirm_request,
	  "bluetooth" },
	{ "hci_conn_params_lookup", (void *)&klpe_hci_conn_params_lookup,
	  "bluetooth" },
	{ "hci_bdaddr_list_lookup", (void *)&klpe_hci_bdaddr_list_lookup,
	  "bluetooth" },
	{ "hci_sco_setup", (void *)&klpe_hci_sco_setup, "bluetooth" },
	{ "hci_add_link_key", (void *)&klpe_hci_add_link_key, "bluetooth" },
	{ "mgmt_device_connected", (void *)&klpe_mgmt_device_connected,
	  "bluetooth" },
	{ "mgmt_auth_failed", (void *)&klpe_mgmt_auth_failed, "bluetooth" },
	{ "mgmt_pin_code_request", (void *)&klpe_mgmt_pin_code_request,
	  "bluetooth" },
	{ "mgmt_connect_failed", (void *)&klpe_mgmt_connect_failed,
	  "bluetooth" },
	{ "mgmt_new_link_key", (void *)&klpe_mgmt_new_link_key, "bluetooth" },
	{ "hci_setup_sync", (void *)&klpe_hci_setup_sync, "bluetooth" },
	{ "hci_conn_add", (void *)&klpe_hci_conn_add, "bluetooth" },
	{ "hci_disconnect", (void *)&klpe_hci_disconnect, "bluetooth" },
	{ "mgmt_device_disconnected", (void *)&klpe_mgmt_device_disconnected,
	  "bluetooth" },
	{ "hci_send_cmd", (void *)&klpe_hci_send_cmd, "bluetooth" },
	{ "hci_find_link_key", (void *)&klpe_hci_find_link_key, "bluetooth" },
	{ "hci_conn_add_sysfs", (void *)&klpe_hci_conn_add_sysfs, "bluetooth" },
	{ "hci_chan_lookup_handle", (void *)&klpe_hci_chan_lookup_handle,
	  "bluetooth" },
	{ "hci_remove_link_key", (void *)&klpe_hci_remove_link_key,
	  "bluetooth" },
	{ "hci_conn_del", (void *)&klpe_hci_conn_del, "bluetooth" },
	{ "hci_req_init", (void *)&klpe_hci_req_init, "bluetooth" },
	{ "hci_req_run_skb", (void *)&klpe_hci_req_run_skb, "bluetooth" },
	{ "hci_req_add", (void *)&klpe_hci_req_add, "bluetooth" },
	{ "hci_req_cmd_complete", (void *)&klpe_hci_req_cmd_complete,
	  "bluetooth" },
	{ "hci_req_reenable_advertising",
	  (void *)&klpe_hci_req_reenable_advertising, "bluetooth" },
	{ "l2cap_logical_cfm", (void *)&klpe_l2cap_logical_cfm, "bluetooth" },
	{ "amp_read_loc_assoc_final_data",
	  (void *)&klpe_amp_read_loc_assoc_final_data, "bluetooth" },
	{ "amp_physical_cfm", (void *)&klpe_amp_physical_cfm, "bluetooth" },
	{ "amp_destroy_logical_link", (void *)&klpe_amp_destroy_logical_link,
	  "bluetooth" },
	{ "hci_resolve_name", (void *)&klpe_hci_resolve_name, "bluetooth" },
	{ "hci_check_pending_name", (void *)&klpe_hci_check_pending_name,
	  "bluetooth" },
	{ "read_enc_key_size_complete",
	  (void *)&klpe_read_enc_key_size_complete, "bluetooth" },
	{ "hci_cmd_status_evt", (void *)&klpe_hci_cmd_status_evt, "bluetooth" },
	{ "hci_cmd_complete_evt", (void *)&klpe_hci_cmd_complete_evt,
	  "bluetooth" },
	{ "conn_set_key", (void *)&klpe_conn_set_key, "bluetooth" },
	{ "hci_le_meta_evt", (void *)&klpe_hci_le_meta_evt, "bluetooth" },
};

static int livepatch_bsc1186285_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1186285_module_nb = {
	.notifier_call = livepatch_bsc1186285_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1186285_hci_event_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1186285_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1186285_hci_event_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1186285_module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
