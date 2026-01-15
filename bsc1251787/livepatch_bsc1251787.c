/*
 * livepatch_bsc1251787
 *
 * Fix for CVE-2023-53676, bsc#1251787
 *
 *  Copyright (c) 2025 SUSE
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



/* klp-ccp: from drivers/target/iscsi/iscsi_target_configfs.c */
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <linux/export.h>
#include <linux/inet.h>
#include <linux/module.h>
#include <net/ipv6.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_transport.h>
#include <target/iscsi/iscsi_target_core.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_parameters.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_erl0.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_nodeattrib.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_tpg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_util.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>        /* itt_t */
/* klp-ccp: from drivers/target/iscsi/iscsi_target.h */
#include <linux/types.h>
#include <linux/spinlock.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_configfs.c */
#include <target/iscsi/iscsi_target_stat.h>

ssize_t klpp_lio_target_nacl_info_show(struct config_item *item, char *page)
{
	struct se_node_acl *se_nacl = acl_to_nacl(item);
	struct iscsit_session *sess;
	struct iscsit_conn *conn;
	struct se_session *se_sess;
	ssize_t rb = 0;
	u32 max_cmd_sn;

	spin_lock_bh(&se_nacl->nacl_sess_lock);
	se_sess = se_nacl->nacl_sess;
	if (!se_sess) {
		rb += sysfs_emit_at(page, rb, "No active iSCSI Session for Initiator"
			" Endpoint: %s\n", se_nacl->initiatorname);
	} else {
		sess = se_sess->fabric_sess_ptr;

		rb += sysfs_emit_at(page, rb, "InitiatorName: %s\n",
			sess->sess_ops->InitiatorName);
		rb += sysfs_emit_at(page, rb, "InitiatorAlias: %s\n",
			sess->sess_ops->InitiatorAlias);

		rb += sysfs_emit_at(page, rb,
			      "LIO Session ID: %u   ISID: 0x%6ph  TSIH: %hu  ",
			      sess->sid, sess->isid, sess->tsih);
		rb += sysfs_emit_at(page, rb, "SessionType: %s\n",
				(sess->sess_ops->SessionType) ?
				"Discovery" : "Normal");
		rb += sysfs_emit_at(page, rb, "Session State: ");
		switch (sess->session_state) {
		case TARG_SESS_STATE_FREE:
			rb += sysfs_emit_at(page, rb, "TARG_SESS_FREE\n");
			break;
		case TARG_SESS_STATE_ACTIVE:
			rb += sysfs_emit_at(page, rb, "TARG_SESS_STATE_ACTIVE\n");
			break;
		case TARG_SESS_STATE_LOGGED_IN:
			rb += sysfs_emit_at(page, rb, "TARG_SESS_STATE_LOGGED_IN\n");
			break;
		case TARG_SESS_STATE_FAILED:
			rb += sysfs_emit_at(page, rb, "TARG_SESS_STATE_FAILED\n");
			break;
		case TARG_SESS_STATE_IN_CONTINUE:
			rb += sysfs_emit_at(page, rb, "TARG_SESS_STATE_IN_CONTINUE\n");
			break;
		default:
			rb += sysfs_emit_at(page, rb, "ERROR: Unknown Session"
					" State!\n");
			break;
		}

		rb += sysfs_emit_at(page, rb, "---------------------[iSCSI Session"
				" Values]-----------------------\n");
		rb += sysfs_emit_at(page, rb, "  CmdSN/WR  :  CmdSN/WC  :  ExpCmdSN"
				"  :  MaxCmdSN  :     ITT    :     TTT\n");
		max_cmd_sn = (u32) atomic_read(&sess->max_cmd_sn);
		rb += sysfs_emit_at(page, rb, " 0x%08x   0x%08x   0x%08x   0x%08x"
				"   0x%08x   0x%08x\n",
			sess->cmdsn_window,
			(max_cmd_sn - sess->exp_cmd_sn) + 1,
			sess->exp_cmd_sn, max_cmd_sn,
			sess->init_task_tag, sess->targ_xfer_tag);
		rb += sysfs_emit_at(page, rb, "----------------------[iSCSI"
				" Connections]-------------------------\n");

		spin_lock(&sess->conn_lock);
		list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
			rb += sysfs_emit_at(page, rb, "CID: %hu  Connection"
					" State: ", conn->cid);
			switch (conn->conn_state) {
			case TARG_CONN_STATE_FREE:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_FREE\n");
				break;
			case TARG_CONN_STATE_XPT_UP:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_XPT_UP\n");
				break;
			case TARG_CONN_STATE_IN_LOGIN:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_IN_LOGIN\n");
				break;
			case TARG_CONN_STATE_LOGGED_IN:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_LOGGED_IN\n");
				break;
			case TARG_CONN_STATE_IN_LOGOUT:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_IN_LOGOUT\n");
				break;
			case TARG_CONN_STATE_LOGOUT_REQUESTED:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_LOGOUT_REQUESTED\n");
				break;
			case TARG_CONN_STATE_CLEANUP_WAIT:
				rb += sysfs_emit_at(page, rb,
					"TARG_CONN_STATE_CLEANUP_WAIT\n");
				break;
			default:
				rb += sysfs_emit_at(page, rb,
					"ERROR: Unknown Connection State!\n");
				break;
			}

			rb += sysfs_emit_at(page, rb, "   Address %pISc %s", &conn->login_sockaddr,
				(conn->network_transport == ISCSI_TCP) ?
				"TCP" : "SCTP");
			rb += sysfs_emit_at(page, rb, "  StatSN: 0x%08x\n",
				conn->stat_sn);
		}
		spin_unlock(&sess->conn_lock);
	}
	spin_unlock_bh(&se_nacl->nacl_sess_lock);

	return rb;
}


#include "livepatch_bsc1251787.h"

