/*
 * bsc1272386_drivers_target_iscsi_iscsi_target_nego
 *
 * Fix for CVE-2026-63887, bsc#1272386
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


#include "livepatch_bsc1272386.h"


/* klp-ccp: from drivers/target/iscsi/iscsi_target_nego.c */
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <net/sock.h>
#include <trace/events/sock.h>
#include <scsi/iscsi_proto.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_transport.h>
#include <target/iscsi/iscsi_target_core.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_parameters.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>

struct iscsi_param {
	char *name;
	char *value;
	u8 set_param;
	u8 phase;
	u8 scope;
	u8 sender;
	u8 type;
	u8 use;
	u16 type_range;
	u32 state;
	struct list_head p_list;
} ____cacheline_aligned;

extern struct iscsi_param *iscsi_find_param_from_key(char *, struct iscsi_param_list *);

extern int iscsi_decode_text_input(u8, u8, char *, u32, struct iscsit_conn *);
extern int iscsi_check_negotiated_keys(struct iscsi_param_list *);

#define NONE				"None"

#define AUTHMETHOD			"AuthMethod"

#define INITIATORNAME			"InitiatorName"

#define SESSIONTYPE			"SessionType"

#define DISCOVERY			"Discovery"

#define	SENDER_INITIATOR		0x01
#define SENDER_TARGET			0x02

#define SENDER_RECEIVER			0x04

#define PHASE_SECURITY			0x01
#define PHASE_OPERATIONAL		0x02
#define PHASE_DECLARATIVE		0x04

#define PSTATE_ACCEPTOR			0x01

#define IS_PSTATE_ACCEPTOR(p)		((p)->state & PSTATE_ACCEPTOR)

/* klp-ccp: from drivers/target/iscsi/iscsi_target_login.h */
#include <linux/types.h>

/* klp-ccp: from drivers/target/iscsi/iscsi_target_nego.h */
extern bool iscsi_conn_auth_required(struct iscsit_conn *conn);

/* klp-ccp: from drivers/target/iscsi/iscsi_target_tpg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_util.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>        /* itt_t */

extern int iscsit_tx_login_rsp(struct iscsit_conn *, u8, u8);

/* klp-ccp: from drivers/target/iscsi/iscsi_target.h */
#include <linux/types.h>
#include <linux/spinlock.h>

extern struct iscsit_global *iscsit_global;

/* klp-ccp: from drivers/target/iscsi/iscsi_target_auth.h */
#include <linux/types.h>

extern u32 chap_main_loop(struct iscsit_conn *, struct iscsi_node_auth *, char *, char *,
				int *, int *);

/* klp-ccp: from drivers/target/iscsi/iscsi_target_nego.c */
#define MAX_LOGIN_PDUS  7

static struct iscsi_node_auth *iscsi_get_node_auth(struct iscsit_conn *conn)
{
	struct iscsi_portal_group *tpg;
	struct iscsi_node_acl *nacl;
	struct se_node_acl *se_nacl;

	if (conn->sess->sess_ops->SessionType)
		return &iscsit_global->discovery_acl.node_auth;

	se_nacl = conn->sess->se_sess->se_node_acl;
	if (!se_nacl) {
		pr_err("Unable to locate struct se_node_acl for CHAP auth\n");
		return NULL;
	}

	if (se_nacl->dynamic_node_acl) {
		tpg = to_iscsi_tpg(se_nacl->se_tpg);
		return &tpg->tpg_demo_auth;
	}

	nacl = to_iscsi_nacl(se_nacl);

	return &nacl->node_auth;
}

static u32 iscsi_handle_authentication(
	struct iscsit_conn *conn,
	char *in_buf,
	char *out_buf,
	int in_length,
	int *out_length,
	unsigned char *authtype)
{
	struct iscsi_node_auth *auth;

	auth = iscsi_get_node_auth(conn);
	if (!auth)
		return -1;

	if (strstr("CHAP", authtype))
		strcpy(conn->sess->auth_type, "CHAP");
	else
		strcpy(conn->sess->auth_type, NONE);

	if (strstr("None", authtype))
		return 1;
	else if (strstr("CHAP", authtype))
		return chap_main_loop(conn, auth, in_buf, out_buf,
				&in_length, out_length);
	/* SRP, SPKM1, SPKM2 and KRB5 are unsupported */
	return 2;
}

static int iscsi_target_check_first_request(
	struct iscsit_conn *conn,
	struct iscsi_login *login)
{
	struct iscsi_param *param = NULL;
	struct se_node_acl *se_nacl;

	login->first_request = 0;

	list_for_each_entry(param, &conn->param_list->param_list, p_list) {
		if (!strncmp(param->name, SESSIONTYPE, 11)) {
			if (!IS_PSTATE_ACCEPTOR(param)) {
				pr_err("SessionType key not received"
					" in first login request.\n");
				iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
					ISCSI_LOGIN_STATUS_MISSING_FIELDS);
				return -1;
			}
			if (!strncmp(param->value, DISCOVERY, 9))
				return 0;
		}

		if (!strncmp(param->name, INITIATORNAME, 13)) {
			if (!IS_PSTATE_ACCEPTOR(param)) {
				if (!login->leading_connection)
					continue;

				pr_err("InitiatorName key not received"
					" in first login request.\n");
				iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
					ISCSI_LOGIN_STATUS_MISSING_FIELDS);
				return -1;
			}

			/*
			 * For non-leading connections, double check that the
			 * received InitiatorName matches the existing session's
			 * struct iscsi_node_acl.
			 */
			if (!login->leading_connection) {
				se_nacl = conn->sess->se_sess->se_node_acl;
				if (!se_nacl) {
					pr_err("Unable to locate"
						" struct se_node_acl\n");
					iscsit_tx_login_rsp(conn,
							ISCSI_STATUS_CLS_INITIATOR_ERR,
							ISCSI_LOGIN_STATUS_TGT_NOT_FOUND);
					return -1;
				}

				if (strcmp(param->value,
						se_nacl->initiatorname)) {
					pr_err("Incorrect"
						" InitiatorName: %s for this"
						" iSCSI Initiator Node.\n",
						param->value);
					iscsit_tx_login_rsp(conn,
							ISCSI_STATUS_CLS_INITIATOR_ERR,
							ISCSI_LOGIN_STATUS_TGT_NOT_FOUND);
					return -1;
				}
			}
		}
	}

	return 0;
}

extern int iscsi_target_do_tx_login_io(struct iscsit_conn *conn, struct iscsi_login *login);

extern void iscsi_target_restore_sock_callbacks(struct iscsit_conn *conn);
extern bool iscsi_target_sk_check_close(struct iscsit_conn *conn);

extern int iscsi_target_check_for_existing_instances(
	struct iscsit_conn *conn,
	struct iscsi_login *login);

static int iscsi_target_do_authentication(
	struct iscsit_conn *conn,
	struct iscsi_login *login)
{
	int authret;
	u32 payload_length;
	struct iscsi_param *param;
	struct iscsi_login_req *login_req;
	struct iscsi_login_rsp *login_rsp;

	login_req = (struct iscsi_login_req *) login->req;
	login_rsp = (struct iscsi_login_rsp *) login->rsp;
	payload_length = ntoh24(login_req->dlength);

	param = iscsi_find_param_from_key(AUTHMETHOD, conn->param_list);
	if (!param)
		return -1;

	authret = iscsi_handle_authentication(
			conn,
			login->req_buf,
			login->rsp_buf,
			payload_length,
			&login->rsp_length,
			param->value);
	switch (authret) {
	case 0:
		pr_debug("Received OK response"
		" from LIO Authentication, continuing.\n");
		break;
	case 1:
		pr_debug("iSCSI security negotiation"
			" completed successfully.\n");
		login->auth_complete = 1;
		if ((login_req->flags & ISCSI_FLAG_LOGIN_NEXT_STAGE1) &&
		    (login_req->flags & ISCSI_FLAG_LOGIN_TRANSIT)) {
			login_rsp->flags |= (ISCSI_FLAG_LOGIN_NEXT_STAGE1 |
					     ISCSI_FLAG_LOGIN_TRANSIT);
			login->current_stage = 1;
		}
		return iscsi_target_check_for_existing_instances(
				conn, login);
	case 2:
		pr_err("Security negotiation"
			" failed.\n");
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_AUTH_FAILED);
		return -1;
	default:
		pr_err("Received unknown error %d from LIO"
				" Authentication\n", authret);
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_TARGET_ERR,
				ISCSI_LOGIN_STATUS_TARGET_ERROR);
		return -1;
	}

	return 0;
}

bool iscsi_conn_auth_required(struct iscsit_conn *conn);

static int klpp_iscsi_target_handle_csg_zero(
	struct iscsit_conn *conn,
	struct iscsi_login *login)
{
	int ret;
	u32 payload_length;
	struct iscsi_param *param;
	struct iscsi_login_req *login_req;
	struct iscsi_login_rsp *login_rsp;

	login_req = (struct iscsi_login_req *) login->req;
	login_rsp = (struct iscsi_login_rsp *) login->rsp;
	payload_length = ntoh24(login_req->dlength);

	param = iscsi_find_param_from_key(AUTHMETHOD, conn->param_list);
	if (!param)
		return -1;

	ret = iscsi_decode_text_input(
			PHASE_SECURITY|PHASE_DECLARATIVE,
			SENDER_INITIATOR|SENDER_RECEIVER,
			login->req_buf,
			payload_length,
			conn);
	if (ret < 0)
		return -1;

	if (ret > 0) {
		if (login->auth_complete) {
			pr_err("Initiator has already been"
				" successfully authenticated, but is still"
				" sending %s keys.\n", param->value);
			iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
					ISCSI_LOGIN_STATUS_INIT_ERR);
			return -1;
		}

		goto do_auth;
	} else if (!payload_length) {
		pr_err("Initiator sent zero length security payload,"
		       " login failed\n");
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				    ISCSI_LOGIN_STATUS_AUTH_FAILED);
		return -1;
	}

	if (login->first_request)
		if (iscsi_target_check_first_request(conn, login) < 0)
			return -1;

	ret = klpp_iscsi_encode_text_output(
			PHASE_SECURITY|PHASE_DECLARATIVE,
			SENDER_TARGET,
			login->rsp_buf,
			&login->rsp_length,
			MAX_KEY_VALUE_PAIRS,
			conn->param_list,
			conn->tpg->tpg_attrib.login_keys_workaround);
	if (ret < 0) {
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_INIT_ERR);
		return -1;
	}

	if (!iscsi_check_negotiated_keys(conn->param_list)) {
		bool auth_required = iscsi_conn_auth_required(conn);

		if (auth_required) {
			if (!strncmp(param->value, NONE, 4)) {
				pr_err("Initiator sent AuthMethod=None but"
				       " Target is enforcing iSCSI Authentication,"
				       " login failed.\n");
				iscsit_tx_login_rsp(conn,
						ISCSI_STATUS_CLS_INITIATOR_ERR,
						ISCSI_LOGIN_STATUS_AUTH_FAILED);
				return -1;
			}

			if (!login->auth_complete)
				return 0;

			if (strncmp(param->value, NONE, 4) &&
			    !login->auth_complete)
				return 0;
		}

		if ((login_req->flags & ISCSI_FLAG_LOGIN_NEXT_STAGE1) &&
		    (login_req->flags & ISCSI_FLAG_LOGIN_TRANSIT)) {
			login_rsp->flags |= ISCSI_FLAG_LOGIN_NEXT_STAGE1 |
					    ISCSI_FLAG_LOGIN_TRANSIT;
			login->current_stage = 1;
		}
	}

	return 0;
do_auth:
	return iscsi_target_do_authentication(conn, login);
}

static bool iscsi_conn_authenticated(struct iscsit_conn *conn,
				     struct iscsi_login *login)
{
	if (!iscsi_conn_auth_required(conn))
		return true;

	if (login->auth_complete)
		return true;

	return false;
}

static int klpp_iscsi_target_handle_csg_one(struct iscsit_conn *conn, struct iscsi_login *login)
{
	int ret;
	u32 payload_length;
	struct iscsi_login_req *login_req;
	struct iscsi_login_rsp *login_rsp;

	login_req = (struct iscsi_login_req *) login->req;
	login_rsp = (struct iscsi_login_rsp *) login->rsp;
	payload_length = ntoh24(login_req->dlength);

	ret = iscsi_decode_text_input(
			PHASE_OPERATIONAL|PHASE_DECLARATIVE,
			SENDER_INITIATOR|SENDER_RECEIVER,
			login->req_buf,
			payload_length,
			conn);
	if (ret < 0) {
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_INIT_ERR);
		return -1;
	}

	if (login->first_request)
		if (iscsi_target_check_first_request(conn, login) < 0)
			return -1;

	if (iscsi_target_check_for_existing_instances(conn, login) < 0)
		return -1;

	ret = klpp_iscsi_encode_text_output(
			PHASE_OPERATIONAL|PHASE_DECLARATIVE,
			SENDER_TARGET,
			login->rsp_buf,
			&login->rsp_length,
			MAX_KEY_VALUE_PAIRS,
			conn->param_list,
			conn->tpg->tpg_attrib.login_keys_workaround);
	if (ret < 0) {
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_INIT_ERR);
		return -1;
	}

	if (!iscsi_conn_authenticated(conn, login)) {
		pr_err("Initiator is requesting CSG: 1, has not been"
		       " successfully authenticated, and the Target is"
		       " enforcing iSCSI Authentication, login failed.\n");
		iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_AUTH_FAILED);
		return -1;
	}

	if (!iscsi_check_negotiated_keys(conn->param_list))
		if ((login_req->flags & ISCSI_FLAG_LOGIN_NEXT_STAGE3) &&
		    (login_req->flags & ISCSI_FLAG_LOGIN_TRANSIT))
			login_rsp->flags |= ISCSI_FLAG_LOGIN_NEXT_STAGE3 |
					    ISCSI_FLAG_LOGIN_TRANSIT;

	return 0;
}

int klpp_iscsi_target_do_login(struct iscsit_conn *conn, struct iscsi_login *login)
{
	int pdu_count = 0;
	struct iscsi_login_req *login_req;
	struct iscsi_login_rsp *login_rsp;

	login_req = (struct iscsi_login_req *) login->req;
	login_rsp = (struct iscsi_login_rsp *) login->rsp;

	while (1) {
		if (++pdu_count > MAX_LOGIN_PDUS) {
			pr_err("MAX_LOGIN_PDUS count reached.\n");
			iscsit_tx_login_rsp(conn, ISCSI_STATUS_CLS_TARGET_ERR,
					ISCSI_LOGIN_STATUS_TARGET_ERROR);
			return -1;
		}

		switch (ISCSI_LOGIN_CURRENT_STAGE(login_req->flags)) {
		case 0:
			login_rsp->flags &= ~ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK;
			if (klpp_iscsi_target_handle_csg_zero(conn, login) < 0)
				return -1;
			break;
		case 1:
			login_rsp->flags |= ISCSI_FLAG_LOGIN_CURRENT_STAGE1;
			if (klpp_iscsi_target_handle_csg_one(conn, login) < 0)
				return -1;
			if (login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT) {
				/*
				 * Check to make sure the TCP connection has not
				 * dropped asynchronously while session reinstatement
				 * was occuring in this kthread context, before
				 * transitioning to full feature phase operation.
				 */
				if (iscsi_target_sk_check_close(conn))
					return -1;

				login->tsih = conn->sess->tsih;
				login->login_complete = 1;
				iscsi_target_restore_sock_callbacks(conn);
				if (iscsi_target_do_tx_login_io(conn,
						login) < 0)
					return -1;
				return 1;
			}
			break;
		default:
			pr_err("Illegal CSG: %d received from"
				" Initiator, protocol error.\n",
				ISCSI_LOGIN_CURRENT_STAGE(login_req->flags));
			break;
		}

		if (iscsi_target_do_tx_login_io(conn, login) < 0)
			return -1;

		if (login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT) {
			login_rsp->flags &= ~ISCSI_FLAG_LOGIN_TRANSIT;
			login_rsp->flags &= ~ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		}
		break;
	}

	return 0;
}


#include <linux/livepatch.h>

extern typeof(chap_main_loop) chap_main_loop
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, chap_main_loop);
extern typeof(iscsi_check_negotiated_keys) iscsi_check_negotiated_keys
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_check_negotiated_keys);
extern typeof(iscsi_conn_auth_required) iscsi_conn_auth_required
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_conn_auth_required);
extern typeof(iscsi_decode_text_input) iscsi_decode_text_input
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_decode_text_input);
extern typeof(iscsi_find_param_from_key) iscsi_find_param_from_key
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_find_param_from_key);
extern typeof(iscsi_target_check_for_existing_instances)
	 iscsi_target_check_for_existing_instances
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_target_check_for_existing_instances);
extern typeof(iscsi_target_do_tx_login_io) iscsi_target_do_tx_login_io
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_target_do_tx_login_io);
extern typeof(iscsi_target_restore_sock_callbacks)
	 iscsi_target_restore_sock_callbacks
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_target_restore_sock_callbacks);
extern typeof(iscsi_target_sk_check_close) iscsi_target_sk_check_close
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsi_target_sk_check_close);
extern typeof(iscsit_global) iscsit_global
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_global);
extern typeof(iscsit_tx_login_rsp) iscsit_tx_login_rsp
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_tx_login_rsp);
