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


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/target/iscsi/iscsi_target_nego.c */
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <net/sock.h>
#include <scsi/iscsi_proto.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_transport.h>

/* klp-ccp: from include/target/iscsi/iscsi_transport.h */
static struct iscsi_param *(*klpe_iscsi_find_param_from_key)(
	char *, struct iscsi_param_list *);

/* klp-ccp: from drivers/target/iscsi/iscsi_target_nego.c */
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
static int (*klpe_iscsi_decode_text_input)(u8, u8, char *, u32, struct iscsi_conn *);
static int (*klpe_iscsi_check_negotiated_keys)(struct iscsi_param_list *);

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
/* klp-ccp: from drivers/target/iscsi/iscsi_target_tpg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_util.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>        /* itt_t */

static int (*klpe_iscsit_tx_login_rsp)(struct iscsi_conn *, u8, u8);

/* klp-ccp: from drivers/target/iscsi/iscsi_target.h */
#include <linux/types.h>
#include <linux/spinlock.h>

static struct iscsit_global *(*klpe_iscsit_global);

/* klp-ccp: from drivers/target/iscsi/iscsi_target_auth.h */
#include <linux/types.h>

static u32 (*klpe_chap_main_loop)(struct iscsi_conn *, struct iscsi_node_auth *, char *, char *,
				int *, int *);

/* klp-ccp: from drivers/target/iscsi/iscsi_target_nego.c */
#define MAX_LOGIN_PDUS  7

static u32 klpr_iscsi_handle_authentication(
	struct iscsi_conn *conn,
	char *in_buf,
	char *out_buf,
	int in_length,
	int *out_length,
	unsigned char *authtype)
{
	struct iscsi_session *sess = conn->sess;
	struct iscsi_node_auth *auth;
	struct iscsi_node_acl *iscsi_nacl;
	struct iscsi_portal_group *iscsi_tpg;
	struct se_node_acl *se_nacl;

	if (!sess->sess_ops->SessionType) {
		/*
		 * For SessionType=Normal
		 */
		se_nacl = conn->sess->se_sess->se_node_acl;
		if (!se_nacl) {
			pr_err("Unable to locate struct se_node_acl for"
					" CHAP auth\n");
			return -1;
		}
		iscsi_nacl = container_of(se_nacl, struct iscsi_node_acl,
				se_node_acl);
		if (!iscsi_nacl) {
			pr_err("Unable to locate struct iscsi_node_acl for"
					" CHAP auth\n");
			return -1;
		}

		if (se_nacl->dynamic_node_acl) {
			iscsi_tpg = container_of(se_nacl->se_tpg,
					struct iscsi_portal_group, tpg_se_tpg);

			auth = &iscsi_tpg->tpg_demo_auth;
		} else {
			iscsi_nacl = container_of(se_nacl, struct iscsi_node_acl,
						  se_node_acl);

			auth = &iscsi_nacl->node_auth;
		}
	} else {
		/*
		 * For SessionType=Discovery
		 */
		auth = &(*klpe_iscsit_global)->discovery_acl.node_auth;
	}

	if (strstr("CHAP", authtype))
		strcpy(conn->sess->auth_type, "CHAP");
	else
		strcpy(conn->sess->auth_type, NONE);

	if (strstr("None", authtype))
		return 1;
#ifdef CANSRP
#error "klp-ccp: non-taken branch"
#endif
	else if (strstr("CHAP", authtype))
		return (*klpe_chap_main_loop)(conn, auth, in_buf, out_buf,
				&in_length, out_length);
	else if (strstr("SPKM1", authtype))
		return 2;
	else if (strstr("SPKM2", authtype))
		return 2;
	else if (strstr("KRB5", authtype))
		return 2;
	else
		return 2;
}

static int klpr_iscsi_target_check_first_request(
	struct iscsi_conn *conn,
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
				(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
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
				(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
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
					(*klpe_iscsit_tx_login_rsp)(conn,
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
					(*klpe_iscsit_tx_login_rsp)(conn,
							ISCSI_STATUS_CLS_INITIATOR_ERR,
							ISCSI_LOGIN_STATUS_TGT_NOT_FOUND);
					return -1;
				}
			}
		}
	}

	return 0;
}

static int (*klpe_iscsi_target_do_tx_login_io)(struct iscsi_conn *conn, struct iscsi_login *login);

static void (*klpe_iscsi_target_restore_sock_callbacks)(struct iscsi_conn *conn);
static bool (*klpe_iscsi_target_sk_check_close)(struct iscsi_conn *conn);

static int (*klpe_iscsi_target_check_for_existing_instances)(
	struct iscsi_conn *conn,
	struct iscsi_login *login);

static int klpr_iscsi_target_do_authentication(
	struct iscsi_conn *conn,
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

	param = (*klpe_iscsi_find_param_from_key)(AUTHMETHOD, conn->param_list);
	if (!param)
		return -1;

	authret = klpr_iscsi_handle_authentication(
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
		return (*klpe_iscsi_target_check_for_existing_instances)(
				conn, login);
	case 2:
		pr_err("Security negotiation"
			" failed.\n");
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_AUTH_FAILED);
		return -1;
	default:
		pr_err("Received unknown error %d from LIO"
				" Authentication\n", authret);
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_TARGET_ERR,
				ISCSI_LOGIN_STATUS_TARGET_ERROR);
		return -1;
	}

	return 0;
}

static int klpp_iscsi_target_handle_csg_zero(
	struct iscsi_conn *conn,
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

	param = (*klpe_iscsi_find_param_from_key)(AUTHMETHOD, conn->param_list);
	if (!param)
		return -1;

	ret = (*klpe_iscsi_decode_text_input)(
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
			(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
					ISCSI_LOGIN_STATUS_INIT_ERR);
			return -1;
		}

		goto do_auth;
	} else if (!payload_length) {
		pr_err("Initiator sent zero length security payload,"
		       " login failed\n");
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				    ISCSI_LOGIN_STATUS_AUTH_FAILED);
		return -1;
	}

	if (login->first_request)
		if (klpr_iscsi_target_check_first_request(conn, login) < 0)
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
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_INIT_ERR);
		return -1;
	}

	if (!(*klpe_iscsi_check_negotiated_keys)(conn->param_list)) {
		if (conn->tpg->tpg_attrib.authentication &&
		    !strncmp(param->value, NONE, 4)) {
			pr_err("Initiator sent AuthMethod=None but"
				" Target is enforcing iSCSI Authentication,"
					" login failed.\n");
			(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
					ISCSI_LOGIN_STATUS_AUTH_FAILED);
			return -1;
		}

		if (conn->tpg->tpg_attrib.authentication &&
		    !login->auth_complete)
			return 0;

		if (strncmp(param->value, NONE, 4) && !login->auth_complete)
			return 0;

		if ((login_req->flags & ISCSI_FLAG_LOGIN_NEXT_STAGE1) &&
		    (login_req->flags & ISCSI_FLAG_LOGIN_TRANSIT)) {
			login_rsp->flags |= ISCSI_FLAG_LOGIN_NEXT_STAGE1 |
					    ISCSI_FLAG_LOGIN_TRANSIT;
			login->current_stage = 1;
		}
	}

	return 0;
do_auth:
	return klpr_iscsi_target_do_authentication(conn, login);
}

static int klpp_iscsi_target_handle_csg_one(struct iscsi_conn *conn, struct iscsi_login *login)
{
	int ret;
	u32 payload_length;
	struct iscsi_login_req *login_req;
	struct iscsi_login_rsp *login_rsp;

	login_req = (struct iscsi_login_req *) login->req;
	login_rsp = (struct iscsi_login_rsp *) login->rsp;
	payload_length = ntoh24(login_req->dlength);

	ret = (*klpe_iscsi_decode_text_input)(
			PHASE_OPERATIONAL|PHASE_DECLARATIVE,
			SENDER_INITIATOR|SENDER_RECEIVER,
			login->req_buf,
			payload_length,
			conn);
	if (ret < 0) {
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_INIT_ERR);
		return -1;
	}

	if (login->first_request)
		if (klpr_iscsi_target_check_first_request(conn, login) < 0)
			return -1;

	if ((*klpe_iscsi_target_check_for_existing_instances)(conn, login) < 0)
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
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_INIT_ERR);
		return -1;
	}

	if (!login->auth_complete &&
	     conn->tpg->tpg_attrib.authentication) {
		pr_err("Initiator is requesting CSG: 1, has not been"
			 " successfully authenticated, and the Target is"
			" enforcing iSCSI Authentication, login failed.\n");
		(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_INITIATOR_ERR,
				ISCSI_LOGIN_STATUS_AUTH_FAILED);
		return -1;
	}

	if (!(*klpe_iscsi_check_negotiated_keys)(conn->param_list))
		if ((login_req->flags & ISCSI_FLAG_LOGIN_NEXT_STAGE3) &&
		    (login_req->flags & ISCSI_FLAG_LOGIN_TRANSIT))
			login_rsp->flags |= ISCSI_FLAG_LOGIN_NEXT_STAGE3 |
					    ISCSI_FLAG_LOGIN_TRANSIT;

	return 0;
}

int klpp_iscsi_target_do_login(struct iscsi_conn *conn, struct iscsi_login *login)
{
	int pdu_count = 0;
	struct iscsi_login_req *login_req;
	struct iscsi_login_rsp *login_rsp;

	login_req = (struct iscsi_login_req *) login->req;
	login_rsp = (struct iscsi_login_rsp *) login->rsp;

	while (1) {
		if (++pdu_count > MAX_LOGIN_PDUS) {
			pr_err("MAX_LOGIN_PDUS count reached.\n");
			(*klpe_iscsit_tx_login_rsp)(conn, ISCSI_STATUS_CLS_TARGET_ERR,
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
				if ((*klpe_iscsi_target_sk_check_close)(conn))
					return -1;

				login->tsih = conn->sess->tsih;
				login->login_complete = 1;
				(*klpe_iscsi_target_restore_sock_callbacks)(conn);
				if ((*klpe_iscsi_target_do_tx_login_io)(conn,
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

		if ((*klpe_iscsi_target_do_tx_login_io)(conn, login) < 0)
			return -1;

		if (login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT) {
			login_rsp->flags &= ~ISCSI_FLAG_LOGIN_TRANSIT;
			login_rsp->flags &= ~ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		}
		break;
	}

	return 0;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "iscsi_target_mod"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "chap_main_loop", (void *)&klpe_chap_main_loop, "iscsi_target_mod" },
	{ "iscsi_check_negotiated_keys",
	  (void *)&klpe_iscsi_check_negotiated_keys, "iscsi_target_mod" },
	{ "iscsi_decode_text_input", (void *)&klpe_iscsi_decode_text_input,
	  "iscsi_target_mod" },
	{ "iscsi_find_param_from_key", (void *)&klpe_iscsi_find_param_from_key,
	  "iscsi_target_mod" },
	{ "iscsi_target_check_for_existing_instances",
	  (void *)&klpe_iscsi_target_check_for_existing_instances,
	  "iscsi_target_mod" },
	{ "iscsi_target_do_tx_login_io",
	  (void *)&klpe_iscsi_target_do_tx_login_io, "iscsi_target_mod" },
	{ "iscsi_target_restore_sock_callbacks",
	  (void *)&klpe_iscsi_target_restore_sock_callbacks,
	  "iscsi_target_mod" },
	{ "iscsi_target_sk_check_close",
	  (void *)&klpe_iscsi_target_sk_check_close, "iscsi_target_mod" },
	{ "iscsit_global", (void *)&klpe_iscsit_global, "iscsi_target_mod" },
	{ "iscsit_tx_login_rsp", (void *)&klpe_iscsit_tx_login_rsp,
	  "iscsi_target_mod" },
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

int bsc1272386_drivers_target_iscsi_iscsi_target_nego_init(void)
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

void bsc1272386_drivers_target_iscsi_iscsi_target_nego_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
