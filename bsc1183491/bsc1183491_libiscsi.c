/*
 * bsc1183491_libiscsi
 *
 * Fix for the libiscsi part of CVE-2021-27365, bsc#1183491.
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

#if !IS_MODULE(CONFIG_ISCSI_TCP)
#error "Live patch supports only CONFIG_ISCSI_TCP=m"
#endif

/* klp-ccp: from drivers/scsi/libiscsi.c */
#include <linux/types.h>
#include <linux/kfifo.h>
#include <linux/delay.h>
#include <linux/log2.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>
#include <scsi/iscsi_proto.h>
#include <scsi/scsi_transport_iscsi.h>
#include <scsi/libiscsi.h>

/* klp-ccp: from include/scsi/libiscsi.h */
int klpp_iscsi_host_get_param(struct Scsi_Host *shost,
				enum iscsi_host_param param, char *buf);

int klpp_iscsi_session_get_param(struct iscsi_cls_session *cls_session,
				   enum iscsi_param param, char *buf);

int klpp_iscsi_conn_get_param(struct iscsi_cls_conn *cls_conn,
				enum iscsi_param param, char *buf);
int klpp_iscsi_conn_get_addr_param(struct sockaddr_storage *addr,
				     enum iscsi_param param, char *buf);

/* klp-ccp: from drivers/scsi/libiscsi.c */
int klpp_iscsi_session_get_param(struct iscsi_cls_session *cls_session,
			    enum iscsi_param param, char *buf)
{
	struct iscsi_session *session = cls_session->dd_data;
	int len;

	switch(param) {
	case ISCSI_PARAM_FAST_ABORT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->fast_abort);
		break;
	case ISCSI_PARAM_ABORT_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->abort_timeout);
		break;
	case ISCSI_PARAM_LU_RESET_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->lu_reset_timeout);
		break;
	case ISCSI_PARAM_TGT_RESET_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->tgt_reset_timeout);
		break;
	case ISCSI_PARAM_INITIAL_R2T_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->initial_r2t_en);
		break;
	case ISCSI_PARAM_MAX_R2T:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%hu\n", session->max_r2t);
		break;
	case ISCSI_PARAM_IMM_DATA_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->imm_data_en);
		break;
	case ISCSI_PARAM_FIRST_BURST:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->first_burst);
		break;
	case ISCSI_PARAM_MAX_BURST:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->max_burst);
		break;
	case ISCSI_PARAM_PDU_INORDER_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->pdu_inorder_en);
		break;
	case ISCSI_PARAM_DATASEQ_INORDER_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->dataseq_inorder_en);
		break;
	case ISCSI_PARAM_DEF_TASKMGMT_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->def_taskmgmt_tmo);
		break;
	case ISCSI_PARAM_ERL:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->erl);
		break;
	case ISCSI_PARAM_TARGET_NAME:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->targetname);
		break;
	case ISCSI_PARAM_TARGET_ALIAS:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->targetalias);
		break;
	case ISCSI_PARAM_TPGT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->tpgt);
		break;
	case ISCSI_PARAM_USERNAME:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->username);
		break;
	case ISCSI_PARAM_USERNAME_IN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->username_in);
		break;
	case ISCSI_PARAM_PASSWORD:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->password);
		break;
	case ISCSI_PARAM_PASSWORD_IN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->password_in);
		break;
	case ISCSI_PARAM_IFACE_NAME:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->ifacename);
		break;
	case ISCSI_PARAM_INITIATOR_NAME:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->initiatorname);
		break;
	case ISCSI_PARAM_BOOT_ROOT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->boot_root);
		break;
	case ISCSI_PARAM_BOOT_NIC:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->boot_nic);
		break;
	case ISCSI_PARAM_BOOT_TARGET:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->boot_target);
		break;
	case ISCSI_PARAM_AUTO_SND_TGT_DISABLE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->auto_snd_tgt_disable);
		break;
	case ISCSI_PARAM_DISCOVERY_SESS:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->discovery_sess);
		break;
	case ISCSI_PARAM_PORTAL_TYPE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", session->portal_type);
		break;
	case ISCSI_PARAM_CHAP_AUTH_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->chap_auth_en);
		break;
	case ISCSI_PARAM_DISCOVERY_LOGOUT_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->discovery_logout_en);
		break;
	case ISCSI_PARAM_BIDI_CHAP_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->bidi_chap_en);
		break;
	case ISCSI_PARAM_DISCOVERY_AUTH_OPTIONAL:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->discovery_auth_optional);
		break;
	case ISCSI_PARAM_DEF_TIME2WAIT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->time2wait);
		break;
	case ISCSI_PARAM_DEF_TIME2RETAIN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", session->time2retain);
		break;
	case ISCSI_PARAM_TSID:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->tsid);
		break;
	case ISCSI_PARAM_ISID:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%02x%02x%02x%02x%02x%02x\n",
			      session->isid[0], session->isid[1],
			      session->isid[2], session->isid[3],
			      session->isid[4], session->isid[5]);
		break;
	case ISCSI_PARAM_DISCOVERY_PARENT_IDX:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", session->discovery_parent_idx);
		break;
	case ISCSI_PARAM_DISCOVERY_PARENT_TYPE:
		if (session->discovery_parent_type)
			/*
			 * Fix CVE-2021-27365
			 *  -1 line, +1 line
			 */
			len = scnprintf(buf, PAGE_SIZE, "%s\n",
				      session->discovery_parent_type);
		else
			/*
			 * Fix CVE-2021-27365
			 *  -1 line, +1 line
			 */
			len = scnprintf(buf, PAGE_SIZE, "\n");
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

int klpp_iscsi_conn_get_addr_param(struct sockaddr_storage *addr,
			      enum iscsi_param param, char *buf)
{
	struct sockaddr_in6 *sin6 = NULL;
	struct sockaddr_in *sin = NULL;
	int len;

	switch (addr->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)addr;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)addr;
		break;
	default:
		return -EINVAL;
	}

	switch (param) {
	case ISCSI_PARAM_CONN_ADDRESS:
	case ISCSI_HOST_PARAM_IPADDRESS:
		if (sin)
			/*
			 * Fix CVE-2021-27365
			 *  -1 line, +1 line
			 */
			len = scnprintf(buf, PAGE_SIZE, "%pI4\n", &sin->sin_addr.s_addr);
		else
			/*
			 * Fix CVE-2021-27365
			 *  -1 line, +1 line
			 */
			len = scnprintf(buf, PAGE_SIZE, "%pI6\n", &sin6->sin6_addr);
		break;
	case ISCSI_PARAM_CONN_PORT:
	case ISCSI_PARAM_LOCAL_PORT:
		if (sin)
			/*
			 * Fix CVE-2021-27365
			 *  -1 line, +1 line
			 */
			len = scnprintf(buf, PAGE_SIZE, "%hu\n", be16_to_cpu(sin->sin_port));
		else
			/*
			 * Fix CVE-2021-27365
			 *  -1 line, +1 line
			 */
			len = scnprintf(buf, PAGE_SIZE, "%hu\n",
				      be16_to_cpu(sin6->sin6_port));
		break;
	default:
		return -EINVAL;
	}

	return len;
}

int klpp_iscsi_conn_get_param(struct iscsi_cls_conn *cls_conn,
			 enum iscsi_param param, char *buf)
{
	struct iscsi_conn *conn = cls_conn->dd_data;
	int len;

	switch(param) {
	case ISCSI_PARAM_PING_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->ping_timeout);
		break;
	case ISCSI_PARAM_RECV_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->recv_timeout);
		break;
	case ISCSI_PARAM_MAX_RECV_DLENGTH:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->max_recv_dlength);
		break;
	case ISCSI_PARAM_MAX_XMIT_DLENGTH:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->max_xmit_dlength);
		break;
	case ISCSI_PARAM_HDRDGST_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", conn->hdrdgst_en);
		break;
	case ISCSI_PARAM_DATADGST_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", conn->datadgst_en);
		break;
	case ISCSI_PARAM_IFMARKER_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", conn->ifmarker_en);
		break;
	case ISCSI_PARAM_OFMARKER_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", conn->ofmarker_en);
		break;
	case ISCSI_PARAM_EXP_STATSN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->exp_statsn);
		break;
	case ISCSI_PARAM_PERSISTENT_PORT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%d\n", conn->persistent_port);
		break;
	case ISCSI_PARAM_PERSISTENT_ADDRESS:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", conn->persistent_address);
		break;
	case ISCSI_PARAM_STATSN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->statsn);
		break;
	case ISCSI_PARAM_MAX_SEGMENT_SIZE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->max_segment_size);
		break;
	case ISCSI_PARAM_KEEPALIVE_TMO:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->keepalive_tmo);
		break;
	case ISCSI_PARAM_LOCAL_PORT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->local_port);
		break;
	case ISCSI_PARAM_TCP_TIMESTAMP_STAT:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_timestamp_stat);
		break;
	case ISCSI_PARAM_TCP_NAGLE_DISABLE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_nagle_disable);
		break;
	case ISCSI_PARAM_TCP_WSF_DISABLE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_wsf_disable);
		break;
	case ISCSI_PARAM_TCP_TIMER_SCALE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_timer_scale);
		break;
	case ISCSI_PARAM_TCP_TIMESTAMP_EN:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_timestamp_en);
		break;
	case ISCSI_PARAM_IP_FRAGMENT_DISABLE:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->fragment_disable);
		break;
	case ISCSI_PARAM_IPV4_TOS:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->ipv4_tos);
		break;
	case ISCSI_PARAM_IPV6_TC:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->ipv6_traffic_class);
		break;
	case ISCSI_PARAM_IPV6_FLOW_LABEL:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->ipv6_flow_label);
		break;
	case ISCSI_PARAM_IS_FW_ASSIGNED_IPV6:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->is_fw_assigned_ipv6);
		break;
	case ISCSI_PARAM_TCP_XMIT_WSF:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_xmit_wsf);
		break;
	case ISCSI_PARAM_TCP_RECV_WSF:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%u\n", conn->tcp_recv_wsf);
		break;
	case ISCSI_PARAM_LOCAL_IPADDR:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", conn->local_ipaddr);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}

int klpp_iscsi_host_get_param(struct Scsi_Host *shost, enum iscsi_host_param param,
			 char *buf)
{
	struct iscsi_host *ihost = shost_priv(shost);
	int len;

	switch (param) {
	case ISCSI_HOST_PARAM_NETDEV_NAME:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", ihost->netdev);
		break;
	case ISCSI_HOST_PARAM_HWADDRESS:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", ihost->hwaddress);
		break;
	case ISCSI_HOST_PARAM_INITIATOR_NAME:
		/*
		 * Fix CVE-2021-27365
		 *  -1 line, +1 line
		 */
		len = scnprintf(buf, PAGE_SIZE, "%s\n", ihost->initiatorname);
		break;
	default:
		return -ENOSYS;
	}

	return len;
}



#include "livepatch_bsc1183491.h"
