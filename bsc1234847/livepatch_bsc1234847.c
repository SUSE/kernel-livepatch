/*
 * livepatch_bsc1234847
 *
 * Fix for CVE-2024-53156, bsc#1234847
 *
 *  Upstream commit:
 *  8619593634cb ("wifi: ath9k: add range check for conn_rsp_epid in htc_connect_service()")
 *
 *  SLE12-SP5 commit:
 *  22125f2033534c7377d9146ac65df4ef7be1c21a
 *
 *  SLE15-SP3 commit:
 *  4be073086946618b439b1a66f250ba1f94c70629
 *
 *  SLE15-SP4 and -SP5 commit:
 *  747e6645286575c4dff971c0fd7dedf000ef14cd
 *
 *  SLE15-SP6 commit:
 *  3eb2c7affea7b4ab89b6d5f90511a0120d71c730
 *
 *  SLE MICRO-6-0 commit:
 *  3eb2c7affea7b4ab89b6d5f90511a0120d71c730
 *
 *  Copyright (c) 2025 SUSE
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

#if IS_ENABLED(CONFIG_ATH9K_HTC)

#if !IS_MODULE(CONFIG_ATH9K_HTC)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc_hst.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc.h */
#include <linux/module.h>
#include <linux/usb.h>

/* klp-ccp: from include/linux/firmware.h */
#define _LINUX_FIRMWARE_H

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc.h */
#include <linux/skbuff.h>

/* klp-ccp: from include/linux/if_ether.h */
#define _LINUX_IF_ETHER_H

/* klp-ccp: from include/linux/etherdevice.h */
#define _LINUX_ETHERDEVICE_H

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc.h */
#include <linux/slab.h>

/* klp-ccp: from include/net/mac80211.h */
#define MAC80211_H

/* klp-ccp: from include/net/cfg80211.h */
#define __NET_CFG80211_H

/* klp-ccp: from include/uapi/linux/nl80211.h */
#define __LINUX_NL80211_H

/* klp-ccp: from drivers/net/wireless/ath/ath9k/common.h */
#include <net/mac80211.h>
/* klp-ccp: from drivers/net/wireless/ath/ath.h */
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <net/mac80211.h>

/* klp-ccp: from drivers/net/wireless/ath/ath9k/hw.h */
#include <linux/if_ether.h>
#include <linux/delay.h>

#include <linux/firmware.h>

/* klp-ccp: from drivers/net/wireless/ath/ath9k/mac.h */
#include <net/cfg80211.h>
/* klp-ccp: from drivers/net/wireless/ath/ath9k/eeprom.h */
#include <net/cfg80211.h>
/* klp-ccp: from drivers/net/wireless/ath/ath9k/ar9003_eeprom.h */
#include <linux/types.h>
/* klp-ccp: from drivers/net/wireless/ath/regd.h */
#include <linux/nl80211.h>
#include <net/cfg80211.h>

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc_hst.h */
enum ath9k_hif_transports {
	ATH9K_HIF_USB,
};

struct ath9k_htc_hif {
	struct list_head list;
	const enum ath9k_hif_transports transport;
	const char *name;

	u8 control_dl_pipe;
	u8 control_ul_pipe;

	void (*start) (void *hif_handle);
	void (*stop) (void *hif_handle);
	void (*sta_drain) (void *hif_handle, u8 idx);
	int (*send) (void *hif_handle, u8 pipe, struct sk_buff *buf);
};

enum htc_endpoint_id {
	ENDPOINT_UNUSED = -1,
	ENDPOINT0 = 0,
	ENDPOINT1 = 1,
	ENDPOINT2 = 2,
	ENDPOINT3 = 3,
	ENDPOINT4 = 4,
	ENDPOINT5 = 5,
	ENDPOINT6 = 6,
	ENDPOINT7 = 7,
	ENDPOINT8 = 8,
	ENDPOINT_MAX = 22
};

struct htc_frame_hdr {
	u8 endpoint_id;
	u8 flags;
	__be16 payload_len;
	u8 control[4];
} __packed;

struct htc_ep_callbacks {
	void *priv;
	void (*tx) (void *, struct sk_buff *, enum htc_endpoint_id, bool txok);
	void (*rx) (void *, struct sk_buff *, enum htc_endpoint_id);
};

struct htc_endpoint {
	u16 service_id;

	struct htc_ep_callbacks ep_callbacks;
	u32 max_txqdepth;
	int max_msglen;

	u8 ul_pipeid;
	u8 dl_pipeid;
};

struct htc_target {
	void *hif_dev;
	struct ath9k_htc_priv *drv_priv;
	struct device *dev;
	struct ath9k_htc_hif *hif;
	struct htc_endpoint endpoint[ENDPOINT_MAX];
	struct completion target_wait;
	struct completion cmd_wait;
	struct list_head list;
	enum htc_endpoint_id conn_rsp_epid;
	u16 credits;
	u16 credit_size;
	u8 htc_flags;
	atomic_t tgt_ready;
};

enum htc_msg_id {
	HTC_MSG_READY_ID = 1,
	HTC_MSG_CONNECT_SERVICE_ID,
	HTC_MSG_CONNECT_SERVICE_RESPONSE_ID,
	HTC_MSG_SETUP_COMPLETE_ID,
	HTC_MSG_CONFIG_PIPE_ID,
	HTC_MSG_CONFIG_PIPE_RESPONSE_ID,
};

struct htc_service_connreq {
	u16 service_id;
	u16 con_flags;
	u32 max_send_qdepth;
	struct htc_ep_callbacks ep_callbacks;
};

enum htc_service_group_ids{
	RSVD_SERVICE_GROUP = 0,
	WMI_SERVICE_GROUP = 1,

	HTC_SERVICE_GROUP_LAST = 255
};

#define MAKE_SERVICE_ID(group, index)		\
	(int)(((int)group << 8) | (int)(index))

#define WMI_CONTROL_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 0)
#define WMI_BEACON_SVC	  MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 1)
#define WMI_CAB_SVC	  MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 2)
#define WMI_UAPSD_SVC	  MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 3)
#define WMI_MGMT_SVC	  MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 4)
#define WMI_DATA_VO_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 5)
#define WMI_DATA_VI_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 6)
#define WMI_DATA_BE_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 7)
#define WMI_DATA_BK_SVC   MAKE_SERVICE_ID(WMI_SERVICE_GROUP, 8)

struct htc_conn_svc_msg {
	__be16 msg_id;
	__be16 service_id;
	__be16 con_flags;
	u8 dl_pipeid;
	u8 ul_pipeid;
	u8 svc_meta_len;
	u8 pad;
} __packed;

/* klp-ccp: from drivers/net/wireless/ath/ath9k/htc_hst.c */
static int htc_issue_send(struct htc_target *target, struct sk_buff* skb,
			  u16 len, u8 flags, u8 epid)

{
	struct htc_frame_hdr *hdr;
	struct htc_endpoint *endpoint = &target->endpoint[epid];
	int status;

	hdr = skb_push(skb, sizeof(struct htc_frame_hdr));
	hdr->endpoint_id = epid;
	hdr->flags = flags;
	hdr->payload_len = cpu_to_be16(len);
	memset(hdr->control, 0, sizeof(hdr->control));

	status = target->hif->send(target->hif_dev, endpoint->ul_pipeid, skb);

	return status;
}

static struct htc_endpoint *get_next_avail_ep(struct htc_endpoint *endpoint)
{
	enum htc_endpoint_id avail_epid;

	for (avail_epid = (ENDPOINT_MAX - 1); avail_epid > ENDPOINT0; avail_epid--)
		if (endpoint[avail_epid].service_id == 0)
			return &endpoint[avail_epid];
	return NULL;
}

static u8 service_to_ulpipe(u16 service_id)
{
	switch (service_id) {
	case WMI_CONTROL_SVC:
		return 4;
	case WMI_BEACON_SVC:
	case WMI_CAB_SVC:
	case WMI_UAPSD_SVC:
	case WMI_MGMT_SVC:
	case WMI_DATA_VO_SVC:
	case WMI_DATA_VI_SVC:
	case WMI_DATA_BE_SVC:
	case WMI_DATA_BK_SVC:
		return 1;
	default:
		return 0;
	}
}

static u8 service_to_dlpipe(u16 service_id)
{
	switch (service_id) {
	case WMI_CONTROL_SVC:
		return 3;
	case WMI_BEACON_SVC:
	case WMI_CAB_SVC:
	case WMI_UAPSD_SVC:
	case WMI_MGMT_SVC:
	case WMI_DATA_VO_SVC:
	case WMI_DATA_VI_SVC:
	case WMI_DATA_BE_SVC:
	case WMI_DATA_BK_SVC:
		return 2;
	default:
		return 0;
	}
}

int klpp_htc_connect_service(struct htc_target *target,
		     struct htc_service_connreq *service_connreq,
		     enum htc_endpoint_id *conn_rsp_epid)
{
	struct sk_buff *skb;
	struct htc_endpoint *endpoint;
	struct htc_conn_svc_msg *conn_msg;
	int ret;
	unsigned long time_left;

	/* Find an available endpoint */
	endpoint = get_next_avail_ep(target->endpoint);
	if (!endpoint) {
		dev_err(target->dev, "Endpoint is not available for service %d\n",
			service_connreq->service_id);
		return -EINVAL;
	}

	endpoint->service_id = service_connreq->service_id;
	endpoint->max_txqdepth = service_connreq->max_send_qdepth;
	endpoint->ul_pipeid = service_to_ulpipe(service_connreq->service_id);
	endpoint->dl_pipeid = service_to_dlpipe(service_connreq->service_id);
	endpoint->ep_callbacks = service_connreq->ep_callbacks;

	skb = alloc_skb(sizeof(struct htc_conn_svc_msg) +
			    sizeof(struct htc_frame_hdr), GFP_ATOMIC);
	if (!skb) {
		dev_err(target->dev, "Failed to allocate buf to send"
			"service connect req\n");
		return -ENOMEM;
	}

	skb_reserve(skb, sizeof(struct htc_frame_hdr));

	conn_msg = skb_put(skb, sizeof(struct htc_conn_svc_msg));
	conn_msg->service_id = cpu_to_be16(service_connreq->service_id);
	conn_msg->msg_id = cpu_to_be16(HTC_MSG_CONNECT_SERVICE_ID);
	conn_msg->con_flags = cpu_to_be16(service_connreq->con_flags);
	conn_msg->dl_pipeid = endpoint->dl_pipeid;
	conn_msg->ul_pipeid = endpoint->ul_pipeid;

	/* To prevent infoleak */
	conn_msg->svc_meta_len = 0;
	conn_msg->pad = 0;

	ret = htc_issue_send(target, skb, skb->len, 0, ENDPOINT0);
	if (ret)
		goto err;

	time_left = wait_for_completion_timeout(&target->cmd_wait, HZ);
	if (!time_left) {
		dev_err(target->dev, "Service connection timeout for: %d\n",
			service_connreq->service_id);
		return -ETIMEDOUT;
	}

	if (target->conn_rsp_epid < 0 || target->conn_rsp_epid >= ENDPOINT_MAX)
		return -EINVAL;

	*conn_rsp_epid = target->conn_rsp_epid;
	return 0;
err:
	kfree_skb(skb);
	return ret;
}


#include "livepatch_bsc1234847.h"


#endif /* IS_ENABLED(CONFIG_ATH9K_HTC) */
