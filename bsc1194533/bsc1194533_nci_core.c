/*
 * livepatch_bsc1194533
 *
 * bsc1194533_nci_core
 *
 * Fix for CVE-2021-4202, bsc#1194533 (net/nfc/nci/core.c part)
 *
 *  Copyright (c) 2022 SUSE
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

#if IS_ENABLED(CONFIG_NFC)

#if !IS_MODULE(CONFIG_NFC_NCI)
#error "Live patch supports only CONFIG_NFC_NCI=m"
#endif

#include <linux/types.h>
#include "livepatch_bsc1194533.h"

/* klp-ccp: from net/nfc/nci/core.c */
#define pr_fmt(fmt) "nci" ": %s: " fmt, __func__

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/skbuff.h>
/* klp-ccp: from net/nfc/nfc.h */
#include <net/nfc/nfc.h>

/* klp-ccp: from include/net/nfc/nfc.h */
static u8 *(*klpe_nfc_get_local_general_bytes)(struct nfc_dev *dev, size_t *gb_len);

static int (*klpe_nfc_tm_deactivated)(struct nfc_dev *dev);

/* klp-ccp: from net/nfc/nfc.h */
#define NFC_TARGET_MODE_SLEEP 1

/* klp-ccp: from net/nfc/nci/core.c */
#include <net/nfc/nci.h>
#include <net/nfc/nci_core.h>

/* klp-ccp: from include/net/nfc/nci_core.h */
/*
 * Fix CVE-2021-4202
 *  +1 line
 */
#define KLPP_NCI_UNREG (NCI_DATA_EXCHANGE_TO + 1)

void klpp_nci_unregister_device(struct nci_dev *ndev);
int klpp_nci_request(struct nci_dev *ndev,
		void (*req)(struct nci_dev *ndev,
			    unsigned long opt),
		unsigned long opt, __u32 timeout);

static int (*klpe_nci_set_config)(struct nci_dev *ndev, __u8 id, size_t len, __u8 *val);

static int (*klpe_nci_core_conn_create)(struct nci_dev *ndev, u8 destination_type,
			 u8 number_destination_params,
			 size_t params_len,
			 struct core_conn_create_dest_spec_params *params);

int klpp_nci_nfcc_loopback(struct nci_dev *ndev, void *data, size_t data_len,
		      struct sk_buff **resp);

static void (*klpe_nci_clear_target_list)(struct nci_dev *ndev);

static struct nci_conn_info *(*klpe_nci_get_conn_info_by_conn_id)(struct nci_dev *ndev,
						   int conn_id);
static int (*klpe_nci_get_conn_info_by_dest_type_params)(struct nci_dev *ndev, u8 dest_type,
					  struct dest_spec_params *params);

/* klp-ccp: from net/nfc/nci/core.c */
#include <linux/nfc.h>

static void nci_req_cancel(struct nci_dev *ndev, int err)
{
	if (ndev->req_status == NCI_REQ_PEND) {
		ndev->req_result = err;
		ndev->req_status = NCI_REQ_CANCELED;
		complete(&ndev->req_completion);
	}
}

static int (*klpe___nci_request)(struct nci_dev *ndev,
			 void (*req)(struct nci_dev *ndev, unsigned long opt),
			 unsigned long opt, __u32 timeout);

int klpp_nci_request(struct nci_dev *ndev,
		       void (*req)(struct nci_dev *ndev,
				   unsigned long opt),
		       unsigned long opt, __u32 timeout)
{
	int rc;

	/*
	 * Fix CVE-2021-4202
	 *  -2 lines
	 */

	/* Serialize all requests */
	mutex_lock(&ndev->req_lock);
	/*
	 * Fix CVE-2021-4202
	 *  -1 line, +4 lines
	 */
	if (test_bit(NCI_UP, &ndev->flags))
		rc = (*klpe___nci_request)(ndev, req, opt, timeout);
	else
		rc = -ENETDOWN;
	mutex_unlock(&ndev->req_lock);

	return rc;
}

static void (*klpe_nci_reset_req)(struct nci_dev *ndev, unsigned long opt);

static void (*klpe_nci_init_req)(struct nci_dev *ndev, unsigned long opt);

static void (*klpe_nci_init_complete_req)(struct nci_dev *ndev, unsigned long opt);

struct nci_set_config_param {
	__u8	id;
	size_t	len;
	__u8	*val;
};

static void (*klpe_nci_set_config_req)(struct nci_dev *ndev, unsigned long opt);

struct nci_rf_discover_param {
	__u32	im_protocols;
	__u32	tm_protocols;
};

static void (*klpe_nci_rf_discover_req)(struct nci_dev *ndev, unsigned long opt);

struct nci_rf_discover_select_param {
	__u8	rf_discovery_id;
	__u8	rf_protocol;
};

static void (*klpe_nci_rf_discover_select_req)(struct nci_dev *ndev, unsigned long opt);

static void (*klpe_nci_rf_deactivate_req)(struct nci_dev *ndev, unsigned long opt);

struct nci_loopback_data {
	u8 conn_id;
	struct sk_buff *data;
};

static void (*klpe_nci_send_data_req)(struct nci_dev *ndev, unsigned long opt);

static void (*klpe_nci_nfcc_loopback_cb)(void *context, struct sk_buff *skb, int err);

int klpp_nci_nfcc_loopback(struct nci_dev *ndev, void *data, size_t data_len,
		      struct sk_buff **resp)
{
	int r;
	struct nci_loopback_data loopback_data;
	struct nci_conn_info *conn_info;
	struct sk_buff *skb;
	int conn_id = (*klpe_nci_get_conn_info_by_dest_type_params)(ndev,
					NCI_DESTINATION_NFCC_LOOPBACK, NULL);

	if (conn_id < 0) {
		r = (*klpe_nci_core_conn_create)(ndev, NCI_DESTINATION_NFCC_LOOPBACK,
					 0, 0, NULL);
		if (r != NCI_STATUS_OK)
			return r;

		conn_id = (*klpe_nci_get_conn_info_by_dest_type_params)(ndev,
					NCI_DESTINATION_NFCC_LOOPBACK,
					NULL);
	}

	conn_info = (*klpe_nci_get_conn_info_by_conn_id)(ndev, conn_id);
	if (!conn_info)
		return -EPROTO;

	/* store cb and context to be used on receiving data */
	conn_info->data_exchange_cb = (*klpe_nci_nfcc_loopback_cb);
	conn_info->data_exchange_cb_context = ndev;

	skb = nci_skb_alloc(ndev, NCI_DATA_HDR_SIZE + data_len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, NCI_DATA_HDR_SIZE);
	skb_put_data(skb, data, data_len);

	loopback_data.conn_id = conn_id;
	loopback_data.data = skb;

	ndev->cur_conn_id = conn_id;
	r = klpp_nci_request(ndev, (*klpe_nci_send_data_req), (unsigned long)&loopback_data,
			msecs_to_jiffies(NCI_DATA_TIMEOUT));
	if (r == NCI_STATUS_OK && resp)
		*resp = conn_info->rx_skb;

	return r;
}

static int klpp_nci_open_device(struct nci_dev *ndev)
{
	int rc = 0;

	mutex_lock(&ndev->req_lock);

	/*
	 * Fix CVE-2021-4202
	 *  +4 lines
	 */
	if (test_bit(KLPP_NCI_UNREG, &ndev->flags)) {
		rc = -ENODEV;
		goto done;
	}

	if (test_bit(NCI_UP, &ndev->flags)) {
		rc = -EALREADY;
		goto done;
	}

	if (ndev->ops->open(ndev)) {
		rc = -EIO;
		goto done;
	}

	atomic_set(&ndev->cmd_cnt, 1);

	set_bit(NCI_INIT, &ndev->flags);

	if (ndev->ops->init)
		rc = ndev->ops->init(ndev);

	if (!rc) {
		rc = (*klpe___nci_request)(ndev, (*klpe_nci_reset_req), 0,
				   msecs_to_jiffies(NCI_RESET_TIMEOUT));
	}

	if (!rc && ndev->ops->setup) {
		rc = ndev->ops->setup(ndev);
	}

	if (!rc) {
		rc = (*klpe___nci_request)(ndev, (*klpe_nci_init_req), 0,
				   msecs_to_jiffies(NCI_INIT_TIMEOUT));
	}

	if (!rc && ndev->ops->post_setup)
		rc = ndev->ops->post_setup(ndev);

	if (!rc) {
		rc = (*klpe___nci_request)(ndev, (*klpe_nci_init_complete_req), 0,
				   msecs_to_jiffies(NCI_INIT_TIMEOUT));
	}

	clear_bit(NCI_INIT, &ndev->flags);

	if (!rc) {
		set_bit(NCI_UP, &ndev->flags);
		(*klpe_nci_clear_target_list)(ndev);
		atomic_set(&ndev->state, NCI_IDLE);
	} else {
		/* Init failed, cleanup */
		skb_queue_purge(&ndev->cmd_q);
		skb_queue_purge(&ndev->rx_q);
		skb_queue_purge(&ndev->tx_q);

		ndev->ops->close(ndev);
		ndev->flags = 0;
	}

done:
	mutex_unlock(&ndev->req_lock);
	return rc;
}

int klpp_nci_close_device(struct nci_dev *ndev)
{
	nci_req_cancel(ndev, ENODEV);
	mutex_lock(&ndev->req_lock);

	if (!test_and_clear_bit(NCI_UP, &ndev->flags)) {
		del_timer_sync(&ndev->cmd_timer);
		del_timer_sync(&ndev->data_timer);
		mutex_unlock(&ndev->req_lock);
		return 0;
	}

	/* Drop RX and TX queues */
	skb_queue_purge(&ndev->rx_q);
	skb_queue_purge(&ndev->tx_q);

	/* Flush RX and TX wq */
	flush_workqueue(ndev->rx_wq);
	flush_workqueue(ndev->tx_wq);

	/* Reset device */
	skb_queue_purge(&ndev->cmd_q);
	atomic_set(&ndev->cmd_cnt, 1);

	set_bit(NCI_INIT, &ndev->flags);
	(*klpe___nci_request)(ndev, (*klpe_nci_reset_req), 0,
		      msecs_to_jiffies(NCI_RESET_TIMEOUT));

	/* After this point our queues are empty
	 * and no works are scheduled.
	 */
	ndev->ops->close(ndev);

	clear_bit(NCI_INIT, &ndev->flags);

	del_timer_sync(&ndev->cmd_timer);

	/* Flush cmd wq */
	flush_workqueue(ndev->cmd_wq);

	/*
	 * Fix CVE-2021-4202
	 *  -2 lines, +2 lines
	 */
	/* Clear flags except NCI_UNREG */
	ndev->flags &= BIT(KLPP_NCI_UNREG);

	mutex_unlock(&ndev->req_lock);

	return 0;
}

int klpp_nci_dev_up(struct nfc_dev *nfc_dev)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);

	return klpp_nci_open_device(ndev);
}

static int klpp_nci_set_local_general_bytes(struct nfc_dev *nfc_dev)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);
	struct nci_set_config_param param;
	int rc;

	param.val = (*klpe_nfc_get_local_general_bytes)(nfc_dev, &param.len);
	if ((param.val == NULL) || (param.len == 0))
		return 0;

	if (param.len > NFC_MAX_GT_LEN)
		return -EINVAL;

	param.id = NCI_PN_ATR_REQ_GEN_BYTES;

	rc = klpp_nci_request(ndev, (*klpe_nci_set_config_req), (unsigned long)&param,
			 msecs_to_jiffies(NCI_SET_CONFIG_TIMEOUT));
	if (rc)
		return rc;

	param.id = NCI_LN_ATR_RES_GEN_BYTES;

	return klpp_nci_request(ndev, (*klpe_nci_set_config_req), (unsigned long)&param,
			   msecs_to_jiffies(NCI_SET_CONFIG_TIMEOUT));
}

static int klpr_nci_set_listen_parameters(struct nfc_dev *nfc_dev)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);
	int rc;
	__u8 val;

	val = NCI_LA_SEL_INFO_NFC_DEP_MASK;

	rc = (*klpe_nci_set_config)(ndev, NCI_LA_SEL_INFO, 1, &val);
	if (rc)
		return rc;

	val = NCI_LF_PROTOCOL_TYPE_NFC_DEP_MASK;

	rc = (*klpe_nci_set_config)(ndev, NCI_LF_PROTOCOL_TYPE, 1, &val);
	if (rc)
		return rc;

	val = NCI_LF_CON_BITR_F_212 | NCI_LF_CON_BITR_F_424;

	return (*klpe_nci_set_config)(ndev, NCI_LF_CON_BITR_F, 1, &val);
}

int klpp_nci_start_poll(struct nfc_dev *nfc_dev,
			  __u32 im_protocols, __u32 tm_protocols)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);
	struct nci_rf_discover_param param;
	int rc;

	if ((atomic_read(&ndev->state) == NCI_DISCOVERY) ||
	    (atomic_read(&ndev->state) == NCI_W4_ALL_DISCOVERIES)) {
		pr_err("unable to start poll, since poll is already active\n");
		return -EBUSY;
	}

	if (ndev->target_active_prot) {
		pr_err("there is an active target\n");
		return -EBUSY;
	}

	if ((atomic_read(&ndev->state) == NCI_W4_HOST_SELECT) ||
	    (atomic_read(&ndev->state) == NCI_POLL_ACTIVE)) {
		pr_debug("target active or w4 select, implicitly deactivate\n");

		rc = klpp_nci_request(ndev, (*klpe_nci_rf_deactivate_req),
				 NCI_DEACTIVATE_TYPE_IDLE_MODE,
				 msecs_to_jiffies(NCI_RF_DEACTIVATE_TIMEOUT));
		if (rc)
			return -EBUSY;
	}

	if ((im_protocols | tm_protocols) & NFC_PROTO_NFC_DEP_MASK) {
		rc = klpp_nci_set_local_general_bytes(nfc_dev);
		if (rc) {
			pr_err("failed to set local general bytes\n");
			return rc;
		}
	}

	if (tm_protocols & NFC_PROTO_NFC_DEP_MASK) {
		rc = klpr_nci_set_listen_parameters(nfc_dev);
		if (rc)
			pr_err("failed to set listen parameters\n");
	}

	param.im_protocols = im_protocols;
	param.tm_protocols = tm_protocols;
	rc = klpp_nci_request(ndev, (*klpe_nci_rf_discover_req), (unsigned long)&param,
			 msecs_to_jiffies(NCI_RF_DISC_TIMEOUT));

	if (!rc)
		ndev->poll_prots = im_protocols;

	return rc;
}

void klpp_nci_stop_poll(struct nfc_dev *nfc_dev)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);

	if ((atomic_read(&ndev->state) != NCI_DISCOVERY) &&
	    (atomic_read(&ndev->state) != NCI_W4_ALL_DISCOVERIES)) {
		pr_err("unable to stop poll, since poll is not active\n");
		return;
	}

	klpp_nci_request(ndev, (*klpe_nci_rf_deactivate_req), NCI_DEACTIVATE_TYPE_IDLE_MODE,
		    msecs_to_jiffies(NCI_RF_DEACTIVATE_TIMEOUT));
}

int klpp_nci_activate_target(struct nfc_dev *nfc_dev,
			       struct nfc_target *target, __u32 protocol)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);
	struct nci_rf_discover_select_param param;
	struct nfc_target *nci_target = NULL;
	int i;
	int rc = 0;

	pr_debug("target_idx %d, protocol 0x%x\n", target->idx, protocol);

	if ((atomic_read(&ndev->state) != NCI_W4_HOST_SELECT) &&
	    (atomic_read(&ndev->state) != NCI_POLL_ACTIVE)) {
		pr_err("there is no available target to activate\n");
		return -EINVAL;
	}

	if (ndev->target_active_prot) {
		pr_err("there is already an active target\n");
		return -EBUSY;
	}

	for (i = 0; i < ndev->n_targets; i++) {
		if (ndev->targets[i].idx == target->idx) {
			nci_target = &ndev->targets[i];
			break;
		}
	}

	if (!nci_target) {
		pr_err("unable to find the selected target\n");
		return -EINVAL;
	}

	if (!(nci_target->supported_protocols & (1 << protocol))) {
		pr_err("target does not support the requested protocol 0x%x\n",
		       protocol);
		return -EINVAL;
	}

	if (atomic_read(&ndev->state) == NCI_W4_HOST_SELECT) {
		param.rf_discovery_id = nci_target->logical_idx;

		if (protocol == NFC_PROTO_JEWEL)
			param.rf_protocol = NCI_RF_PROTOCOL_T1T;
		else if (protocol == NFC_PROTO_MIFARE)
			param.rf_protocol = NCI_RF_PROTOCOL_T2T;
		else if (protocol == NFC_PROTO_FELICA)
			param.rf_protocol = NCI_RF_PROTOCOL_T3T;
		else if (protocol == NFC_PROTO_ISO14443 ||
			 protocol == NFC_PROTO_ISO14443_B)
			param.rf_protocol = NCI_RF_PROTOCOL_ISO_DEP;
		else
			param.rf_protocol = NCI_RF_PROTOCOL_NFC_DEP;

		rc = klpp_nci_request(ndev, (*klpe_nci_rf_discover_select_req),
				 (unsigned long)&param,
				 msecs_to_jiffies(NCI_RF_DISC_SELECT_TIMEOUT));
	}

	if (!rc)
		ndev->target_active_prot = protocol;

	return rc;
}

void klpp_nci_deactivate_target(struct nfc_dev *nfc_dev,
				  struct nfc_target *target,
				  __u8 mode)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);
	u8 nci_mode = NCI_DEACTIVATE_TYPE_IDLE_MODE;

	pr_debug("entry\n");

	if (!ndev->target_active_prot) {
		pr_err("unable to deactivate target, no active target\n");
		return;
	}

	ndev->target_active_prot = 0;

	switch (mode) {
	case NFC_TARGET_MODE_SLEEP:
		nci_mode = NCI_DEACTIVATE_TYPE_SLEEP_MODE;
		break;
	}

	if (atomic_read(&ndev->state) == NCI_POLL_ACTIVE) {
		klpp_nci_request(ndev, (*klpe_nci_rf_deactivate_req), nci_mode,
			    msecs_to_jiffies(NCI_RF_DEACTIVATE_TIMEOUT));
	}
}

int klpp_nci_dep_link_down(struct nfc_dev *nfc_dev)
{
	struct nci_dev *ndev = nfc_get_drvdata(nfc_dev);
	int rc;

	pr_debug("entry\n");

	if (nfc_dev->rf_mode == NFC_RF_INITIATOR) {
		klpp_nci_deactivate_target(nfc_dev, NULL, NCI_DEACTIVATE_TYPE_IDLE_MODE);
	} else {
		if (atomic_read(&ndev->state) == NCI_LISTEN_ACTIVE ||
		    atomic_read(&ndev->state) == NCI_DISCOVERY) {
			klpp_nci_request(ndev, (*klpe_nci_rf_deactivate_req), 0,
				msecs_to_jiffies(NCI_RF_DEACTIVATE_TIMEOUT));
		}

		rc = (*klpe_nfc_tm_deactivated)(nfc_dev);
		if (rc)
			pr_err("error when signaling tm deactivation\n");
	}

	return 0;
}

void klpp_nci_unregister_device(struct nci_dev *ndev)
{
	struct nci_conn_info    *conn_info, *n;

	/*
	 * Fix CVE-2021-4202
	 *  + lines
	 */
	/* This set_bit is not protected with specialized barrier,
	 * However, it is fine because the mutex_lock(&ndev->req_lock);
	 * in nci_close_device() will help to emit one.
	 */
	set_bit(KLPP_NCI_UNREG, &ndev->flags);

	klpp_nci_close_device(ndev);

	destroy_workqueue(ndev->cmd_wq);
	destroy_workqueue(ndev->rx_wq);
	destroy_workqueue(ndev->tx_wq);

	list_for_each_entry_safe(conn_info, n, &ndev->conn_info_list, list) {
		list_del(&conn_info->list);
		/* conn_info is allocated with devm_kzalloc */
	}

	klpp_nfc_unregister_device(ndev->nfc_dev);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "bsc1194533_common.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nci"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__nci_request", (void *)&klpe___nci_request, "nci" },
	{ "nci_clear_target_list", (void *)&klpe_nci_clear_target_list, "nci" },
	{ "nci_core_conn_create", (void *)&klpe_nci_core_conn_create, "nci" },
	{ "nci_get_conn_info_by_conn_id",
	  (void *)&klpe_nci_get_conn_info_by_conn_id, "nci" },
	{ "nci_get_conn_info_by_dest_type_params",
	  (void *)&klpe_nci_get_conn_info_by_dest_type_params, "nci" },
	{ "nci_init_complete_req", (void *)&klpe_nci_init_complete_req, "nci" },
	{ "nci_init_req", (void *)&klpe_nci_init_req, "nci" },
	{ "nci_nfcc_loopback_cb", (void *)&klpe_nci_nfcc_loopback_cb, "nci" },
	{ "nci_reset_req", (void *)&klpe_nci_reset_req, "nci" },
	{ "nci_rf_deactivate_req", (void *)&klpe_nci_rf_deactivate_req, "nci" },
	{ "nci_rf_discover_req", (void *)&klpe_nci_rf_discover_req, "nci" },
	{ "nci_rf_discover_select_req",
	  (void *)&klpe_nci_rf_discover_select_req, "nci" },
	{ "nci_send_data_req", (void *)&klpe_nci_send_data_req, "nci" },
	{ "nci_set_config", (void *)&klpe_nci_set_config, "nci" },
	{ "nci_set_config_req", (void *)&klpe_nci_set_config_req, "nci" },
	{ "nfc_get_local_general_bytes",
	  (void *)&klpe_nfc_get_local_general_bytes, "nfc" },
	{ "nfc_tm_deactivated", (void *)&klpe_nfc_tm_deactivated, "nfc" },
};

static int livepatch_bsc1194533_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1194533_module_nb = {
	.notifier_call = livepatch_bsc1194533_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1194533_nci_core_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1194533_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1194533_nci_core_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1194533_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC) */
