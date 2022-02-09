/*
 * livepatch_bsc1194533
 *
 * bsc1194533_nci_core
 *
 * Fix for CVE-2021-4202, bsc#1194533 (net/nfc/nci/hci.c part)
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
#include "bsc1194533_common.h"

/* klp-ccp: from net/nfc/nci/hci.c */
#include <linux/skbuff.h>
/* klp-ccp: from net/nfc/nfc.h */
#include <net/nfc/nfc.h>

/* klp-ccp: from net/nfc/nci/hci.c */
#include <net/nfc/nci.h>
#include <net/nfc/nci_core.h>

/* klp-ccp: from include/net/nfc/nci_core.h */
int klpp_nci_hci_send_cmd(struct nci_dev *ndev, u8 gate,
		     u8 cmd, const u8 *param, size_t param_len,
		     struct sk_buff **skb);
int klpp_nci_hci_open_pipe(struct nci_dev *ndev, u8 pipe);

int klpp_nci_hci_set_param(struct nci_dev *ndev, u8 gate, u8 idx,
		      const u8 *param, size_t param_len);
int klpp_nci_hci_get_param(struct nci_dev *ndev, u8 gate, u8 idx,
		      struct sk_buff **skb);

/* klp-ccp: from net/nfc/nci/hci.c */
#include <linux/nfc.h>

struct nci_data {
	u8              conn_id;
	u8              pipe;
	u8              cmd;
	const u8        *data;
	u32             data_len;
} __packed;

struct nci_hcp_message {
	u8 header;      /* type -cmd,evt,rsp- + instruction */
	u8 data[];
} __packed;

#define NCI_HCI_ANY_SET_PARAMETER  0x01
#define NCI_HCI_ANY_GET_PARAMETER  0x02

#define NCI_HCI_HCP_MESSAGE_HEADER_LEN     1

#define NCI_HCI_HCP_COMMAND        0x00

#define NCI_HCP_HEADER(type, instr) ((((type) & 0x03) << 6) |\
				      ((instr) & 0x3f))

#define NCI_HCP_MSG_GET_CMD(header)  (header & 0x3f)

static int nci_hci_result_to_errno(u8 result)
{
	switch (result) {
	case NCI_HCI_ANY_OK:
		return 0;
	case NCI_HCI_ANY_E_REG_PAR_UNKNOWN:
		return -EOPNOTSUPP;
	case NCI_HCI_ANY_E_TIMEOUT:
		return -ETIME;
	default:
		return -1;
	}
}

static void (*klpe_nci_hci_send_data_req)(struct nci_dev *ndev, unsigned long opt);

int klpp_nci_hci_send_cmd(struct nci_dev *ndev, u8 gate, u8 cmd,
		     const u8 *param, size_t param_len,
		     struct sk_buff **skb)
{
	struct nci_hcp_message *message;
	struct nci_conn_info   *conn_info;
	struct nci_data data;
	int r;
	u8 pipe = ndev->hci_dev->gate2pipe[gate];

	if (pipe == NCI_HCI_INVALID_PIPE)
		return -EADDRNOTAVAIL;

	conn_info = ndev->hci_dev->conn_info;
	if (!conn_info)
		return -EPROTO;

	data.conn_id = conn_info->conn_id;
	data.pipe = pipe;
	data.cmd = NCI_HCP_HEADER(NCI_HCI_HCP_COMMAND, cmd);
	data.data = param;
	data.data_len = param_len;

	r = klpp_nci_request(ndev, (*klpe_nci_hci_send_data_req), (unsigned long)&data,
			msecs_to_jiffies(NCI_DATA_TIMEOUT));
	if (r == NCI_STATUS_OK) {
		message = (struct nci_hcp_message *)conn_info->rx_skb->data;
		r = nci_hci_result_to_errno(
			NCI_HCP_MSG_GET_CMD(message->header));
		skb_pull(conn_info->rx_skb, NCI_HCI_HCP_MESSAGE_HEADER_LEN);

		if (!r && skb)
			*skb = conn_info->rx_skb;
	}

	return r;
}

int klpp_nci_hci_open_pipe(struct nci_dev *ndev, u8 pipe)
{
	struct nci_data data;
	struct nci_conn_info    *conn_info;

	conn_info = ndev->hci_dev->conn_info;
	if (!conn_info)
		return -EPROTO;

	data.conn_id = conn_info->conn_id;
	data.pipe = pipe;
	data.cmd = NCI_HCP_HEADER(NCI_HCI_HCP_COMMAND,
				       NCI_HCI_ANY_OPEN_PIPE);
	data.data = NULL;
	data.data_len = 0;

	return klpp_nci_request(ndev, (*klpe_nci_hci_send_data_req),
			(unsigned long)&data,
			msecs_to_jiffies(NCI_DATA_TIMEOUT));
}

int klpp_nci_hci_set_param(struct nci_dev *ndev, u8 gate, u8 idx,
		      const u8 *param, size_t param_len)
{
	struct nci_hcp_message *message;
	struct nci_conn_info *conn_info;
	struct nci_data data;
	int r;
	u8 *tmp;
	u8 pipe = ndev->hci_dev->gate2pipe[gate];

	pr_debug("idx=%d to gate %d\n", idx, gate);

	if (pipe == NCI_HCI_INVALID_PIPE)
		return -EADDRNOTAVAIL;

	conn_info = ndev->hci_dev->conn_info;
	if (!conn_info)
		return -EPROTO;

	tmp = kmalloc(1 + param_len, GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	*tmp = idx;
	memcpy(tmp + 1, param, param_len);

	data.conn_id = conn_info->conn_id;
	data.pipe = pipe;
	data.cmd = NCI_HCP_HEADER(NCI_HCI_HCP_COMMAND,
				       NCI_HCI_ANY_SET_PARAMETER);
	data.data = tmp;
	data.data_len = param_len + 1;

	r = klpp_nci_request(ndev, (*klpe_nci_hci_send_data_req),
			(unsigned long)&data,
			msecs_to_jiffies(NCI_DATA_TIMEOUT));
	if (r == NCI_STATUS_OK) {
		message = (struct nci_hcp_message *)conn_info->rx_skb->data;
		r = nci_hci_result_to_errno(
			NCI_HCP_MSG_GET_CMD(message->header));
		skb_pull(conn_info->rx_skb, NCI_HCI_HCP_MESSAGE_HEADER_LEN);
	}

	kfree(tmp);
	return r;
}

int klpp_nci_hci_get_param(struct nci_dev *ndev, u8 gate, u8 idx,
		      struct sk_buff **skb)
{
	struct nci_hcp_message *message;
	struct nci_conn_info    *conn_info;
	struct nci_data data;
	int r;
	u8 pipe = ndev->hci_dev->gate2pipe[gate];

	pr_debug("idx=%d to gate %d\n", idx, gate);

	if (pipe == NCI_HCI_INVALID_PIPE)
		return -EADDRNOTAVAIL;

	conn_info = ndev->hci_dev->conn_info;
	if (!conn_info)
		return -EPROTO;

	data.conn_id = conn_info->conn_id;
	data.pipe = pipe;
	data.cmd = NCI_HCP_HEADER(NCI_HCI_HCP_COMMAND,
				  NCI_HCI_ANY_GET_PARAMETER);
	data.data = &idx;
	data.data_len = 1;

	r = klpp_nci_request(ndev, (*klpe_nci_hci_send_data_req), (unsigned long)&data,
			msecs_to_jiffies(NCI_DATA_TIMEOUT));

	if (r == NCI_STATUS_OK) {
		message = (struct nci_hcp_message *)conn_info->rx_skb->data;
		r = nci_hci_result_to_errno(
			NCI_HCP_MSG_GET_CMD(message->header));
		skb_pull(conn_info->rx_skb, NCI_HCI_HCP_MESSAGE_HEADER_LEN);

		if (!r && skb)
			*skb = conn_info->rx_skb;
	}

	return r;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1194533.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "nci"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nci_hci_send_data_req", (void *)&klpe_nci_hci_send_data_req, "nci" },
};

static int livepatch_bsc1194533_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1194533_module_nb = {
	.notifier_call = livepatch_bsc1194533_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1194533_nci_hci_init(void)
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

void livepatch_bsc1194533_nci_hci_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1194533_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC) */
