/*
 * livepatch_bsc1201656
 *
 * Fix for CVE-2022-26490, bsc#1201656
 *
 *  Upstream commit:
 *  4fbcc1a4cb20 ("nfc: st21nfca: Fix potential buffer overflows in
 *                 EVT_TRANSACTION")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  47ae8c535dd175ee841f2bdbf5b1cb5c52337758
 *
 *  SLE15-SP2 and -SP3 commit:
 *  fd10acefb85f8d9353c73dc55f2891e12dbb6af5
 *
 *  SLE15-SP4 commit:
 *  b6213c46214545d1ba4838fb803cab97c38b2cdc
 *
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

#if IS_ENABLED(CONFIG_NFC_ST21NFCA)

#if !IS_MODULE(CONFIG_NFC_ST21NFCA)
#error "Live patch supports only CONFIG_NFC_ST21NFCA=m"
#endif

/* klp-ccp: from drivers/nfc/st21nfca/se.c */
#include <net/nfc/hci.h>

/* klp-ccp: from include/net/nfc/nfc.h */
static int (*klpe_nfc_se_transaction)(struct nfc_dev *dev, u8 se_idx,
		       struct nfc_evt_transaction *evt_transaction);
static int (*klpe_nfc_se_connectivity)(struct nfc_dev *dev, u8 se_idx);

/* klp-ccp: from drivers/nfc/st21nfca/st21nfca.h */
#include <net/nfc/hci.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

int klpp_st21nfca_connectivity_event_received(struct nfc_hci_dev *hdev, u8 host,
					u8 event, struct sk_buff *skb);

/* klp-ccp: from drivers/nfc/st21nfca/se.c */
#define ST21NFCA_EVT_CONNECTIVITY		0x10
#define ST21NFCA_EVT_TRANSACTION		0x12

int klpp_st21nfca_connectivity_event_received(struct nfc_hci_dev *hdev, u8 host,
				u8 event, struct sk_buff *skb)
{
	int r = 0;
	struct device *dev = &hdev->ndev->dev;
	struct nfc_evt_transaction *transaction;

	pr_debug("connectivity gate event: %x\n", event);

	switch (event) {
	case ST21NFCA_EVT_CONNECTIVITY:
		r = (*klpe_nfc_se_connectivity)(hdev->ndev, host);
	break;
	case ST21NFCA_EVT_TRANSACTION:
		/*
		 * According to specification etsi 102 622
		 * 11.2.2.4 EVT_TRANSACTION Table 52
		 * Description	Tag	Length
		 * AID		81	5 to 16
		 * PARAMETERS	82	0 to 255
		 */
		if (skb->len < NFC_MIN_AID_LENGTH + 2 &&
		    skb->data[0] != NFC_EVT_TRANSACTION_AID_TAG)
			return -EPROTO;

		transaction = (struct nfc_evt_transaction *)devm_kzalloc(dev,
						   skb->len - 2, GFP_KERNEL);
		if (!transaction)
			return -ENOMEM;

		transaction->aid_len = skb->data[1];
		/*
		 * Fix CVE-2022-26490
		 *  +4 lines
		 */
		/* Checking if the length of the AID is valid */
		if (transaction->aid_len > sizeof(transaction->aid))
			return -EINVAL;

		memcpy(transaction->aid, &skb->data[2],
		       transaction->aid_len);

		/* Check next byte is PARAMETERS tag (82) */
		if (skb->data[transaction->aid_len + 2] !=
		    NFC_EVT_TRANSACTION_PARAMS_TAG)
			return -EPROTO;

		transaction->params_len = skb->data[transaction->aid_len + 3];
		/*
		 * Fix CVE-2022-26490
		 *  +4 lines
		 */
		/* Total size is allocated (skb->len - 2) minus fixed array members */
		if (transaction->params_len > ((skb->len - 2) - sizeof(struct nfc_evt_transaction)))
			return -EINVAL;

		memcpy(transaction->params, skb->data +
		       transaction->aid_len + 4, transaction->params_len);

		r = (*klpe_nfc_se_transaction)(hdev->ndev, host, transaction);
	break;
	default:
		nfc_err(&hdev->ndev->dev, "Unexpected event on connectivity gate\n");
		return 1;
	}
	kfree_skb(skb);
	return r;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1201656.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "st21nfca_hci"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nfc_se_connectivity", (void *)&klpe_nfc_se_connectivity, "nfc" },
	{ "nfc_se_transaction", (void *)&klpe_nfc_se_transaction, "nfc" },
};

static int livepatch_bsc1201656_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1201656_module_nb = {
	.notifier_call = livepatch_bsc1201656_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1201656_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1201656_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1201656_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1201656_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC_ST21NFCA) */
