/*
 * livepatch_bsc1199606
 *
 * Fix for CVE-2022-1734, bsc#1199606
 *
 *  Upstream commit:
 *  d270453a0d9e ("nfc: nfcmrvl: main: reorder destructive operations in
 *                 nfcmrvl_nci_unregister_dev to avoid bugs")
 *
 *  SLE12-SP3 commit:
 *  405e1b684119ce28a36e9f4fe9d86ada0870ad17
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d9ccce0ab4df5f74ebfab356ef80cf28010423a3
 *
 *  SLE15-SP2 and -SP3 commit:
 *  48413126a891eafb8f4bf5c18197eb4f5094344f
 *
 *  Copyright (c) 2022 SUSE
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

#if IS_ENABLED(CONFIG_NFC_MRVL)

#if !IS_MODULE(CONFIG_NFC_MRVL)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/nfc/nfcmrvl/main.c */
#include <linux/module.h>
#include <linux/gpio.h>
#include <linux/nfc.h>
#include <net/nfc/nci.h>
#include <net/nfc/nci_core.h>

/* klp-ccp: from include/net/nfc/nci_core.h */
static void (*klpe_nci_free_device)(struct nci_dev *ndev);

static void (*klpe_nci_unregister_device)(struct nci_dev *ndev);

/* klp-ccp: from drivers/nfc/nfcmrvl/nfcmrvl.h */
#include <linux/platform_data/nfcmrvl.h>
/* klp-ccp: from drivers/nfc/nfcmrvl/fw_dnld.h */
#include <linux/workqueue.h>

struct nfcmrvl_private;

struct nfcmrvl_fw_dnld {
	char name[NFC_FIRMWARE_NAME_MAXSIZE + 1];
	const struct firmware *fw;

	const struct nfcmrvl_fw *header;
	const struct nfcmrvl_fw_binary_config *binary_config;

	int state;
	int substate;
	int offset;
	int chunk_len;

	struct workqueue_struct	*rx_wq;
	struct work_struct rx_work;
	struct sk_buff_head rx_q;

	struct timer_list timer;
};

static void (*klpe_nfcmrvl_fw_dnld_deinit)(struct nfcmrvl_private *priv);
static void (*klpe_nfcmrvl_fw_dnld_abort)(struct nfcmrvl_private *priv);

/* klp-ccp: from drivers/nfc/nfcmrvl/nfcmrvl.h */
enum nfcmrvl_phy {
	NFCMRVL_PHY_USB		= 0,
	NFCMRVL_PHY_UART	= 1,
	NFCMRVL_PHY_I2C		= 2,
	NFCMRVL_PHY_SPI		= 3,
};

struct nfcmrvl_private {

	unsigned long flags;

	/* Platform configuration */
	struct nfcmrvl_platform_data config;

	/* Parent dev */
	struct nci_dev *ndev;

	/* FW download context */
	struct nfcmrvl_fw_dnld fw_dnld;

	/* FW download support */
	bool support_fw_dnld;

	/*
	** PHY related information
	*/

	/* PHY driver context */
	void *drv_data;
	/* PHY device */
	struct device *dev;
	/* PHY type */
	enum nfcmrvl_phy phy;
	/* Low level driver ops */
	struct nfcmrvl_if_ops *if_ops;
};

/* klp-ccp: from drivers/nfc/nfcmrvl/main.c */
void klpp_nfcmrvl_nci_unregister_dev(struct nfcmrvl_private *priv)
{
	struct nci_dev *ndev = priv->ndev;

	(*klpe_nci_unregister_device)(ndev);
	if (priv->ndev->nfc_dev->fw_download_in_progress)
		(*klpe_nfcmrvl_fw_dnld_abort)(priv);

	(*klpe_nfcmrvl_fw_dnld_deinit)(priv);

	if (priv->config.reset_n_io)
		gpio_free(priv->config.reset_n_io);

	(*klpe_nci_free_device)(ndev);
	kfree(priv);
}



#define LP_MODULE "nfcmrvl"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1199606.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nci_free_device", (void *)&klpe_nci_free_device, "nci" },
	{ "nci_unregister_device", (void *)&klpe_nci_unregister_device,
	  "nci" },
	{ "nfcmrvl_fw_dnld_abort", (void *)&klpe_nfcmrvl_fw_dnld_abort,
	  "nfcmrvl" },
	{ "nfcmrvl_fw_dnld_deinit", (void *)&klpe_nfcmrvl_fw_dnld_deinit,
	  "nfcmrvl" },
};

static int livepatch_bsc1199606_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1199606_module_nb = {
	.notifier_call = livepatch_bsc1199606_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1199606_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1199606_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1199606_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1199606_module_nb);
}

#endif /* IS_ENABLED(CONFIG_NFC_MRVL) */
