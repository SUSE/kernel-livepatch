/*
 * livepatch_bsc1195949
 *
 * Fix for CVE-2022-0487, bsc#1195949
 *
 *  Upstream commit:
 *  42933c8aa14b ("memstick: rtsx_usb_ms: fix UAF")
 *
 *  SLE12-SP3 commit:
 *  9dca5583744bbaef9cb59f535fa2123442d70f87
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  9692e2521a5cd2e4186d71355ec936d4c787fd42
 *
 *  SLE15-SP2 and -SP3 commit:
 *  e5d4f2bd865f9456422beaa212b8875c1afa337b
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

#if IS_ENABLED(CONFIG_MEMSTICK_REALTEK_USB)

#if !IS_MODULE(CONFIG_MEMSTICK_REALTEK_USB)
#error "Live patch supports only CONFIG_MEMSTICK_REALTEK_USB=m"
#endif

/* klp-ccp: from drivers/memstick/host/rtsx_usb_ms.c */
#include <linux/module.h>
#include <linux/highmem.h>
#include <linux/platform_device.h>
#include <linux/workqueue.h>
#include <linux/memstick.h>

/* klp-ccp: from include/linux/memstick.h */
static void (*klpe_memstick_remove_host)(struct memstick_host *host);
static void (*klpe_memstick_free_host)(struct memstick_host *host);

static int (*klpe_memstick_next_req)(struct memstick_host *host,
		      struct memstick_request **mrq);

/* klp-ccp: from drivers/memstick/host/rtsx_usb_ms.c */
#include <linux/rtsx_usb.h>
#include <linux/pm_runtime.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/completion.h>

struct rtsx_usb_ms {
	struct platform_device	*pdev;
	struct rtsx_ucr	*ucr;
	struct memstick_host	*msh;
	struct memstick_request	*req;

	struct mutex		host_mutex;
	struct work_struct	handle_req;

	struct task_struct	*detect_ms;
	struct completion	detect_ms_exit;

	u8			ssc_depth;
	unsigned int		clock;
	int			power_mode;
	unsigned char           ifmode;
	bool			eject;
};

static inline struct device *ms_dev(struct rtsx_usb_ms *host)
{
	return &(host->pdev->dev);
}

int klpp_rtsx_usb_ms_drv_remove(struct platform_device *pdev)
{
	struct rtsx_usb_ms *host = platform_get_drvdata(pdev);
	struct memstick_host *msh;
	int err;

	msh = host->msh;
	host->eject = true;
	cancel_work_sync(&host->handle_req);

	mutex_lock(&host->host_mutex);
	if (host->req) {
		dev_dbg(&(pdev->dev),
			"%s: Controller removed during transfer\n",
			dev_name(&msh->dev));
		host->req->error = -ENOMEDIUM;
		do {
			err = (*klpe_memstick_next_req)(msh, &host->req);
			if (!err)
				host->req->error = -ENOMEDIUM;
		} while (!err);
	}
	mutex_unlock(&host->host_mutex);

	wait_for_completion(&host->detect_ms_exit);

	/* Balance possible unbalanced usage count
	 * e.g. unconditional module removal
	 */
	if (pm_runtime_active(ms_dev(host)))
		pm_runtime_put(ms_dev(host));

	pm_runtime_disable(&pdev->dev);

	(*klpe_memstick_remove_host)(msh);
	dev_dbg(&(pdev->dev),
		": Realtek USB Memstick controller has been removed\n");
	(*klpe_memstick_free_host)(msh);
	platform_set_drvdata(pdev, NULL);

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1195949.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "rtsx_usb_ms"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "memstick_free_host", (void *)&klpe_memstick_free_host, "memstick" },
	{ "memstick_next_req", (void *)&klpe_memstick_next_req, "memstick" },
	{ "memstick_remove_host", (void *)&klpe_memstick_remove_host,
	  "memstick" },
};

static int livepatch_bsc1195949_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1195949_module_nb = {
	.notifier_call = livepatch_bsc1195949_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1195949_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1195949_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1195949_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1195949_module_nb);
}

#endif /* IS_ENABLED(CONFIG_MEMSTICK_REALTEK_USB) */
