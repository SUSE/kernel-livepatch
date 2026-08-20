/*
 * livepatch_bsc1264078
 *
 * Fix for CVE-2026-31759, bsc#1264078
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_USB_ULPI_BUS)

#if !IS_MODULE(CONFIG_USB_ULPI_BUS)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1264078.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/usb/common/ulpi.c */
#include <linux/ulpi/interface.h>

/* klp-ccp: from include/linux/ulpi/interface.h */
struct ulpi *klpp_ulpi_register_interface(struct device *, const struct ulpi_ops *);

/* klp-ccp: from drivers/usb/common/ulpi.c */
#include <linux/ulpi/driver.h>

/* klp-ccp: from include/linux/ulpi/driver.h */
static int (*klpe_ulpi_read)(struct ulpi *ulpi, u8 addr);
static int (*klpe_ulpi_write)(struct ulpi *ulpi, u8 addr, u8 val);

/* klp-ccp: from drivers/usb/common/ulpi.c */
#include <linux/ulpi/regs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/clk/clk-conf.h>

static struct bus_type (*klpe_ulpi_bus);

static const struct device_type (*klpe_ulpi_dev_type);

static int ulpi_of_register(struct ulpi *ulpi)
{
	struct device_node *np = NULL, *child;
	struct device *parent;

	/* Find a ulpi bus underneath the parent or the grandparent */
	parent = ulpi->dev.parent;
	if (parent->of_node)
		np = of_get_child_by_name(parent->of_node, "ulpi");
	else if (parent->parent && parent->parent->of_node)
		np = of_get_child_by_name(parent->parent->of_node, "ulpi");
	if (!np)
		return 0;

	child = of_get_next_available_child(np, NULL);
	of_node_put(np);
	if (!child)
		return -EINVAL;

	ulpi->dev.of_node = child;

	return 0;
}

static int klpr_ulpi_read_id(struct ulpi *ulpi)
{
	int ret;

	/* Test the interface */
	ret = (*klpe_ulpi_write)(ulpi, ULPI_SCRATCH, 0xaa);
	if (ret < 0)
		goto err;

	ret = (*klpe_ulpi_read)(ulpi, ULPI_SCRATCH);
	if (ret < 0)
		return ret;

	if (ret != 0xaa)
		goto err;

	ulpi->id.vendor = (*klpe_ulpi_read)(ulpi, ULPI_VENDOR_ID_LOW);
	ulpi->id.vendor |= (*klpe_ulpi_read)(ulpi, ULPI_VENDOR_ID_HIGH) << 8;

	ulpi->id.product = (*klpe_ulpi_read)(ulpi, ULPI_PRODUCT_ID_LOW);
	ulpi->id.product |= (*klpe_ulpi_read)(ulpi, ULPI_PRODUCT_ID_HIGH) << 8;

	/* Some ULPI devices don't have a vendor id so rely on OF match */
	if (ulpi->id.vendor == 0)
		goto err;

	request_module("ulpi:v%04xp%04x", ulpi->id.vendor, ulpi->id.product);
	return 0;
err:
	of_device_request_module(&ulpi->dev);
	return 0;
}

static int klpp_ulpi_register(struct device *dev, struct ulpi *ulpi)
{
	int ret;

	ulpi->dev.parent = dev; /* needed early for ops */
	ulpi->dev.bus = &(*klpe_ulpi_bus);
	ulpi->dev.type = &(*klpe_ulpi_dev_type);
	dev_set_name(&ulpi->dev, "%s.ulpi", dev_name(dev));

	ACPI_COMPANION_SET(&ulpi->dev, ACPI_COMPANION(dev));

	ret = ulpi_of_register(ulpi);
	if (ret) {
		kfree(ulpi);
		return ret;
	}

	ret = klpr_ulpi_read_id(ulpi);
	if (ret) {
		of_node_put(ulpi->dev.of_node);
		kfree(ulpi);
		return ret;
	}

	ret = device_register(&ulpi->dev);
	if (ret) {
		put_device(&ulpi->dev);
		return ret;
	}

	dev_dbg(&ulpi->dev, "registered ULPI PHY: vendor %04x, product %04x\n",
		ulpi->id.vendor, ulpi->id.product);

	return 0;
}

struct ulpi *klpp_ulpi_register_interface(struct device *dev,
				     const struct ulpi_ops *ops)
{
	struct ulpi *ulpi;
	int ret;

	ulpi = kzalloc(sizeof(*ulpi), GFP_KERNEL);
	if (!ulpi)
		return ERR_PTR(-ENOMEM);

	ulpi->ops = ops;

	ret = klpp_ulpi_register(dev, ulpi);
	if (ret)
		return ERR_PTR(ret);
	return ulpi;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ulpi"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ulpi_bus", (void *)&klpe_ulpi_bus, "ulpi" },
	{ "ulpi_dev_type", (void *)&klpe_ulpi_dev_type, "ulpi" },
	{ "ulpi_read", (void *)&klpe_ulpi_read, "ulpi" },
	{ "ulpi_write", (void *)&klpe_ulpi_write, "ulpi" },
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

int livepatch_bsc1264078_init(void)
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

void livepatch_bsc1264078_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_USB_ULPI_BUS) */
