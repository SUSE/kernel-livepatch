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


#include "livepatch_bsc1264078.h"


/* klp-ccp: from drivers/usb/common/ulpi.c */
#include <linux/ulpi/interface.h>

/* klp-ccp: from include/linux/ulpi/interface.h */
struct ulpi *klpp_ulpi_register_interface(struct device *, const struct ulpi_ops *);

/* klp-ccp: from drivers/usb/common/ulpi.c */
#include <linux/ulpi/driver.h>
#include <linux/ulpi/regs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/clk/clk-conf.h>

int ulpi_read(struct ulpi *ulpi, u8 addr);

int ulpi_write(struct ulpi *ulpi, u8 addr, u8 val);

extern const struct bus_type ulpi_bus;

extern const struct device_type ulpi_dev_type;

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

static int ulpi_read_id(struct ulpi *ulpi)
{
	int ret;

	/* Test the interface */
	ret = ulpi_write(ulpi, ULPI_SCRATCH, 0xaa);
	if (ret < 0)
		goto err;

	ret = ulpi_read(ulpi, ULPI_SCRATCH);
	if (ret < 0)
		return ret;

	if (ret != 0xaa)
		goto err;

	ulpi->id.vendor = ulpi_read(ulpi, ULPI_VENDOR_ID_LOW);
	ulpi->id.vendor |= ulpi_read(ulpi, ULPI_VENDOR_ID_HIGH) << 8;

	ulpi->id.product = ulpi_read(ulpi, ULPI_PRODUCT_ID_LOW);
	ulpi->id.product |= ulpi_read(ulpi, ULPI_PRODUCT_ID_HIGH) << 8;

	/* Some ULPI devices don't have a vendor id so rely on OF match */
	if (ulpi->id.vendor == 0)
		goto err;

	request_module("ulpi:v%04xp%04x", ulpi->id.vendor, ulpi->id.product);
	return 0;
err:
	of_request_module(ulpi->dev.of_node);
	return 0;
}

extern const struct file_operations ulpi_regs_fops;

extern struct dentry *ulpi_root;

static int klpp_ulpi_register(struct device *dev, struct ulpi *ulpi)
{
	int ret;
	struct dentry *root;

	ulpi->dev.parent = dev; /* needed early for ops */
	ulpi->dev.bus = &ulpi_bus;
	ulpi->dev.type = &ulpi_dev_type;
	dev_set_name(&ulpi->dev, "%s.ulpi", dev_name(dev));

	ACPI_COMPANION_SET(&ulpi->dev, ACPI_COMPANION(dev));

	ret = ulpi_of_register(ulpi);
	if (ret) {
		kfree(ulpi);
		return ret;
	}

	ret = ulpi_read_id(ulpi);
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

	root = debugfs_create_dir(dev_name(&ulpi->dev), ulpi_root);
	debugfs_create_file("regs", 0444, root, ulpi, &ulpi_regs_fops);

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


#include <linux/livepatch.h>

extern typeof(ulpi_bus) ulpi_bus KLP_RELOC_SYMBOL(ulpi, ulpi, ulpi_bus);
extern typeof(ulpi_dev_type) ulpi_dev_type
	 KLP_RELOC_SYMBOL(ulpi, ulpi, ulpi_dev_type);
extern typeof(ulpi_read) ulpi_read KLP_RELOC_SYMBOL(ulpi, ulpi, ulpi_read);
extern typeof(ulpi_regs_fops) ulpi_regs_fops
	 KLP_RELOC_SYMBOL(ulpi, ulpi, ulpi_regs_fops);
extern typeof(ulpi_root) ulpi_root KLP_RELOC_SYMBOL(ulpi, ulpi, ulpi_root);
extern typeof(ulpi_write) ulpi_write KLP_RELOC_SYMBOL(ulpi, ulpi, ulpi_write);
