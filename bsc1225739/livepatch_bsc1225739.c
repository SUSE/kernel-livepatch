/*
 * livepatch_bsc1225739
 *
 * Fix for CVE-2024-36899, bsc#1225739
 *
 *  Upstream commit:
 *  02f6b0e1ec7e ("gpiolib: cdev: Fix use after free in lineinfo_changed_notify")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  9b295f50f9fb89f75fd965317ebb0f705e008302
 *
 *  SLE15-SP6 commit:
 *  24144dbc5d98d56514c92ef3ca4e999d2a74d692
 *
 *  Copyright (c) 2024 SUSE
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

#if IS_ENABLED(CONFIG_GPIO_CDEV)

/* klp-ccp: from drivers/gpio/gpiolib-cdev.c */
#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/build_bug.h>
#include <linux/cdev.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/device.h>
#include <linux/err.h>

/* klp-ccp: from include/linux/gpio/consumer.h */
#define __LINUX_GPIO_CONSUMER_H

/* klp-ccp: from drivers/gpio/gpiolib-cdev.c */
#include <linux/gpio/driver.h>
#include <linux/irqreturn.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <uapi/linux/gpio.h>
/* klp-ccp: from drivers/gpio/gpiolib.h */
#include <linux/gpio/driver.h>
#include <linux/gpio/consumer.h> /* for enum gpiod_flags */
#include <linux/err.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/rwsem.h>

struct gpio_device {
	struct device		dev;
	struct cdev		chrdev;
	int			id;
	struct device		*mockdev;
	struct module		*owner;
	struct gpio_chip	*chip;
	struct gpio_desc	*descs;
	int			base;
	u16			ngpio;
	const char		*label;
	void			*data;
	struct list_head        list;
	struct blocking_notifier_head notifier;
	struct rw_semaphore	sem;
#ifdef CONFIG_PINCTRL
	struct list_head pin_ranges;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

/* klp-ccp: from drivers/gpio/gpiolib-cdev.h */
#include <linux/types.h>

/* klp-ccp: from drivers/gpio/gpiolib-cdev.c */
struct gpio_chardev_data {
	struct gpio_device *gdev;
	wait_queue_head_t wait;
	DECLARE_KFIFO(events, struct gpio_v2_line_info_changed, 32);
	struct notifier_block lineinfo_changed_nb;
	unsigned long *watched_lines;
#ifdef CONFIG_GPIO_CDEV_V1
	atomic_t watch_abi_version;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

int klpp_gpio_chrdev_release(struct inode *inode, struct file *file)
{
	struct gpio_chardev_data *cdev = file->private_data;
	struct gpio_device *gdev = cdev->gdev;

	blocking_notifier_chain_unregister(&gdev->notifier,
					   &cdev->lineinfo_changed_nb);
	bitmap_free(cdev->watched_lines);
	gpio_device_put(gdev);
	kfree(cdev);

	return 0;
}

#include "livepatch_bsc1225739.h"

#endif /* IS_ENABLED(CONFIG_GPIO_CDEV) */
