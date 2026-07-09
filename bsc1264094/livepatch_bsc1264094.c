/*
 * livepatch_bsc1264094
 *
 * Fix for CVE-2026-31758, bsc#1264094
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_USB_TMC)

#if !IS_MODULE(CONFIG_USB_TMC)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1264094.h"


/* klp-ccp: from drivers/usb/class/usbtmc.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/usb.h>
#include <linux/compat.h>
#include <linux/usb/tmc.h>

struct usbtmc_dev_capabilities {
	__u8 interface_capabilities;
	__u8 device_capabilities;
	__u8 usb488_interface_capabilities;
	__u8 usb488_device_capabilities;
};

struct usbtmc_device_data {
	const struct usb_device_id *id;
	struct usb_device *usb_dev;
	struct usb_interface *intf;
	struct list_head file_list;

	unsigned int bulk_in;
	unsigned int bulk_out;

	u8 bTag;
	u8 bTag_last_write;	/* needed for abort */
	u8 bTag_last_read;	/* needed for abort */

	/* packet size of IN bulk */
	u16            wMaxPacketSize;

	/* data for interrupt in endpoint handling */
	u8             bNotify1;
	u8             bNotify2;
	u16            ifnum;
	u8             iin_bTag;
	u8            *iin_buffer;
	atomic_t       iin_data_valid;
	unsigned int   iin_ep;
	int            iin_ep_present;
	int            iin_interval;
	struct urb    *iin_urb;
	u16            iin_wMaxPacketSize;

	/* coalesced usb488_caps from usbtmc_dev_capabilities */
	__u8 usb488_caps;

	bool zombie; /* fd of disconnected device */

	struct usbtmc_dev_capabilities	capabilities;
	struct kref kref;
	struct mutex io_mutex;	/* only one i/o function running at a time */
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	spinlock_t dev_lock; /* lock for file_list */
};

struct usbtmc_file_data {
	struct usbtmc_device_data *data;
	struct list_head file_elem;

	u32            timeout;
	u8             srq_byte;
	atomic_t       srq_asserted;
	atomic_t       closing;
	u8             bmTransferAttributes; /* member of DEV_DEP_MSG_IN */

	u8             eom_val;
	u8             term_char;
	bool           term_char_enabled;
	bool           auto_abort;

	spinlock_t     err_lock; /* lock for errors */

	struct usb_anchor submitted;

	/* data for generic_write */
	struct semaphore limit_write_sem;
	u32 out_transfer_size;
	int out_status;

	/* data for generic_read */
	u32 in_transfer_size;
	int in_status;
	int in_urbs_used;
	struct usb_anchor in_anchor;
	wait_queue_head_t wait_bulk_in;
};

extern void usbtmc_draw_down(struct usbtmc_file_data *file_data);

extern void usbtmc_delete(struct kref *kref);

int klpp_usbtmc_release(struct inode *inode, struct file *file)
{
	struct usbtmc_file_data *file_data = file->private_data;

	/* prevent IO _AND_ usbtmc_interrupt */
	mutex_lock(&file_data->data->io_mutex);
	spin_lock_irq(&file_data->data->dev_lock);

	list_del(&file_data->file_elem);

	spin_unlock_irq(&file_data->data->dev_lock);

	/* flush anchored URBs */
	usbtmc_draw_down(file_data);
	mutex_unlock(&file_data->data->io_mutex);

	kref_put(&file_data->data->kref, usbtmc_delete);
	file_data->data = NULL;
	kfree(file_data);
	return 0;
}

void usbtmc_draw_down(struct usbtmc_file_data *file_data);


#include <linux/livepatch.h>

extern typeof(usbtmc_delete) usbtmc_delete
	 KLP_RELOC_SYMBOL(usbtmc, usbtmc, usbtmc_delete);
extern typeof(usbtmc_draw_down) usbtmc_draw_down
	 KLP_RELOC_SYMBOL(usbtmc, usbtmc, usbtmc_draw_down);

#endif /* IS_ENABLED(CONFIG_USB_TMC) */
