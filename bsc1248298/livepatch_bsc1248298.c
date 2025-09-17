/*
 * livepatch_bsc1248298
 *
 * Fix for CVE-2025-38555, bsc#1248298
 *
 *  Upstream commit:
 *  151c0aa896c4 ("usb: gadget : fix use-after-free in composite_dev_cleanup()")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  d29d36aa8e634808a1ee399f8f614e1c19e99c75
 *
 *  SLE15-SP6 commit:
 *  e4ac187a4b8a3bbcde0c6716cca8f4fbbeb1d9ae
 *
 *  SLE MICRO-6-0 commit:
 *  e4ac187a4b8a3bbcde0c6716cca8f4fbbeb1d9ae
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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

#if IS_ENABLED(CONFIG_USB_LIBCOMPOSITE)

#if !IS_MODULE(CONFIG_USB_LIBCOMPOSITE)
#error "Live patch supports only CONFIG=m"
#endif

#define __KERNEL__ 1
#define MODULE 1
/* klp-ccp: from drivers/usb/gadget/composite.c */
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/device.h>

#include <linux/uuid.h>

#include <linux/usb/composite.h>

/* klp-ccp: from drivers/usb/gadget/composite.c */
#include <linux/usb/webusb.h>

/* klp-ccp: from include/asm-generic/unaligned.h */
#define __ASM_GENERIC_UNALIGNED_H

/* klp-ccp: from drivers/usb/gadget/u_os_desc.h */
#include <asm/unaligned.h>

/* klp-ccp: from drivers/usb/gadget/composite.c */
extern void composite_setup_complete(struct usb_ep *ep, struct usb_request *req);

int klpp_composite_os_desc_req_prepare(struct usb_composite_dev *cdev,
				  struct usb_ep *ep0)
{
	int ret = 0;

	cdev->os_desc_req = usb_ep_alloc_request(ep0, GFP_KERNEL);
	if (!cdev->os_desc_req) {
		ret = -ENOMEM;
		goto end;
	}

	cdev->os_desc_req->buf = kmalloc(USB_COMP_EP0_OS_DESC_BUFSIZ,
					 GFP_KERNEL);
	if (!cdev->os_desc_req->buf) {
		ret = -ENOMEM;
		usb_ep_free_request(ep0, cdev->os_desc_req);
		/*
		 * Set os_desc_req to NULL so that composite_dev_cleanup()
		 * will not try to free it again.
		 */
		cdev->os_desc_req = NULL;
		goto end;
	}
	cdev->os_desc_req->context = cdev;
	cdev->os_desc_req->complete = composite_setup_complete;
end:
	return ret;
}


#include "livepatch_bsc1248298.h"

#include <linux/livepatch.h>

extern typeof(composite_setup_complete) composite_setup_complete
	 KLP_RELOC_SYMBOL(libcomposite, libcomposite, composite_setup_complete);

#endif /* IS_ENABLED(CONFIG_USB_LIBCOMPOSITE) */
