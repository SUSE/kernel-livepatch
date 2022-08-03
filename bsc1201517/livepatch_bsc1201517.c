/*
 * livepatch_bsc1201517
 *
 * Fix for CVE-2022-28390, bsc#1201517
 *
 *  Upstream commit:
 *  c70222752228 ("can: ems_usb: ems_usb_start_xmit(): fix double
 *                 dev_kfree_skb() in error path")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  004fa7cbe5ac2b59c8364bbe8fd2c004c8230b6f
 *
 *  SLE15-SP2 and -SP3 commit:
 *  9a351e62f809d81aae7693f0715191aac5d61f2b
 *
 *  SLE15-SP4 commit:
 *  25171b06883b27b9417a6b7d18d43dfa7eeef290
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

#if IS_ENABLED(CONFIG_CAN_EMS_USB)

#if !IS_MODULE(CONFIG_CAN_EMS_USB)
#error "Live patch supports only CONFIG_CAN_EMS_USB=m"
#endif

/* klp-ccp: from drivers/net/can/usb/ems_usb.c */
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/usb.h>

/* klp-ccp: from include/linux/usb.h */
static struct urb *(*klpe_usb_alloc_urb)(int iso_packets, gfp_t mem_flags);
static void (*klpe_usb_free_urb)(struct urb *urb);

static int (*klpe_usb_submit_urb)(struct urb *urb, gfp_t mem_flags);

static void (*klpe_usb_anchor_urb)(struct urb *urb, struct usb_anchor *anchor);
static void (*klpe_usb_unanchor_urb)(struct urb *urb);

static void *(*klpe_usb_alloc_coherent)(struct usb_device *dev, size_t size,
	gfp_t mem_flags, dma_addr_t *dma);
static void (*klpe_usb_free_coherent)(struct usb_device *dev, size_t size,
	void *addr, dma_addr_t dma);

/* klp-ccp: from drivers/net/can/usb/ems_usb.c */
#include <linux/can.h>
#include <linux/can/dev.h>

/* klp-ccp: from include/linux/can/dev.h */
static void (*klpe_can_put_echo_skb)(struct sk_buff *skb, struct net_device *dev,
		      unsigned int idx);

static void (*klpe_can_free_echo_skb)(struct net_device *dev, unsigned int idx);

/* klp-ccp: from drivers/net/can/usb/ems_usb.c */
#include <linux/can/error.h>

#define CPC_CMD_TYPE_CAN_FRAME     1   /* CAN data frame */

#define CPC_CMD_TYPE_RTR_FRAME     13  /* CAN remote frame */

#define CPC_CMD_TYPE_EXT_CAN_FRAME 15  /* Extended CAN data frame */
#define CPC_CMD_TYPE_EXT_RTR_FRAME 16  /* Extended CAN remote frame */

#define CPC_MSG_HEADER_LEN   11
#define CPC_CAN_MSG_MIN_SIZE 5

#define CPC_TX_QUEUE_TRIGGER_LOW	25

struct cpc_can_msg {
	__le32 id;
	u8 length;
	u8 msg[8];
};

struct cpc_sja1000_params {
	u8 mode;
	u8 acc_code0;
	u8 acc_code1;
	u8 acc_code2;
	u8 acc_code3;
	u8 acc_mask0;
	u8 acc_mask1;
	u8 acc_mask2;
	u8 acc_mask3;
	u8 btr0;
	u8 btr1;
	u8 outp_contr;
};

struct cpc_can_params {
	u8 cc_type;

	/* Will support M16C CAN controller in the future */
	union {
		struct cpc_sja1000_params sja1000;
	} cc_params;
};

struct cpc_confirm {
	u8 error; /* error code */
};

struct cpc_overrun {
	u8 event;
	u8 count;
};

struct cpc_sja1000_can_error {
	u8 ecc;
	u8 rxerr;
	u8 txerr;
};

struct cpc_can_error {
	u8 ecode;

	struct {
		u8 cc_type;

		/* Other controllers may also provide error code capture regs */
		union {
			struct cpc_sja1000_can_error sja1000;
		} regs;
	} cc;
};

struct cpc_can_err_counter {
	u8 rx;
	u8 tx;
};

struct __packed ems_cpc_msg {
	u8 type;	/* type of message */
	u8 length;	/* length of data within union 'msg' */
	u8 msgid;	/* confirmation handle */
	__le32 ts_sec;	/* timestamp in seconds */
	__le32 ts_nsec;	/* timestamp in nano seconds */

	union {
		u8 generic[64];
		struct cpc_can_msg can_msg;
		struct cpc_can_params can_params;
		struct cpc_confirm confirmation;
		struct cpc_overrun overrun;
		struct cpc_can_error error;
		struct cpc_can_err_counter err_counter;
		u8 can_state;
	} msg;
};

#define CPC_HEADER_SIZE     4

#define MAX_RX_URBS 10
#define MAX_TX_URBS 10

struct ems_tx_urb_context {
	struct ems_usb *dev;

	u32 echo_index;
	u8 dlc;
};

struct ems_usb {
	struct can_priv can; /* must be the first member */

	struct sk_buff *echo_skb[MAX_TX_URBS];

	struct usb_device *udev;
	struct net_device *netdev;

	atomic_t active_tx_urbs;
	struct usb_anchor tx_submitted;
	struct ems_tx_urb_context tx_contexts[MAX_TX_URBS];

	struct usb_anchor rx_submitted;

	struct urb *intr_urb;

	u8 *tx_msg_buffer;

	u8 *intr_in_buffer;
	unsigned int free_slots; /* remember number of available slots */

	struct ems_cpc_msg active_params; /* active controller parameters */
	void *rxbuf[MAX_RX_URBS];
	dma_addr_t rxbuf_dma[MAX_RX_URBS];
};

static void (*klpe_ems_usb_write_bulk_callback)(struct urb *urb);

netdev_tx_t klpp_ems_usb_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct ems_usb *dev = netdev_priv(netdev);
	struct ems_tx_urb_context *context = NULL;
	struct net_device_stats *stats = &netdev->stats;
	struct can_frame *cf = (struct can_frame *)skb->data;
	struct ems_cpc_msg *msg;
	struct urb *urb;
	u8 *buf;
	int i, err;
	size_t size = CPC_HEADER_SIZE + CPC_MSG_HEADER_LEN
			+ sizeof(struct cpc_can_msg);

	if (can_dropped_invalid_skb(netdev, skb))
		return NETDEV_TX_OK;

	/* create a URB, and a buffer for it, and copy the data to the URB */
	urb = (*klpe_usb_alloc_urb)(0, GFP_ATOMIC);
	if (!urb)
		goto nomem;

	buf = (*klpe_usb_alloc_coherent)(dev->udev, size, GFP_ATOMIC, &urb->transfer_dma);
	if (!buf) {
		netdev_err(netdev, "No memory left for USB buffer\n");
		(*klpe_usb_free_urb)(urb);
		goto nomem;
	}

	msg = (struct ems_cpc_msg *)&buf[CPC_HEADER_SIZE];

	msg->msg.can_msg.id = cpu_to_le32(cf->can_id & CAN_ERR_MASK);
	msg->msg.can_msg.length = cf->can_dlc;

	if (cf->can_id & CAN_RTR_FLAG) {
		msg->type = cf->can_id & CAN_EFF_FLAG ?
			CPC_CMD_TYPE_EXT_RTR_FRAME : CPC_CMD_TYPE_RTR_FRAME;

		msg->length = CPC_CAN_MSG_MIN_SIZE;
	} else {
		msg->type = cf->can_id & CAN_EFF_FLAG ?
			CPC_CMD_TYPE_EXT_CAN_FRAME : CPC_CMD_TYPE_CAN_FRAME;

		for (i = 0; i < cf->can_dlc; i++)
			msg->msg.can_msg.msg[i] = cf->data[i];

		msg->length = CPC_CAN_MSG_MIN_SIZE + cf->can_dlc;
	}

	for (i = 0; i < MAX_TX_URBS; i++) {
		if (dev->tx_contexts[i].echo_index == MAX_TX_URBS) {
			context = &dev->tx_contexts[i];
			break;
		}
	}

	/*
	 * May never happen! When this happens we'd more URBs in flight as
	 * allowed (MAX_TX_URBS).
	 */
	if (!context) {
		(*klpe_usb_free_coherent)(dev->udev, size, buf, urb->transfer_dma);
		(*klpe_usb_free_urb)(urb);

		netdev_warn(netdev, "couldn't find free context\n");

		return NETDEV_TX_BUSY;
	}

	context->dev = dev;
	context->echo_index = i;
	context->dlc = cf->can_dlc;

	usb_fill_bulk_urb(urb, dev->udev, usb_sndbulkpipe(dev->udev, 2), buf,
			  size, (*klpe_ems_usb_write_bulk_callback), context);
	urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	(*klpe_usb_anchor_urb)(urb, &dev->tx_submitted);

	(*klpe_can_put_echo_skb)(skb, netdev, context->echo_index);

	atomic_inc(&dev->active_tx_urbs);

	err = (*klpe_usb_submit_urb)(urb, GFP_ATOMIC);
	if (unlikely(err)) {
		(*klpe_can_free_echo_skb)(netdev, context->echo_index);

		(*klpe_usb_unanchor_urb)(urb);
		(*klpe_usb_free_coherent)(dev->udev, size, buf, urb->transfer_dma);
		/*
		 * Fix CVE-2022-28390
		 *  -1 line
		 */

		atomic_dec(&dev->active_tx_urbs);

		if (err == -ENODEV) {
			netif_device_detach(netdev);
		} else {
			netdev_warn(netdev, "failed tx_urb %d\n", err);

			stats->tx_dropped++;
		}
	} else {
		netif_trans_update(netdev);

		/* Slow down tx path */
		if (atomic_read(&dev->active_tx_urbs) >= MAX_TX_URBS ||
		    dev->free_slots < CPC_TX_QUEUE_TRIGGER_LOW) {
			netif_stop_queue(netdev);
		}
	}

	/*
	 * Release our reference to this URB, the USB core will eventually free
	 * it entirely.
	 */
	(*klpe_usb_free_urb)(urb);

	return NETDEV_TX_OK;

nomem:
	dev_kfree_skb(skb);
	stats->tx_dropped++;

	return NETDEV_TX_OK;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1201517.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "ems_usb"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "can_free_echo_skb", (void *)&klpe_can_free_echo_skb, "can_dev" },
	{ "can_put_echo_skb", (void *)&klpe_can_put_echo_skb, "can_dev" },
	{ "ems_usb_write_bulk_callback",
	  (void *)&klpe_ems_usb_write_bulk_callback, "ems_usb" },
	{ "usb_alloc_coherent", (void *)&klpe_usb_alloc_coherent, "usbcore" },
	{ "usb_alloc_urb", (void *)&klpe_usb_alloc_urb, "usbcore" },
	{ "usb_anchor_urb", (void *)&klpe_usb_anchor_urb, "usbcore" },
	{ "usb_free_coherent", (void *)&klpe_usb_free_coherent, "usbcore" },
	{ "usb_free_urb", (void *)&klpe_usb_free_urb, "usbcore" },
	{ "usb_submit_urb", (void *)&klpe_usb_submit_urb, "usbcore" },
	{ "usb_unanchor_urb", (void *)&klpe_usb_unanchor_urb, "usbcore" },
};

static int livepatch_bsc1201517_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1201517_module_nb = {
	.notifier_call = livepatch_bsc1201517_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1201517_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1201517_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1201517_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1201517_module_nb);
}

#endif /* IS_ENABLED(CONFIG_CAN_EMS_USB) */
