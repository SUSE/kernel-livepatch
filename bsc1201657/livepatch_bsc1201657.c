/*
 * livepatch_bsc1201657
 *
 * Fix for CVE-2022-28389, bsc#1201657
 *
 *  Upstream commit:
 *  04c9b00ba835 ("can: mcba_usb: mcba_usb_start_xmit(): fix double
 *                 dev_kfree_skb in error path")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  2396928e2a666d2f910eb79c329f5a8b0ca7410d
 *
 *  SLE15-SP2 and -SP3 commit:
 *  d6e6523e8387414baae1fa88f68ab75bd2967eb0
 *
 *  SLE15-SP4 commit:
 *  fbe952a8eb1507b07559641adedc33e89686b1c4
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

#if IS_ENABLED(CONFIG_CAN_MCBA_USB)

#if !IS_MODULE(CONFIG_CAN_MCBA_USB)
#error "Live patch supports only CONFIG_CAN_MCBA_USB=m"
#endif

/* klp-ccp: from drivers/net/can/usb/mcba_usb.c */
#include <asm/unaligned.h>
#include <linux/can.h>
#include <linux/can/dev.h>

/* klp-ccp: from include/linux/can/dev.h */
static void (*klpe_can_put_echo_skb)(struct sk_buff *skb, struct net_device *dev,
		      unsigned int idx);

static void (*klpe_can_free_echo_skb)(struct net_device *dev, unsigned int idx);

/* klp-ccp: from drivers/net/can/usb/mcba_usb.c */
#include <linux/can/error.h>
#include <linux/can/led.h>
#include <linux/netdevice.h>
#include <linux/slab.h>
#include <linux/usb.h>

#define MCBA_MAX_RX_URBS 20
#define MCBA_MAX_TX_URBS 20
#define MCBA_CTX_FREE MCBA_MAX_TX_URBS

#define MBCA_CMD_TRANSMIT_MESSAGE_EV 0xA3

#define MCBA_SIDL_EXID_MASK 0x8

#define MCBA_DLC_RTR_MASK 0x40

struct mcba_usb_ctx {
	struct mcba_priv *priv;
	u32 ndx;
	u8 dlc;
	bool can;
};

struct mcba_priv {
	struct can_priv can; /* must be the first member */
	struct sk_buff *echo_skb[MCBA_MAX_TX_URBS];
	struct mcba_usb_ctx tx_context[MCBA_MAX_TX_URBS];
	struct usb_device *udev;
	struct net_device *netdev;
	struct usb_anchor tx_submitted;
	struct usb_anchor rx_submitted;
	struct can_berr_counter bec;
	bool usb_ka_first_pass;
	bool can_ka_first_pass;
	bool can_speed_check;
	atomic_t free_ctx_cnt;
	void *rxbuf[MCBA_MAX_RX_URBS];
	dma_addr_t rxbuf_dma[MCBA_MAX_RX_URBS];
};

struct __packed mcba_usb_msg_can {
	u8 cmd_id;
	__be16 eid;
	__be16 sid;
	u8 dlc;
	u8 data[8];
	u8 timestamp[4];
	u8 checksum;
};

struct mcba_usb_msg;

static inline struct mcba_usb_ctx *mcba_usb_get_free_ctx(struct mcba_priv *priv,
							 struct can_frame *cf)
{
	int i = 0;
	struct mcba_usb_ctx *ctx = NULL;

	for (i = 0; i < MCBA_MAX_TX_URBS; i++) {
		if (priv->tx_context[i].ndx == MCBA_CTX_FREE) {
			ctx = &priv->tx_context[i];
			ctx->ndx = i;

			if (cf) {
				ctx->can = true;
				ctx->dlc = cf->can_dlc;
			} else {
				ctx->can = false;
				ctx->dlc = 0;
			}

			atomic_dec(&priv->free_ctx_cnt);
			break;
		}
	}

	if (!atomic_read(&priv->free_ctx_cnt))
		/* That was the last free ctx. Slow down tx path */
		netif_stop_queue(priv->netdev);

	return ctx;
}

static inline void mcba_usb_free_ctx(struct mcba_usb_ctx *ctx)
{
	/* Increase number of free ctxs before freeing ctx */
	atomic_inc(&ctx->priv->free_ctx_cnt);

	ctx->ndx = MCBA_CTX_FREE;

	/* Wake up the queue once ctx is marked free */
	netif_wake_queue(ctx->priv->netdev);
}

static netdev_tx_t (*klpe_mcba_usb_xmit)(struct mcba_priv *priv,
				 struct mcba_usb_msg *usb_msg,
				 struct mcba_usb_ctx *ctx);

netdev_tx_t klpp_mcba_usb_start_xmit(struct sk_buff *skb,
				       struct net_device *netdev)
{
	struct mcba_priv *priv = netdev_priv(netdev);
	struct can_frame *cf = (struct can_frame *)skb->data;
	struct mcba_usb_ctx *ctx = NULL;
	struct net_device_stats *stats = &priv->netdev->stats;
	u16 sid;
	int err;
	struct mcba_usb_msg_can usb_msg = {
		.cmd_id = MBCA_CMD_TRANSMIT_MESSAGE_EV
	};

	if (can_dropped_invalid_skb(netdev, skb))
		return NETDEV_TX_OK;

	ctx = mcba_usb_get_free_ctx(priv, cf);
	if (!ctx)
		return NETDEV_TX_BUSY;

	if (cf->can_id & CAN_EFF_FLAG) {
		/* SIDH    | SIDL                 | EIDH   | EIDL
		 * 28 - 21 | 20 19 18 x x x 17 16 | 15 - 8 | 7 - 0
		 */
		sid = MCBA_SIDL_EXID_MASK;
		/* store 28-18 bits */
		sid |= (cf->can_id & 0x1ffc0000) >> 13;
		/* store 17-16 bits */
		sid |= (cf->can_id & 0x30000) >> 16;
		put_unaligned_be16(sid, &usb_msg.sid);

		/* store 15-0 bits */
		put_unaligned_be16(cf->can_id & 0xffff, &usb_msg.eid);
	} else {
		/* SIDH   | SIDL
		 * 10 - 3 | 2 1 0 x x x x x
		 */
		put_unaligned_be16((cf->can_id & CAN_SFF_MASK) << 5,
				   &usb_msg.sid);
		usb_msg.eid = 0;
	}

	usb_msg.dlc = cf->can_dlc;

	memcpy(usb_msg.data, cf->data, usb_msg.dlc);

	if (cf->can_id & CAN_RTR_FLAG)
		usb_msg.dlc |= MCBA_DLC_RTR_MASK;

	(*klpe_can_put_echo_skb)(skb, priv->netdev, ctx->ndx);

	err = (*klpe_mcba_usb_xmit)(priv, (struct mcba_usb_msg *)&usb_msg, ctx);
	if (err)
		goto xmit_failed;

	return NETDEV_TX_OK;

xmit_failed:
	(*klpe_can_free_echo_skb)(priv->netdev, ctx->ndx);
	mcba_usb_free_ctx(ctx);
	/*
	 * Fix CVE-2022-28389
	 *  -1 line
	 */

	stats->tx_dropped++;

	return NETDEV_TX_OK;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1201657.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "mcba_usb"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "can_free_echo_skb", (void *)&klpe_can_free_echo_skb, "can_dev" },
	{ "can_put_echo_skb", (void *)&klpe_can_put_echo_skb, "can_dev" },
	{ "mcba_usb_xmit", (void *)&klpe_mcba_usb_xmit, "mcba_usb" },
};

static int livepatch_bsc1201657_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1201657_module_nb = {
	.notifier_call = livepatch_bsc1201657_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1201657_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1201657_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1201657_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1201657_module_nb);
}

#endif /* IS_ENABLED(CONFIG_CAN_MCBA_USB) */
