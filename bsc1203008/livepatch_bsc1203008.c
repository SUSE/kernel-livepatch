/*
 * livepatch_bsc1203008
 *
 * Fix for CVE-2022-2964, bsc#1203008
 *
 *  Upstream commit:
 *  57bc3d3ae8c1 ("net: usb: ax88179_178a: Fix out-of-bounds accesses in RX fixup")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  95d7e2ccceba77a63799ac0ecc0363151fcbae69
 *
 *  SLE15-SP2 and -SP3 commit:
 *  1580ab2404978f913e9846bb6b255a3be0a351bf
 *
 *  SLE15-SP4 commit:
 *  42429c881e9f439d11c3a98d1b284e44e59cd938
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

#if IS_ENABLED(CONFIG_USB_NET_AX88179_178A)

#if !IS_MODULE(CONFIG_USB_NET_AX88179_178A)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/net/usb/ax88179_178a.c */
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/usb/usbnet.h>

/* klp-ccp: from include/linux/usb/usbnet.h */
static void (*klpe_usbnet_skb_return)(struct usbnet *, struct sk_buff *);

/* klp-ccp: from drivers/net/usb/ax88179_178a.c */
#define AX_RXHDR_L4_TYPE_MASK			0x1c
#define AX_RXHDR_L4_TYPE_UDP			4
#define AX_RXHDR_L4_TYPE_TCP			16
#define AX_RXHDR_L3CSUM_ERR			2
#define AX_RXHDR_L4CSUM_ERR			1
#define AX_RXHDR_CRC_ERR			((u32)BIT(29))
#define AX_RXHDR_DROP_ERR			((u32)BIT(31))

static void
ax88179_rx_checksum(struct sk_buff *skb, u32 *pkt_hdr)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* checksum error bit is set */
	if ((*pkt_hdr & AX_RXHDR_L3CSUM_ERR) ||
	    (*pkt_hdr & AX_RXHDR_L4CSUM_ERR))
		return;

	/* It must be a TCP or UDP packet with a valid checksum */
	if (((*pkt_hdr & AX_RXHDR_L4_TYPE_MASK) == AX_RXHDR_L4_TYPE_TCP) ||
	    ((*pkt_hdr & AX_RXHDR_L4_TYPE_MASK) == AX_RXHDR_L4_TYPE_UDP))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
}

int klpp_ax88179_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	struct sk_buff *ax_skb;
	int pkt_cnt;
	u32 rx_hdr;
	u16 hdr_off;
	u32 *pkt_hdr;

	/* At the end of the SKB, there's a header telling us how many packets
	 * are bundled into this buffer and where we can find an array of
	 * per-packet metadata (which contains elements encoded into u16).
	 */
	if (skb->len < 4)
		return 0;
	skb_trim(skb, skb->len - 4);
	rx_hdr = get_unaligned_le32(skb_tail_pointer(skb));
	pkt_cnt = (u16)rx_hdr;
	hdr_off = (u16)(rx_hdr >> 16);

	if (pkt_cnt == 0)
		return 0;

	/* Make sure that the bounds of the metadata array are inside the SKB
	 * (and in front of the counter at the end).
	 */
	if (pkt_cnt * 2 + hdr_off > skb->len)
		return 0;
	pkt_hdr = (u32 *)(skb->data + hdr_off);

	/* Packets must not overlap the metadata array */
	skb_trim(skb, hdr_off);

	for (; ; pkt_cnt--, pkt_hdr++) {
		u16 pkt_len;

		le32_to_cpus(pkt_hdr);
		pkt_len = (*pkt_hdr >> 16) & 0x1fff;

		if (pkt_len > skb->len)
			return 0;

		/* Check CRC or runt packet */
		if (((*pkt_hdr & (AX_RXHDR_CRC_ERR | AX_RXHDR_DROP_ERR)) == 0) &&
		    pkt_len >= 2 + ETH_HLEN) {
			bool last = (pkt_cnt == 0);

			if (last) {
				ax_skb = skb;
			} else {
				ax_skb = skb_clone(skb, GFP_ATOMIC);
				if (!ax_skb)
					return 0;
			}
			ax_skb->len = pkt_len;
			/* Skip IP alignment pseudo header */
			skb_pull(ax_skb, 2);
			skb_set_tail_pointer(ax_skb, ax_skb->len);
			ax_skb->truesize = pkt_len + sizeof(struct sk_buff);
			ax88179_rx_checksum(ax_skb, pkt_hdr);

			if (last)
				return 1;

			(*klpe_usbnet_skb_return)(dev, ax_skb);
		}

		/* Trim this packet away from the SKB */
		if (!skb_pull(skb, (pkt_len + 7) & 0xFFF8))
			return 0;
	}
}



#define LP_MODULE "ax88179_178a"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1203008.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "usbnet_skb_return", (void *)&klpe_usbnet_skb_return, "usbnet" },
};

static int livepatch_bsc1203008_module_notify(struct notifier_block *nb,
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
	.notifier_call = livepatch_bsc1203008_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1203008_init(void)
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

void livepatch_bsc1203008_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_USB_NET_AX88179_178A) */
