/*
 * livepatch_bsc1250314
 *
 * Fix for CVE-2023-53321, bsc#1250314
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.de>
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

#if IS_ENABLED(CONFIG_MAC80211_HWSIM)

/* klp-ccp: from drivers/net/wireless/mac80211_hwsim.c */
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/dst.h>
#include <net/xfrm.h>
#include <net/mac80211.h>

/* klp-ccp: from include/net/mac80211.h */
static void (*klpe_ieee80211_rx_irqsafe)(struct ieee80211_hw *hw, struct sk_buff *skb);

/* klp-ccp: from drivers/net/wireless/mac80211_hwsim.c */
#include <net/ieee80211_radiotap.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/ktime.h>
#include <net/genetlink.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/rhashtable.h>

/* klp-ccp: from drivers/net/wireless/mac80211_hwsim.h */
enum {
	HWSIM_ATTR_UNSPEC,
	HWSIM_ATTR_ADDR_RECEIVER,
	HWSIM_ATTR_ADDR_TRANSMITTER,
	HWSIM_ATTR_FRAME,
	HWSIM_ATTR_FLAGS,
	HWSIM_ATTR_RX_RATE,
	HWSIM_ATTR_SIGNAL,
	HWSIM_ATTR_TX_INFO,
	HWSIM_ATTR_COOKIE,
	HWSIM_ATTR_CHANNELS,
	HWSIM_ATTR_RADIO_ID,
	HWSIM_ATTR_REG_HINT_ALPHA2,
	HWSIM_ATTR_REG_CUSTOM_REG,
	HWSIM_ATTR_REG_STRICT_REG,
	HWSIM_ATTR_SUPPORT_P2P_DEVICE,
	HWSIM_ATTR_USE_CHANCTX,
	HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE,
	HWSIM_ATTR_RADIO_NAME,
	HWSIM_ATTR_NO_VIF,
	HWSIM_ATTR_FREQ,
	HWSIM_ATTR_PAD,
	HWSIM_ATTR_TX_INFO_FLAGS,
	__HWSIM_ATTR_MAX,
};

/* klp-ccp: from drivers/net/wireless/mac80211_hwsim.c */
static unsigned int (*klpe_hwsim_net_id);

struct hwsim_net {
	int netgroup;
	u32 wmediumd;
};

static inline int klpr_hwsim_net_get_netgroup(struct net *net)
{
	struct hwsim_net *hwsim_net = net_generic(net, (*klpe_hwsim_net_id));

	return hwsim_net->netgroup;
}

static const struct ieee80211_channel hwsim_channels_2ghz[14];

static const struct ieee80211_channel hwsim_channels_5ghz[25];

static const struct ieee80211_rate hwsim_rates[12];

struct mac80211_hwsim_data {
	struct list_head list;
	struct rhash_head rht;
	struct ieee80211_hw *hw;
	struct device *dev;
	struct ieee80211_supported_band bands[NUM_NL80211_BANDS];
	struct ieee80211_channel channels_2ghz[ARRAY_SIZE(hwsim_channels_2ghz)];
	struct ieee80211_channel channels_5ghz[ARRAY_SIZE(hwsim_channels_5ghz)];
	struct ieee80211_rate rates[ARRAY_SIZE(hwsim_rates)];
	struct ieee80211_iface_combination if_combination;

	struct mac_address addresses[2];
	int channels, idx;
	bool use_chanctx;
	bool destroy_on_close;
	u32 portid;
	char alpha2[2];
	const struct ieee80211_regdomain *regd;

	struct ieee80211_channel *tmp_chan;
	struct ieee80211_channel *roc_chan;
	u32 roc_duration;
	struct delayed_work roc_start;
	struct delayed_work roc_done;
	struct delayed_work hw_scan;
	struct cfg80211_scan_request *hw_scan_request;
	struct ieee80211_vif *hw_scan_vif;
	int scan_chan_idx;
	u8 scan_addr[ETH_ALEN];
	struct {
		struct ieee80211_channel *channel;
		unsigned long next_start, start, end;
	} survey_data[ARRAY_SIZE(hwsim_channels_2ghz) +
		      ARRAY_SIZE(hwsim_channels_5ghz)];

	struct ieee80211_channel *channel;
	u64 beacon_int	/* beacon interval in us */;
	unsigned int rx_filter;
	bool started, idle, scanning;
	struct mutex mutex;
	struct tasklet_hrtimer beacon_timer;
	enum ps_mode {
		PS_DISABLED, PS_ENABLED, PS_AUTO_POLL, PS_MANUAL_POLL
	} ps;
	bool ps_poll_pending;
	struct dentry *debugfs;

	uintptr_t pending_cookie;
	struct sk_buff_head pending;	/* packets pending */
	/*
	 * Only radios in the same group can communicate together (the
	 * channel has to match too). Each bit represents a group. A
	 * radio can be in more than one group.
	 */
	u64 group;

	/* group shared by radios created in the same netns */
	int netgroup;
	/* wmediumd portid responsible for netgroup of this radio */
	u32 wmediumd;

	/* difference between this hw's clock and the real clock, in usecs */
	s64 tsf_offset;
	s64 bcn_delta;
	/* absolute beacon transmission time. Used to cover up "tx" delay. */
	u64 abs_bcn_ts;

	/* Stats */
	u64 tx_pkts;
	u64 rx_pkts;
	u64 tx_bytes;
	u64 rx_bytes;
	u64 tx_dropped;
	u64 tx_failed;
};

static struct mac80211_hwsim_data *(*klpe_get_hwsim_data_ref_from_addr)(const u8 *addr);

int klpp_hwsim_cloned_frame_received_nl(struct sk_buff *skb_2,
					struct genl_info *info)
{
	struct mac80211_hwsim_data *data2;
	struct ieee80211_rx_status rx_status;
	const u8 *dst;
	int frame_data_len;
	void *frame_data;
	struct sk_buff *skb = NULL;

	if (!info->attrs[HWSIM_ATTR_ADDR_RECEIVER] ||
	    !info->attrs[HWSIM_ATTR_FRAME] ||
	    !info->attrs[HWSIM_ATTR_RX_RATE] ||
	    !info->attrs[HWSIM_ATTR_SIGNAL])
		goto out;

	dst = (void *)nla_data(info->attrs[HWSIM_ATTR_ADDR_RECEIVER]);
	frame_data_len = nla_len(info->attrs[HWSIM_ATTR_FRAME]);
	frame_data = (void *)nla_data(info->attrs[HWSIM_ATTR_FRAME]);

	if (frame_data_len < sizeof(struct ieee80211_hdr_3addr) ||
	    frame_data_len > IEEE80211_MAX_DATA_LEN)
		goto err;

	/* Allocate new skb here */
	skb = alloc_skb(frame_data_len, GFP_KERNEL);
	if (skb == NULL)
		goto err;

	/* Copy the data */
	skb_put_data(skb, frame_data, frame_data_len);

	data2 = (*klpe_get_hwsim_data_ref_from_addr)(dst);
	if (!data2)
		goto out;

	if (klpr_hwsim_net_get_netgroup(genl_info_net(info)) != data2->netgroup)
		goto out;

	if (info->snd_portid != data2->wmediumd)
		goto out;

	/* check if radio is configured properly */

	if (data2->idle || !data2->started)
		goto out;

	/* A frame is received from user space */
	memset(&rx_status, 0, sizeof(rx_status));
	if (info->attrs[HWSIM_ATTR_FREQ]) {
		/* throw away off-channel packets, but allow both the temporary
		 * ("hw" scan/remain-on-channel) and regular channel, since the
		 * internal datapath also allows this
		 */
		mutex_lock(&data2->mutex);
		rx_status.freq = nla_get_u32(info->attrs[HWSIM_ATTR_FREQ]);

		if (rx_status.freq != data2->channel->center_freq &&
		    (!data2->tmp_chan ||
		     rx_status.freq != data2->tmp_chan->center_freq)) {
			mutex_unlock(&data2->mutex);
			goto out;
		}
		mutex_unlock(&data2->mutex);
	} else {
		rx_status.freq = data2->channel->center_freq;
	}

	rx_status.band = data2->channel->band;
	rx_status.rate_idx = nla_get_u32(info->attrs[HWSIM_ATTR_RX_RATE]);
	rx_status.signal = nla_get_u32(info->attrs[HWSIM_ATTR_SIGNAL]);

	memcpy(IEEE80211_SKB_RXCB(skb), &rx_status, sizeof(rx_status));
	data2->rx_pkts++;
	data2->rx_bytes += skb->len;
	(*klpe_ieee80211_rx_irqsafe)(data2->hw, skb);

	return 0;
err:
	pr_debug("mac80211_hwsim: error occurred in %s\n", __func__);
out:
	dev_kfree_skb(skb);
	return -EINVAL;
}


#include "livepatch_bsc1250314.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "mac80211_hwsim"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "get_hwsim_data_ref_from_addr",
	  (void *)&klpe_get_hwsim_data_ref_from_addr, "mac80211_hwsim" },
	{ "hwsim_net_id", (void *)&klpe_hwsim_net_id, "mac80211_hwsim" },
	{ "ieee80211_rx_irqsafe", (void *)&klpe_ieee80211_rx_irqsafe,
	  "mac80211" },
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

int livepatch_bsc1250314_init(void)
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

void livepatch_bsc1250314_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_MAC80211_HWSIM) */
