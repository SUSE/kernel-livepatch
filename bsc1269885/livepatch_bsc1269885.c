/*
 * livepatch_bsc1269885
 *
 * Fix for CVE-2026-53182, bsc#1269885
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

#if IS_ENABLED(CONFIG_CFG80211)

#if !IS_MODULE(CONFIG_CFG80211)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1269885.h"


/* klp-ccp: from net/wireless/nl80211.c */
#include <linux/if.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/ieee80211.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <linux/nospec.h>
#include <linux/etherdevice.h>
#include <linux/if_vlan.h>
#include <net/net_namespace.h>
#include <net/genetlink.h>
#include <net/cfg80211.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>

/* klp-ccp: from net/wireless/core.h */
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/rbtree.h>
#include <linux/debugfs.h>
#include <linux/rfkill.h>
#include <linux/workqueue.h>
#include <linux/rtnetlink.h>
#include <net/genetlink.h>
#include <net/cfg80211.h>

/* klp-ccp: from net/wireless/reg.h */
#include <net/cfg80211.h>

/* klp-ccp: from net/wireless/core.h */
struct cfg80211_registered_device {
	const struct cfg80211_ops *ops;
	struct list_head list;

	/* rfkill support */
	struct rfkill_ops rfkill_ops;
	struct work_struct rfkill_block;

	/* ISO / IEC 3166 alpha2 for which this device is receiving
	 * country IEs on, this can help disregard country IEs from APs
	 * on the same alpha2 quickly. The alpha2 may differ from
	 * cfg80211_regdomain's alpha2 when an intersection has occurred.
	 * If the AP is reconfigured this can also be used to tell us if
	 * the country on the country IE changed. */
	char country_ie_alpha2[2];

	/*
	 * the driver requests the regulatory core to set this regulatory
	 * domain as the wiphy's. Only used for %REGULATORY_WIPHY_SELF_MANAGED
	 * devices using the regulatory_set_wiphy_regd() API
	 */
	const struct ieee80211_regdomain *requested_regd;

	/* If a Country IE has been received this tells us the environment
	 * which its telling us its in. This defaults to ENVIRON_ANY */
	enum environment_cap env;

	/* wiphy index, internal only */
	int wiphy_idx;

	/* protected by RTNL */
	int devlist_generation, wdev_id;
	int opencount;
	wait_queue_head_t dev_wait;

	struct list_head beacon_registrations;
	spinlock_t beacon_registrations_lock;

	/* protected by RTNL only */
	int num_running_ifaces;
	int num_running_monitor_ifaces;
	u64 cookie_counter;

	/* BSSes/scanning */
	spinlock_t bss_lock;
	struct list_head bss_list;
	struct rb_root bss_tree;
	u32 bss_generation;
	u32 bss_entries;
	struct cfg80211_scan_request *scan_req; /* protected by RTNL */
	struct cfg80211_scan_request *int_scan_req;
	struct sk_buff *scan_msg;
	struct list_head sched_scan_req_list;
	time64_t suspend_at;
	struct wiphy_work scan_done_wk;

	struct genl_info *cur_cmd_info;

	struct work_struct conn_work;
	struct work_struct event_work;

	struct delayed_work dfs_update_channels_wk;

	struct wireless_dev *background_radar_wdev;
	struct cfg80211_chan_def background_radar_chandef;
	struct delayed_work background_cac_done_wk;
	struct work_struct background_cac_abort_wk;

	/* netlink port which started critical protocol (0 means not started) */
	u32 crit_proto_nlportid;

	struct cfg80211_coalesce *coalesce;

	struct work_struct destroy_work;
	struct wiphy_work sched_scan_stop_wk;
	struct work_struct sched_scan_res_wk;

	struct cfg80211_chan_def radar_chandef;
	struct work_struct propagate_radar_detect_wk;

	struct cfg80211_chan_def cac_done_chandef;
	struct work_struct propagate_cac_done_wk;

	struct work_struct mgmt_registrations_update_wk;
	/* lock for all wdev lists */
	spinlock_t mgmt_registrations_lock;

	struct work_struct wiphy_work;
	struct list_head wiphy_work_list;
	/* protects the list above */
	spinlock_t wiphy_work_lock;
	bool suspended;

	/* must be last because of the way we do wiphy_priv(),
	 * and it should at least be aligned to NETDEV_ALIGN */
	struct wiphy wiphy __aligned(NETDEV_ALIGN);
};

/* klp-ccp: from net/wireless/rdev-ops.h */
#include <linux/rtnetlink.h>
#include <net/cfg80211.h>

/* klp-ccp: from net/wireless/trace.h */
#if !defined(__RDEV_OPS_TRACE) || defined(TRACE_HEADER_MULTI_READ)

#include <linux/tracepoint.h>

#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <net/cfg80211.h>

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* !__RDEV_OPS_TRACE || TRACE_HEADER_MULTI_READ */

#include <trace/define_trace.h>

/* klp-ccp: from net/wireless/nl80211.c */
extern int validate_ie_attr(const struct nlattr *attr,
			    struct netlink_ext_ack *extack);

extern const struct nla_policy
he_bss_color_policy[NL80211_HE_BSS_COLOR_ATTR_MAX + 1];

static unsigned int nl80211_link_id(struct nlattr **attrs)
{
	struct nlattr *linkid = attrs[NL80211_ATTR_MLO_LINK_ID];

	if (!linkid)
		return 0;

	return nla_get_u8(linkid);
}

static struct cfg80211_mbssid_elems *
nl80211_parse_mbssid_elems(struct wiphy *wiphy, struct nlattr *attrs)
{
	struct nlattr *nl_elems;
	struct cfg80211_mbssid_elems *elems;
	int rem_elems;
	u8 i = 0, num_elems = 0;

	if (!wiphy->mbssid_max_interfaces)
		return ERR_PTR(-EINVAL);

	nla_for_each_nested(nl_elems, attrs, rem_elems) {
		if (num_elems >= 255)
			return ERR_PTR(-EINVAL);
		num_elems++;
	}

	elems = kzalloc(struct_size(elems, elem, num_elems), GFP_KERNEL);
	if (!elems)
		return ERR_PTR(-ENOMEM);
	elems->cnt = num_elems;

	nla_for_each_nested(nl_elems, attrs, rem_elems) {
		elems->elem[i].data = nla_data(nl_elems);
		elems->elem[i].len = nla_len(nl_elems);
		i++;
	}
	return elems;
}

static struct cfg80211_rnr_elems *
klpp_nl80211_parse_rnr_elems(struct wiphy *wiphy, struct nlattr *attrs,
			struct netlink_ext_ack *extack)
{
	struct nlattr *nl_elems;
	struct cfg80211_rnr_elems *elems;
	int rem_elems;
	u8 i = 0, num_elems = 0;

	nla_for_each_nested(nl_elems, attrs, rem_elems) {
		int ret;

		ret = validate_ie_attr(nl_elems, extack);
		if (ret)
			return ERR_PTR(ret);

		if (num_elems >= 255)
			return ERR_PTR(-EINVAL);

		num_elems++;
	}

	elems = kzalloc(struct_size(elems, elem, num_elems), GFP_KERNEL);
	if (!elems)
		return ERR_PTR(-ENOMEM);
	elems->cnt = num_elems;

	nla_for_each_nested(nl_elems, attrs, rem_elems) {
		elems->elem[i].data = nla_data(nl_elems);
		elems->elem[i].len = nla_len(nl_elems);
		i++;
	}
	return elems;
}

static int nl80211_parse_he_bss_color(struct nlattr *attrs,
				      struct cfg80211_he_bss_color *he_bss_color)
{
	struct nlattr *tb[NL80211_HE_BSS_COLOR_ATTR_MAX + 1];
	int err;

	err = nla_parse_nested(tb, NL80211_HE_BSS_COLOR_ATTR_MAX, attrs,
			       he_bss_color_policy, NULL);
	if (err)
		return err;

	if (!tb[NL80211_HE_BSS_COLOR_ATTR_COLOR])
		return -EINVAL;

	he_bss_color->color =
		nla_get_u8(tb[NL80211_HE_BSS_COLOR_ATTR_COLOR]);
	he_bss_color->enabled =
		!nla_get_flag(tb[NL80211_HE_BSS_COLOR_ATTR_DISABLED]);
	he_bss_color->partial =
		nla_get_flag(tb[NL80211_HE_BSS_COLOR_ATTR_PARTIAL]);

	return 0;
}

int klpp_nl80211_parse_beacon(struct cfg80211_registered_device *rdev,
				struct nlattr *attrs[],
				struct cfg80211_beacon_data *bcn,
				struct netlink_ext_ack *extack)
{
	bool haveinfo = false;
	int err;

	memset(bcn, 0, sizeof(*bcn));

	bcn->link_id = nl80211_link_id(attrs);

	if (attrs[NL80211_ATTR_BEACON_HEAD]) {
		bcn->head = nla_data(attrs[NL80211_ATTR_BEACON_HEAD]);
		bcn->head_len = nla_len(attrs[NL80211_ATTR_BEACON_HEAD]);
		if (!bcn->head_len)
			return -EINVAL;
		haveinfo = true;
	}

	if (attrs[NL80211_ATTR_BEACON_TAIL]) {
		bcn->tail = nla_data(attrs[NL80211_ATTR_BEACON_TAIL]);
		bcn->tail_len = nla_len(attrs[NL80211_ATTR_BEACON_TAIL]);
		haveinfo = true;
	}

	if (!haveinfo)
		return -EINVAL;

	if (attrs[NL80211_ATTR_IE]) {
		bcn->beacon_ies = nla_data(attrs[NL80211_ATTR_IE]);
		bcn->beacon_ies_len = nla_len(attrs[NL80211_ATTR_IE]);
	}

	if (attrs[NL80211_ATTR_IE_PROBE_RESP]) {
		bcn->proberesp_ies =
			nla_data(attrs[NL80211_ATTR_IE_PROBE_RESP]);
		bcn->proberesp_ies_len =
			nla_len(attrs[NL80211_ATTR_IE_PROBE_RESP]);
	}

	if (attrs[NL80211_ATTR_IE_ASSOC_RESP]) {
		bcn->assocresp_ies =
			nla_data(attrs[NL80211_ATTR_IE_ASSOC_RESP]);
		bcn->assocresp_ies_len =
			nla_len(attrs[NL80211_ATTR_IE_ASSOC_RESP]);
	}

	if (attrs[NL80211_ATTR_PROBE_RESP]) {
		bcn->probe_resp = nla_data(attrs[NL80211_ATTR_PROBE_RESP]);
		bcn->probe_resp_len = nla_len(attrs[NL80211_ATTR_PROBE_RESP]);
	}

	if (attrs[NL80211_ATTR_FTM_RESPONDER]) {
		struct nlattr *tb[NL80211_FTM_RESP_ATTR_MAX + 1];

		err = nla_parse_nested_deprecated(tb,
						  NL80211_FTM_RESP_ATTR_MAX,
						  attrs[NL80211_ATTR_FTM_RESPONDER],
						  NULL, NULL);
		if (err)
			return err;

		if (tb[NL80211_FTM_RESP_ATTR_ENABLED] &&
		    wiphy_ext_feature_isset(&rdev->wiphy,
					    NL80211_EXT_FEATURE_ENABLE_FTM_RESPONDER))
			bcn->ftm_responder = 1;
		else
			return -EOPNOTSUPP;

		if (tb[NL80211_FTM_RESP_ATTR_LCI]) {
			bcn->lci = nla_data(tb[NL80211_FTM_RESP_ATTR_LCI]);
			bcn->lci_len = nla_len(tb[NL80211_FTM_RESP_ATTR_LCI]);
		}

		if (tb[NL80211_FTM_RESP_ATTR_CIVICLOC]) {
			bcn->civicloc = nla_data(tb[NL80211_FTM_RESP_ATTR_CIVICLOC]);
			bcn->civicloc_len = nla_len(tb[NL80211_FTM_RESP_ATTR_CIVICLOC]);
		}
	} else {
		bcn->ftm_responder = -1;
	}

	if (attrs[NL80211_ATTR_HE_BSS_COLOR]) {
		err = nl80211_parse_he_bss_color(attrs[NL80211_ATTR_HE_BSS_COLOR],
						 &bcn->he_bss_color);
		if (err)
			return err;
		bcn->he_bss_color_valid = true;
	}

	if (attrs[NL80211_ATTR_MBSSID_ELEMS]) {
		struct cfg80211_mbssid_elems *mbssid =
			nl80211_parse_mbssid_elems(&rdev->wiphy,
						   attrs[NL80211_ATTR_MBSSID_ELEMS]);

		if (IS_ERR(mbssid))
			return PTR_ERR(mbssid);

		bcn->mbssid_ies = mbssid;

		if (bcn->mbssid_ies && attrs[NL80211_ATTR_EMA_RNR_ELEMS]) {
			struct cfg80211_rnr_elems *rnr =
				klpp_nl80211_parse_rnr_elems(&rdev->wiphy,
							attrs[NL80211_ATTR_EMA_RNR_ELEMS],
							extack);

			if (IS_ERR(rnr))
				return PTR_ERR(rnr);

			if (rnr && rnr->cnt < bcn->mbssid_ies->cnt)
				return -EINVAL;

			bcn->rnr_ies = rnr;
		}
	}

	return 0;
}


#include <linux/livepatch.h>

extern typeof(he_bss_color_policy) he_bss_color_policy
	 KLP_RELOC_SYMBOL(cfg80211, cfg80211, he_bss_color_policy);
extern typeof(validate_ie_attr) validate_ie_attr
	 KLP_RELOC_SYMBOL(cfg80211, cfg80211, validate_ie_attr);

#endif /* IS_ENABLED(CONFIG_CFG80211) */
