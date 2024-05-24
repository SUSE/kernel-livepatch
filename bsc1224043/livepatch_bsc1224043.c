/*
 * livepatch_bsc1224043
 *
 * Fix for CVE-2022-48687, bsc#1224043
 *
 *  Upstream commit:
 *  84a53580c5d2 ("ipv6: sr: fix out-of-bounds read when setting HMAC data.")
 *
 *  SLE12-SP5 commit:
 *  b97c30d716c13ca4c9d962d2786c3305255732cc
 *
 *  SLE15-SP2 and -SP3 commit:
 *  f37c1a1b999569ee9c9c50d4bf9b3c32bb4873b7
 *
 *  SLE15-SP4 and -SP5 commit:
 *  5a240f0ca6e940ae33f8883c10b82b9d10e2b703
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from net/ipv6/seg6.c */
#include <linux/errno.h>
#include <linux/types.h>

/* klp-ccp: from net/ipv6/seg6.c */
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <net/ipv6.h>
#include <net/seg6.h>
#include <net/genetlink.h>
#include <linux/seg6.h>
#include <linux/seg6_genl.h>
#include <net/seg6_hmac.h>

int klpp_seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct seg6_pernet_data *sdata;
	struct seg6_hmac_info *hinfo;
	u32 hmackeyid;
	char *secret;
	int err = 0;
	u8 algid;
	u8 slen;

	sdata = seg6_pernet(net);

	if (!info->attrs[SEG6_ATTR_HMACKEYID] ||
	    !info->attrs[SEG6_ATTR_SECRETLEN] ||
	    !info->attrs[SEG6_ATTR_ALGID])
		return -EINVAL;

	hmackeyid = nla_get_u32(info->attrs[SEG6_ATTR_HMACKEYID]);
	slen = nla_get_u8(info->attrs[SEG6_ATTR_SECRETLEN]);
	algid = nla_get_u8(info->attrs[SEG6_ATTR_ALGID]);

	if (hmackeyid == 0)
		return -EINVAL;

	if (slen > SEG6_HMAC_SECRET_LEN)
		return -EINVAL;

	mutex_lock(&sdata->lock);
	hinfo = seg6_hmac_info_lookup(net, hmackeyid);

	if (!slen) {
		err = seg6_hmac_info_del(net, hmackeyid);

		goto out_unlock;
	}

	if (!info->attrs[SEG6_ATTR_SECRET]) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (slen > nla_len(info->attrs[SEG6_ATTR_SECRET])) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (hinfo) {
		err = seg6_hmac_info_del(net, hmackeyid);
		if (err)
			goto out_unlock;
	}

	secret = (char *)nla_data(info->attrs[SEG6_ATTR_SECRET]);

	hinfo = kzalloc(sizeof(*hinfo), GFP_KERNEL);
	if (!hinfo) {
		err = -ENOMEM;
		goto out_unlock;
	}

	memcpy(hinfo->secret, secret, slen);
	hinfo->slen = slen;
	hinfo->alg_id = algid;
	hinfo->hmackeyid = hmackeyid;

	err = seg6_hmac_info_add(net, hmackeyid, hinfo);
	if (err)
		kfree(hinfo);

out_unlock:
	mutex_unlock(&sdata->lock);
	return err;
}

#include "livepatch_bsc1224043.h"
