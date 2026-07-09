/*
 * livepatch_bsc1263118
 *
 * Fix for CVE-2026-31570, bsc#1263118
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


#include "livepatch_bsc1263118.h"


/* klp-ccp: from net/can/gw.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/can.h>
#include <linux/can/core.h>
#include <linux/can/skb.h>
#include <linux/can/gw.h>
#include <net/rtnetlink.h>
#include <net/net_namespace.h>
#include <net/sock.h>

static inline int calc_idx(int idx, int rx_len)
{
	if (idx < 0)
		return rx_len + idx;
	else
		return idx;
}

void klpp_cgw_csum_crc8_rel(struct canfd_frame *cf,
			      struct cgw_csum_crc8 *crc8)
{
	int from = calc_idx(crc8->from_idx, cf->len);
	int to = calc_idx(crc8->to_idx, cf->len);
	int res = calc_idx(crc8->result_idx, cf->len);
	u8 crc = crc8->init_crc_val;
	int i;

	if (from < 0 || to < 0 || res < 0)
		return;

	if (from <= to) {
		for (i = from; i <= to; i++)
			crc = crc8->crctab[crc ^ cf->data[i]];
	} else {
		for (i = from; i >= to; i--)
			crc = crc8->crctab[crc ^ cf->data[i]];
	}

	switch (crc8->profile) {
	case CGW_CRC8PRF_1U8:
		crc = crc8->crctab[crc ^ crc8->profile_data[0]];
		break;

	case  CGW_CRC8PRF_16U8:
		crc = crc8->crctab[crc ^ crc8->profile_data[cf->data[1] & 0xF]];
		break;

	case CGW_CRC8PRF_SFFID_XOR:
		crc = crc8->crctab[crc ^ (cf->can_id & 0xFF) ^
				   (cf->can_id >> 8 & 0xFF)];
		break;
	}

	cf->data[res] = crc ^ crc8->final_xor_val;
}


