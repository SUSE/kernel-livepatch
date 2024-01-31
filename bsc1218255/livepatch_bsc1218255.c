/*
 * livepatch_bsc1218255
 *
 * Fix for CVE-2023-6932, bsc#1218255
 *
 *  Upstream commit:
 *  e2b706c69190 ("ipv4: igmp: fix refcnt uaf issue when receiving igmp query packet")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  ebe786aae555f323111d69d2eba2a29de1cd21ad
 *
 *  SLE15-SP2 and -SP3 commit:
 *  1240db6049f20cea67dd81fda0a6dd2ba6b06891
 *
 *  SLE15-SP4 and -SP5 commit:
 *  87dfb8486f1eadefd0c9bde4b29710e21cafa174
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

/* klp-ccp: from net/ipv4/igmp.c */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/byteorder/generic.h>
#include <net/net_namespace.h>

/* klp-ccp: from net/ipv4/igmp.c */
#include <net/route.h>
#include <net/sock.h>
#include <net/checksum.h>

#include <linux/seq_file.h>

static void ip_ma_put(struct ip_mc_list *im)
{
	if (atomic_dec_and_test(&im->refcnt)) {
		in_dev_put(im->interface);
		kfree_rcu(im, rcu);
	}
}

void klpp_igmp_start_timer(struct ip_mc_list *im, int max_delay)
{
	int tv = prandom_u32() % max_delay;

	im->tm_running = 1;
	if (atomic_inc_not_zero(&im->refcnt)) {
		if (mod_timer(&im->timer, jiffies + tv + 2))
			ip_ma_put(im);
	}
}

#include "livepatch_bsc1218255.h"
