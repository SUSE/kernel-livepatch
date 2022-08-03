/*
 * livepatch_bsc1200605
 *
 * Fix for CVE-2022-20141, bsc#1200605
 *
 *  Upstream commit:
 *  23d2b94043ca ("igmp: Add ip_mc_list lock in ip_check_mc_rcu")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  5040a6dcd269fa99233cd6e74fbf18de55497939
 *
 *  SLE15-SP2 and -SP3 commit:
 *  34bf46423b3b098c3536f263c2654cac82b02350
 *
 *  SLE15-SP4 commit:
 *  48e5eaa4dddd120424e7dca0e7b66fbfee076274
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

/* klp-ccp: from include/linux/igmp.h */
int klpp_ip_check_mc_rcu(struct in_device *dev, __be32 mc_addr, __be32 src_addr, u8 proto);

/* klp-ccp: from net/ipv4/igmp.c */
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <linux/byteorder/generic.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <net/sock.h>
#include <net/checksum.h>

#ifdef CONFIG_PROC_FS

#include <linux/seq_file.h>
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

#define for_each_pmc_rcu(in_dev, pmc)				\
	for (pmc = rcu_dereference(in_dev->mc_list);		\
	     pmc != NULL;					\
	     pmc = rcu_dereference(pmc->next_rcu))

int klpp_ip_check_mc_rcu(struct in_device *in_dev, __be32 mc_addr, __be32 src_addr, u8 proto)
{
	struct ip_mc_list *im;
	struct ip_mc_list __rcu **mc_hash;
	struct ip_sf_list *psf;
	int rv = 0;

	mc_hash = rcu_dereference(in_dev->mc_hash);
	if (mc_hash) {
		u32 hash = hash_32((__force u32)mc_addr, MC_HASH_SZ_LOG);

		for (im = rcu_dereference(mc_hash[hash]);
		     im != NULL;
		     im = rcu_dereference(im->next_hash)) {
			if (im->multiaddr == mc_addr)
				break;
		}
	} else {
		for_each_pmc_rcu(in_dev, im) {
			if (im->multiaddr == mc_addr)
				break;
		}
	}
	if (im && proto == IPPROTO_IGMP) {
		rv = 1;
	} else if (im) {
		if (src_addr) {
			/*
			 * Fix CVE-2022-20141
			 *  +1 line
			 */
			spin_lock_bh(&im->lock);
			for (psf = im->sources; psf; psf = psf->sf_next) {
				if (psf->sf_inaddr == src_addr)
					break;
			}
			if (psf)
				rv = psf->sf_count[MCAST_INCLUDE] ||
					psf->sf_count[MCAST_EXCLUDE] !=
					im->sfcount[MCAST_EXCLUDE];
			else
				rv = im->sfcount[MCAST_EXCLUDE] != 0;
			/*
			 * Fix CVE-2022-20141
			 *  +1 line
			 */
			spin_unlock_bh(&im->lock);
		} else
			rv = 1; /* unspecified source; tentatively allow */
	}
	return rv;
}



#include "livepatch_bsc1200605.h"
