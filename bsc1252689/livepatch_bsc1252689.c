/*
 * livepatch_bsc1252689
 *
 * Fix for CVE-2025-40018, bsc#1252689
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

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>

#include <linux/gfp.h>

#include <net/ip_vs.h>

#include "livepatch_bsc1252689.h"

extern struct ip_vs_app ip_vs_ftp;
extern struct module klpe_ip_vs_ftp_mod;

void klpp___ip_vs_ftp_exit(struct net *net)
{
	struct netns_ipvs *ipvs = net_ipvs(net);

	if (!ipvs || module_is_live(&klpe_ip_vs_ftp_mod))
		return;

	unregister_ip_vs_app(ipvs, &ip_vs_ftp);
}

#include <linux/livepatch.h>

extern typeof(ip_vs_ftp) ip_vs_ftp
	 KLP_RELOC_SYMBOL(ip_vs_ftp, ip_vs_ftp, ip_vs_ftp);
extern typeof(unregister_ip_vs_app) unregister_ip_vs_app
	 KLP_RELOC_SYMBOL(ip_vs_ftp, ip_vs, unregister_ip_vs_app);
extern struct module klpe_ip_vs_ftp_mod KLP_RELOC_SYMBOL(ip_vs_ftp, ip_vs_ftp, __this_module);
