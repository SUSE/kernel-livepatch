/*
 * livepatch_bsc1274942
 *
 * Fix for CVE-2026-68138, bsc#1274942
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Vincenzo Mezzela <vincenzo.mezzela@suse.com>
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


#include "livepatch_bsc1274942.h"


#define CC_USING_FENTRY 1
/* klp-ccp: from net/sched/sch_api.c */
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

/* klp-ccp: from include/net/pkt_sched.h */
/* klp-ccp: from net/sched/sch_api.c */
#include <net/pkt_cls.h>
#include <net/tc_wrapper.h>
#include <trace/events/qdisc.h>

static __u8 __detect_linklayer(struct tc_ratespec *r, __u32 *rtab)
{
	int low       = roundup(r->mpu, 48);
	int high      = roundup(low+1, 48);
	int cell_low  = low >> r->cell_log;
	int cell_high = (high >> r->cell_log) - 1;

	/* rtab is too inaccurate at rates > 100Mbit/s */
	if ((r->rate > (100000000/8)) || (rtab[0] == 0)) {
		pr_debug("TC linklayer: Giving up ATM detection\n");
		return TC_LINKLAYER_ETHERNET;
	}

	if ((cell_high > cell_low) && (cell_high < 256)
	    && (rtab[cell_low] == rtab[cell_high])) {
		pr_debug("TC linklayer: Detected ATM, low(%d)=high(%d)=%u\n",
			 cell_low, cell_high, rtab[cell_high]);
		return TC_LINKLAYER_ATM;
	}
	return TC_LINKLAYER_ETHERNET;
}

extern struct qdisc_rate_table *qdisc_rtab_list;
static DEFINE_SPINLOCK(qdisc_rtab_lock);

struct qdisc_rate_table *klpp_qdisc_get_rtab(struct tc_ratespec *r,
					struct nlattr *tab,
					struct netlink_ext_ack *extack)
{
	struct qdisc_rate_table *rtab, *new_rtab;

	if (tab == NULL || r->rate == 0 ||
	    r->cell_log == 0 || r->cell_log >= 32 ||
	    nla_len(tab) != TC_RTAB_SIZE) {
		NL_SET_ERR_MSG(extack, "Invalid rate table parameters for searching");
		return NULL;
	}

	new_rtab = kmalloc(sizeof(*rtab), GFP_KERNEL);

	spin_lock(&qdisc_rtab_lock);
	for (rtab = qdisc_rtab_list; rtab; rtab = rtab->next) {
		if (!memcmp(&rtab->rate, r, sizeof(struct tc_ratespec)) &&
		    !memcmp(&rtab->data, nla_data(tab), 1024)) {
			rtab->refcnt++;
			spin_unlock(&qdisc_rtab_lock);
			kfree(new_rtab);
			return rtab;
		}
	}

	rtab = new_rtab;
	if (rtab) {
		rtab->rate = *r;
		rtab->refcnt = 1;
		memcpy(rtab->data, nla_data(tab), 1024);
		if (r->linklayer == TC_LINKLAYER_UNAWARE)
			r->linklayer = __detect_linklayer(r, rtab->data);
		rtab->next = qdisc_rtab_list;
		qdisc_rtab_list = rtab;
	} else {
		NL_SET_ERR_MSG(extack, "Failed to allocate new qdisc rate table");
	}
	spin_unlock(&qdisc_rtab_lock);
	return rtab;
}
void klpp_qdisc_put_rtab(struct qdisc_rate_table *tab)
{
	struct qdisc_rate_table *rtab, **rtabp;

	if (!tab)
		return;

	spin_lock(&qdisc_rtab_lock);
	if (--tab->refcnt) {
		spin_unlock(&qdisc_rtab_lock);
		return;
	}

	for (rtabp = &qdisc_rtab_list;
	     (rtab = *rtabp) != NULL;
	     rtabp = &rtab->next) {
		if (rtab == tab) {
			*rtabp = rtab->next;
			break;
		}
	}
	spin_unlock(&qdisc_rtab_lock);
	kfree(tab);
}



#include <linux/livepatch.h>

extern typeof(qdisc_rtab_list) qdisc_rtab_list
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, qdisc_rtab_list);
