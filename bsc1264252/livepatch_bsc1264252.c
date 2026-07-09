/*
 * livepatch_bsc1264252
 *
 * Fix for CVE-2026-43027, bsc#1264252
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


#include "livepatch_bsc1264252.h"


/* klp-ccp: from net/netfilter/nf_conntrack_helper.c */
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/stddef.h>
#include <linux/random.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/rculist.h>
#include <linux/rtnetlink.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_helper.h>

/* klp-ccp: from include/net/netfilter/nf_conntrack_helper.h */
void klpp_nf_conntrack_helper_unregister(struct nf_conntrack_helper *);

/* klp-ccp: from net/netfilter/nf_conntrack_helper.c */
#include <net/netfilter/nf_conntrack_l4proto.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_log.h>
#include <net/ip.h>

extern struct mutex nf_ct_helper_mutex;

extern unsigned int nf_ct_helper_count __read_mostly;

extern int unhelp(struct nf_conn *ct, void *me);

extern bool expect_iter_me(struct nf_conntrack_expect *exp, void *data);

void klpp_nf_conntrack_helper_unregister(struct nf_conntrack_helper *me)
{
	mutex_lock(&nf_ct_helper_mutex);
	hlist_del_rcu(&me->hnode);
	nf_ct_helper_count--;
	mutex_unlock(&nf_ct_helper_mutex);

	/* Make sure every nothing is still using the helper unless its a
	 * connection in the hash.
	 */
	synchronize_rcu();

	nf_ct_expect_iterate_destroy(expect_iter_me, me);
	nf_ct_iterate_destroy(unhelp, me);
}

typeof(klpp_nf_conntrack_helper_unregister) klpp_nf_conntrack_helper_unregister;


#include <linux/livepatch.h>

extern typeof(expect_iter_me) expect_iter_me
	 KLP_RELOC_SYMBOL(nf_conntrack, nf_conntrack, expect_iter_me);
extern typeof(nf_ct_expect_iterate_destroy) nf_ct_expect_iterate_destroy
	 KLP_RELOC_SYMBOL(nf_conntrack, nf_conntrack, nf_ct_expect_iterate_destroy);
extern typeof(nf_ct_helper_count) nf_ct_helper_count
	 KLP_RELOC_SYMBOL(nf_conntrack, nf_conntrack, nf_ct_helper_count);
extern typeof(nf_ct_helper_mutex) nf_ct_helper_mutex
	 KLP_RELOC_SYMBOL(nf_conntrack, nf_conntrack, nf_ct_helper_mutex);
extern typeof(nf_ct_iterate_destroy) nf_ct_iterate_destroy
	 KLP_RELOC_SYMBOL(nf_conntrack, nf_conntrack, nf_ct_iterate_destroy);
extern typeof(unhelp) unhelp
	 KLP_RELOC_SYMBOL(nf_conntrack, nf_conntrack, unhelp);
