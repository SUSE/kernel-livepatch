/*
 * livepatch_bsc1267370
 *
 * Fix for CVE-2026-46116, bsc#1267370
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


#include "livepatch_bsc1267370.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from net/xfrm/xfrm_state.c */
#include <linux/workqueue.h>
#include <net/xfrm.h>

/* klp-ccp: from include/net/xfrm.h */
/* klp-ccp: from net/xfrm/xfrm_state.c */
#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <linux/audit.h>
#include <linux/uaccess.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
/* klp-ccp: from net/xfrm/xfrm_hash.h */
#include <linux/xfrm.h>
#include <linux/socket.h>
#include <linux/jhash.h>

/* klp-ccp: from net/xfrm/xfrm_state.c */
void __xfrm_state_destroy(struct xfrm_state *x);

extern typeof(__xfrm_state_destroy) __xfrm_state_destroy;

int klpp___xfrm_state_delete(struct xfrm_state *x)
{
	struct net *net = xs_net(x);
	int err = -ESRCH;

	if (x->km.state != XFRM_STATE_DEAD) {
		x->km.state = XFRM_STATE_DEAD;
		spin_lock(&net->xfrm.xfrm_state_lock);
		list_del(&x->km.all);
		hlist_del_init_rcu(&x->bydst);
		hlist_del_init_rcu(&x->bysrc);
		if (!hlist_unhashed(&x->byspi))
			hlist_del_init_rcu(&x->byspi);
		net->xfrm.state_num--;
		spin_unlock(&net->xfrm.xfrm_state_lock);

		xfrm_dev_state_delete(x);

		/* All xfrm_state objects are created by xfrm_state_alloc.
		 * The xfrm_state_alloc call gives a reference, and that
		 * is what we are dropping here.
		 */
		xfrm_state_put(x);
		err = 0;
	}

	return err;
}



