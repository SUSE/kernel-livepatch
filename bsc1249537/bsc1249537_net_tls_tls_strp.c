/*
 * bsc1249537_net_tls_tls_strp
 *
 * Fix for CVE-2025-38616, bsc#1249537
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from net/tls/tls_strp.c */
#include <linux/skbuff.h>
#include <linux/skbuff_ref.h>
#include <linux/workqueue.h>
#include <net/strparser.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/tls.h>
/* klp-ccp: from net/tls/tls.h */
#include <asm/byteorder.h>
#include <linux/types.h>
#include <linux/skmsg.h>
#include <net/tls.h>
#include <net/tls_prot.h>

bool klpp_tls_strp_msg_load(struct tls_strparser *strp, bool force_refresh);

static inline struct tls_msg *tls_msg(struct sk_buff *skb)
{
	struct sk_skb_cb *scb = (struct sk_skb_cb *)skb->cb;

	return &scb->tls;
}

/* klp-ccp: from net/tls/tls_strp.c */
extern void tls_strp_load_anchor_with_queue(struct tls_strparser *strp, int len);

bool klpp_tls_strp_msg_load(struct tls_strparser *strp, bool force_refresh)
{
	struct strp_msg *rxm;
	struct tls_msg *tlm;

	DEBUG_NET_WARN_ON_ONCE(!strp->msg_ready);
	DEBUG_NET_WARN_ON_ONCE(!strp->stm.full_len);

	if (!strp->copy_mode && force_refresh) {
		if (unlikely(tcp_inq(strp->sk) < strp->stm.full_len)) {
			strp->msg_ready = 0;
			memset(&strp->stm, 0, sizeof(strp->stm));
			return false;
		}

		tls_strp_load_anchor_with_queue(strp, strp->stm.full_len);
	}

	rxm = strp_msg(strp->anchor);
	rxm->full_len	= strp->stm.full_len;
	rxm->offset	= strp->stm.offset;
	tlm = tls_msg(strp->anchor);
	tlm->control	= strp->mark;

	return true;
}


#include "livepatch_bsc1249537.h"

#include <linux/livepatch.h>

extern typeof(tls_strp_load_anchor_with_queue) tls_strp_load_anchor_with_queue
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_load_anchor_with_queue);
