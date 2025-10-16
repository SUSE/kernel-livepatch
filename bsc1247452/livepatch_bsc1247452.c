/*
 * livepatch_bsc1247452
 *
 * Fix for CVE-2025-38471, bsc#1247452
 *
 *  Upstream commit:
 *  4ab26bce3969 ("tls: always refresh the queue when reading sock")
 *
 *  SLE12-SP5 commit:
 *  Not affected
 *
 *  SLE15-SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  Not affected
 *
 *  SLE15-SP6 commit:
 *  4468ab0d379c7314a7a674764afdf88e4abee1e3
 *
 *  SLE MICRO-6-0 commit:
 *  4468ab0d379c7314a7a674764afdf88e4abee1e3
 *
 *  Copyright (c) 2025 SUSE
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


/* klp-ccp: from net/tls/tls_strp.c */
#include <linux/skbuff.h>

#include <linux/workqueue.h>
#include <net/strparser.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/tls.h>

/* klp-ccp: from net/tls/tls.h */
#include <asm/byteorder.h>
#include <linux/types.h>

#include <net/tls.h>

int tls_rx_msg_size(struct tls_strparser *strp, struct sk_buff *skb);
void tls_rx_msg_ready(struct tls_strparser *strp);

/* klp-ccp: from net/tls/tls_strp.c */
extern struct workqueue_struct *tls_strp_wq;

static void tls_strp_abort_strp(struct tls_strparser *strp, int err)
{
	if (strp->stopped)
		return;

	strp->stopped = 1;

	/* Report an error on the lower socket */
	WRITE_ONCE(strp->sk->sk_err, -err);
	/* Paired with smp_rmb() in tcp_poll() */
	smp_wmb();
	sk_error_report(strp->sk);
}

extern int tls_strp_copyin(read_descriptor_t *desc, struct sk_buff *in_skb,
			   unsigned int offset, size_t in_len);

static int tls_strp_read_copyin(struct tls_strparser *strp)
{
	read_descriptor_t desc;

	desc.arg.data = strp;
	desc.error = 0;
	desc.count = 1; /* give more than one skb per call */

	/* sk should be locked here, so okay to do read_sock */
	tcp_read_sock(strp->sk, &desc, tls_strp_copyin);

	return desc.error;
}

extern int tls_strp_read_copy(struct tls_strparser *strp, bool qshort);

static bool tls_strp_check_queue_ok(struct tls_strparser *strp)
{
	unsigned int len = strp->stm.offset + strp->stm.full_len;
	struct sk_buff *first, *skb;
	u32 seq;

	first = skb_shinfo(strp->anchor)->frag_list;
	skb = first;
	seq = TCP_SKB_CB(first)->seq;

	/* Make sure there's no duplicate data in the queue,
	 * and the decrypted status matches.
	 */
	while (skb->len < len) {
		seq += skb->len;
		len -= skb->len;
		skb = skb->next;

		if (TCP_SKB_CB(skb)->seq != seq)
			return false;
		if (skb_cmp_decrypted(first, skb))
			return false;
	}

	return true;
}

extern void tls_strp_load_anchor_with_queue(struct tls_strparser *strp, int len);

static int klpp_tls_strp_read_sock(struct tls_strparser *strp)
{
	int sz, inq;

	inq = tcp_inq(strp->sk);
	if (inq < 1)
		return 0;

	if (unlikely(strp->copy_mode))
		return tls_strp_read_copyin(strp);

	if (inq < strp->stm.full_len)
		return tls_strp_read_copy(strp, true);

	tls_strp_load_anchor_with_queue(strp, inq);
	if (!strp->stm.full_len) {
		sz = tls_rx_msg_size(strp, strp->anchor);
		if (sz < 0) {
			tls_strp_abort_strp(strp, sz);
			return sz;
		}

		strp->stm.full_len = sz;

		if (!strp->stm.full_len || inq < strp->stm.full_len)
			return tls_strp_read_copy(strp, true);
	}

	if (!tls_strp_check_queue_ok(strp))
		return tls_strp_read_copy(strp, false);

	strp->msg_ready = 1;
	tls_rx_msg_ready(strp);

	return 0;
}

void klpp_tls_strp_check_rcv(struct tls_strparser *strp)
{
	if (unlikely(strp->stopped) || strp->msg_ready)
		return;

	if (klpp_tls_strp_read_sock(strp) == -ENOMEM)
		queue_work(tls_strp_wq, &strp->work);
}


#include "livepatch_bsc1247452.h"

#include <linux/livepatch.h>

extern typeof(tls_rx_msg_ready) tls_rx_msg_ready
	 KLP_RELOC_SYMBOL(tls, tls, tls_rx_msg_ready);
extern typeof(tls_rx_msg_size) tls_rx_msg_size
	 KLP_RELOC_SYMBOL(tls, tls, tls_rx_msg_size);
extern typeof(tls_strp_copyin) tls_strp_copyin
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_copyin);
extern typeof(tls_strp_load_anchor_with_queue) tls_strp_load_anchor_with_queue
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_load_anchor_with_queue);
extern typeof(tls_strp_read_copy) tls_strp_read_copy
	 KLP_RELOC_SYMBOL(tls, tls, tls_strp_read_copy);
extern typeof(tls_strp_wq) tls_strp_wq KLP_RELOC_SYMBOL(tls, tls, tls_strp_wq);
