/*
 * livepatch_bsc1206314
 *
 * Fix for CVE-2022-3564, bsc#1206314
 *
 *  Upstream commit:
 *  3aff8aaca4e3 ("Bluetooth: L2CAP: Fix use-after-free caused by l2cap_reassemble_sdu")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  d5fc0df99053394b7087fe513fa7608f92481a48
 *
 *  SLE15-SP2 and -SP3 commit:
 *  549579376fde1eeb5e030f07a2743368ab2ad5fd
 *
 *  SLE15-SP4 commit:
 *  7d5149c5b47a861c4bcd62110188cb8168fba499
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_BT)

#if !IS_MODULE(CONFIG_BT)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <linux/module.h>
#include <linux/debugfs.h>

/* klp-ccp: from include/linux/crc16.h */
static u16 (*klpe_crc16)(u16 crc, const u8 *buffer, size_t len);

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <linux/filter.h>
#include <net/bluetooth/bluetooth.h>

/* klp-ccp: from include/net/bluetooth/bluetooth.h */
static __printf(1, 2)
void (*klpe_bt_err)(const char *fmt, ...);

/* klp-ccp: from net/bluetooth/l2cap_core.c */
#include <net/bluetooth/l2cap.h>

/* klp-ccp: from include/net/bluetooth/l2cap.h */
static void (*klpe_l2cap_chan_hold)(struct l2cap_chan *c);
static void (*klpe_l2cap_chan_put)(struct l2cap_chan *c);

static inline void klpr_l2cap_set_timer(struct l2cap_chan *chan,
				   struct delayed_work *work, long timeout)
{
	BT_DBG("chan %p state %s timeout %ld", chan,
	       state_to_string(chan->state), timeout);

	/* If delayed work cancelled do not hold(chan)
	   since it is already done with previous set_timer */
	if (!cancel_delayed_work(work))
		(*klpe_l2cap_chan_hold)(chan);

	schedule_delayed_work(work, timeout);
}

static inline bool klpr_l2cap_clear_timer(struct l2cap_chan *chan,
				     struct delayed_work *work)
{
	bool ret;

	/* put(chan) if delayed work cancelled otherwise it
	   is done in delayed work function */
	ret = cancel_delayed_work(work);
	if (ret)
		(*klpe_l2cap_chan_put)(chan);

	return ret;
}

/* klp-ccp: from net/bluetooth/a2mp.h */
#include <net/bluetooth/l2cap.h>

#if IS_ENABLED(CONFIG_BT_HS)

static struct l2cap_chan *(*klpe_a2mp_channel_create)(struct l2cap_conn *conn,
				       struct sk_buff *skb);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from net/bluetooth/l2cap_core.c */
static void (*klpe_l2cap_send_disconn_req)(struct l2cap_chan *chan, int err);

static struct l2cap_chan *(*klpe_l2cap_get_chan_by_scid)(struct l2cap_conn *conn,
						 u16 cid);

static void klpr___set_retrans_timer(struct l2cap_chan *chan)
{
	if (!delayed_work_pending(&chan->monitor_timer) &&
	    chan->retrans_timeout) {
		klpr_l2cap_set_timer(chan, &chan->retrans_timer,
				msecs_to_jiffies(chan->retrans_timeout));
	}
}

static void l2cap_seq_list_clear(struct l2cap_seq_list *seq_list)
{
	u16 i;

	if (seq_list->head == L2CAP_SEQ_LIST_CLEAR)
		return;

	for (i = 0; i <= seq_list->mask; i++)
		seq_list->list[i] = L2CAP_SEQ_LIST_CLEAR;

	seq_list->head = L2CAP_SEQ_LIST_CLEAR;
	seq_list->tail = L2CAP_SEQ_LIST_CLEAR;
}

static bool __chan_is_moving(struct l2cap_chan *chan)
{
	return chan->move_state != L2CAP_MOVE_STABLE &&
	       chan->move_state != L2CAP_MOVE_WAIT_PREPARE;
}

static void __unpack_enhanced_control(u16 enh, struct l2cap_ctrl *control)
{
	control->reqseq = (enh & L2CAP_CTRL_REQSEQ) >> L2CAP_CTRL_REQSEQ_SHIFT;
	control->final = (enh & L2CAP_CTRL_FINAL) >> L2CAP_CTRL_FINAL_SHIFT;

	if (enh & L2CAP_CTRL_FRAME_TYPE) {
		/* S-Frame */
		control->sframe = 1;
		control->poll = (enh & L2CAP_CTRL_POLL) >> L2CAP_CTRL_POLL_SHIFT;
		control->super = (enh & L2CAP_CTRL_SUPERVISE) >> L2CAP_CTRL_SUPER_SHIFT;

		control->sar = 0;
		control->txseq = 0;
	} else {
		/* I-Frame */
		control->sframe = 0;
		control->sar = (enh & L2CAP_CTRL_SAR) >> L2CAP_CTRL_SAR_SHIFT;
		control->txseq = (enh & L2CAP_CTRL_TXSEQ) >> L2CAP_CTRL_TXSEQ_SHIFT;

		control->poll = 0;
		control->super = 0;
	}
}

static void __unpack_extended_control(u32 ext, struct l2cap_ctrl *control)
{
	control->reqseq = (ext & L2CAP_EXT_CTRL_REQSEQ) >> L2CAP_EXT_CTRL_REQSEQ_SHIFT;
	control->final = (ext & L2CAP_EXT_CTRL_FINAL) >> L2CAP_EXT_CTRL_FINAL_SHIFT;

	if (ext & L2CAP_EXT_CTRL_FRAME_TYPE) {
		/* S-Frame */
		control->sframe = 1;
		control->poll = (ext & L2CAP_EXT_CTRL_POLL) >> L2CAP_EXT_CTRL_POLL_SHIFT;
		control->super = (ext & L2CAP_EXT_CTRL_SUPERVISE) >> L2CAP_EXT_CTRL_SUPER_SHIFT;

		control->sar = 0;
		control->txseq = 0;
	} else {
		/* I-Frame */
		control->sframe = 0;
		control->sar = (ext & L2CAP_EXT_CTRL_SAR) >> L2CAP_EXT_CTRL_SAR_SHIFT;
		control->txseq = (ext & L2CAP_EXT_CTRL_TXSEQ) >> L2CAP_EXT_CTRL_TXSEQ_SHIFT;

		control->poll = 0;
		control->super = 0;
	}
}

static inline void __unpack_control(struct l2cap_chan *chan,
				    struct sk_buff *skb)
{
	if (test_bit(FLAG_EXT_CTRL, &chan->flags)) {
		__unpack_extended_control(get_unaligned_le32(skb->data),
					  &bt_cb(skb)->l2cap);
		skb_pull(skb, L2CAP_EXT_CTRL_SIZE);
	} else {
		__unpack_enhanced_control(get_unaligned_le16(skb->data),
					  &bt_cb(skb)->l2cap);
		skb_pull(skb, L2CAP_ENH_CTRL_SIZE);
	}
}

static void (*klpe_l2cap_send_rr_or_rnr)(struct l2cap_chan *chan, bool poll);

static void klpr_l2cap_chan_ready(struct l2cap_chan *chan)
{
	/* The channel may have already been flagged as connected in
	 * case of receiving data before the L2CAP info req/rsp
	 * procedure is complete.
	 */
	if (chan->state == BT_CONNECTED)
		return;

	/* This clears all conf flags, including CONF_NOT_COMPLETE */
	chan->conf_state = 0;
	klpr_l2cap_clear_timer(chan, &chan->chan_timer);

	if (chan->mode == L2CAP_MODE_LE_FLOWCTL && !chan->tx_credits)
		chan->ops->suspend(chan);

	chan->state = BT_CONNECTED;

	chan->ops->ready(chan);
}

static void (*klpe_l2cap_send_disconn_req)(struct l2cap_chan *chan, int err);

static int (*klpe_l2cap_ertm_send)(struct l2cap_chan *chan);

static void (*klpe_l2cap_retransmit_all)(struct l2cap_chan *chan,
				 struct l2cap_ctrl *control);

static void (*klpe_l2cap_send_ack)(struct l2cap_chan *chan);

static void (*klpe_l2cap_send_srej)(struct l2cap_chan *chan, u16 txseq);

static void (*klpe_l2cap_pass_to_tx)(struct l2cap_chan *chan,
			     struct l2cap_ctrl *control);

static int klpr_l2cap_check_fcs(struct l2cap_chan *chan,  struct sk_buff *skb)
{
	u16 our_fcs, rcv_fcs;
	int hdr_size;

	if (test_bit(FLAG_EXT_CTRL, &chan->flags))
		hdr_size = L2CAP_EXT_HDR_SIZE;
	else
		hdr_size = L2CAP_ENH_HDR_SIZE;

	if (chan->fcs == L2CAP_FCS_CRC16) {
		skb_trim(skb, skb->len - L2CAP_FCS_SIZE);
		rcv_fcs = get_unaligned_le16(skb->data + skb->len);
		our_fcs = (*klpe_crc16)(0, skb->data - hdr_size, skb->len + hdr_size);

		if (our_fcs != rcv_fcs)
			return -EBADMSG;
	}
	return 0;
}

static void (*klpe_l2cap_send_i_or_rr_or_rnr)(struct l2cap_chan *chan);

static void (*klpe_append_skb_frag)(struct sk_buff *skb, struct sk_buff *new_frag,
			    struct sk_buff **last_frag);

static int (*klpe_l2cap_reassemble_sdu)(struct l2cap_chan *chan, struct sk_buff *skb,
				struct l2cap_ctrl *control);

static void (*klpe_l2cap_handle_srej)(struct l2cap_chan *chan,
			      struct l2cap_ctrl *control);

static void (*klpe_l2cap_handle_rej)(struct l2cap_chan *chan,
			     struct l2cap_ctrl *control);

static u8 (*klpe_l2cap_classify_txseq)(struct l2cap_chan *chan, u16 txseq);

int klpp_l2cap_rx_state_recv(struct l2cap_chan *chan,
			       struct l2cap_ctrl *control,
			       struct sk_buff *skb, u8 event)
{
	struct l2cap_ctrl local_control;
	int err = 0;
	bool skb_in_use = false;

	BT_DBG("chan %p, control %p, skb %p, event %d", chan, control, skb,
	       event);

	switch (event) {
	case L2CAP_EV_RECV_IFRAME:
		switch ((*klpe_l2cap_classify_txseq)(chan, control->txseq)) {
		case L2CAP_TXSEQ_EXPECTED:
			(*klpe_l2cap_pass_to_tx)(chan, control);

			if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
				BT_DBG("Busy, discarding expected seq %d",
				       control->txseq);
				break;
			}

			chan->expected_tx_seq = __next_seq(chan,
							   control->txseq);

			chan->buffer_seq = chan->expected_tx_seq;
			skb_in_use = true;

			/* l2cap_reassemble_sdu may free skb, hence invalidate
			 * control, so make a copy in advance to use it after
			 * l2cap_reassemble_sdu returns and to avoid the race
			 * condition, for example:
			 *
			 * The current thread calls:
			 *   l2cap_reassemble_sdu
			 *     chan->ops->recv == l2cap_sock_recv_cb
			 *       __sock_queue_rcv_skb
			 * Another thread calls:
			 *   bt_sock_recvmsg
			 *     skb_recv_datagram
			 *     skb_free_datagram
			 * Then the current thread tries to access control, but
			 * it was freed by skb_free_datagram.
			 */
			local_control = *control;
			err = (*klpe_l2cap_reassemble_sdu)(chan, skb, control);
			if (err)
				break;

			if (local_control.final) {
				if (!test_and_clear_bit(CONN_REJ_ACT,
							&chan->conn_state)) {
					local_control.final = 0;
					(*klpe_l2cap_retransmit_all)(chan, &local_control);
					(*klpe_l2cap_ertm_send)(chan);
				}
			}

			if (!test_bit(CONN_LOCAL_BUSY, &chan->conn_state))
				(*klpe_l2cap_send_ack)(chan);
			break;
		case L2CAP_TXSEQ_UNEXPECTED:
			(*klpe_l2cap_pass_to_tx)(chan, control);

			/* Can't issue SREJ frames in the local busy state.
			 * Drop this frame, it will be seen as missing
			 * when local busy is exited.
			 */
			if (test_bit(CONN_LOCAL_BUSY, &chan->conn_state)) {
				BT_DBG("Busy, discarding unexpected seq %d",
				       control->txseq);
				break;
			}

			/* There was a gap in the sequence, so an SREJ
			 * must be sent for each missing frame.  The
			 * current frame is stored for later use.
			 */
			skb_queue_tail(&chan->srej_q, skb);
			skb_in_use = true;
			BT_DBG("Queued %p (queue len %d)", skb,
			       skb_queue_len(&chan->srej_q));

			clear_bit(CONN_SREJ_ACT, &chan->conn_state);
			l2cap_seq_list_clear(&chan->srej_list);
			(*klpe_l2cap_send_srej)(chan, control->txseq);

			chan->rx_state = L2CAP_RX_STATE_SREJ_SENT;
			break;
		case L2CAP_TXSEQ_DUPLICATE:
			(*klpe_l2cap_pass_to_tx)(chan, control);
			break;
		case L2CAP_TXSEQ_INVALID_IGNORE:
			break;
		case L2CAP_TXSEQ_INVALID:
		default:
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
			break;
		}
		break;
	case L2CAP_EV_RECV_RR:
		(*klpe_l2cap_pass_to_tx)(chan, control);
		if (control->final) {
			clear_bit(CONN_REMOTE_BUSY, &chan->conn_state);

			if (!test_and_clear_bit(CONN_REJ_ACT, &chan->conn_state) &&
			    !__chan_is_moving(chan)) {
				control->final = 0;
				(*klpe_l2cap_retransmit_all)(chan, control);
			}

			(*klpe_l2cap_ertm_send)(chan);
		} else if (control->poll) {
			(*klpe_l2cap_send_i_or_rr_or_rnr)(chan);
		} else {
			if (test_and_clear_bit(CONN_REMOTE_BUSY,
					       &chan->conn_state) &&
			    chan->unacked_frames)
				klpr___set_retrans_timer(chan);

			(*klpe_l2cap_ertm_send)(chan);
		}
		break;
	case L2CAP_EV_RECV_RNR:
		set_bit(CONN_REMOTE_BUSY, &chan->conn_state);
		(*klpe_l2cap_pass_to_tx)(chan, control);
		if (control && control->poll) {
			set_bit(CONN_SEND_FBIT, &chan->conn_state);
			(*klpe_l2cap_send_rr_or_rnr)(chan, 0);
		}
		klpr_l2cap_clear_timer(chan, &chan->retrans_timer);
		l2cap_seq_list_clear(&chan->retrans_list);
		break;
	case L2CAP_EV_RECV_REJ:
		(*klpe_l2cap_handle_rej)(chan, control);
		break;
	case L2CAP_EV_RECV_SREJ:
		(*klpe_l2cap_handle_srej)(chan, control);
		break;
	default:
		break;
	}

	if (skb && !skb_in_use) {
		BT_DBG("Freeing %p", skb);
		kfree_skb(skb);
	}

	return err;
}

static int (*klpe_l2cap_rx)(struct l2cap_chan *chan, struct l2cap_ctrl *control,
		    struct sk_buff *skb, u8 event);

static int klpr_l2cap_stream_rx(struct l2cap_chan *chan, struct l2cap_ctrl *control,
			   struct sk_buff *skb)
{
	/* l2cap_reassemble_sdu may free skb, hence invalidate control, so store
	 * the txseq field in advance to use it after l2cap_reassemble_sdu
	 * returns and to avoid the race condition, for example:
	 *
	 * The current thread calls:
	 *   l2cap_reassemble_sdu
	 *     chan->ops->recv == l2cap_sock_recv_cb
	 *       __sock_queue_rcv_skb
	 * Another thread calls:
	 *   bt_sock_recvmsg
	 *     skb_recv_datagram
	 *     skb_free_datagram
	 * Then the current thread tries to access control, but it was freed by
	 * skb_free_datagram.
	 */
	u16 txseq = control->txseq;

	BT_DBG("chan %p, control %p, skb %p, state %d", chan, control, skb,
	       chan->rx_state);

	if ((*klpe_l2cap_classify_txseq)(chan, txseq) == L2CAP_TXSEQ_EXPECTED) {
		(*klpe_l2cap_pass_to_tx)(chan, control);

		BT_DBG("buffer_seq %d->%d", chan->buffer_seq,
		       __next_seq(chan, chan->buffer_seq));

		chan->buffer_seq = __next_seq(chan, chan->buffer_seq);

		(*klpe_l2cap_reassemble_sdu)(chan, skb, control);
	} else {
		if (chan->sdu) {
			kfree_skb(chan->sdu);
			chan->sdu = NULL;
		}
		chan->sdu_last_frag = NULL;
		chan->sdu_len = 0;

		if (skb) {
			BT_DBG("Freeing %p", skb);
			kfree_skb(skb);
		}
	}

	chan->last_acked_seq = txseq;
	chan->expected_tx_seq = __next_seq(chan, txseq);

	return 0;
}

static int klpr_l2cap_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	struct l2cap_ctrl *control = &bt_cb(skb)->l2cap;
	u16 len;
	u8 event;

	__unpack_control(chan, skb);

	len = skb->len;

	/*
	 * We can just drop the corrupted I-frame here.
	 * Receiver will miss it and start proper recovery
	 * procedures and ask for retransmission.
	 */
	if (klpr_l2cap_check_fcs(chan, skb))
		goto drop;

	if (!control->sframe && control->sar == L2CAP_SAR_START)
		len -= L2CAP_SDULEN_SIZE;

	if (chan->fcs == L2CAP_FCS_CRC16)
		len -= L2CAP_FCS_SIZE;

	if (len > chan->mps) {
		(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
		goto drop;
	}

	/* XXX: kABI workaround for SLE15-SP2; checking the special flag */
	if (test_bit(FLAG_CHAN_OPS_SK_FILTER, &chan->flags) &&
	    chan->ops->filter) {
		if (chan->ops->filter(chan, skb))
			goto drop;
	}

	if (!control->sframe) {
		int err;

		BT_DBG("iframe sar %d, reqseq %d, final %d, txseq %d",
		       control->sar, control->reqseq, control->final,
		       control->txseq);

		/* Validate F-bit - F=0 always valid, F=1 only
		 * valid in TX WAIT_F
		 */
		if (control->final && chan->tx_state != L2CAP_TX_STATE_WAIT_F)
			goto drop;

		if (chan->mode != L2CAP_MODE_STREAMING) {
			event = L2CAP_EV_RECV_IFRAME;
			err = (*klpe_l2cap_rx)(chan, control, skb, event);
		} else {
			err = klpr_l2cap_stream_rx(chan, control, skb);
		}

		if (err)
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
	} else {
		const u8 rx_func_to_event[4] = {
			L2CAP_EV_RECV_RR, L2CAP_EV_RECV_REJ,
			L2CAP_EV_RECV_RNR, L2CAP_EV_RECV_SREJ
		};

		/* Only I-frames are expected in streaming mode */
		if (chan->mode == L2CAP_MODE_STREAMING)
			goto drop;

		BT_DBG("sframe reqseq %d, final %d, poll %d, super %d",
		       control->reqseq, control->final, control->poll,
		       control->super);

		if (len != 0) {
			(*klpe_bt_err)("Trailing bytes: %d in sframe" "\n",len);
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
			goto drop;
		}

		/* Validate F and P bits */
		if (control->final && (control->poll ||
				       chan->tx_state != L2CAP_TX_STATE_WAIT_F))
			goto drop;

		event = rx_func_to_event[control->super];
		if ((*klpe_l2cap_rx)(chan, control, skb, event))
			(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
	}

	return 0;

drop:
	kfree_skb(skb);
	return 0;
}

static void (*klpe_l2cap_chan_le_send_credits)(struct l2cap_chan *chan);

static int klpr_l2cap_le_data_rcv(struct l2cap_chan *chan, struct sk_buff *skb)
{
	int err;

	if (!chan->rx_credits) {
		(*klpe_bt_err)("No credits to receive LE L2CAP data" "\n");
		(*klpe_l2cap_send_disconn_req)(chan, ECONNRESET);
		return -ENOBUFS;
	}

	if (chan->imtu < skb->len) {
		(*klpe_bt_err)("Too big LE L2CAP PDU" "\n");
		return -ENOBUFS;
	}

	chan->rx_credits--;
	BT_DBG("rx_credits %u -> %u", chan->rx_credits + 1, chan->rx_credits);

	(*klpe_l2cap_chan_le_send_credits)(chan);

	err = 0;

	if (!chan->sdu) {
		u16 sdu_len;

		sdu_len = get_unaligned_le16(skb->data);
		skb_pull(skb, L2CAP_SDULEN_SIZE);

		BT_DBG("Start of new SDU. sdu_len %u skb->len %u imtu %u",
		       sdu_len, skb->len, chan->imtu);

		if (sdu_len > chan->imtu) {
			(*klpe_bt_err)("Too big LE L2CAP SDU length received" "\n");
			err = -EMSGSIZE;
			goto failed;
		}

		if (skb->len > sdu_len) {
			(*klpe_bt_err)("Too much LE L2CAP data received" "\n");
			err = -EINVAL;
			goto failed;
		}

		if (skb->len == sdu_len)
			return chan->ops->recv(chan, skb);

		chan->sdu = skb;
		chan->sdu_len = sdu_len;
		chan->sdu_last_frag = skb;

		/* Detect if remote is not able to use the selected MPS */
		if (skb->len + L2CAP_SDULEN_SIZE < chan->mps) {
			u16 mps_len = skb->len + L2CAP_SDULEN_SIZE;

			/* Adjust the number of credits */
			BT_DBG("chan->mps %u -> %u", chan->mps, mps_len);
			chan->mps = mps_len;
			(*klpe_l2cap_chan_le_send_credits)(chan);
		}

		return 0;
	}

	BT_DBG("SDU fragment. chan->sdu->len %u skb->len %u chan->sdu_len %u",
	       chan->sdu->len, skb->len, chan->sdu_len);

	if (chan->sdu->len + skb->len > chan->sdu_len) {
		(*klpe_bt_err)("Too much LE L2CAP data received" "\n");
		err = -EINVAL;
		goto failed;
	}

	(*klpe_append_skb_frag)(chan->sdu, skb, &chan->sdu_last_frag);
	skb = NULL;

	if (chan->sdu->len == chan->sdu_len) {
		err = chan->ops->recv(chan, chan->sdu);
		if (!err) {
			chan->sdu = NULL;
			chan->sdu_last_frag = NULL;
			chan->sdu_len = 0;
		}
	}

failed:
	if (err) {
		kfree_skb(skb);
		kfree_skb(chan->sdu);
		chan->sdu = NULL;
		chan->sdu_last_frag = NULL;
		chan->sdu_len = 0;
	}

	/* We can't return an error here since we took care of the skb
	 * freeing internally. An error return would cause the caller to
	 * do a double-free of the skb.
	 */
	return 0;
}

void klpp_l2cap_data_channel(struct l2cap_conn *conn, u16 cid,
			       struct sk_buff *skb)
{
	struct l2cap_chan *chan;

	chan = (*klpe_l2cap_get_chan_by_scid)(conn, cid);
	if (!chan) {
		if (cid == L2CAP_CID_A2MP) {
			chan = (*klpe_a2mp_channel_create)(conn, skb);
			if (!chan) {
				kfree_skb(skb);
				return;
			}

			l2cap_chan_lock(chan);
		} else {
			BT_DBG("unknown cid 0x%4.4x", cid);
			/* Drop packet and return */
			kfree_skb(skb);
			return;
		}
	}

	BT_DBG("chan %p, len %d", chan, skb->len);

	/* If we receive data on a fixed channel before the info req/rsp
	 * procdure is done simply assume that the channel is supported
	 * and mark it as ready.
	 */
	if (chan->chan_type == L2CAP_CHAN_FIXED)
		klpr_l2cap_chan_ready(chan);

	if (chan->state != BT_CONNECTED)
		goto drop;

	switch (chan->mode) {
	case L2CAP_MODE_LE_FLOWCTL:
		if (klpr_l2cap_le_data_rcv(chan, skb) < 0)
			goto drop;

		goto done;

	case L2CAP_MODE_BASIC:
		/* If socket recv buffers overflows we drop data here
		 * which is *bad* because L2CAP has to be reliable.
		 * But we don't have any other choice. L2CAP doesn't
		 * provide flow control mechanism. */

		if (chan->imtu < skb->len) {
			(*klpe_bt_err)("Dropping L2CAP data: receive buffer overflow" "\n");
			goto drop;
		}

		if (!chan->ops->recv(chan, skb))
			goto done;
		break;

	case L2CAP_MODE_ERTM:
	case L2CAP_MODE_STREAMING:
		klpr_l2cap_data_rcv(chan, skb);
		goto done;

	default:
		BT_DBG("chan %p: bad mode 0x%2.2x", chan, chan->mode);
		break;
	}

drop:
	kfree_skb(skb);

done:
	l2cap_chan_unlock(chan);
}



#define LP_MODULE "bluetooth"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1206314.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "a2mp_channel_create", (void *)&klpe_a2mp_channel_create,
	  "bluetooth" },
	{ "append_skb_frag", (void *)&klpe_append_skb_frag, "bluetooth" },
	{ "bt_err", (void *)&klpe_bt_err, "bluetooth" },
	{ "crc16", (void *)&klpe_crc16, "crc16" },
	{ "l2cap_chan_hold", (void *)&klpe_l2cap_chan_hold, "bluetooth" },
	{ "l2cap_chan_le_send_credits",
	  (void *)&klpe_l2cap_chan_le_send_credits, "bluetooth" },
	{ "l2cap_chan_put", (void *)&klpe_l2cap_chan_put, "bluetooth" },
	{ "l2cap_classify_txseq", (void *)&klpe_l2cap_classify_txseq,
	  "bluetooth" },
	{ "l2cap_ertm_send", (void *)&klpe_l2cap_ertm_send, "bluetooth" },
	{ "l2cap_get_chan_by_scid", (void *)&klpe_l2cap_get_chan_by_scid,
	  "bluetooth" },
	{ "l2cap_handle_rej", (void *)&klpe_l2cap_handle_rej, "bluetooth" },
	{ "l2cap_handle_srej", (void *)&klpe_l2cap_handle_srej, "bluetooth" },
	{ "l2cap_pass_to_tx", (void *)&klpe_l2cap_pass_to_tx, "bluetooth" },
	{ "l2cap_reassemble_sdu", (void *)&klpe_l2cap_reassemble_sdu,
	  "bluetooth" },
	{ "l2cap_retransmit_all", (void *)&klpe_l2cap_retransmit_all,
	  "bluetooth" },
	{ "l2cap_rx", (void *)&klpe_l2cap_rx, "bluetooth" },
	{ "l2cap_send_ack", (void *)&klpe_l2cap_send_ack, "bluetooth" },
	{ "l2cap_send_disconn_req", (void *)&klpe_l2cap_send_disconn_req,
	  "bluetooth" },
	{ "l2cap_send_i_or_rr_or_rnr", (void *)&klpe_l2cap_send_i_or_rr_or_rnr,
	  "bluetooth" },
	{ "l2cap_send_rr_or_rnr", (void *)&klpe_l2cap_send_rr_or_rnr,
	  "bluetooth" },
	{ "l2cap_send_srej", (void *)&klpe_l2cap_send_srej, "bluetooth" },
};

static int livepatch_bsc1206314_module_notify(struct notifier_block *nb,
					unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = livepatch_bsc1206314_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1206314_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1206314_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_BT) */
