/*
 * livepatch_bsc1188323
 *
 * Fix for CVE-2021-3609, bsc#1188323
 *
 *  Upstream commit:
 *  d5f9023fa61e ("can: bcm: delay release of struct bcm_op after
 *                 synchronize_rcu()")
 *
 *  SLE12-SP3 commit:
 *  cf3fef852cebb5c3df11905abee9f5ab5716d0f5
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  36fe7dacd4b41f78bdd2985087f0d0714f867cf1
 *
 *  SLE15-SP2 and -SP3 commit:
 *  a57ee2fb8ecd426452fcfa7cf34ba0438ba6f1e8
 *
 *
 *  Copyright (c) 2021 SUSE
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

#if IS_ENABLED(CONFIG_CAN_BCM)

#if !IS_MODULE(CONFIG_CAN_BCM)
#error "Live patch supports only CONFIG_CAN_BCM=m"
#endif

/* klp-ccp: from net/can/bcm.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/hrtimer.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <uapi/linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/can.h>

/* klp-ccp: from include/linux/can/core.h */
static int (*klpe_can_rx_register)(struct net *net, struct net_device *dev,
		    canid_t can_id, canid_t mask,
		    void (*func)(struct sk_buff *, void *),
		    void *data, char *ident, struct sock *sk);

static void (*klpe_can_rx_unregister)(struct net *net, struct net_device *dev,
			      canid_t can_id, canid_t mask,
			      void (*func)(struct sk_buff *, void *),
			      void *data);

static int (*klpe_can_send)(struct sk_buff *skb, int loop);

/* klp-ccp: from net/can/bcm.c */
#include <linux/can/skb.h>
#include <linux/can/bcm.h>
#include <linux/slab.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#define MAX_NFRAMES 256

#define REGMASK(id) ((id & CAN_EFF_FLAG) ? \
		     (CAN_EFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG) : \
		     (CAN_SFF_MASK | CAN_EFF_FLAG | CAN_RTR_FLAG))

struct bcm_op {
	struct list_head list;
	int ifindex;
	canid_t can_id;
	u32 flags;
	unsigned long frames_abs, frames_filtered;
	struct bcm_timeval ival1, ival2;
	struct hrtimer timer, thrtimer;
	struct tasklet_struct tsklet, thrtsklet;
	ktime_t rx_stamp, kt_ival1, kt_ival2, kt_lastmsg;
	int rx_ifindex;
	int cfsiz;
	u32 count;
	u32 nframes;
	u32 currframe;
	/* void pointers to arrays of struct can[fd]_frame */
	void *frames;
	void *last_frames;
	struct canfd_frame sframe;
	struct canfd_frame last_sframe;
	struct sock *sk;
	struct net_device *rx_reg_dev;
};

struct bcm_sock {
	struct sock sk;
	int bound;
	int ifindex;
	struct notifier_block notifier;
	struct list_head rx_ops;
	struct list_head tx_ops;
	unsigned long dropped_usr_msgs;
	struct proc_dir_entry *bcm_proc_read;
	char procname [32]; /* inode number in decimal with \0 */
};

static inline struct bcm_sock *bcm_sk(const struct sock *sk)
{
	return (struct bcm_sock *)sk;
}

static inline ktime_t bcm_timeval_to_ktime(struct bcm_timeval tv)
{
	return ktime_set(tv.tv_sec, tv.tv_usec * NSEC_PER_USEC);
}

static bool (*klpe_bcm_is_invalid_tv)(struct bcm_msg_head *msg_head);

#define CFSIZ(flags) ((flags & CAN_FD_FRAME) ? CANFD_MTU : CAN_MTU)
#define OPSIZ sizeof(struct bcm_op)
#define MHSIZ sizeof(struct bcm_msg_head)

static void (*klpe_bcm_can_tx)(struct bcm_op *op);

static void (*klpe_bcm_tx_start_timer)(struct bcm_op *op);

static void (*klpe_bcm_tx_timeout_tsklet)(unsigned long data);

static enum hrtimer_restart (*klpe_bcm_tx_timeout_handler)(struct hrtimer *hrtimer);

static void (*klpe_bcm_rx_timeout_tsklet)(unsigned long data);

static enum hrtimer_restart (*klpe_bcm_rx_timeout_handler)(struct hrtimer *hrtimer);

static int (*klpe_bcm_rx_thr_flush)(struct bcm_op *op, int update);

static void (*klpe_bcm_rx_thr_tsklet)(unsigned long data);

static enum hrtimer_restart (*klpe_bcm_rx_thr_handler)(struct hrtimer *hrtimer);

static void (*klpe_bcm_rx_handler)(struct sk_buff *skb, void *data);

static struct bcm_op *bcm_find_op(struct list_head *ops,
				  struct bcm_msg_head *mh, int ifindex)
{
	struct bcm_op *op;

	list_for_each_entry(op, ops, list) {
		if ((op->can_id == mh->can_id) && (op->ifindex == ifindex) &&
		    (op->flags & CAN_FD_FRAME) == (mh->flags & CAN_FD_FRAME))
			return op;
	}

	return NULL;
}

static void (*klpe_bcm_remove_op)(struct bcm_op *op);

static void (*klpe_bcm_rx_unreg)(struct net_device *dev, struct bcm_op *op);

static int klpp_bcm_delete_rx_op(struct list_head *ops, struct bcm_msg_head *mh,
			    int ifindex)
{
	struct bcm_op *op, *n;

	list_for_each_entry_safe(op, n, ops, list) {
		if ((op->can_id == mh->can_id) && (op->ifindex == ifindex) &&
		    (op->flags & CAN_FD_FRAME) == (mh->flags & CAN_FD_FRAME)) {

			/*
			 * Don't care if we're bound or not (due to netdev
			 * problems) can_rx_unregister() is always a save
			 * thing to do here.
			 */
			if (op->ifindex) {
				/*
				 * Only remove subscriptions that had not
				 * been removed due to NETDEV_UNREGISTER
				 * in bcm_notifier()
				 */
				if (op->rx_reg_dev) {
					struct net_device *dev;

					dev = dev_get_by_index(sock_net(op->sk),
							       op->ifindex);
					if (dev) {
						(*klpe_bcm_rx_unreg)(dev, op);
						dev_put(dev);
					}
				}
			} else
				(*klpe_can_rx_unregister)(sock_net(op->sk), NULL,
						  op->can_id,
						  REGMASK(op->can_id),
						  (*klpe_bcm_rx_handler), op);

			list_del(&op->list);
			/*
			 * Fix CVE-2021-3609
			 *  +1 line
			 */
			synchronize_rcu();
			(*klpe_bcm_remove_op)(op);
			return 1; /* done */
		}
	}

	return 0; /* not found */
}

static int klpr_bcm_delete_tx_op(struct list_head *ops, struct bcm_msg_head *mh,
			    int ifindex)
{
	struct bcm_op *op, *n;

	list_for_each_entry_safe(op, n, ops, list) {
		if ((op->can_id == mh->can_id) && (op->ifindex == ifindex) &&
		    (op->flags & CAN_FD_FRAME) == (mh->flags & CAN_FD_FRAME)) {
			list_del(&op->list);
			(*klpe_bcm_remove_op)(op);
			return 1; /* done */
		}
	}

	return 0; /* not found */
}

static int (*klpe_bcm_read_op)(struct list_head *ops, struct bcm_msg_head *msg_head,
		       int ifindex);

static int klpr_bcm_tx_setup(struct bcm_msg_head *msg_head, struct msghdr *msg,
			int ifindex, struct sock *sk)
{
	struct bcm_sock *bo = bcm_sk(sk);
	struct bcm_op *op;
	struct canfd_frame *cf;
	unsigned int i;
	int err;

	/* we need a real device to send frames */
	if (!ifindex)
		return -ENODEV;

	/* check nframes boundaries - we need at least one CAN frame */
	if (msg_head->nframes < 1 || msg_head->nframes > MAX_NFRAMES)
		return -EINVAL;

	/* check timeval limitations */
	if ((msg_head->flags & SETTIMER) && (*klpe_bcm_is_invalid_tv)(msg_head))
		return -EINVAL;

	/* check the given can_id */
	op = bcm_find_op(&bo->tx_ops, msg_head, ifindex);
	if (op) {
		/* update existing BCM operation */

		/*
		 * Do we need more space for the CAN frames than currently
		 * allocated? -> This is a _really_ unusual use-case and
		 * therefore (complexity / locking) it is not supported.
		 */
		if (msg_head->nframes > op->nframes)
			return -E2BIG;

		/* update CAN frames content */
		for (i = 0; i < msg_head->nframes; i++) {

			cf = op->frames + op->cfsiz * i;
			err = memcpy_from_msg((u8 *)cf, msg, op->cfsiz);

			if (op->flags & CAN_FD_FRAME) {
				if (cf->len > 64)
					err = -EINVAL;
			} else {
				if (cf->len > 8)
					err = -EINVAL;
			}

			if (err < 0)
				return err;

			if (msg_head->flags & TX_CP_CAN_ID) {
				/* copy can_id into frame */
				cf->can_id = msg_head->can_id;
			}
		}
		op->flags = msg_head->flags;

	} else {
		/* insert new BCM operation for the given can_id */

		op = kzalloc(OPSIZ, GFP_KERNEL);
		if (!op)
			return -ENOMEM;

		op->can_id = msg_head->can_id;
		op->cfsiz = CFSIZ(msg_head->flags);
		op->flags = msg_head->flags;

		/* create array for CAN frames and copy the data */
		if (msg_head->nframes > 1) {
			op->frames = kmalloc(msg_head->nframes * op->cfsiz,
					     GFP_KERNEL);
			if (!op->frames) {
				kfree(op);
				return -ENOMEM;
			}
		} else
			op->frames = &op->sframe;

		for (i = 0; i < msg_head->nframes; i++) {

			cf = op->frames + op->cfsiz * i;
			err = memcpy_from_msg((u8 *)cf, msg, op->cfsiz);

			if (op->flags & CAN_FD_FRAME) {
				if (cf->len > 64)
					err = -EINVAL;
			} else {
				if (cf->len > 8)
					err = -EINVAL;
			}

			if (err < 0) {
				if (op->frames != &op->sframe)
					kfree(op->frames);
				kfree(op);
				return err;
			}

			if (msg_head->flags & TX_CP_CAN_ID) {
				/* copy can_id into frame */
				cf->can_id = msg_head->can_id;
			}
		}

		/* tx_ops never compare with previous received messages */
		op->last_frames = NULL;

		/* bcm_can_tx / bcm_tx_timeout_handler needs this */
		op->sk = sk;
		op->ifindex = ifindex;

		/* initialize uninitialized (kzalloc) structure */
		hrtimer_init(&op->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		op->timer.function = (*klpe_bcm_tx_timeout_handler);

		/* initialize tasklet for tx countevent notification */
		tasklet_init(&op->tsklet, (*klpe_bcm_tx_timeout_tsklet),
			     (unsigned long) op);

		/* currently unused in tx_ops */
		hrtimer_init(&op->thrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

		/* add this bcm_op to the list of the tx_ops */
		list_add(&op->list, &bo->tx_ops);

	} /* if ((op = bcm_find_op(&bo->tx_ops, msg_head->can_id, ifindex))) */

	if (op->nframes != msg_head->nframes) {
		op->nframes   = msg_head->nframes;
		/* start multiple frame transmission with index 0 */
		op->currframe = 0;
	}

	/* check flags */

	if (op->flags & TX_RESET_MULTI_IDX) {
		/* start multiple frame transmission with index 0 */
		op->currframe = 0;
	}

	if (op->flags & SETTIMER) {
		/* set timer values */
		op->count = msg_head->count;
		op->ival1 = msg_head->ival1;
		op->ival2 = msg_head->ival2;
		op->kt_ival1 = bcm_timeval_to_ktime(msg_head->ival1);
		op->kt_ival2 = bcm_timeval_to_ktime(msg_head->ival2);

		/* disable an active timer due to zero values? */
		if (!op->kt_ival1 && !op->kt_ival2)
			hrtimer_cancel(&op->timer);
	}

	if (op->flags & STARTTIMER) {
		hrtimer_cancel(&op->timer);
		/* spec: send CAN frame when starting timer */
		op->flags |= TX_ANNOUNCE;
	}

	if (op->flags & TX_ANNOUNCE) {
		(*klpe_bcm_can_tx)(op);
		if (op->count)
			op->count--;
	}

	if (op->flags & STARTTIMER)
		(*klpe_bcm_tx_start_timer)(op);

	return msg_head->nframes * op->cfsiz + MHSIZ;
}

static int klpr_bcm_rx_setup(struct bcm_msg_head *msg_head, struct msghdr *msg,
			int ifindex, struct sock *sk)
{
	struct bcm_sock *bo = bcm_sk(sk);
	struct bcm_op *op;
	int do_rx_register;
	int err = 0;

	if ((msg_head->flags & RX_FILTER_ID) || (!(msg_head->nframes))) {
		/* be robust against wrong usage ... */
		msg_head->flags |= RX_FILTER_ID;
		/* ignore trailing garbage */
		msg_head->nframes = 0;
	}

	/* the first element contains the mux-mask => MAX_NFRAMES + 1  */
	if (msg_head->nframes > MAX_NFRAMES + 1)
		return -EINVAL;

	if ((msg_head->flags & RX_RTR_FRAME) &&
	    ((msg_head->nframes != 1) ||
	     (!(msg_head->can_id & CAN_RTR_FLAG))))
		return -EINVAL;

	/* check timeval limitations */
	if ((msg_head->flags & SETTIMER) && (*klpe_bcm_is_invalid_tv)(msg_head))
		return -EINVAL;

	/* check the given can_id */
	op = bcm_find_op(&bo->rx_ops, msg_head, ifindex);
	if (op) {
		/* update existing BCM operation */

		/*
		 * Do we need more space for the CAN frames than currently
		 * allocated? -> This is a _really_ unusual use-case and
		 * therefore (complexity / locking) it is not supported.
		 */
		if (msg_head->nframes > op->nframes)
			return -E2BIG;

		if (msg_head->nframes) {
			/* update CAN frames content */
			err = memcpy_from_msg(op->frames, msg,
					      msg_head->nframes * op->cfsiz);
			if (err < 0)
				return err;

			/* clear last_frames to indicate 'nothing received' */
			memset(op->last_frames, 0, msg_head->nframes * op->cfsiz);
		}

		op->nframes = msg_head->nframes;
		op->flags = msg_head->flags;

		/* Only an update -> do not call can_rx_register() */
		do_rx_register = 0;

	} else {
		/* insert new BCM operation for the given can_id */
		op = kzalloc(OPSIZ, GFP_KERNEL);
		if (!op)
			return -ENOMEM;

		op->can_id = msg_head->can_id;
		op->nframes = msg_head->nframes;
		op->cfsiz = CFSIZ(msg_head->flags);
		op->flags = msg_head->flags;

		if (msg_head->nframes > 1) {
			/* create array for CAN frames and copy the data */
			op->frames = kmalloc(msg_head->nframes * op->cfsiz,
					     GFP_KERNEL);
			if (!op->frames) {
				kfree(op);
				return -ENOMEM;
			}

			/* create and init array for received CAN frames */
			op->last_frames = kzalloc(msg_head->nframes * op->cfsiz,
						  GFP_KERNEL);
			if (!op->last_frames) {
				kfree(op->frames);
				kfree(op);
				return -ENOMEM;
			}

		} else {
			op->frames = &op->sframe;
			op->last_frames = &op->last_sframe;
		}

		if (msg_head->nframes) {
			err = memcpy_from_msg(op->frames, msg,
					      msg_head->nframes * op->cfsiz);
			if (err < 0) {
				if (op->frames != &op->sframe)
					kfree(op->frames);
				if (op->last_frames != &op->last_sframe)
					kfree(op->last_frames);
				kfree(op);
				return err;
			}
		}

		/* bcm_can_tx / bcm_tx_timeout_handler needs this */
		op->sk = sk;
		op->ifindex = ifindex;

		/* ifindex for timeout events w/o previous frame reception */
		op->rx_ifindex = ifindex;

		/* initialize uninitialized (kzalloc) structure */
		hrtimer_init(&op->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		op->timer.function = (*klpe_bcm_rx_timeout_handler);

		/* initialize tasklet for rx timeout notification */
		tasklet_init(&op->tsklet, (*klpe_bcm_rx_timeout_tsklet),
			     (unsigned long) op);

		hrtimer_init(&op->thrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		op->thrtimer.function = (*klpe_bcm_rx_thr_handler);

		/* initialize tasklet for rx throttle handling */
		tasklet_init(&op->thrtsklet, (*klpe_bcm_rx_thr_tsklet),
			     (unsigned long) op);

		/* add this bcm_op to the list of the rx_ops */
		list_add(&op->list, &bo->rx_ops);

		/* call can_rx_register() */
		do_rx_register = 1;

	} /* if ((op = bcm_find_op(&bo->rx_ops, msg_head->can_id, ifindex))) */

	/* check flags */

	if (op->flags & RX_RTR_FRAME) {
		struct canfd_frame *frame0 = op->frames;

		/* no timers in RTR-mode */
		hrtimer_cancel(&op->thrtimer);
		hrtimer_cancel(&op->timer);

		/*
		 * funny feature in RX(!)_SETUP only for RTR-mode:
		 * copy can_id into frame BUT without RTR-flag to
		 * prevent a full-load-loopback-test ... ;-]
		 */
		if ((op->flags & TX_CP_CAN_ID) ||
		    (frame0->can_id == op->can_id))
			frame0->can_id = op->can_id & ~CAN_RTR_FLAG;

	} else {
		if (op->flags & SETTIMER) {

			/* set timer value */
			op->ival1 = msg_head->ival1;
			op->ival2 = msg_head->ival2;
			op->kt_ival1 = bcm_timeval_to_ktime(msg_head->ival1);
			op->kt_ival2 = bcm_timeval_to_ktime(msg_head->ival2);

			/* disable an active timer due to zero value? */
			if (!op->kt_ival1)
				hrtimer_cancel(&op->timer);

			/*
			 * In any case cancel the throttle timer, flush
			 * potentially blocked msgs and reset throttle handling
			 */
			op->kt_lastmsg = 0;
			hrtimer_cancel(&op->thrtimer);
			(*klpe_bcm_rx_thr_flush)(op, 1);
		}

		if ((op->flags & STARTTIMER) && op->kt_ival1)
			hrtimer_start(&op->timer, op->kt_ival1,
				      HRTIMER_MODE_REL);
	}

	/* now we can register for can_ids, if we added a new bcm_op */
	if (do_rx_register) {
		if (ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(sock_net(sk), ifindex);
			if (dev) {
				err = (*klpe_can_rx_register)(sock_net(sk), dev,
						      op->can_id,
						      REGMASK(op->can_id),
						      (*klpe_bcm_rx_handler), op,
						      "bcm", sk);

				op->rx_reg_dev = dev;
				dev_put(dev);
			}

		} else
			err = (*klpe_can_rx_register)(sock_net(sk), NULL, op->can_id,
					      REGMASK(op->can_id),
					      (*klpe_bcm_rx_handler), op, "bcm", sk);
		if (err) {
			/* this bcm rx op is broken -> remove it */
			list_del(&op->list);
			(*klpe_bcm_remove_op)(op);
			return err;
		}
	}

	return msg_head->nframes * op->cfsiz + MHSIZ;
}

static int klpr_bcm_tx_send(struct msghdr *msg, int ifindex, struct sock *sk,
		       int cfsiz)
{
	struct sk_buff *skb;
	struct net_device *dev;
	int err;

	/* we need a real device to send frames */
	if (!ifindex)
		return -ENODEV;

	skb = alloc_skb(cfsiz + sizeof(struct can_skb_priv), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	can_skb_reserve(skb);

	err = memcpy_from_msg(skb_put(skb, cfsiz), msg, cfsiz);
	if (err < 0) {
		kfree_skb(skb);
		return err;
	}

	dev = dev_get_by_index(sock_net(sk), ifindex);
	if (!dev) {
		kfree_skb(skb);
		return -ENODEV;
	}

	can_skb_prv(skb)->ifindex = dev->ifindex;
	can_skb_prv(skb)->skbcnt = 0;
	skb->dev = dev;
	can_skb_set_owner(skb, sk);
	err = (*klpe_can_send)(skb, 1); /* send with loopback */
	dev_put(dev);

	if (err)
		return err;

	return cfsiz + MHSIZ;
}

int klpp_bcm_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;
	struct bcm_sock *bo = bcm_sk(sk);
	int ifindex = bo->ifindex; /* default ifindex for this bcm_op */
	struct bcm_msg_head msg_head;
	int cfsiz;
	int ret; /* read bytes or error codes as return value */

	if (!bo->bound)
		return -ENOTCONN;

	/* check for valid message length from userspace */
	if (size < MHSIZ)
		return -EINVAL;

	/* read message head information */
	ret = memcpy_from_msg((u8 *)&msg_head, msg, MHSIZ);
	if (ret < 0)
		return ret;

	cfsiz = CFSIZ(msg_head.flags);
	if ((size - MHSIZ) % cfsiz)
		return -EINVAL;

	/* check for alternative ifindex for this bcm_op */

	if (!ifindex && msg->msg_name) {
		/* no bound device as default => check msg_name */
		DECLARE_SOCKADDR(struct sockaddr_can *, addr, msg->msg_name);

		if (msg->msg_namelen < sizeof(*addr))
			return -EINVAL;

		if (addr->can_family != AF_CAN)
			return -EINVAL;

		/* ifindex from sendto() */
		ifindex = addr->can_ifindex;

		if (ifindex) {
			struct net_device *dev;

			dev = dev_get_by_index(sock_net(sk), ifindex);
			if (!dev)
				return -ENODEV;

			if (dev->type != ARPHRD_CAN) {
				dev_put(dev);
				return -ENODEV;
			}

			dev_put(dev);
		}
	}

	lock_sock(sk);

	switch (msg_head.opcode) {

	case TX_SETUP:
		ret = klpr_bcm_tx_setup(&msg_head, msg, ifindex, sk);
		break;

	case RX_SETUP:
		ret = klpr_bcm_rx_setup(&msg_head, msg, ifindex, sk);
		break;

	case TX_DELETE:
		if (klpr_bcm_delete_tx_op(&bo->tx_ops, &msg_head, ifindex))
			ret = MHSIZ;
		else
			ret = -EINVAL;
		break;

	case RX_DELETE:
		if (klpp_bcm_delete_rx_op(&bo->rx_ops, &msg_head, ifindex))
			ret = MHSIZ;
		else
			ret = -EINVAL;
		break;

	case TX_READ:
		/* reuse msg_head for the reply to TX_READ */
		msg_head.opcode  = TX_STATUS;
		ret = (*klpe_bcm_read_op)(&bo->tx_ops, &msg_head, ifindex);
		break;

	case RX_READ:
		/* reuse msg_head for the reply to RX_READ */
		msg_head.opcode  = RX_STATUS;
		ret = (*klpe_bcm_read_op)(&bo->rx_ops, &msg_head, ifindex);
		break;

	case TX_SEND:
		/* we need exactly one CAN frame behind the msg head */
		if ((msg_head.nframes != 1) || (size != cfsiz + MHSIZ))
			ret = -EINVAL;
		else
			ret = klpr_bcm_tx_send(msg, ifindex, sk, cfsiz);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	release_sock(sk);

	return ret;
}

int klpp_bcm_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct net *net;
	struct bcm_sock *bo;
	struct bcm_op *op, *next;

	if (!sk)
		return 0;

	net = sock_net(sk);
	bo = bcm_sk(sk);

	/* remove bcm_ops, timer, rx_unregister(), etc. */

	unregister_netdevice_notifier(&bo->notifier);

	lock_sock(sk);

	list_for_each_entry_safe(op, next, &bo->tx_ops, list)
		(*klpe_bcm_remove_op)(op);

	list_for_each_entry_safe(op, next, &bo->rx_ops, list) {
		/*
		 * Don't care if we're bound or not (due to netdev problems)
		 * can_rx_unregister() is always a save thing to do here.
		 */
		if (op->ifindex) {
			/*
			 * Only remove subscriptions that had not
			 * been removed due to NETDEV_UNREGISTER
			 * in bcm_notifier()
			 */
			if (op->rx_reg_dev) {
				struct net_device *dev;

				dev = dev_get_by_index(net, op->ifindex);
				if (dev) {
					(*klpe_bcm_rx_unreg)(dev, op);
					dev_put(dev);
				}
			}
		} else
			(*klpe_can_rx_unregister)(net, NULL, op->can_id,
					  REGMASK(op->can_id),
					  (*klpe_bcm_rx_handler), op);

		/*
		 * Fix CVE-2021-3609
		 *  -1 line
		 */
	}

	/*
	 * Fix CVE-2021-3609
	 *  +5 lines
	 */
	synchronize_rcu();

	list_for_each_entry_safe(op, next, &bo->rx_ops, list)
		(*klpe_bcm_remove_op)(op);

#if IS_ENABLED(CONFIG_PROC_FS)
	if (net->can.bcmproc_dir && bo->bcm_proc_read)
		remove_proc_entry(bo->procname, net->can.bcmproc_dir);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_PROC_FS */
	if (bo->bound) {
		bo->bound   = 0;
		bo->ifindex = 0;
	}

	sock_orphan(sk);
	sock->sk = NULL;

	release_sock(sk);
	sock_put(sk);

	return 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1188323.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "can_bcm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "can_rx_register", (void *)&klpe_can_rx_register, "can" },
	{ "can_rx_unregister", (void *)&klpe_can_rx_unregister, "can" },
	{ "can_send", (void *)&klpe_can_send, "can" },
	{ "bcm_tx_start_timer", (void *)&klpe_bcm_tx_start_timer, "can_bcm" },
	{ "bcm_is_invalid_tv", (void *)&klpe_bcm_is_invalid_tv, "can_bcm" },
	{ "bcm_tx_timeout_tsklet", (void *)&klpe_bcm_tx_timeout_tsklet,
	  "can_bcm" },
	{ "bcm_rx_unreg", (void *)&klpe_bcm_rx_unreg, "can_bcm" },
	{ "bcm_rx_thr_handler", (void *)&klpe_bcm_rx_thr_handler, "can_bcm" },
	{ "bcm_tx_timeout_handler", (void *)&klpe_bcm_tx_timeout_handler,
	  "can_bcm" },
	{ "bcm_rx_thr_flush", (void *)&klpe_bcm_rx_thr_flush, "can_bcm" },
	{ "bcm_rx_thr_tsklet", (void *)&klpe_bcm_rx_thr_tsklet, "can_bcm" },
	{ "bcm_rx_timeout_tsklet", (void *)&klpe_bcm_rx_timeout_tsklet,
	  "can_bcm" },
	{ "bcm_rx_handler", (void *)&klpe_bcm_rx_handler, "can_bcm" },
	{ "bcm_can_tx", (void *)&klpe_bcm_can_tx, "can_bcm" },
	{ "bcm_rx_timeout_handler", (void *)&klpe_bcm_rx_timeout_handler,
	  "can_bcm" },
	{ "bcm_remove_op", (void *)&klpe_bcm_remove_op, "can_bcm" },
	{ "bcm_read_op", (void *)&klpe_bcm_read_op, "can_bcm" },
};

static int livepatch_bsc1188323_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1188323_module_nb = {
	.notifier_call = livepatch_bsc1188323_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1188323_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1188323_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1188323_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1188323_module_nb);
}

#endif /* IS_ENABLED(CONFIG_CAN_BCM) */
