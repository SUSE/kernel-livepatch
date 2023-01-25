/*
 * livepatch_bsc1204432
 *
 * Fix for CVE-2022-3565, bsc#1204432
 *
 *  Upstream commit:
 *  2568a7e0832e ("mISDN: fix use-after-free bugs in l1oip timer handlers")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  a6ab2c63381218e465b5253254dc2d72aa465aa3
 *
 *  SLE15-SP2 and -SP3 commit:
 *  1917bcffcaa062d5f79b5afe17725aff4fd88611
 *
 *  SLE15-SP4 commit:
 *  86d22c2fe2bec8069f481dd9a2df2aa806b2199b
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

#if IS_ENABLED(CONFIG_MISDN_L1OIP)

#if !IS_MODULE(CONFIG_MISDN_L1OIP)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/isdn/mISDN/l1oip_core.c */
#define L1OIP_VERSION	0	/* 0...3 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/mISDNif.h>

/* klp-ccp: from include/linux/mISDNif.h */
static void	(*klpe_mISDN_unregister_device)(struct mISDNdevice *);

/* klp-ccp: from drivers/isdn/mISDN/l1oip_core.c */
#include <linux/mISDNhw.h>

/* klp-ccp: from include/linux/mISDNhw.h */
static int	(*klpe_mISDN_freedchannel)(struct dchannel *);

static void	(*klpe_mISDN_freebchannel)(struct bchannel *);

static void	(*klpe_queue_ch_frame)(struct mISDNchannel *, u_int,
			int, struct sk_buff *);

/* klp-ccp: from drivers/isdn/mISDN/l1oip_core.c */
#include <linux/init.h>
#include <linux/in.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <net/sock.h>

/* klp-ccp: from drivers/isdn/mISDN/l1oip.h */
#define DEBUG_L1OIP_SOCKET	0x00020000

#define DEBUG_L1OIP_MSG		0x00080000

#define L1OIP_MAX_LEN		2048		/* max packet size form l2 */
#define L1OIP_MAX_PERFRAME	1400		/* max data size in one frame */

#define L1OIP_KEEPALIVE		15

struct l1oip_chan {
	struct dchannel		*dch;
	struct bchannel		*bch;
	u32			tx_counter;	/* counts xmit bytes/packets */
	u32			rx_counter;	/* counts recv bytes/packets */
	u32			codecstate;	/* used by codec to save data */
#ifdef REORDER_DEBUG
#error "klp-ccp: non-taken branch"
#endif
};

struct l1oip {
	struct list_head        list;

	/* card */
	int			registered;	/* if registered with mISDN */
	char			name[MISDN_MAX_IDLEN];
	int			idx;		/* card index */
	int			pri;		/* 1=pri, 0=bri */
	int			d_idx;		/* current dchannel number */
	int			b_num;		/* number of bchannels */
	u32			id;		/* id of connection */
	int			ondemand;	/* if transmis. is on demand */
	int			bundle;		/* bundle channels in one frm */
	int			codec;		/* codec to use for transmis. */
	int			limit;		/* limit number of bchannels */

	/* timer */
	struct timer_list	keep_tl;
	struct timer_list	timeout_tl;
	int			timeout_on;
	struct work_struct	workq;

	/* socket */
	struct socket		*socket;	/* if set, socket is created */
	struct completion	socket_complete;/* completion of sock thread */
	struct task_struct	*socket_thread;
	spinlock_t		socket_lock;	/* access sock outside thread */
	u32			remoteip;	/* if all set, ip is assigned */
	u16			localport;	/* must always be set */
	u16			remoteport;	/* must always be set */
	struct sockaddr_in	sin_local;	/* local socket name */
	struct sockaddr_in	sin_remote;	/* remote socket name */
	struct msghdr		sendmsg;	/* ip message to send */
	struct kvec		sendiov;	/* iov for message */

	/* frame */
	struct l1oip_chan	chan[128];	/* channel instances */
};

static int (*klpe_l1oip_law_to_4bit)(u8 *data, int len, u8 *result, u32 *state);

static int (*klpe_l1oip_alaw_to_ulaw)(u8 *data, int len, u8 *result);
static int (*klpe_l1oip_ulaw_to_alaw)(u8 *data, int len, u8 *result);
static void (*klpe_l1oip_4bit_free)(void);

/* klp-ccp: from drivers/isdn/mISDN/l1oip_core.c */
static spinlock_t (*klpe_l1oip_lock);
static struct list_head (*klpe_l1oip_ilist);

static int (*klpe_debug);
static int (*klpe_ulaw);

#define KLPR_MAX_CARDS 16

struct klp_bsc1204432_shared_state {
	unsigned long refcount;
	bool shutdown[KLPR_MAX_CARDS];
};

static struct klp_bsc1204432_shared_state *klp_bsc1204432_shared_state;

#include "shadow.h"
#include <linux/livepatch.h>

#define KLP_BSC1204432_SHARED_STATE_ID KLP_SHADOW_ID(1204432, 0)

static int klp_bsc1204432_init_shared_state(void *obj,
					    void *shadow_data,
					    void *ctor_dat)
{
	memset(shadow_data, 0, sizeof(*klp_bsc1204432_shared_state));
	return 0;
}

/* Must be called with module_mutex held. */
static int __klp_bsc1204432_get_shared_state(void)
{
	klp_bsc1204432_shared_state =
		klp_shadow_get_or_alloc(NULL, KLP_BSC1204432_SHARED_STATE_ID,
					sizeof(*klp_bsc1204432_shared_state),
					GFP_KERNEL,
					klp_bsc1204432_init_shared_state, NULL);
	if (!klp_bsc1204432_shared_state)
		return -ENOMEM;

	++klp_bsc1204432_shared_state->refcount;

	return 0;
}

/* Must be called with module_mutex held. */
static void __klp_bsc1204432_put_shared_state(void)
{
	--klp_bsc1204432_shared_state->refcount;

	if (!klp_bsc1204432_shared_state->refcount)
		klp_shadow_free(NULL, KLP_BSC1204432_SHARED_STATE_ID, NULL);

	klp_bsc1204432_shared_state = NULL;
}

static int
klpr_l1oip_socket_send(struct l1oip *hc, u8 localcodec, u8 channel, u32 chanmask,
		  u16 timebase, u8 *buf, int len)
{
	u8 *p;
	u8 frame[len + 32];
	struct socket *socket = NULL;

	if ((*klpe_debug) & DEBUG_L1OIP_MSG)
		printk(KERN_DEBUG "%s: sending data to socket (len = %d)\n",
		       __func__, len);

	p = frame;

	/* restart timer */
	if (time_before(hc->keep_tl.expires, jiffies + 5 * HZ) &&
	    !klp_bsc1204432_shared_state->shutdown[hc->idx])
		mod_timer(&hc->keep_tl, jiffies + L1OIP_KEEPALIVE * HZ);
	else
		hc->keep_tl.expires = jiffies + L1OIP_KEEPALIVE * HZ;

	if ((*klpe_debug) & DEBUG_L1OIP_MSG)
		printk(KERN_DEBUG "%s: resetting timer\n", __func__);

	/* drop if we have no remote ip or port */
	if (!hc->sin_remote.sin_addr.s_addr || !hc->sin_remote.sin_port) {
		if ((*klpe_debug) & DEBUG_L1OIP_MSG)
			printk(KERN_DEBUG "%s: dropping frame, because remote "
			       "IP is not set.\n", __func__);
		return len;
	}

	/* assemble frame */
	*p++ = (L1OIP_VERSION << 6) /* version and coding */
		| (hc->pri ? 0x20 : 0x00) /* type */
		| (hc->id ? 0x10 : 0x00) /* id */
		| localcodec;
	if (hc->id) {
		*p++ = hc->id >> 24; /* id */
		*p++ = hc->id >> 16;
		*p++ = hc->id >> 8;
		*p++ = hc->id;
	}
	*p++ =  0x00 + channel; /* m-flag, channel */
	*p++ = timebase >> 8; /* time base */
	*p++ = timebase;

	if (buf && len) { /* add data to frame */
		if (localcodec == 1 && (*klpe_ulaw))
			(*klpe_l1oip_ulaw_to_alaw)(buf, len, p);
		else if (localcodec == 2 && !(*klpe_ulaw))
			(*klpe_l1oip_alaw_to_ulaw)(buf, len, p);
		else if (localcodec == 3)
			len = (*klpe_l1oip_law_to_4bit)(buf, len, p,
						&hc->chan[channel].codecstate);
		else
			memcpy(p, buf, len);
	}
	len += p - frame;

	/* check for socket in safe condition */
	spin_lock(&hc->socket_lock);
	if (!hc->socket) {
		spin_unlock(&hc->socket_lock);
		return 0;
	}
	/* seize socket */
	socket = hc->socket;
	hc->socket = NULL;
	spin_unlock(&hc->socket_lock);
	/* send packet */
	if ((*klpe_debug) & DEBUG_L1OIP_MSG)
		printk(KERN_DEBUG "%s: sending packet to socket (len "
		       "= %d)\n", __func__, len);
	hc->sendiov.iov_base = frame;
	hc->sendiov.iov_len  = len;
	len = kernel_sendmsg(socket, &hc->sendmsg, &hc->sendiov, 1, len);
	/* give socket back */
	hc->socket = socket; /* no locking required */

	return len;
}

static void
(*klpe_l1oip_socket_close)(struct l1oip *hc);

void
klpp_l1oip_send_bh(struct work_struct *work)
{
	struct l1oip *hc = container_of(work, struct l1oip, workq);

	if ((*klpe_debug) & (DEBUG_L1OIP_MSG | DEBUG_L1OIP_SOCKET))
		printk(KERN_DEBUG "%s: keepalive timer expired, sending empty "
		       "frame on dchannel\n", __func__);

	/* send an empty l1oip frame at D-channel */
	klpr_l1oip_socket_send(hc, 0, hc->d_idx, 0, 0, NULL, 0);
}

int
klpp_handle_dmsg(struct mISDNchannel *ch, struct sk_buff *skb)
{
	struct mISDNdevice	*dev = container_of(ch, struct mISDNdevice, D);
	struct dchannel		*dch = container_of(dev, struct dchannel, dev);
	struct l1oip			*hc = dch->hw;
	struct mISDNhead	*hh = mISDN_HEAD_P(skb);
	int			ret = -EINVAL;
	int			l, ll;
	unsigned char		*p;

	switch (hh->prim) {
	case PH_DATA_REQ:
		if (skb->len < 1) {
			printk(KERN_WARNING "%s: skb too small\n",
			       __func__);
			break;
		}
		if (skb->len > MAX_DFRAME_LEN_L1 || skb->len > L1OIP_MAX_LEN) {
			printk(KERN_WARNING "%s: skb too large\n",
			       __func__);
			break;
		}
		/* send frame */
		p = skb->data;
		l = skb->len;
		while (l) {
			ll = (l < L1OIP_MAX_PERFRAME) ? l : L1OIP_MAX_PERFRAME;
			klpr_l1oip_socket_send(hc, 0, dch->slot, 0,
					  hc->chan[dch->slot].tx_counter++, p, ll);
			p += ll;
			l -= ll;
		}
		skb_trim(skb, 0);
		(*klpe_queue_ch_frame)(ch, PH_DATA_CNF, hh->id, skb);
		return 0;
	case PH_ACTIVATE_REQ:
		if ((*klpe_debug) & (DEBUG_L1OIP_MSG | DEBUG_L1OIP_SOCKET))
			printk(KERN_DEBUG "%s: PH_ACTIVATE channel %d (1..%d)\n"
			       , __func__, dch->slot, hc->b_num + 1);
		skb_trim(skb, 0);
		if (test_bit(FLG_ACTIVE, &dch->Flags))
			(*klpe_queue_ch_frame)(ch, PH_ACTIVATE_IND, hh->id, skb);
		else
			(*klpe_queue_ch_frame)(ch, PH_DEACTIVATE_IND, hh->id, skb);
		return 0;
	case PH_DEACTIVATE_REQ:
		if ((*klpe_debug) & (DEBUG_L1OIP_MSG | DEBUG_L1OIP_SOCKET))
			printk(KERN_DEBUG "%s: PH_DEACTIVATE channel %d "
			       "(1..%d)\n", __func__, dch->slot,
			       hc->b_num + 1);
		skb_trim(skb, 0);
		if (test_bit(FLG_ACTIVE, &dch->Flags))
			(*klpe_queue_ch_frame)(ch, PH_ACTIVATE_IND, hh->id, skb);
		else
			(*klpe_queue_ch_frame)(ch, PH_DEACTIVATE_IND, hh->id, skb);
		return 0;
	}
	if (!ret)
		dev_kfree_skb(skb);
	return ret;
}

int
klpp_handle_bmsg(struct mISDNchannel *ch, struct sk_buff *skb)
{
	struct bchannel		*bch = container_of(ch, struct bchannel, ch);
	struct l1oip			*hc = bch->hw;
	int			ret = -EINVAL;
	struct mISDNhead	*hh = mISDN_HEAD_P(skb);
	int			l, ll;
	unsigned char		*p;

	switch (hh->prim) {
	case PH_DATA_REQ:
		if (skb->len <= 0) {
			printk(KERN_WARNING "%s: skb too small\n",
			       __func__);
			break;
		}
		if (skb->len > MAX_DFRAME_LEN_L1 || skb->len > L1OIP_MAX_LEN) {
			printk(KERN_WARNING "%s: skb too large\n",
			       __func__);
			break;
		}
		/* check for AIS / ulaw-silence */
		l = skb->len;
		if (!memchr_inv(skb->data, 0xff, l)) {
			if ((*klpe_debug) & DEBUG_L1OIP_MSG)
				printk(KERN_DEBUG "%s: got AIS, not sending, "
				       "but counting\n", __func__);
			hc->chan[bch->slot].tx_counter += l;
			skb_trim(skb, 0);
			(*klpe_queue_ch_frame)(ch, PH_DATA_CNF, hh->id, skb);
			return 0;
		}
		/* check for silence */
		l = skb->len;
		if (!memchr_inv(skb->data, 0x2a, l)) {
			if ((*klpe_debug) & DEBUG_L1OIP_MSG)
				printk(KERN_DEBUG "%s: got silence, not sending"
				       ", but counting\n", __func__);
			hc->chan[bch->slot].tx_counter += l;
			skb_trim(skb, 0);
			(*klpe_queue_ch_frame)(ch, PH_DATA_CNF, hh->id, skb);
			return 0;
		}

		/* send frame */
		p = skb->data;
		l = skb->len;
		while (l) {
			ll = (l < L1OIP_MAX_PERFRAME) ? l : L1OIP_MAX_PERFRAME;
			klpr_l1oip_socket_send(hc, hc->codec, bch->slot, 0,
					  hc->chan[bch->slot].tx_counter, p, ll);
			hc->chan[bch->slot].tx_counter += ll;
			p += ll;
			l -= ll;
		}
		skb_trim(skb, 0);
		(*klpe_queue_ch_frame)(ch, PH_DATA_CNF, hh->id, skb);
		return 0;
	case PH_ACTIVATE_REQ:
		if ((*klpe_debug) & (DEBUG_L1OIP_MSG | DEBUG_L1OIP_SOCKET))
			printk(KERN_DEBUG "%s: PH_ACTIVATE channel %d (1..%d)\n"
			       , __func__, bch->slot, hc->b_num + 1);
		hc->chan[bch->slot].codecstate = 0;
		test_and_set_bit(FLG_ACTIVE, &bch->Flags);
		skb_trim(skb, 0);
		(*klpe_queue_ch_frame)(ch, PH_ACTIVATE_IND, hh->id, skb);
		return 0;
	case PH_DEACTIVATE_REQ:
		if ((*klpe_debug) & (DEBUG_L1OIP_MSG | DEBUG_L1OIP_SOCKET))
			printk(KERN_DEBUG "%s: PH_DEACTIVATE channel %d "
			       "(1..%d)\n", __func__, bch->slot,
			       hc->b_num + 1);
		test_and_clear_bit(FLG_ACTIVE, &bch->Flags);
		skb_trim(skb, 0);
		(*klpe_queue_ch_frame)(ch, PH_DEACTIVATE_IND, hh->id, skb);
		return 0;
	}
	if (!ret)
		dev_kfree_skb(skb);
	return ret;
}

static void
klpp_release_card(struct l1oip *hc)
{
	int	ch;
	bool thread_was_alive = hc->socket_thread != NULL;

	klp_bsc1204432_shared_state->shutdown[hc->idx] = true;

	if (hc->socket_thread) {
		send_sig(SIGTERM, hc->socket_thread, 0);
		wait_for_completion(&hc->socket_complete);
	}

	del_timer_sync(&hc->keep_tl);
	del_timer_sync(&hc->timeout_tl);

	cancel_work_sync(&hc->workq);

	if (thread_was_alive)
		(*klpe_l1oip_socket_close)(hc);

	if (hc->registered && hc->chan[hc->d_idx].dch)
		(*klpe_mISDN_unregister_device)(&hc->chan[hc->d_idx].dch->dev);
	for (ch = 0; ch < 128; ch++) {
		if (hc->chan[ch].dch) {
			(*klpe_mISDN_freedchannel)(hc->chan[ch].dch);
			kfree(hc->chan[ch].dch);
		}
		if (hc->chan[ch].bch) {
			(*klpe_mISDN_freebchannel)(hc->chan[ch].bch);
			kfree(hc->chan[ch].bch);
#ifdef REORDER_DEBUG
#error "klp-ccp: non-taken branch"
#endif
		}
	}

	spin_lock(&(*klpe_l1oip_lock));
	list_del(&hc->list);
	spin_unlock(&(*klpe_l1oip_lock));

	kfree(hc);
}

void
klpp_l1oip_cleanup(void)
{
	struct l1oip *hc, *next;

	list_for_each_entry_safe(hc, next, &(*klpe_l1oip_ilist), list)
		klpp_release_card(hc);

	(*klpe_l1oip_4bit_free)();
}



#define LP_MODULE "l1oip"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1204432.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "debug", (void *)&klpe_debug, "l1oip" },
	{ "l1oip_4bit_free", (void *)&klpe_l1oip_4bit_free, "l1oip" },
	{ "l1oip_alaw_to_ulaw", (void *)&klpe_l1oip_alaw_to_ulaw, "l1oip" },
	{ "l1oip_ilist", (void *)&klpe_l1oip_ilist, "l1oip" },
	{ "l1oip_law_to_4bit", (void *)&klpe_l1oip_law_to_4bit, "l1oip" },
	{ "l1oip_lock", (void *)&klpe_l1oip_lock, "l1oip" },
	{ "l1oip_socket_close", (void *)&klpe_l1oip_socket_close, "l1oip" },
	{ "l1oip_ulaw_to_alaw", (void *)&klpe_l1oip_ulaw_to_alaw, "l1oip" },
	{ "mISDN_freebchannel", (void *)&klpe_mISDN_freebchannel,
	  "mISDN_core" },
	{ "mISDN_freedchannel", (void *)&klpe_mISDN_freedchannel,
	  "mISDN_core" },
	{ "mISDN_unregister_device", (void *)&klpe_mISDN_unregister_device,
	  "mISDN_core" },
	{ "queue_ch_frame", (void *)&klpe_queue_ch_frame, "mISDN_core" },
	{ "ulaw", (void *)&klpe_ulaw, "l1oip" },
};

static int livepatch_bsc1204432_module_notify(struct notifier_block *nb,
					unsigned long action, void *data)
{
	struct module *mod = data;
	int ret, i;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;

	for (i = 0; i < KLPR_MAX_CARDS; i++)
		klp_bsc1204432_shared_state->shutdown[i] = false;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = livepatch_bsc1204432_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1204432_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	ret = __klp_bsc1204432_get_shared_state();
	if (ret)
		goto out;
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret) {
			__klp_bsc1204432_put_shared_state();
			goto out;
		}
	}

	ret = register_module_notifier(&module_nb);
	if (ret)
		__klp_bsc1204432_put_shared_state();
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1204432_cleanup(void)
{
	unregister_module_notifier(&module_nb);
	mutex_lock(&module_mutex);
	__klp_bsc1204432_put_shared_state();
	mutex_unlock(&module_mutex);
}

#endif /* IS_ENABLED(CONFIG_MISDN_L1OIP) */
