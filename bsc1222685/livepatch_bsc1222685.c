/*
 * livepatch_bsc1222685
 *
 * Fix for CVE-2023-6546, bsc#1222685
 *
 *  Upstream commit:
 *  67c37756898a ("tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc")
 *
 *  SLE12-SP5 commit:
 *  94fc6e948ed337da73b3483f4ef330510dfbbb8e
 *
 *  SLE15-SP2 and -SP3 commit:
 *  94fc6e948ed337da73b3483f4ef330510dfbbb8e
 *
 *  SLE15-SP4 and -SP5 commit:
 *  94fc6e948ed337da73b3483f4ef330510dfbbb8e
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from drivers/tty/n_gsm.c */
#include <linux/sched/signal.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/tty_driver.h>

/* klp-ccp: from drivers/tty/n_gsm.c */
#include <linux/netdevice.h>

#define T1	10		/* 100mS */
#define T2	34		/* 333mS */
#define N2	3		/* Retry 3 times */

#define MAX_MRU 1500

#define NUM_DLCI		64

struct gsm_mux {
	struct tty_struct *tty;		/* The tty our ldisc is bound to */
	spinlock_t lock;
	struct mutex mutex;
	unsigned int num;
	struct kref ref;

	/* Events on the GSM channel */
	wait_queue_head_t event;

	/* Bits for GSM mode decoding */

	/* Framing Layer */
	unsigned char *buf;
	int state;
	unsigned int len;
	unsigned int address;
	unsigned int count;
	int escape;
	int encoding;
	u8 control;
	u8 fcs;
	u8 received_fcs;
	u8 *txframe;			/* TX framing buffer */

	/* Methods for the receiver side */
	void (*receive)(struct gsm_mux *gsm, u8 ch);
	void (*error)(struct gsm_mux *gsm, u8 ch, u8 flag);
	/* And transmit side */
	int (*output)(struct gsm_mux *mux, u8 *data, int len);

	/* Link Layer */
	unsigned int mru;
	unsigned int mtu;
	int initiator;			/* Did we initiate connection */
	int dead;			/* Has the mux been shut down */
	struct gsm_dlci *dlci[NUM_DLCI];
	int constipated;		/* Asked by remote to shut up */

	spinlock_t tx_lock;
	unsigned int tx_bytes;		/* TX data outstanding */
	struct list_head tx_list;	/* Pending data packets */

	/* Control messages */
	struct timer_list t2_timer;	/* Retransmit timer for commands */
	int cretries;			/* Command retry counter */
	struct gsm_control *pending_cmd;/* Our current pending command */
	spinlock_t control_lock;	/* Protects the pending command */

	/* Configuration */
	int adaption;		/* 1 or 2 supported */
	u8 ftype;		/* UI or UIH */
	int t1, t2;		/* Timers in 1/100th of a sec */
	int n2;			/* Retry count */

	/* Statistics (not currently exposed) */
	unsigned long bad_fcs;
	unsigned long malformed;
	unsigned long io_error;
	unsigned long bad_size;
	unsigned long unsupported;
};

static struct tty_driver *(*klpe_gsm_tty_driver);

#define	UIH			0xEF

static void (*klpe_gsm_cleanup_mux)(struct gsm_mux *gsm);

static int (*klpe_gsm_activate_mux)(struct gsm_mux *gsm);

static void gsm_free_mux(struct gsm_mux *gsm)
{
	kfree(gsm->txframe);
	kfree(gsm->buf);
	kfree(gsm);
}

static void gsm_free_muxr(struct kref *ref)
{
	struct gsm_mux *gsm = container_of(ref, struct gsm_mux, ref);
	gsm_free_mux(gsm);
}

static inline void mux_put(struct gsm_mux *gsm)
{
	kref_put(&gsm->ref, gsm_free_muxr);
}

static struct gsm_mux *gsm_alloc_mux(void)
{
	struct gsm_mux *gsm = kzalloc(sizeof(struct gsm_mux), GFP_KERNEL);
	if (gsm == NULL)
		return NULL;
	gsm->buf = kmalloc(MAX_MRU + 1, GFP_KERNEL);
	if (gsm->buf == NULL) {
		kfree(gsm);
		return NULL;
	}
	gsm->txframe = kmalloc(2 * MAX_MRU + 2, GFP_KERNEL);
	if (gsm->txframe == NULL) {
		kfree(gsm->buf);
		kfree(gsm);
		return NULL;
	}
	spin_lock_init(&gsm->lock);
	mutex_init(&gsm->mutex);
	kref_init(&gsm->ref);
	INIT_LIST_HEAD(&gsm->tx_list);

	gsm->t1 = T1;
	gsm->t2 = T2;
	gsm->n2 = N2;
	gsm->ftype = UIH;
	gsm->adaption = 1;
	gsm->encoding = 1;
	gsm->mru = 64;	/* Default to encoding 1 so these should be 64 */
	gsm->mtu = 64;
	gsm->dead = 1;	/* Avoid early tty opens */

	return gsm;
}

static int (*klpe_gsmld_output)(struct gsm_mux *gsm, u8 *data, int len);

static int klpr_gsmld_attach_gsm(struct tty_struct *tty, struct gsm_mux *gsm)
{
	int ret, i, base;

	gsm->tty = tty_kref_get(tty);
	gsm->output = (*klpe_gsmld_output);
	ret =  (*klpe_gsm_activate_mux)(gsm);
	if (ret != 0)
		tty_kref_put(gsm->tty);
	else {
		/* Don't register device 0 - this is the control channel and not
		   a usable tty interface */
		base = gsm->num << 6; /* Base for this MUX */
		for (i = 1; i < NUM_DLCI; i++)
			tty_register_device((*klpe_gsm_tty_driver), base + i, NULL);
	}
	return ret;
}

int klpp_gsmld_open(struct tty_struct *tty)
{
	struct gsm_mux *gsm;
	int ret;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (tty->ops->write == NULL)
		return -EINVAL;

	/* Attach our ldisc data */
	gsm = gsm_alloc_mux();
	if (gsm == NULL)
		return -ENOMEM;

	tty->disc_data = gsm;
	tty->receive_room = 65536;

	/* Attach the initial passive connection */
	gsm->encoding = 1;

	ret = klpr_gsmld_attach_gsm(tty, gsm);
	if (ret != 0) {
		(*klpe_gsm_cleanup_mux)(gsm);
		mux_put(gsm);
	}
	return ret;
}



#include "livepatch_bsc1222685.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "n_gsm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "gsm_activate_mux", (void *)&klpe_gsm_activate_mux, "n_gsm" },
	{ "gsm_cleanup_mux", (void *)&klpe_gsm_cleanup_mux, "n_gsm" },
	{ "gsm_tty_driver", (void *)&klpe_gsm_tty_driver, "n_gsm" },
	{ "gsmld_output", (void *)&klpe_gsmld_output, "n_gsm" },
};

static int module_notify(struct notifier_block *nb,
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
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1222685_init(void)
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

void livepatch_bsc1222685_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
