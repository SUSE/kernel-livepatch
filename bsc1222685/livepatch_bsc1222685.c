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
#include <linux/types.h>
#include <linux/major.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/fcntl.h>
#include <linux/sched/signal.h>
#include <linux/interrupt.h>
#include <linux/tty.h>

/* klp-ccp: from drivers/tty/n_gsm.c */
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
#define MAX_MTU 1500

#define PROT_OVERHEAD 7

#define NUM_DLCI		64

enum gsm_mux_state {
	GSM_SEARCH,
	GSM_START,
	GSM_ADDRESS,
	GSM_CONTROL,
	GSM_LEN,
	GSM_DATA,
	GSM_FCS,
	GSM_OVERRUN,
	GSM_LEN0,
	GSM_LEN1,
	GSM_SSOF,
};

struct gsm_mux {
	struct tty_struct *tty;		/* The tty our ldisc is bound to */
	spinlock_t lock;
	struct mutex mutex;
	unsigned int num;
	struct kref ref;

	/* Events on the GSM channel */
	wait_queue_head_t event;

	/* ldisc send work */
	struct work_struct tx_work;

	/* Bits for GSM mode decoding */

	/* Framing Layer */
	unsigned char *buf;
	enum gsm_mux_state state;
	unsigned int len;
	unsigned int address;
	unsigned int count;
	bool escape;
	int encoding;
	u8 control;
	u8 fcs;
	u8 *txframe;			/* TX framing buffer */

	/* Method for the receiver side */
	void (*receive)(struct gsm_mux *gsm, u8 ch);

	/* Link Layer */
	unsigned int mru;
	unsigned int mtu;
	int initiator;			/* Did we initiate connection */
	bool dead;			/* Has the mux been shut down */
	struct gsm_dlci *dlci[NUM_DLCI];
	int old_c_iflag;		/* termios c_iflag value before attach */
	bool constipated;		/* Asked by remote to shut up */
	bool has_devices;		/* Devices were registered */

	spinlock_t tx_lock;
	unsigned int tx_bytes;		/* TX data outstanding */
	struct list_head tx_ctrl_list;	/* Pending control packets */
	struct list_head tx_data_list;	/* Pending data packets */

	/* Control messages */
	struct timer_list kick_timer;	/* Kick TX queuing on timeout */
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

#define MAX_MUX		4			/* 256 minors */
static struct gsm_mux *(*klpe_gsm_mux)[MAX_MUX];
static spinlock_t (*klpe_gsm_mux_lock);

#define	UIH			0xEF

static void (*klpe_gsmld_write_task)(struct work_struct *work);

static void (*klpe_gsm_control_retransmit)(struct timer_list *t);

static void (*klpe_gsm_kick_timer)(struct timer_list *t);

static struct gsm_mux *klpr_gsm_alloc_mux(void)
{
	int i;
	struct gsm_mux *gsm = kzalloc(sizeof(struct gsm_mux), GFP_KERNEL);
	if (gsm == NULL)
		return NULL;
	gsm->buf = kmalloc(MAX_MRU + 1, GFP_KERNEL);
	if (gsm->buf == NULL) {
		kfree(gsm);
		return NULL;
	}
	gsm->txframe = kmalloc(2 * (MAX_MTU + PROT_OVERHEAD - 1), GFP_KERNEL);
	if (gsm->txframe == NULL) {
		kfree(gsm->buf);
		kfree(gsm);
		return NULL;
	}
	spin_lock_init(&gsm->lock);
	mutex_init(&gsm->mutex);
	kref_init(&gsm->ref);
	INIT_LIST_HEAD(&gsm->tx_ctrl_list);
	INIT_LIST_HEAD(&gsm->tx_data_list);
	timer_setup(&gsm->kick_timer, (*klpe_gsm_kick_timer), 0);
	timer_setup(&gsm->t2_timer, (*klpe_gsm_control_retransmit), 0);
	INIT_WORK(&gsm->tx_work, (*klpe_gsmld_write_task));
	init_waitqueue_head(&gsm->event);
	spin_lock_init(&gsm->control_lock);
	spin_lock_init(&gsm->tx_lock);

	gsm->t1 = T1;
	gsm->t2 = T2;
	gsm->n2 = N2;
	gsm->ftype = UIH;
	gsm->adaption = 1;
	gsm->encoding = 1;
	gsm->mru = 64;	/* Default to encoding 1 so these should be 64 */
	gsm->mtu = 64;
	gsm->dead = true;	/* Avoid early tty opens */

	/* Store the instance to the mux array or abort if no space is
	 * available.
	 */
	spin_lock(&(*klpe_gsm_mux_lock));
	for (i = 0; i < MAX_MUX; i++) {
		if (!(*klpe_gsm_mux)[i]) {
			(*klpe_gsm_mux)[i] = gsm;
			gsm->num = i;
			break;
		}
	}
	spin_unlock(&(*klpe_gsm_mux_lock));
	if (i == MAX_MUX) {
		mutex_destroy(&gsm->mutex);
		kfree(gsm->txframe);
		kfree(gsm->buf);
		kfree(gsm);
		return NULL;
	}

	return gsm;
}

static void (*klpe_gsmld_write_task)(struct work_struct *work);

static void gsmld_attach_gsm(struct tty_struct *tty, struct gsm_mux *gsm)
{
	gsm->tty = tty_kref_get(tty);
	/* Turn off tty XON/XOFF handling to handle it explicitly. */
	gsm->old_c_iflag = tty->termios.c_iflag;
	tty->termios.c_iflag &= (IXON | IXOFF);
}

int klpp_gsmld_open(struct tty_struct *tty)
{
	struct gsm_mux *gsm;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (tty->ops->write == NULL)
		return -EINVAL;

	/* Attach our ldisc data */
	gsm = klpr_gsm_alloc_mux();
	if (gsm == NULL)
		return -ENOMEM;

	tty->disc_data = gsm;
	tty->receive_room = 65536;

	/* Attach the initial passive connection */
	gsm->encoding = 1;

	gsmld_attach_gsm(tty, gsm);

	return 0;
}



#include "livepatch_bsc1222685.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "n_gsm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "gsm_control_retransmit", (void *)&klpe_gsm_control_retransmit,
	  "n_gsm" },
	{ "gsm_kick_timer", (void *)&klpe_gsm_kick_timer, "n_gsm" },
	{ "gsm_mux", (void *)&klpe_gsm_mux, "n_gsm" },
	{ "gsm_mux_lock", (void *)&klpe_gsm_mux_lock, "n_gsm" },
	{ "gsmld_write_task", (void *)&klpe_gsmld_write_task, "n_gsm" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

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
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1222685_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
