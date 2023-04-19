/*
 * livepatch_bsc1208910
 *
 * Fix for CVE-2023-1118, bsc#1208910
 *
 *  Upstream commit:
 *  29b0589a865b ("media: rc: Fix use-after-free bugs caused by ene_tx_irqsim()")
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  e7939530329d29872d78ac45c01c4eaef0c08d0e
 *
 *  SLE15-SP2 and -SP3 commit:
 *  52c897ac6c6eac30f90c5b71d93d3a78fcd97485
 *
 *  SLE15-SP4 commit:
 *  778b9f29243ffb325f11007c77bce7d1aa1c7be2
 *  dde5a3556c0b2c1acb799ee9b579fe71286e2992
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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

#if IS_ENABLED(CONFIG_IR_ENE)

#if !IS_MODULE(CONFIG_IR_ENE)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/media/rc/ene_ir.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pnp.h>

#include <linux/io.h>

/* klp-ccp: from drivers/media/rc/ene_ir.c */
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <media/rc-core.h>

/* klp-ccp: from include/media/rc-core.h */
static void (*klpe_rc_unregister_device)(struct rc_dev *dev);

/* klp-ccp: from drivers/media/rc/ene_ir.h */
#include <linux/spinlock.h>

#define ENE_IO_SIZE		4

#define ENE_FW_SAMPLE_BUFFER	0xF8F0	/* sample buffer */

#define ENE_FW1			0xF8F8  /* flagr */

#define ENE_FW1_EXTRA_BUF_HND	0x08	/* extra buffer handshake bit*/

struct ene_device {
	struct pnp_dev *pnp_dev;
	struct rc_dev *rdev;

	/* hw IO settings */
	long hw_io;
	int irq;
	spinlock_t hw_lock;

	/* HW features */
	int hw_revision;			/* hardware revision */
	bool hw_use_gpio_0a;			/* gpio0a is demodulated input*/
	bool hw_extra_buffer;			/* hardware has 'extra buffer' */
	bool hw_fan_input;			/* fan input is IR data source */
	bool hw_learning_and_tx_capable;	/* learning & tx capable */
	int  pll_freq;
	int buffer_len;

	/* Extra RX buffer location */
	int extra_buf1_address;
	int extra_buf1_len;
	int extra_buf2_address;
	int extra_buf2_len;

	/* HW state*/
	int r_pointer;				/* pointer to next sample to read */
	int w_pointer;				/* pointer to next sample hw will write */
	bool rx_fan_input_inuse;		/* is fan input in use for rx*/
	int tx_reg;				/* current reg used for TX */
	u8  saved_conf1;			/* saved FEC0 reg */
	unsigned int tx_sample;			/* current sample for TX */
	bool tx_sample_pulse;			/* current sample is pulse */

	/* TX buffer */
	unsigned *tx_buffer;			/* input samples buffer*/
	int tx_pos;				/* position in that buffer */
	int tx_len;				/* current len of tx buffer */
	int tx_done;				/* done transmitting */
						/* one more sample pending*/
	struct completion tx_complete;		/* TX completion */
	struct timer_list tx_sim_timer;

	/* TX settings */
	int tx_period;
	int tx_duty_cycle;
	int transmitter_mask;

	/* RX settings */
	bool learning_mode_enabled;		/* learning input enabled */
	bool carrier_detect_enabled;		/* carrier detect enabled */
	int rx_period_adjust;
	bool rx_enabled;
};

/* klp-ccp: from drivers/media/rc/ene_ir.c */
static void (*klpe_ene_write_reg)(struct ene_device *dev, u16 reg, u8 value);

static void (*klpe_ene_clear_reg_mask)(struct ene_device *dev, u16 reg, u8 mask);

static void klpr_ene_rx_restore_hw_buffer(struct ene_device *dev)
{
	if (!dev->hw_extra_buffer)
		return;

	(*klpe_ene_write_reg)(dev, ENE_FW_SAMPLE_BUFFER + 0,
				dev->extra_buf1_address & 0xFF);
	(*klpe_ene_write_reg)(dev, ENE_FW_SAMPLE_BUFFER + 1,
				dev->extra_buf1_address >> 8);
	(*klpe_ene_write_reg)(dev, ENE_FW_SAMPLE_BUFFER + 2, dev->extra_buf1_len);

	(*klpe_ene_write_reg)(dev, ENE_FW_SAMPLE_BUFFER + 3,
				dev->extra_buf2_address & 0xFF);
	(*klpe_ene_write_reg)(dev, ENE_FW_SAMPLE_BUFFER + 4,
				dev->extra_buf2_address >> 8);
	(*klpe_ene_write_reg)(dev, ENE_FW_SAMPLE_BUFFER + 5,
				dev->extra_buf2_len);
	(*klpe_ene_clear_reg_mask)(dev, ENE_FW1, ENE_FW1_EXTRA_BUF_HND);
}

static void (*klpe_ene_rx_disable_hw)(struct ene_device *dev);

static void klpr_ene_rx_disable(struct ene_device *dev)
{
	(*klpe_ene_rx_disable_hw)(dev);
	dev->rx_enabled = false;
}

void klpp_ene_remove(struct pnp_dev *pnp_dev)
{
	struct ene_device *dev = pnp_get_drvdata(pnp_dev);
	unsigned long flags;

	(*klpe_rc_unregister_device)(dev->rdev);
	del_timer_sync(&dev->tx_sim_timer);
	spin_lock_irqsave(&dev->hw_lock, flags);
	klpr_ene_rx_disable(dev);
	klpr_ene_rx_restore_hw_buffer(dev);
	spin_unlock_irqrestore(&dev->hw_lock, flags);

	free_irq(dev->irq, dev);
	release_region(dev->hw_io, ENE_IO_SIZE);
	kfree(dev);
}



#define LP_MODULE "ene_ir"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1208910.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "ene_clear_reg_mask", (void *)&klpe_ene_clear_reg_mask, "ene_ir" },
	{ "ene_rx_disable_hw", (void *)&klpe_ene_rx_disable_hw, "ene_ir" },
	{ "ene_write_reg", (void *)&klpe_ene_write_reg, "ene_ir" },
	{ "rc_unregister_device", (void *)&klpe_rc_unregister_device,
	  "rc_core" },
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

int livepatch_bsc1208910_init(void)
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

void livepatch_bsc1208910_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_IR_ENE) */
