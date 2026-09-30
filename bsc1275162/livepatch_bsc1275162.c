/*
 * livepatch_bsc1275162
 *
 * Fix for CVE-2026-68202, bsc#1275162
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

#if IS_ENABLED(CONFIG_SND_SEQUENCER)

#if !IS_MODULE(CONFIG_SND_SEQUENCER)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1275162.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from sound/core/seq/seq_timer.c */
#include <sound/core.h>
#include <linux/slab.h>
/* klp-ccp: from sound/core/seq/seq_timer.h */
#include <sound/timer.h>

/* klp-ccp: from include/sound/timer.h */
static int (*klpe_snd_timer_close)(struct snd_timer_instance *timeri);

/* klp-ccp: from sound/core/seq/seq_timer.h */
#include <sound/seq_kernel.h>

struct snd_seq_timer_tick {
	snd_seq_tick_time_t	cur_tick;	/* current tick */
	unsigned long		resolution;	/* time per tick in nsec */
	unsigned long		fraction;	/* current time per tick in nsec */
};

struct snd_seq_timer {
	/* ... tempo / offset / running state */

	unsigned int		running:1,	/* running state of queue */	
				initialized:1;	/* timer is initialized */

	unsigned int		tempo;		/* current tempo, us/tick */
	int			ppq;		/* time resolution, ticks/quarter */

	snd_seq_real_time_t	cur_time;	/* current time */
	struct snd_seq_timer_tick	tick;	/* current tick */
	int tick_updated;
	
	int			type;		/* timer type */
	struct snd_timer_id	alsa_id;	/* ALSA's timer ID */
	struct snd_timer_instance	*timeri;	/* timer instance */
	unsigned int		ticks;
	unsigned long		preferred_resolution; /* timer resolution, ticks/sec */

	unsigned int skew;
	unsigned int skew_base;

	struct timespec64	last_update;	 /* time of last clock update, used for interpolation */

	spinlock_t lock;
};
static void (*klpe_snd_seq_timer_reset)(struct snd_seq_timer *tmr);
static int (*klpe_snd_seq_timer_stop)(struct snd_seq_timer *tmr);

/* klp-ccp: from sound/core/seq/seq_memory.h */
#include <sound/seq_kernel.h>
#include <linux/poll.h>
/* klp-ccp: from sound/core/seq/seq_lock.h */
#include <linux/sched.h>
/* klp-ccp: from sound/core/seq/seq_queue.h */
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/bitops.h>
/* klp-ccp: from sound/core/seq/seq_info.h */
#include <sound/info.h>
#include <sound/seq_kernel.h>

/* klp-ccp: from sound/core/seq/seq_timer.c */
void klpp_snd_seq_timer_delete(struct snd_seq_timer **tmr)
{
	struct snd_seq_timer *t = *tmr;
	struct snd_timer_instance *ti;

	if (t == NULL) {
		pr_debug("ALSA: seq: snd_seq_timer_delete() called with NULL timer\n");
		return;
	}

	spin_lock_irq(&t->lock);
	ti = t->timeri;
	t->timeri = NULL;
	spin_unlock_irq(&t->lock);

	if (ti) {
		(*klpe_snd_timer_close)(ti);
		//snd_timer_instance_free(t); // FIXME: need 6a34367e52ca backport
	}

	*tmr = NULL;
	t->running = 0;

	/* reset time */
	(*klpe_snd_seq_timer_stop)(t);
	(*klpe_snd_seq_timer_reset)(t);

	kfree(t);
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "snd_seq"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_seq_timer_reset", (void *)&klpe_snd_seq_timer_reset,
	  "snd_seq" },
	{ "snd_seq_timer_stop", (void *)&klpe_snd_seq_timer_stop, "snd_seq" },
	{ "snd_timer_close", (void *)&klpe_snd_timer_close, "snd_timer" },
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

int livepatch_bsc1275162_init(void)
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

void livepatch_bsc1275162_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_SEQUENCER) */
