/*
 * livepatch_bsc1265127
 *
 * Fix for CVE-2026-43437, bsc#1265127
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_SND_PCM)

#if !IS_MODULE(CONFIG_SND_PCM)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1265127.h"

/* klp-ccp: from sound/core/pcm_native.c */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/time.h>
#include <linux/pm_qos.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <sound/core.h>
#include <sound/control.h>
#include <sound/info.h>
#include <sound/pcm.h>

/* klp-ccp: from include/sound/pcm.h */
static int (*klpe_snd_pcm_stop)(struct snd_pcm_substream *substream, snd_pcm_state_t status);

static void (*klpe_snd_pcm_stream_lock_irq)(struct snd_pcm_substream *substream);
static void (*klpe_snd_pcm_stream_unlock_irq)(struct snd_pcm_substream *substream);

/* klp-ccp: from sound/core/pcm_native.c */
#include <sound/pcm_params.h>
#include <sound/timer.h>
#include <sound/minors.h>
#include <linux/uio.h>
#include <linux/delay.h>

static struct rw_semaphore (*klpe_snd_pcm_link_rwsem);

struct action_ops {
	int (*pre_action)(struct snd_pcm_substream *substream, int state);
	int (*do_action)(struct snd_pcm_substream *substream, int state);
	void (*undo_action)(struct snd_pcm_substream *substream, int state);
	void (*post_action)(struct snd_pcm_substream *substream, int state);
};

static int (*klpe_snd_pcm_action)(const struct action_ops *ops,
			  struct snd_pcm_substream *substream,
			  int state);

static const struct action_ops (*klpe_snd_pcm_action_pause);

static int klpr_snd_pcm_pause(struct snd_pcm_substream *substream, int push)
{
	return (*klpe_snd_pcm_action)(&(*klpe_snd_pcm_action_pause), substream, push);
}

static const struct action_ops (*klpe_snd_pcm_action_drain_init);

int klpp_snd_pcm_drain(struct snd_pcm_substream *substream,
			 struct file *file)
{
	struct snd_card *card;
	struct snd_pcm_runtime *runtime;
	struct snd_pcm_substream *s;
	wait_queue_entry_t wait;
	int result = 0;
	int nonblock = 0;

	card = substream->pcm->card;
	runtime = substream->runtime;

	if (runtime->status->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;

	if (file) {
		if (file->f_flags & O_NONBLOCK)
			nonblock = 1;
	} else if (substream->f_flags & O_NONBLOCK)
		nonblock = 1;

	down_read(&(*klpe_snd_pcm_link_rwsem));
	(*klpe_snd_pcm_stream_lock_irq)(substream);
	/* resume pause */
	if (runtime->status->state == SNDRV_PCM_STATE_PAUSED)
		klpr_snd_pcm_pause(substream, 0);

	/* pre-start/stop - all running streams are changed to DRAINING state */
	result = (*klpe_snd_pcm_action)(&(*klpe_snd_pcm_action_drain_init), substream, 0);
	if (result < 0)
		goto unlock;
	/* in non-blocking, we don't wait in ioctl but let caller poll */
	if (nonblock) {
		result = -EAGAIN;
		goto unlock;
	}

	for (;;) {
		long tout;
		struct snd_pcm_runtime *to_check;
		unsigned int drain_rate;
		snd_pcm_uframes_t drain_periodsz;
		bool drain_no_period_wakeup;

		if (signal_pending(current)) {
			result = -ERESTARTSYS;
			break;
		}
		/* find a substream to drain */
		to_check = NULL;
		snd_pcm_group_for_each_entry(s, substream) {
			if (s->stream != SNDRV_PCM_STREAM_PLAYBACK)
				continue;
			runtime = s->runtime;
			if (runtime->status->state == SNDRV_PCM_STATE_DRAINING) {
				to_check = runtime;
				break;
			}
		}
		if (!to_check)
			break; /* all drained */
		/*
		 * Cache the runtime fields needed after unlock.
		 * A concurrent close() on the linked stream may free
		 * its runtime via snd_pcm_detach_substream() once we
		 * release the stream lock below.
		 */
		drain_no_period_wakeup = to_check->no_period_wakeup;
		drain_rate = to_check->rate;
		drain_periodsz = to_check->period_size;
		init_waitqueue_entry(&wait, current);
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&to_check->sleep, &wait);
		(*klpe_snd_pcm_stream_unlock_irq)(substream);
		up_read(&(*klpe_snd_pcm_link_rwsem));
		if (drain_no_period_wakeup)
			tout = MAX_SCHEDULE_TIMEOUT;
		else {
			tout = 10;
			if (drain_rate) {
				long t = drain_periodsz * 2 / drain_rate;
				tout = max(t, tout);
			}
			tout = msecs_to_jiffies(tout * 1000);
		}
		tout = schedule_timeout(tout);
		down_read(&(*klpe_snd_pcm_link_rwsem));
		(*klpe_snd_pcm_stream_lock_irq)(substream);
		remove_wait_queue(&to_check->sleep, &wait);
		if (card->shutdown) {
			result = -ENODEV;
			break;
		}
		if (tout == 0) {
			if (substream->runtime->status->state == SNDRV_PCM_STATE_SUSPENDED)
				result = -ESTRPIPE;
			else {
				dev_dbg(substream->pcm->card->dev,
					"playback drain error (DMA or IRQ trouble?)\n");
				(*klpe_snd_pcm_stop)(substream, SNDRV_PCM_STATE_SETUP);
				result = -EIO;
			}
			break;
		}
	}

 unlock:
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	up_read(&(*klpe_snd_pcm_link_rwsem));

	return result;
}

#ifdef CONFIG_COMPAT

/* klp-ccp: from sound/core/pcm_compat.c */
#include <linux/compat.h>
#include <linux/slab.h>

/* klp-ccp: from sound/core/pcm_native.c */
#else
#error "klp-ccp: non-taken branch"
#endif


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "snd_pcm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_pcm_action", (void *)&klpe_snd_pcm_action, "snd_pcm" },
	{ "snd_pcm_action_drain_init", (void *)&klpe_snd_pcm_action_drain_init,
	  "snd_pcm" },
	{ "snd_pcm_action_pause", (void *)&klpe_snd_pcm_action_pause,
	  "snd_pcm" },
	{ "snd_pcm_link_rwsem", (void *)&klpe_snd_pcm_link_rwsem, "snd_pcm" },
	{ "snd_pcm_stop", (void *)&klpe_snd_pcm_stop, "snd_pcm" },
	{ "snd_pcm_stream_lock_irq", (void *)&klpe_snd_pcm_stream_lock_irq,
	  "snd_pcm" },
	{ "snd_pcm_stream_unlock_irq", (void *)&klpe_snd_pcm_stream_unlock_irq,
	  "snd_pcm" },
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

int livepatch_bsc1265127_init(void)
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

void livepatch_bsc1265127_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_PCM) */
