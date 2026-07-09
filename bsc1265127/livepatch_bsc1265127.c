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
#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/time.h>
#include <linux/pm_qos.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/vmalloc.h>
#include <sound/core.h>
#include <sound/control.h>
#include <sound/info.h>
#include <sound/pcm.h>
#include <sound/pcm_params.h>
#include <sound/timer.h>
#include <sound/minors.h>
#include <linux/uio.h>
#include <linux/delay.h>
#include <linux/bitops.h>

#define DEFINE_PCM_GROUP_LOCK(action, mutex_action) \
static void snd_pcm_group_ ## action(struct snd_pcm_group *group, bool nonatomic) \
{ \
	if (nonatomic) \
		mutex_ ## mutex_action(&group->mutex); \
	else \
		spin_ ## action(&group->lock); \
}

DEFINE_PCM_GROUP_LOCK(unlock, unlock)

void snd_pcm_stream_lock_irq(struct snd_pcm_substream *substream);

extern typeof(snd_pcm_stream_lock_irq) snd_pcm_stream_lock_irq;

void snd_pcm_stream_unlock_irq(struct snd_pcm_substream *substream);

extern typeof(snd_pcm_stream_unlock_irq) snd_pcm_stream_unlock_irq;

#define ACTION_ARG_IGNORE	(__force snd_pcm_state_t)0

struct action_ops {
	int (*pre_action)(struct snd_pcm_substream *substream,
			  snd_pcm_state_t state);
	int (*do_action)(struct snd_pcm_substream *substream,
			 snd_pcm_state_t state);
	void (*undo_action)(struct snd_pcm_substream *substream,
			    snd_pcm_state_t state);
	void (*post_action)(struct snd_pcm_substream *substream,
			    snd_pcm_state_t state);
};

static void snd_pcm_group_unref(struct snd_pcm_group *group,
				struct snd_pcm_substream *substream)
{
	bool do_free;

	if (!group)
		return;
	do_free = refcount_dec_and_test(&group->refs);
	snd_pcm_group_unlock(group, substream->pcm->nonatomic);
	if (do_free)
		kfree(group);
}

extern struct snd_pcm_group *
snd_pcm_stream_group_ref(struct snd_pcm_substream *substream);

extern int snd_pcm_action(const struct action_ops *ops,
			  struct snd_pcm_substream *substream,
			  snd_pcm_state_t state);

int snd_pcm_stop(struct snd_pcm_substream *substream, snd_pcm_state_t state);

extern typeof(snd_pcm_stop) snd_pcm_stop;

extern const struct action_ops snd_pcm_action_pause;

static int snd_pcm_pause(struct snd_pcm_substream *substream, bool push)
{
	return snd_pcm_action(&snd_pcm_action_pause, substream,
			      (__force snd_pcm_state_t)push);
}

extern const struct action_ops snd_pcm_action_drain_init;

int klpp_snd_pcm_drain(struct snd_pcm_substream *substream,
			 struct file *file)
{
	struct snd_card *card;
	struct snd_pcm_runtime *runtime;
	struct snd_pcm_substream *s;
	struct snd_pcm_group *group;
	wait_queue_entry_t wait;
	int result = 0;
	int nonblock = 0;

	card = substream->pcm->card;
	runtime = substream->runtime;

	if (runtime->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;

	if (file) {
		if (file->f_flags & O_NONBLOCK)
			nonblock = 1;
	} else if (substream->f_flags & O_NONBLOCK)
		nonblock = 1;

	snd_pcm_stream_lock_irq(substream);
	/* resume pause */
	if (runtime->state == SNDRV_PCM_STATE_PAUSED)
		snd_pcm_pause(substream, false);

	/* pre-start/stop - all running streams are changed to DRAINING state */
	result = snd_pcm_action(&snd_pcm_action_drain_init, substream,
				ACTION_ARG_IGNORE);
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
		snd_pcm_uframes_t drain_bufsz;
		bool drain_no_period_wakeup;

		if (signal_pending(current)) {
			result = -ERESTARTSYS;
			break;
		}
		/* find a substream to drain */
		to_check = NULL;
		group = snd_pcm_stream_group_ref(substream);
		snd_pcm_group_for_each_entry(s, substream) {
			if (s->stream != SNDRV_PCM_STREAM_PLAYBACK)
				continue;
			runtime = s->runtime;
			if (runtime->state == SNDRV_PCM_STATE_DRAINING) {
				to_check = runtime;
				break;
			}
		}
		snd_pcm_group_unref(group, substream);
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
		drain_bufsz = to_check->buffer_size;
		init_waitqueue_entry(&wait, current);
		set_current_state(TASK_INTERRUPTIBLE);
		add_wait_queue(&to_check->sleep, &wait);
		snd_pcm_stream_unlock_irq(substream);
		if (drain_no_period_wakeup)
			tout = MAX_SCHEDULE_TIMEOUT;
		else {
			tout = 100;
			if (drain_rate) {
				long t = drain_bufsz * 1100 / drain_rate;
				tout = max(t, tout);
			}
			tout = msecs_to_jiffies(tout);
		}
		tout = schedule_timeout(tout);

		snd_pcm_stream_lock_irq(substream);
		group = snd_pcm_stream_group_ref(substream);
		snd_pcm_group_for_each_entry(s, substream) {
			if (s->runtime == to_check) {
				remove_wait_queue(&to_check->sleep, &wait);
				break;
			}
		}
		snd_pcm_group_unref(group, substream);

		if (card->shutdown) {
			result = -ENODEV;
			break;
		}
		if (tout == 0) {
			if (substream->runtime->state == SNDRV_PCM_STATE_SUSPENDED)
				result = -ESTRPIPE;
			else {
				dev_dbg(substream->pcm->card->dev,
					"playback drain timeout (DMA or IRQ trouble?)\n");
				snd_pcm_stop(substream, SNDRV_PCM_STATE_SETUP);
				result = -EIO;
			}
			break;
		}
	}

 unlock:
	snd_pcm_stream_unlock_irq(substream);

	return result;
}

#ifdef CONFIG_COMPAT

/* klp-ccp: from sound/core/pcm_compat.c */
#include <linux/compat.h>
#include <linux/slab.h>

#endif


#include <linux/livepatch.h>

extern typeof(snd_pcm_action) snd_pcm_action
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_action);
extern typeof(snd_pcm_action_drain_init) snd_pcm_action_drain_init
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_action_drain_init);
extern typeof(snd_pcm_action_pause) snd_pcm_action_pause
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_action_pause);
extern typeof(snd_pcm_stop) snd_pcm_stop
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_stop);
extern typeof(snd_pcm_stream_group_ref) snd_pcm_stream_group_ref
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_stream_group_ref);
extern typeof(snd_pcm_stream_lock_irq) snd_pcm_stream_lock_irq
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_stream_lock_irq);
extern typeof(snd_pcm_stream_unlock_irq) snd_pcm_stream_unlock_irq
	 KLP_RELOC_SYMBOL(snd_pcm, snd_pcm, snd_pcm_stream_unlock_irq);

#endif /* IS_ENABLED(CONFIG_SND_PCM) */
