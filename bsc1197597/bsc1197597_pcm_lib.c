/*
 * bsc1197597_pcm_lib
 *
 * Fix for CVE-2022-1048, bsc#1197597
 *
 *  Copyright (c) 2022 SUSE
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

#if IS_ENABLED(CONFIG_SND_PCM)

#if !IS_MODULE(CONFIG_SND_PCM)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1197597.h"

extern struct klp_bsc1197597_shared_state *klp_bsc1197597_shared_state;

/* klp-ccp: from sound/core/pcm_lib.c */
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/time.h>
#include <linux/math64.h>
#include <linux/export.h>
#include <sound/core.h>
#include <sound/control.h>
#include <sound/tlv.h>

/* klp-ccp: from sound/core/pcm_lib.c */
#include <sound/pcm.h>

/* klp-ccp: from include/sound/pcm.h */
static int (*klpe_snd_pcm_start)(struct snd_pcm_substream *substream);
static int (*klpe_snd_pcm_stop)(struct snd_pcm_substream *substream, snd_pcm_state_t status);

static void (*klpe_snd_pcm_stream_lock_irq)(struct snd_pcm_substream *substream);
static void (*klpe_snd_pcm_stream_unlock_irq)(struct snd_pcm_substream *substream);

/* klp-ccp: from sound/core/pcm_local.h */
static int (*klpe_pcm_lib_apply_appl_ptr)(struct snd_pcm_substream *substream,
			   snd_pcm_uframes_t appl_ptr);
static int (*klpe_snd_pcm_update_state)(struct snd_pcm_substream *substream,
			 struct snd_pcm_runtime *runtime);
static int (*klpe_snd_pcm_update_hw_ptr)(struct snd_pcm_substream *substream);

static inline snd_pcm_uframes_t
snd_pcm_avail(struct snd_pcm_substream *substream)
{
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		return snd_pcm_playback_avail(substream->runtime);
	else
		return snd_pcm_capture_avail(substream->runtime);
}

static int klpr_wait_for_avail(struct snd_pcm_substream *substream,
			      snd_pcm_uframes_t *availp)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int is_playback = substream->stream == SNDRV_PCM_STREAM_PLAYBACK;
	wait_queue_entry_t wait;
	int err = 0;
	snd_pcm_uframes_t avail = 0;
	long wait_time, tout;

	init_waitqueue_entry(&wait, current);
	set_current_state(TASK_INTERRUPTIBLE);
	add_wait_queue(&runtime->tsleep, &wait);

	if (runtime->no_period_wakeup)
		wait_time = MAX_SCHEDULE_TIMEOUT;
	else {
		/* use wait time from substream if available */
		if (substream->wait_time) {
			wait_time = substream->wait_time;
		} else {
			wait_time = 10;

			if (runtime->rate) {
				long t = runtime->period_size * 2 /
					 runtime->rate;
				wait_time = max(t, wait_time);
			}
			wait_time = msecs_to_jiffies(wait_time * 1000);
		}
	}

	for (;;) {
		if (signal_pending(current)) {
			err = -ERESTARTSYS;
			break;
		}

		/*
		 * We need to check if space became available already
		 * (and thus the wakeup happened already) first to close
		 * the race of space already having become available.
		 * This check must happen after been added to the waitqueue
		 * and having current state be INTERRUPTIBLE.
		 */
		avail = snd_pcm_avail(substream);
		if (avail >= runtime->twake)
			break;
		(*klpe_snd_pcm_stream_unlock_irq)(substream);

		tout = schedule_timeout(wait_time);

		(*klpe_snd_pcm_stream_lock_irq)(substream);
		set_current_state(TASK_INTERRUPTIBLE);
		switch (runtime->status->state) {
		case SNDRV_PCM_STATE_SUSPENDED:
			err = -ESTRPIPE;
			goto _endloop;
		case SNDRV_PCM_STATE_XRUN:
			err = -EPIPE;
			goto _endloop;
		case SNDRV_PCM_STATE_DRAINING:
			if (is_playback)
				err = -EPIPE;
			else 
				avail = 0; /* indicate draining */
			goto _endloop;
		case SNDRV_PCM_STATE_OPEN:
		case SNDRV_PCM_STATE_SETUP:
		case SNDRV_PCM_STATE_DISCONNECTED:
			err = -EBADFD;
			goto _endloop;
		case SNDRV_PCM_STATE_PAUSED:
			continue;
		}
		if (!tout) {
			pcm_dbg(substream->pcm,
				"%s write error (DMA or IRQ trouble?)\n",
				is_playback ? "playback" : "capture");
			err = -EIO;
			break;
		}
	}
 _endloop:
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&runtime->tsleep, &wait);
	*availp = avail;
	return err;
}

typedef int (*pcm_transfer_f)(struct snd_pcm_substream *substream,
			      int channel, unsigned long hwoff,
			      void *buf, unsigned long bytes);

typedef int (*pcm_copy_f)(struct snd_pcm_substream *, snd_pcm_uframes_t, void *,
			  snd_pcm_uframes_t, snd_pcm_uframes_t, pcm_transfer_f);

static int (*klpe_default_write_copy)(struct snd_pcm_substream *substream,
			      int channel, unsigned long hwoff,
			      void *buf, unsigned long bytes);

static int (*klpe_default_write_copy_kernel)(struct snd_pcm_substream *substream,
				     int channel, unsigned long hwoff,
				     void *buf, unsigned long bytes);

static int (*klpe_fill_silence)(struct snd_pcm_substream *substream, int channel,
			unsigned long hwoff, void *buf, unsigned long bytes);

static int (*klpe_default_read_copy)(struct snd_pcm_substream *substream,
			     int channel, unsigned long hwoff,
			     void *buf, unsigned long bytes);

static int (*klpe_default_read_copy_kernel)(struct snd_pcm_substream *substream,
				    int channel, unsigned long hwoff,
				    void *buf, unsigned long bytes);

static int interleaved_copy(struct snd_pcm_substream *substream,
			    snd_pcm_uframes_t hwoff, void *data,
			    snd_pcm_uframes_t off,
			    snd_pcm_uframes_t frames,
			    pcm_transfer_f transfer)
{
	struct snd_pcm_runtime *runtime = substream->runtime;

	/* convert to bytes */
	hwoff = frames_to_bytes(runtime, hwoff);
	off = frames_to_bytes(runtime, off);
	frames = frames_to_bytes(runtime, frames);
	return transfer(substream, 0, hwoff, data + off, frames);
}

static int (*klpe_noninterleaved_copy)(struct snd_pcm_substream *substream,
			       snd_pcm_uframes_t hwoff, void *data,
			       snd_pcm_uframes_t off,
			       snd_pcm_uframes_t frames,
			       pcm_transfer_f transfer);

static int pcm_sanity_check(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime;
	if (PCM_RUNTIME_CHECK(substream))
		return -ENXIO;
	runtime = substream->runtime;
	if (snd_BUG_ON(!substream->ops->copy_user && !runtime->dma_area))
		return -EINVAL;
	if (runtime->status->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;
	return 0;
}

static int pcm_accessible_state(struct snd_pcm_runtime *runtime)
{
	switch (runtime->status->state) {
	case SNDRV_PCM_STATE_PREPARED:
	case SNDRV_PCM_STATE_RUNNING:
	case SNDRV_PCM_STATE_PAUSED:
		return 0;
	case SNDRV_PCM_STATE_XRUN:
		return -EPIPE;
	case SNDRV_PCM_STATE_SUSPENDED:
		return -ESTRPIPE;
	default:
		return -EBADFD;
	}
}

static bool
klpp_runtime_buffer_accessing_inc_unless_negative(struct snd_pcm_runtime *runtime,
							int **buffer_accessing)
{
	spin_lock(&klp_bsc1197597_shared_state->spin);
	*buffer_accessing = klpp_runtime_get_buffer_accessing(runtime);
	if (!*buffer_accessing) {
		/*
		 * Impossible in practice with GFP_ATOMIC, but better be safe.
		 * Return to the current implementation.
		 */
		spin_unlock(&klp_bsc1197597_shared_state->spin);
		return true;
	} else if (**buffer_accessing < 0) {
		spin_unlock(&klp_bsc1197597_shared_state->spin);
		return false;
	}

	++**buffer_accessing;
	spin_unlock(&klp_bsc1197597_shared_state->spin);
	return true;
}

static void
klpp_runtime_buffer_accessing_dec(struct snd_pcm_runtime *runtime,
					int *buffer_accessing)
{
	if (!buffer_accessing) {
		/* GFP_ATOMIC failed. */
		return;
	}

	spin_lock(&klp_bsc1197597_shared_state->spin);
	if (!(--*buffer_accessing)) {
		/*
		 * The buffer_accessing shadow previously allocated by
		 * klpp_runtime_buffer_accessing_inc_unless_negative()
		 * return to its "neutral" value of zero and we're the last
		 * user. Free it.
		 */
		klpp_runtime_free_buffer_acessing(runtime);
	}
	spin_unlock(&klp_bsc1197597_shared_state->spin);
}

snd_pcm_sframes_t klpp___snd_pcm_lib_xfer(struct snd_pcm_substream *substream,
				     void *data, bool interleaved,
				     snd_pcm_uframes_t size, bool in_kernel)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_uframes_t xfer = 0;
	snd_pcm_uframes_t offset = 0;
	snd_pcm_uframes_t avail;
	pcm_copy_f writer;
	pcm_transfer_f transfer;
	bool nonblock;
	bool is_playback;
	int err;
	int *buffer_accessing;

	err = pcm_sanity_check(substream);
	if (err < 0)
		return err;

	is_playback = substream->stream == SNDRV_PCM_STREAM_PLAYBACK;
	if (interleaved) {
		if (runtime->access != SNDRV_PCM_ACCESS_RW_INTERLEAVED &&
		    runtime->channels > 1)
			return -EINVAL;
		writer = interleaved_copy;
	} else {
		if (runtime->access != SNDRV_PCM_ACCESS_RW_NONINTERLEAVED)
			return -EINVAL;
		writer = (*klpe_noninterleaved_copy);
	}

	if (!data) {
		if (is_playback)
			transfer = (*klpe_fill_silence);
		else
			return -EINVAL;
	} else if (in_kernel) {
		if (substream->ops->copy_kernel)
			transfer = substream->ops->copy_kernel;
		else
			transfer = is_playback ?
				(*klpe_default_write_copy_kernel) : (*klpe_default_read_copy_kernel);
	} else {
		if (substream->ops->copy_user)
			transfer = (pcm_transfer_f)substream->ops->copy_user;
		else
			transfer = is_playback ?
				(*klpe_default_write_copy) : (*klpe_default_read_copy);
	}

	if (size == 0)
		return 0;

	nonblock = !!(substream->f_flags & O_NONBLOCK);

	(*klpe_snd_pcm_stream_lock_irq)(substream);
	err = pcm_accessible_state(runtime);
	if (err < 0)
		goto _end_unlock;

	runtime->twake = runtime->control->avail_min ? : 1;
	if (runtime->status->state == SNDRV_PCM_STATE_RUNNING)
		(*klpe_snd_pcm_update_hw_ptr)(substream);

	if (!is_playback &&
	    runtime->status->state == SNDRV_PCM_STATE_PREPARED &&
	    size >= runtime->start_threshold) {
		err = (*klpe_snd_pcm_start)(substream);
		if (err < 0)
			goto _end_unlock;
	}

	avail = snd_pcm_avail(substream);

	while (size > 0) {
		snd_pcm_uframes_t frames, appl_ptr, appl_ofs;
		snd_pcm_uframes_t cont;
		if (!avail) {
			if (!is_playback &&
			    runtime->status->state == SNDRV_PCM_STATE_DRAINING) {
				(*klpe_snd_pcm_stop)(substream, SNDRV_PCM_STATE_SETUP);
				goto _end_unlock;
			}
			if (nonblock) {
				err = -EAGAIN;
				goto _end_unlock;
			}
			runtime->twake = min_t(snd_pcm_uframes_t, size,
					runtime->control->avail_min ? : 1);
			err = klpr_wait_for_avail(substream, &avail);
			if (err < 0)
				goto _end_unlock;
			if (!avail)
				continue; /* draining */
		}
		frames = size > avail ? avail : size;
		appl_ptr = READ_ONCE(runtime->control->appl_ptr);
		appl_ofs = appl_ptr % runtime->buffer_size;
		cont = runtime->buffer_size - appl_ofs;
		if (frames > cont)
			frames = cont;
		if (snd_BUG_ON(!frames)) {
			runtime->twake = 0;
			(*klpe_snd_pcm_stream_unlock_irq)(substream);
			return -EINVAL;
		}
		if (!klpp_runtime_buffer_accessing_inc_unless_negative(runtime,
							&buffer_accessing)) {
			err = -EBUSY;
			goto _end_unlock;
		}
		(*klpe_snd_pcm_stream_unlock_irq)(substream);
		err = writer(substream, appl_ofs, data, offset, frames,
			     transfer);
		(*klpe_snd_pcm_stream_lock_irq)(substream);
		klpp_runtime_buffer_accessing_dec(runtime, buffer_accessing);
		if (err < 0)
			goto _end_unlock;
		err = pcm_accessible_state(runtime);
		if (err < 0)
			goto _end_unlock;
		appl_ptr += frames;
		if (appl_ptr >= runtime->boundary)
			appl_ptr -= runtime->boundary;
		err = (*klpe_pcm_lib_apply_appl_ptr)(substream, appl_ptr);
		if (err < 0)
			goto _end_unlock;

		offset += frames;
		size -= frames;
		xfer += frames;
		avail -= frames;
		if (is_playback &&
		    runtime->status->state == SNDRV_PCM_STATE_PREPARED &&
		    snd_pcm_playback_hw_avail(runtime) >= (snd_pcm_sframes_t)runtime->start_threshold) {
			err = (*klpe_snd_pcm_start)(substream);
			if (err < 0)
				goto _end_unlock;
		}
	}
 _end_unlock:
	runtime->twake = 0;
	if (xfer > 0 && err >= 0)
		(*klpe_snd_pcm_update_state)(substream, runtime);
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	return xfer > 0 ? (snd_pcm_sframes_t)xfer : err;
}



#define LP_MODULE "snd_pcm"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1197597.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "default_read_copy", (void *)&klpe_default_read_copy, "snd_pcm" },
	{ "default_read_copy_kernel", (void *)&klpe_default_read_copy_kernel,
	  "snd_pcm" },
	{ "default_write_copy", (void *)&klpe_default_write_copy, "snd_pcm" },
	{ "default_write_copy_kernel", (void *)&klpe_default_write_copy_kernel,
	  "snd_pcm" },
	{ "fill_silence", (void *)&klpe_fill_silence, "snd_pcm" },
	{ "noninterleaved_copy", (void *)&klpe_noninterleaved_copy,
	  "snd_pcm" },
	{ "pcm_lib_apply_appl_ptr", (void *)&klpe_pcm_lib_apply_appl_ptr,
	  "snd_pcm" },
	{ "snd_pcm_start", (void *)&klpe_snd_pcm_start, "snd_pcm" },
	{ "snd_pcm_stop", (void *)&klpe_snd_pcm_stop, "snd_pcm" },
	{ "snd_pcm_stream_lock_irq", (void *)&klpe_snd_pcm_stream_lock_irq,
	  "snd_pcm" },
	{ "snd_pcm_stream_unlock_irq", (void *)&klpe_snd_pcm_stream_unlock_irq,
	  "snd_pcm" },
	{ "snd_pcm_update_hw_ptr", (void *)&klpe_snd_pcm_update_hw_ptr,
	  "snd_pcm" },
	{ "snd_pcm_update_state", (void *)&klpe_snd_pcm_update_state,
	  "snd_pcm" },
};

static int bsc1197597_pcm_lib_module_notify(struct notifier_block *nb,
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

static struct notifier_block bsc1197597_pcm_lib_module_nb = {
	.notifier_call = bsc1197597_pcm_lib_module_notify,
	.priority = INT_MIN+1,
};

int bsc1197597_pcm_lib_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&bsc1197597_pcm_lib_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1197597_pcm_lib_cleanup(void)
{
	unregister_module_notifier(&bsc1197597_pcm_lib_module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_PCM) */
