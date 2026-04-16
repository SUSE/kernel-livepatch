/*
 * livepatch_bsc1258396
 *
 * Fix for CVE-2026-23191, bsc#1258396
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

#if IS_ENABLED(CONFIG_SND_ALOOP)

#if !IS_MODULE(CONFIG_SND_ALOOP)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1258396.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from sound/drivers/aloop.c */
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <sound/core.h>
#include <sound/control.h>

/* klp-ccp: from include/sound/control.h */
static void (*klpe_snd_ctl_notify)(struct snd_card * card, unsigned int mask, struct snd_ctl_elem_id * id);

/* klp-ccp: from sound/drivers/aloop.c */
#include <sound/pcm.h>

/* klp-ccp: from include/sound/pcm.h */
static int (*klpe_snd_pcm_stop)(struct snd_pcm_substream *substream, snd_pcm_state_t status);

/* klp-ccp: from sound/drivers/aloop.c */
#include <sound/pcm_params.h>
#include <sound/info.h>
#include <sound/initval.h>

#define MAX_PCM_SUBSTREAMS	8

struct loopback_cable {
	spinlock_t lock;
	struct loopback_pcm *streams[2];
	struct snd_pcm_hardware hw;
	/* flags */
	unsigned int valid;
	unsigned int running;
	unsigned int pause;
};

struct loopback_setup {
	unsigned int notify: 1;
	unsigned int rate_shift;
	unsigned int format;
	unsigned int rate;
	unsigned int channels;
	struct snd_ctl_elem_id active_id;
	struct snd_ctl_elem_id format_id;
	struct snd_ctl_elem_id rate_id;
	struct snd_ctl_elem_id channels_id;
};

struct loopback {
	struct snd_card *card;
	struct mutex cable_lock;
	struct loopback_cable *cables[MAX_PCM_SUBSTREAMS][2];
	struct snd_pcm *pcm[2];
	struct loopback_setup setup[MAX_PCM_SUBSTREAMS][2];
};

struct loopback_pcm {
	struct loopback *loopback;
	struct snd_pcm_substream *substream;
	struct loopback_cable *cable;
	unsigned int pcm_buffer_size;
	unsigned int buf_pos;	/* position in buffer */
	unsigned int silent_size;
	/* PCM parameters */
	unsigned int pcm_period_size;
	unsigned int pcm_bps;		/* bytes per second */
	unsigned int pcm_salign;	/* bytes per sample * channels */
	unsigned int pcm_rate_shift;	/* rate shift value */
	/* flags */
	unsigned int period_update_pending :1;
	/* timer stuff */
	unsigned int irq_pos;		/* fractional IRQ position */
	unsigned int period_size_frac;
	unsigned int last_drift;
	unsigned long last_jiffies;
	struct timer_list timer;
};

static inline struct loopback_setup *get_setup(struct loopback_pcm *dpcm)
{
	int device = dpcm->substream->pstr->pcm->device;
	
	if (dpcm->substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		device ^= 1;
	return &dpcm->loopback->setup[dpcm->substream->number][device];
}

static void (*klpe_loopback_timer_start)(struct loopback_pcm *dpcm);

static inline void loopback_timer_stop(struct loopback_pcm *dpcm)
{
	del_timer(&dpcm->timer);
	dpcm->timer.expires = 0;
}

#define CABLE_VALID_PLAYBACK	(1 << SNDRV_PCM_STREAM_PLAYBACK)
#define CABLE_VALID_CAPTURE	(1 << SNDRV_PCM_STREAM_CAPTURE)
#define CABLE_VALID_BOTH	(CABLE_VALID_PLAYBACK|CABLE_VALID_CAPTURE)

static int klpp_loopback_check_format(struct loopback_cable *cable, int stream)
{
	struct loopback_pcm *dpcm_play, *dpcm_capt;
	struct snd_pcm_runtime *runtime, *cruntime;
	struct loopback_setup *setup;
	struct snd_card *card;
	unsigned long flags;
	bool stop_capture = false;
	int check;
	int err = 0;

	spin_lock_irqsave(&cable->lock, flags);

	dpcm_play = cable->streams[SNDRV_PCM_STREAM_PLAYBACK];
	dpcm_capt = cable->streams[SNDRV_PCM_STREAM_CAPTURE];

	if (cable->valid != CABLE_VALID_BOTH) {
		if (stream == SNDRV_PCM_STREAM_CAPTURE || !dpcm_play)
			goto unlock;
	} else {
		if (!dpcm_play || !dpcm_capt) {
			err = -EIO;
			goto unlock;
		}
		runtime = dpcm_play->substream->runtime;
		cruntime = dpcm_capt->substream->runtime;
		if (!runtime || !cruntime) {
			err = -EIO;
			goto unlock;
		}

		check = runtime->format != cruntime->format ||
			runtime->rate != cruntime->rate ||
			runtime->channels != cruntime->channels;
		if (!check)
			goto unlock;
		if (stream == SNDRV_PCM_STREAM_CAPTURE) {
			err = -EIO;
			goto unlock;
		} else if (cruntime->status->state == SNDRV_PCM_STATE_RUNNING) {
			stop_capture = true;
		}

		setup = get_setup(dpcm_play);
		card = dpcm_play->loopback->card;
		runtime = dpcm_play->substream->runtime;
		if (setup->format != runtime->format) {
			(*klpe_snd_ctl_notify)(card, SNDRV_CTL_EVENT_MASK_VALUE,
							&setup->format_id);
			setup->format = runtime->format;
		}
		if (setup->rate != runtime->rate) {
			(*klpe_snd_ctl_notify)(card, SNDRV_CTL_EVENT_MASK_VALUE,
							&setup->rate_id);
			setup->rate = runtime->rate;
		}
		if (setup->channels != runtime->channels) {
			(*klpe_snd_ctl_notify)(card, SNDRV_CTL_EVENT_MASK_VALUE,
							&setup->channels_id);
			setup->channels = runtime->channels;
		}
	}

 unlock:
	spin_unlock_irqrestore(&cable->lock, flags);
	if (stop_capture)
		(*klpe_snd_pcm_stop)(dpcm_capt->substream, SNDRV_PCM_STATE_DRAINING);

	return err;
}

static void (*klpe_loopback_active_notify)(struct loopback_pcm *dpcm);

int klpp_loopback_trigger(struct snd_pcm_substream *substream, int cmd)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct loopback_pcm *dpcm = runtime->private_data;
	struct loopback_cable *cable = dpcm->cable;
	int err, stream = 1 << substream->stream;

	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		err = klpp_loopback_check_format(cable, substream->stream);
		if (err < 0)
			return err;
		dpcm->last_jiffies = jiffies;
		dpcm->pcm_rate_shift = 0;
		dpcm->last_drift = 0;
		spin_lock(&cable->lock);	
		cable->running |= stream;
		cable->pause &= ~stream;
		(*klpe_loopback_timer_start)(dpcm);
		spin_unlock(&cable->lock);
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
			(*klpe_loopback_active_notify)(dpcm);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
		spin_lock(&cable->lock);	
		cable->running &= ~stream;
		cable->pause &= ~stream;
		loopback_timer_stop(dpcm);
		spin_unlock(&cable->lock);
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
			(*klpe_loopback_active_notify)(dpcm);
		break;
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
		spin_lock(&cable->lock);	
		cable->pause |= stream;
		loopback_timer_stop(dpcm);
		spin_unlock(&cable->lock);
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
			(*klpe_loopback_active_notify)(dpcm);
		break;
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		spin_lock(&cable->lock);
		dpcm->last_jiffies = jiffies;
		cable->pause &= ~stream;
		(*klpe_loopback_timer_start)(dpcm);
		spin_unlock(&cable->lock);
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
			(*klpe_loopback_active_notify)(dpcm);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "snd_aloop"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "loopback_active_notify", (void *)&klpe_loopback_active_notify,
	  "snd_aloop" },
	{ "loopback_timer_start", (void *)&klpe_loopback_timer_start,
	  "snd_aloop" },
	{ "snd_ctl_notify", (void *)&klpe_snd_ctl_notify, "snd" },
	{ "snd_pcm_stop", (void *)&klpe_snd_pcm_stop, "snd_pcm" },
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

int livepatch_bsc1258396_init(void)
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

void livepatch_bsc1258396_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_ALOOP) */
