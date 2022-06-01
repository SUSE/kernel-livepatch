/*
 * bsc1197597_pcm_native
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

/* klp-ccp: from sound/core/pcm_native.c */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/time.h>
#include <linux/pm_qos.h>
#include <sound/core.h>

/* klp-ccp: from include/sound/core.h */
#ifdef CONFIG_PM

static int (*klpe_snd_power_wait)(struct snd_card *card, unsigned int power_state);

#else /* ! CONFIG_PM */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PM */

static int (*klpe_snd_major);

static void *(*klpe_snd_lookup_minor_data)(unsigned int minor, int type);

/* klp-ccp: from sound/core/pcm_native.c */
#include <sound/control.h>
#include <sound/info.h>
#include <sound/pcm.h>

/* klp-ccp: from include/sound/pcm.h */
static int (*klpe_snd_pcm_info_user)(struct snd_pcm_substream *substream,
		      struct snd_pcm_info __user *info);

static void (*klpe_snd_pcm_stream_lock_irq)(struct snd_pcm_substream *substream);
static void (*klpe_snd_pcm_stream_unlock_irq)(struct snd_pcm_substream *substream);

static int (*klpe_snd_pcm_hw_refine)(struct snd_pcm_substream *substream, struct snd_pcm_hw_params *params);

static int (*klpe_snd_pcm_format_physical_width)(snd_pcm_format_t format);

static inline snd_pcm_sframes_t
klpr_snd_pcm_lib_write(struct snd_pcm_substream *substream,
		  const void __user *buf, snd_pcm_uframes_t frames)
{
	return klpp___snd_pcm_lib_xfer(substream, (void __force *)buf, true, frames, false);
}

static inline snd_pcm_sframes_t
klpr_snd_pcm_lib_read(struct snd_pcm_substream *substream,
		 void __user *buf, snd_pcm_uframes_t frames)
{
	return klpp___snd_pcm_lib_xfer(substream, (void __force *)buf, true, frames, false);
}

static inline snd_pcm_sframes_t
klpr_snd_pcm_lib_writev(struct snd_pcm_substream *substream,
		   void __user **bufs, snd_pcm_uframes_t frames)
{
	return klpp___snd_pcm_lib_xfer(substream, (void *)bufs, false, frames, false);
}

static inline snd_pcm_sframes_t
klpr_snd_pcm_lib_readv(struct snd_pcm_substream *substream,
		  void __user **bufs, snd_pcm_uframes_t frames)
{
	return klpp___snd_pcm_lib_xfer(substream, (void *)bufs, false, frames, false);
}

/* klp-ccp: from sound/core/pcm_native.c */
#include <sound/pcm_params.h>

/* klp-ccp: from include/sound/pcm_params.h */
static int (*klpe_snd_pcm_hw_param_first)(struct snd_pcm_substream *pcm, 
			   struct snd_pcm_hw_params *params,
			   snd_pcm_hw_param_t var, int *dir);
static int (*klpe_snd_pcm_hw_param_last)(struct snd_pcm_substream *pcm, 
			  struct snd_pcm_hw_params *params,
			  snd_pcm_hw_param_t var, int *dir);

/* klp-ccp: from sound/core/pcm_native.c */
#include <sound/minors.h>
#include <linux/delay.h>

/* klp-ccp: from sound/core/pcm_local.h */
static int (*klpe_pcm_lib_apply_appl_ptr)(struct snd_pcm_substream *substream,
			   snd_pcm_uframes_t appl_ptr);

static inline snd_pcm_uframes_t
snd_pcm_avail(struct snd_pcm_substream *substream)
{
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		return snd_pcm_playback_avail(substream->runtime);
	else
		return snd_pcm_capture_avail(substream->runtime);
}

static inline snd_pcm_uframes_t
snd_pcm_hw_avail(struct snd_pcm_substream *substream)
{
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		return snd_pcm_playback_hw_avail(substream->runtime);
	else
		return snd_pcm_capture_hw_avail(substream->runtime);
}

#ifdef CONFIG_SND_PCM_TIMER
static void (*klpe_snd_pcm_timer_resolution_change)(struct snd_pcm_substream *substream);

#else
#error "klp-ccp: non-taken branch"
#endif

static void (*klpe___snd_pcm_xrun)(struct snd_pcm_substream *substream);

/* klp-ccp: from sound/core/pcm_native.c */
#ifdef CONFIG_SND_DEBUG

/* klp-ccp: from sound/core/pcm_param_trace.h */
#include <linux/tracepoint.h>

/* klp-ccp: from include/linux/tracepoint.h */
#define KLPR___DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	static struct tracepoint (*klpe___tracepoint_##name); \
	static inline bool klpr_trace_##name##_enabled(void) \
	{ \
		return static_key_enabled(&(*klpe___tracepoint_##name).key); \
	} \
	static inline void klpr_trace_##name(proto) \
	{ \
		if (unlikely(static_key_enabled(&(*klpe___tracepoint_##name).key))) \
			__DO_TRACE(&(*klpe___tracepoint_##name), \
					TP_PROTO(data_proto), \
					TP_ARGS(data_args), \
					TP_CONDITION(cond), 0); \
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) { \
			rcu_read_lock_sched_notrace(); \
			rcu_dereference_sched((*klpe___tracepoint_##name).funcs); \
			rcu_read_unlock_sched_notrace(); \
		} \
	}

#define KLPR_DECLARE_TRACE(name, proto, args) \
	KLPR___DECLARE_TRACE(name, PARAMS(proto), PARAMS(args), \
			cpu_online(raw_smp_processor_id()), \
			PARAMS(void *__data, proto), \
			PARAMS(__data, args))

#define KLPR_TRACE_EVENT(name, proto, args) \
	KLPR_DECLARE_TRACE(name, PARAMS(proto), PARAMS(args))

KLPR_TRACE_EVENT(hw_mask_param,
       TP_PROTO(struct snd_pcm_substream *substream, snd_pcm_hw_param_t type, int index, const struct snd_mask *prev, const struct snd_mask *curr),
       TP_ARGS(substream, type, index, prev, curr)
);

KLPR_TRACE_EVENT(hw_interval_param,
       TP_PROTO(struct snd_pcm_substream *substream, snd_pcm_hw_param_t type, int index, const struct snd_interval *prev, const struct snd_interval *curr),
       TP_ARGS(substream, type, index, prev, curr)
);

#endif /* CONFIG_SND_DEBUG */

struct snd_pcm_hw_params_old {
	unsigned int flags;
	unsigned int masks[SNDRV_PCM_HW_PARAM_SUBFORMAT -
			   SNDRV_PCM_HW_PARAM_ACCESS + 1];
	struct snd_interval intervals[SNDRV_PCM_HW_PARAM_TICK_TIME -
					SNDRV_PCM_HW_PARAM_SAMPLE_BITS + 1];
	unsigned int rmask;
	unsigned int cmask;
	unsigned int info;
	unsigned int msbits;
	unsigned int rate_num;
	unsigned int rate_den;
	snd_pcm_uframes_t fifo_size;
	unsigned char reserved[64];
};

#ifdef CONFIG_SND_SUPPORT_OLD_API
#define SNDRV_PCM_IOCTL_HW_REFINE_OLD _IOWR('A', 0x10, struct snd_pcm_hw_params_old)
#define SNDRV_PCM_IOCTL_HW_PARAMS_OLD _IOWR('A', 0x11, struct snd_pcm_hw_params_old)

static int klpr_snd_pcm_hw_refine_old_user(struct snd_pcm_substream *substream,
				      struct snd_pcm_hw_params_old __user * _oparams);
static int klpr_snd_pcm_hw_params_old_user(struct snd_pcm_substream *substream,
				      struct snd_pcm_hw_params_old __user * _oparams);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static rwlock_t (*klpe_snd_pcm_link_rwlock);
static struct rw_semaphore (*klpe_snd_pcm_link_rwsem);

/* klp-ccp: from sound/core/pcm_native.c */
static inline void down_write_nonfifo(struct rw_semaphore *lock)
{
	while (!down_write_trylock(lock))
		msleep(1);
}

static int (*klpe_fixup_unreferenced_params)(struct snd_pcm_substream *substream,
				     struct snd_pcm_hw_params *params);

static int klpr_snd_pcm_hw_refine_user(struct snd_pcm_substream *substream,
				  struct snd_pcm_hw_params __user * _params)
{
	struct snd_pcm_hw_params *params;
	int err;

	params = memdup_user(_params, sizeof(*params));
	if (IS_ERR(params))
		return PTR_ERR(params);

	err = (*klpe_snd_pcm_hw_refine)(substream, params);
	if (err < 0)
		goto end;

	err = (*klpe_fixup_unreferenced_params)(substream, params);
	if (err < 0)
		goto end;

	if (copy_to_user(_params, params, sizeof(*params)))
		err = -EFAULT;
end:
	kfree(params);
	return err;
}

static int period_to_usecs(struct snd_pcm_runtime *runtime)
{
	int usecs;

	if (! runtime->rate)
		return -1; /* invalid */

	/* take 75% of period time as the deadline */
	usecs = (750000 / runtime->rate) * runtime->period_size;
	usecs += ((750000 % runtime->rate) * runtime->period_size) /
		runtime->rate;

	return usecs;
}

static void (*klpe_snd_pcm_set_state)(struct snd_pcm_substream *substream, int state);

static int klpr_snd_pcm_hw_params_choose(struct snd_pcm_substream *pcm,
				    struct snd_pcm_hw_params *params)
{
	static const int vars[] = {
		SNDRV_PCM_HW_PARAM_ACCESS,
		SNDRV_PCM_HW_PARAM_FORMAT,
		SNDRV_PCM_HW_PARAM_SUBFORMAT,
		SNDRV_PCM_HW_PARAM_CHANNELS,
		SNDRV_PCM_HW_PARAM_RATE,
		SNDRV_PCM_HW_PARAM_PERIOD_TIME,
		SNDRV_PCM_HW_PARAM_BUFFER_SIZE,
		SNDRV_PCM_HW_PARAM_TICK_TIME,
		-1
	};
	const int *v;
	struct snd_mask old_mask;
	struct snd_interval old_interval;
	int changed;

	for (v = vars; *v != -1; v++) {
		/* Keep old parameter to trace. */
		if (klpr_trace_hw_mask_param_enabled()) {
			if (hw_is_mask(*v))
				old_mask = *hw_param_mask(params, *v);
		}
		if (klpr_trace_hw_interval_param_enabled()) {
			if (hw_is_interval(*v))
				old_interval = *hw_param_interval(params, *v);
		}
		if (*v != SNDRV_PCM_HW_PARAM_BUFFER_SIZE)
			changed = (*klpe_snd_pcm_hw_param_first)(pcm, params, *v, NULL);
		else
			changed = (*klpe_snd_pcm_hw_param_last)(pcm, params, *v, NULL);
		if (changed < 0)
			return changed;
		if (changed == 0)
			continue;

		/* Trace the changed parameter. */
		if (hw_is_mask(*v)) {
			klpr_trace_hw_mask_param(pcm, *v, 0, &old_mask,
					    hw_param_mask(params, *v));
		}
		if (hw_is_interval(*v)) {
			klpr_trace_hw_interval_param(pcm, *v, 0, &old_interval,
						hw_param_interval(params, *v));
		}
	}

	return 0;
}

static bool
klpp_runtime_buffer_accessing_dec_unless_positive(struct snd_pcm_runtime *runtime,
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
	} else if (**buffer_accessing > 0) {
		spin_unlock(&klp_bsc1197597_shared_state->spin);
		return false;
	}

	--**buffer_accessing;
	spin_unlock(&klp_bsc1197597_shared_state->spin);

	return true;
}

static void
klpp_runtime_buffer_accessing_inc(struct snd_pcm_runtime *runtime,
				int *buffer_accessing)
{
	if (!buffer_accessing) {
		/* GFP_ATOMIC failed. */
		return;
	}

	spin_lock(&klp_bsc1197597_shared_state->spin);

	if (!(++*buffer_accessing)) {
		/*
		 * The buffer_accessing previously allocated by
		 * klpp_runtime_buffer_accessing_dec_unless_positive() returned
		 * to its "neutral" value zero and we're its last user. Free it.
		 */
		klpp_runtime_free_buffer_acessing(runtime);
	}

	spin_unlock(&klp_bsc1197597_shared_state->spin);
}

/* acquire buffer_mutex; if it's in r/w operation, return -EBUSY, otherwise
 * block the further r/w operations
 */
static int klpp_snd_pcm_buffer_access_lock(struct snd_pcm_runtime *runtime,
					int **buffer_accessing)
{
	if (!klpp_runtime_buffer_accessing_dec_unless_positive(runtime,
							buffer_accessing))
		return -EBUSY;

	mutex_lock(&klp_bsc1197597_shared_state->snd_pcm_runtime_buffer_mutex);
	return 0; /* keep buffer_mutex, unlocked by below */
}

/* release buffer_mutex and clear r/w access flag */
static void klpp_snd_pcm_buffer_access_unlock(struct snd_pcm_runtime *runtime,
					int *buffer_accessing)
{
	mutex_unlock(&klp_bsc1197597_shared_state->snd_pcm_runtime_buffer_mutex);
	klpp_runtime_buffer_accessing_inc(runtime, buffer_accessing);
}

#if IS_ENABLED(CONFIG_SND_PCM_OSS)
#define is_oss_stream(substream)	((substream)->oss.oss)
#else
#define is_oss_stream(substream)	false
#endif

int klpp_snd_pcm_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *params)
{
	struct snd_pcm_runtime *runtime;
	int err, usecs;
	unsigned int bits;
	snd_pcm_uframes_t frames;
	int *buffer_accessing;

	if (PCM_RUNTIME_CHECK(substream))
		return -ENXIO;
	runtime = substream->runtime;
	err = klpp_snd_pcm_buffer_access_lock(runtime, &buffer_accessing);
	if (err < 0)
		return err;
	(*klpe_snd_pcm_stream_lock_irq)(substream);
	switch (runtime->status->state) {
	case SNDRV_PCM_STATE_OPEN:
	case SNDRV_PCM_STATE_SETUP:
	case SNDRV_PCM_STATE_PREPARED:
		if (!is_oss_stream(substream) &&
		    atomic_read(&substream->mmap_count))
			err = -EBADFD;
		break;
	default:
		err = -EBADFD;
		break;
	}
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	if (err)
		goto unlock;

	params->rmask = ~0U;
	err = (*klpe_snd_pcm_hw_refine)(substream, params);
	if (err < 0)
		goto _error;

	err = klpr_snd_pcm_hw_params_choose(substream, params);
	if (err < 0)
		goto _error;

	err = (*klpe_fixup_unreferenced_params)(substream, params);
	if (err < 0)
		goto _error;

	if (substream->ops->hw_params != NULL) {
		err = substream->ops->hw_params(substream, params);
		if (err < 0)
			goto _error;
	}

	runtime->access = params_access(params);
	runtime->format = params_format(params);
	runtime->subformat = params_subformat(params);
	runtime->channels = params_channels(params);
	runtime->rate = params_rate(params);
	runtime->period_size = params_period_size(params);
	runtime->periods = params_periods(params);
	runtime->buffer_size = params_buffer_size(params);
	runtime->info = params->info;
	runtime->rate_num = params->rate_num;
	runtime->rate_den = params->rate_den;
	runtime->no_period_wakeup =
			(params->info & SNDRV_PCM_INFO_NO_PERIOD_WAKEUP) &&
			(params->flags & SNDRV_PCM_HW_PARAMS_NO_PERIOD_WAKEUP);

	bits = (*klpe_snd_pcm_format_physical_width)(runtime->format);
	runtime->sample_bits = bits;
	bits *= runtime->channels;
	runtime->frame_bits = bits;
	frames = 1;
	while (bits % 8 != 0) {
		bits *= 2;
		frames *= 2;
	}
	runtime->byte_align = bits / 8;
	runtime->min_align = frames;

	/* Default sw params */
	runtime->tstamp_mode = SNDRV_PCM_TSTAMP_NONE;
	runtime->period_step = 1;
	runtime->control->avail_min = runtime->period_size;
	runtime->start_threshold = 1;
	runtime->stop_threshold = runtime->buffer_size;
	runtime->silence_threshold = 0;
	runtime->silence_size = 0;
	runtime->boundary = runtime->buffer_size;
	while (runtime->boundary * 2 <= LONG_MAX - runtime->buffer_size)
		runtime->boundary *= 2;

	/* clear the buffer for avoiding possible kernel info leaks */
	if (runtime->dma_area && !substream->ops->copy_user) {
		size_t size = runtime->dma_bytes;

		if (runtime->info & SNDRV_PCM_INFO_MMAP)
			size = PAGE_ALIGN(size);
		memset(runtime->dma_area, 0, size);
	}

	(*klpe_snd_pcm_timer_resolution_change)(substream);
	(*klpe_snd_pcm_set_state)(substream, SNDRV_PCM_STATE_SETUP);

	if (pm_qos_request_active(&substream->latency_pm_qos_req))
		pm_qos_remove_request(&substream->latency_pm_qos_req);
	if ((usecs = period_to_usecs(runtime)) >= 0)
		pm_qos_add_request(&substream->latency_pm_qos_req,
				   PM_QOS_CPU_DMA_LATENCY, usecs);
	err = 0;
 _error:
	if (err) {
		/* hardware might be unusable from this time,
		   so we force application to retry to set
		   the correct hardware parameter settings */
		(*klpe_snd_pcm_set_state)(substream, SNDRV_PCM_STATE_OPEN);
		if (substream->ops->hw_free != NULL)
			substream->ops->hw_free(substream);
	}
unlock:
	klpp_snd_pcm_buffer_access_unlock(runtime, buffer_accessing);
	return err;
}

static int klpr_snd_pcm_hw_params_user(struct snd_pcm_substream *substream,
				  struct snd_pcm_hw_params __user * _params)
{
	struct snd_pcm_hw_params *params;
	int err;

	params = memdup_user(_params, sizeof(*params));
	if (IS_ERR(params))
		return PTR_ERR(params);

	err = klpp_snd_pcm_hw_params(substream, params);
	if (err < 0)
		goto end;

	if (copy_to_user(_params, params, sizeof(*params)))
		err = -EFAULT;
end:
	kfree(params);
	return err;
}

static int klpp_snd_pcm_hw_free(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime;
	int result = 0;
	int *buffer_accessing;

	if (PCM_RUNTIME_CHECK(substream))
		return -ENXIO;
	runtime = substream->runtime;
	result = klpp_snd_pcm_buffer_access_lock(runtime, &buffer_accessing);
	if (result < 0)
		return result;
	(*klpe_snd_pcm_stream_lock_irq)(substream);
	switch (runtime->status->state) {
	case SNDRV_PCM_STATE_SETUP:
	case SNDRV_PCM_STATE_PREPARED:
		if (atomic_read(&substream->mmap_count))
			result = -EBADFD;
		break;
	default:
		result = -EBADFD;
		break;
	}
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	if (result)
		goto unlock;
	if (substream->ops->hw_free)
		result = substream->ops->hw_free(substream);
	(*klpe_snd_pcm_set_state)(substream, SNDRV_PCM_STATE_OPEN);
	pm_qos_remove_request(&substream->latency_pm_qos_req);
unlock:
	klpp_snd_pcm_buffer_access_unlock(runtime, buffer_accessing);
	return result;
}

static int (*klpe_snd_pcm_sw_params_user)(struct snd_pcm_substream *substream,
				  struct snd_pcm_sw_params __user * _params);

static int (*klpe_snd_pcm_status_user)(struct snd_pcm_substream *substream,
			       struct snd_pcm_status __user * _status,
			       bool ext);

static int (*klpe_snd_pcm_channel_info)(struct snd_pcm_substream *substream,
				struct snd_pcm_channel_info * info);

static int klpr_snd_pcm_channel_info_user(struct snd_pcm_substream *substream,
				     struct snd_pcm_channel_info __user * _info)
{
	struct snd_pcm_channel_info info;
	int res;
	
	if (copy_from_user(&info, _info, sizeof(info)))
		return -EFAULT;
	res = (*klpe_snd_pcm_channel_info)(substream, &info);
	if (res < 0)
		return res;
	if (copy_to_user(_info, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

struct action_ops {
	int (*pre_action)(struct snd_pcm_substream *substream, int state);
	int (*do_action)(struct snd_pcm_substream *substream, int state);
	void (*undo_action)(struct snd_pcm_substream *substream, int state);
	void (*post_action)(struct snd_pcm_substream *substream, int state);
};

static int snd_pcm_action_group(const struct action_ops *ops,
				struct snd_pcm_substream *substream,
				int state, int do_lock)
{
	struct snd_pcm_substream *s = NULL;
	struct snd_pcm_substream *s1;
	int res = 0, depth = 1;

	snd_pcm_group_for_each_entry(s, substream) {
		if (do_lock && s != substream) {
			if (s->pcm->nonatomic)
				mutex_lock_nested(&s->self_group.mutex, depth);
			else
				spin_lock_nested(&s->self_group.lock, depth);
			depth++;
		}
		res = ops->pre_action(s, state);
		if (res < 0)
			goto _unlock;
	}
	snd_pcm_group_for_each_entry(s, substream) {
		res = ops->do_action(s, state);
		if (res < 0) {
			if (ops->undo_action) {
				snd_pcm_group_for_each_entry(s1, substream) {
					if (s1 == s) /* failed stream */
						break;
					ops->undo_action(s1, state);
				}
			}
			s = NULL; /* unlock all */
			goto _unlock;
		}
	}
	snd_pcm_group_for_each_entry(s, substream) {
		ops->post_action(s, state);
	}
 _unlock:
	if (do_lock) {
		/* unlock streams */
		snd_pcm_group_for_each_entry(s1, substream) {
			if (s1 != substream) {
				if (s1->pcm->nonatomic)
					mutex_unlock(&s1->self_group.mutex);
				else
					spin_unlock(&s1->self_group.lock);
			}
			if (s1 == s)	/* end */
				break;
		}
	}
	return res;
}

static int (*klpe_snd_pcm_action_single)(const struct action_ops *ops,
				 struct snd_pcm_substream *substream,
				 int state);

static int (*klpe_snd_pcm_action_lock_irq)(const struct action_ops *ops,
				   struct snd_pcm_substream *substream,
				   int state);

int klpp_snd_pcm_action_nonatomic(const struct action_ops *ops,
				    struct snd_pcm_substream *substream,
				    int state)
{
	int res;
	int *buffer_accessing;

	down_read(&(*klpe_snd_pcm_link_rwsem));
	res = klpp_snd_pcm_buffer_access_lock(substream->runtime, &buffer_accessing);
	if (res < 0)
		goto unlock;
	if (snd_pcm_stream_linked(substream))
		res = snd_pcm_action_group(ops, substream, state, 0);
	else
		res = (*klpe_snd_pcm_action_single)(ops, substream, state);
	klpp_snd_pcm_buffer_access_unlock(substream->runtime, buffer_accessing);
unlock:
	up_read(&(*klpe_snd_pcm_link_rwsem));
	return res;
}

static const struct action_ops (*klpe_snd_pcm_action_start);

static int klpr_snd_pcm_start_lock_irq(struct snd_pcm_substream *substream)
{
	return (*klpe_snd_pcm_action_lock_irq)(&(*klpe_snd_pcm_action_start), substream,
				       SNDRV_PCM_STATE_RUNNING);
}

static const struct action_ops (*klpe_snd_pcm_action_pause);

#ifdef CONFIG_PM

static const struct action_ops (*klpe_snd_pcm_action_resume);

static int klpr_snd_pcm_resume(struct snd_pcm_substream *substream)
{
	return (*klpe_snd_pcm_action_lock_irq)(&(*klpe_snd_pcm_action_resume), substream, 0);
}

#else
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PM */

static int klpr_snd_pcm_xrun(struct snd_pcm_substream *substream)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int result;

	(*klpe_snd_pcm_stream_lock_irq)(substream);
	switch (runtime->status->state) {
	case SNDRV_PCM_STATE_XRUN:
		result = 0;	/* already there */
		break;
	case SNDRV_PCM_STATE_RUNNING:
		(*klpe___snd_pcm_xrun)(substream);
		result = 0;
		break;
	default:
		result = -EBADFD;
	}
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	return result;
}

static const struct action_ops (*klpe_snd_pcm_action_reset);

static int klpr_snd_pcm_reset(struct snd_pcm_substream *substream)
{
	return klpp_snd_pcm_action_nonatomic(&(*klpe_snd_pcm_action_reset), substream, 0);
}

static int (*klpe_snd_pcm_prepare)(struct snd_pcm_substream *substream,
			   struct file *file);

static int (*klpe_snd_pcm_drop)(struct snd_pcm_substream *substream);

static int (*klpe_snd_pcm_drain)(struct snd_pcm_substream *substream,
			 struct file *file);

static int (*klpe_snd_pcm_drop)(struct snd_pcm_substream *substream);

static bool klpr_is_pcm_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	unsigned int minor;

	if (!S_ISCHR(inode->i_mode) || imajor(inode) != (*klpe_snd_major))
		return false;
	minor = iminor(inode);
	return (*klpe_snd_lookup_minor_data)(minor, SNDRV_DEVICE_TYPE_PCM_PLAYBACK) ||
		(*klpe_snd_lookup_minor_data)(minor, SNDRV_DEVICE_TYPE_PCM_CAPTURE);
}

static int klpr_snd_pcm_link(struct snd_pcm_substream *substream, int fd)
{
	int res = 0;
	struct snd_pcm_file *pcm_file;
	struct snd_pcm_substream *substream1;
	struct snd_pcm_group *group;
	struct fd f = fdget(fd);

	if (!f.file)
		return -EBADFD;
	if (!klpr_is_pcm_file(f.file)) {
		res = -EBADFD;
		goto _badf;
	}
	pcm_file = f.file->private_data;
	substream1 = pcm_file->substream;
	if (substream == substream1) {
		res = -EINVAL;
		goto _badf;
	}

	group = kmalloc(sizeof(*group), GFP_KERNEL);
	if (!group) {
		res = -ENOMEM;
		goto _nolock;
	}
	down_write_nonfifo(&(*klpe_snd_pcm_link_rwsem));
	write_lock_irq(&(*klpe_snd_pcm_link_rwlock));
	if (substream->runtime->status->state == SNDRV_PCM_STATE_OPEN ||
	    substream->runtime->status->state != substream1->runtime->status->state ||
	    substream->pcm->nonatomic != substream1->pcm->nonatomic) {
		res = -EBADFD;
		goto _end;
	}
	if (snd_pcm_stream_linked(substream1)) {
		res = -EALREADY;
		goto _end;
	}
	if (!snd_pcm_stream_linked(substream)) {
		substream->group = group;
		group = NULL;
		spin_lock_init(&substream->group->lock);
		mutex_init(&substream->group->mutex);
		INIT_LIST_HEAD(&substream->group->substreams);
		list_add_tail(&substream->link_list, &substream->group->substreams);
		substream->group->count = 1;
	}
	list_add_tail(&substream1->link_list, &substream->group->substreams);
	substream->group->count++;
	substream1->group = substream->group;
 _end:
	write_unlock_irq(&(*klpe_snd_pcm_link_rwlock));
	up_write(&(*klpe_snd_pcm_link_rwsem));
 _nolock:
	snd_card_unref(substream1->pcm->card);
	kfree(group);
 _badf:
	fdput(f);
	return res;
}

static int (*klpe_snd_pcm_unlink)(struct snd_pcm_substream *substream);

static int (*klpe_do_pcm_hwsync)(struct snd_pcm_substream *substream);

static snd_pcm_sframes_t klpr_forward_appl_ptr(struct snd_pcm_substream *substream,
					  snd_pcm_uframes_t frames,
					   snd_pcm_sframes_t avail)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_sframes_t appl_ptr;
	int ret;

	if (avail <= 0)
		return 0;
	if (frames > (snd_pcm_uframes_t)avail)
		frames = avail;
	appl_ptr = runtime->control->appl_ptr + frames;
	if (appl_ptr >= (snd_pcm_sframes_t)runtime->boundary)
		appl_ptr -= runtime->boundary;
	ret = (*klpe_pcm_lib_apply_appl_ptr)(substream, appl_ptr);
	return ret < 0 ? ret : frames;
}

static snd_pcm_sframes_t klpr_rewind_appl_ptr(struct snd_pcm_substream *substream,
					 snd_pcm_uframes_t frames,
					 snd_pcm_sframes_t avail)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_sframes_t appl_ptr;
	int ret;

	if (avail <= 0)
		return 0;
	if (frames > (snd_pcm_uframes_t)avail)
		frames = avail;
	appl_ptr = runtime->control->appl_ptr - frames;
	if (appl_ptr < 0)
		appl_ptr += runtime->boundary;
	ret = (*klpe_pcm_lib_apply_appl_ptr)(substream, appl_ptr);
	/* NOTE: we return zero for errors because PulseAudio gets depressed
	 * upon receiving an error from rewind ioctl and stops processing
	 * any longer.  Returning zero means that no rewind is done, so
	 * it's not absolutely wrong to answer like that.
	 */
	return ret < 0 ? 0 : frames;
}

static snd_pcm_sframes_t klpr_snd_pcm_rewind(struct snd_pcm_substream *substream,
					snd_pcm_uframes_t frames)
{
	snd_pcm_sframes_t ret;

	if (frames == 0)
		return 0;

	(*klpe_snd_pcm_stream_lock_irq)(substream);
	ret = (*klpe_do_pcm_hwsync)(substream);
	if (!ret)
		ret = klpr_rewind_appl_ptr(substream, frames,
				      snd_pcm_hw_avail(substream));
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	return ret;
}

static snd_pcm_sframes_t klpr_snd_pcm_forward(struct snd_pcm_substream *substream,
					 snd_pcm_uframes_t frames)
{
	snd_pcm_sframes_t ret;

	if (frames == 0)
		return 0;

	(*klpe_snd_pcm_stream_lock_irq)(substream);
	ret = (*klpe_do_pcm_hwsync)(substream);
	if (!ret)
		ret = klpr_forward_appl_ptr(substream, frames,
				       snd_pcm_avail(substream));
	(*klpe_snd_pcm_stream_unlock_irq)(substream);
	return ret;
}

static int (*klpe_snd_pcm_hwsync)(struct snd_pcm_substream *substream);

static int (*klpe_snd_pcm_delay)(struct snd_pcm_substream *substream,
			 snd_pcm_sframes_t *delay);

static int (*klpe_snd_pcm_sync_ptr)(struct snd_pcm_substream *substream,
			    struct snd_pcm_sync_ptr __user *_sync_ptr);

static int snd_pcm_tstamp(struct snd_pcm_substream *substream, int __user *_arg)
{
	struct snd_pcm_runtime *runtime = substream->runtime;
	int arg;
	
	if (get_user(arg, _arg))
		return -EFAULT;
	if (arg < 0 || arg > SNDRV_PCM_TSTAMP_TYPE_LAST)
		return -EINVAL;
	runtime->tstamp_type = arg;
	return 0;
}

static int klpr_snd_pcm_xferi_frames_ioctl(struct snd_pcm_substream *substream,
				      struct snd_xferi __user *_xferi)
{
	struct snd_xferi xferi;
	struct snd_pcm_runtime *runtime = substream->runtime;
	snd_pcm_sframes_t result;

	if (runtime->status->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;
	if (put_user(0, &_xferi->result))
		return -EFAULT;
	if (copy_from_user(&xferi, _xferi, sizeof(xferi)))
		return -EFAULT;
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		result = klpr_snd_pcm_lib_write(substream, xferi.buf, xferi.frames);
	else
		result = klpr_snd_pcm_lib_read(substream, xferi.buf, xferi.frames);
	if (put_user(result, &_xferi->result))
		return -EFAULT;
	return result < 0 ? result : 0;
}

static int klpr_snd_pcm_xfern_frames_ioctl(struct snd_pcm_substream *substream,
				      struct snd_xfern __user *_xfern)
{
	struct snd_xfern xfern;
	struct snd_pcm_runtime *runtime = substream->runtime;
	void *bufs;
	snd_pcm_sframes_t result;

	if (runtime->status->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;
	if (runtime->channels > 128)
		return -EINVAL;
	if (put_user(0, &_xfern->result))
		return -EFAULT;
	if (copy_from_user(&xfern, _xfern, sizeof(xfern)))
		return -EFAULT;

	bufs = memdup_user(xfern.bufs, sizeof(void *) * runtime->channels);
	if (IS_ERR(bufs))
		return PTR_ERR(bufs);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		result = klpr_snd_pcm_lib_writev(substream, bufs, xfern.frames);
	else
		result = klpr_snd_pcm_lib_readv(substream, bufs, xfern.frames);
	kfree(bufs);
	if (put_user(result, &_xfern->result))
		return -EFAULT;
	return result < 0 ? result : 0;
}

static int klpr_snd_pcm_rewind_ioctl(struct snd_pcm_substream *substream,
				snd_pcm_uframes_t __user *_frames)
{
	snd_pcm_uframes_t frames;
	snd_pcm_sframes_t result;

	if (get_user(frames, _frames))
		return -EFAULT;
	if (put_user(0, _frames))
		return -EFAULT;
	result = klpr_snd_pcm_rewind(substream, frames);
	if (put_user(result, _frames))
		return -EFAULT;
	return result < 0 ? result : 0;
}

static int klpr_snd_pcm_forward_ioctl(struct snd_pcm_substream *substream,
				 snd_pcm_uframes_t __user *_frames)
{
	snd_pcm_uframes_t frames;
	snd_pcm_sframes_t result;

	if (get_user(frames, _frames))
		return -EFAULT;
	if (put_user(0, _frames))
		return -EFAULT;
	result = klpr_snd_pcm_forward(substream, frames);
	if (put_user(result, _frames))
		return -EFAULT;
	return result < 0 ? result : 0;
}

int klpp_snd_pcm_common_ioctl(struct file *file,
				 struct snd_pcm_substream *substream,
				 unsigned int cmd, void __user *arg)
{
	struct snd_pcm_file *pcm_file = file->private_data;
	int res;

	if (PCM_RUNTIME_CHECK(substream))
		return -ENXIO;

	res = (*klpe_snd_power_wait)(substream->pcm->card, SNDRV_CTL_POWER_D0);
	if (res < 0)
		return res;

	switch (cmd) {
	case SNDRV_PCM_IOCTL_PVERSION:
		return put_user(SNDRV_PCM_VERSION, (int __user *)arg) ? -EFAULT : 0;
	case SNDRV_PCM_IOCTL_INFO:
		return (*klpe_snd_pcm_info_user)(substream, arg);
	case SNDRV_PCM_IOCTL_TSTAMP:	/* just for compatibility */
		return 0;
	case SNDRV_PCM_IOCTL_TTSTAMP:
		return snd_pcm_tstamp(substream, arg);
	case SNDRV_PCM_IOCTL_USER_PVERSION:
		if (get_user(pcm_file->user_pversion,
			     (unsigned int __user *)arg))
			return -EFAULT;
		return 0;
	case SNDRV_PCM_IOCTL_HW_REFINE:
		return klpr_snd_pcm_hw_refine_user(substream, arg);
	case SNDRV_PCM_IOCTL_HW_PARAMS:
		return klpr_snd_pcm_hw_params_user(substream, arg);
	case SNDRV_PCM_IOCTL_HW_FREE:
		return klpp_snd_pcm_hw_free(substream);
	case SNDRV_PCM_IOCTL_SW_PARAMS:
		return (*klpe_snd_pcm_sw_params_user)(substream, arg);
	case SNDRV_PCM_IOCTL_STATUS:
		return (*klpe_snd_pcm_status_user)(substream, arg, false);
	case SNDRV_PCM_IOCTL_STATUS_EXT:
		return (*klpe_snd_pcm_status_user)(substream, arg, true);
	case SNDRV_PCM_IOCTL_CHANNEL_INFO:
		return klpr_snd_pcm_channel_info_user(substream, arg);
	case SNDRV_PCM_IOCTL_PREPARE:
		return (*klpe_snd_pcm_prepare)(substream, file);
	case SNDRV_PCM_IOCTL_RESET:
		return klpr_snd_pcm_reset(substream);
	case SNDRV_PCM_IOCTL_START:
		return klpr_snd_pcm_start_lock_irq(substream);
	case SNDRV_PCM_IOCTL_LINK:
		return klpr_snd_pcm_link(substream, (int)(unsigned long) arg);
	case SNDRV_PCM_IOCTL_UNLINK:
		return (*klpe_snd_pcm_unlink)(substream);
	case SNDRV_PCM_IOCTL_RESUME:
		return klpr_snd_pcm_resume(substream);
	case SNDRV_PCM_IOCTL_XRUN:
		return klpr_snd_pcm_xrun(substream);
	case SNDRV_PCM_IOCTL_HWSYNC:
		return (*klpe_snd_pcm_hwsync)(substream);
	case SNDRV_PCM_IOCTL_DELAY:
	{
		snd_pcm_sframes_t delay;
		snd_pcm_sframes_t __user *res = arg;
		int err;

		err = (*klpe_snd_pcm_delay)(substream, &delay);
		if (err)
			return err;
		if (put_user(delay, res))
			return -EFAULT;
		return 0;
	}
	case SNDRV_PCM_IOCTL_SYNC_PTR:
		return (*klpe_snd_pcm_sync_ptr)(substream, arg);
#ifdef CONFIG_SND_SUPPORT_OLD_API
	case SNDRV_PCM_IOCTL_HW_REFINE_OLD:
		return klpr_snd_pcm_hw_refine_old_user(substream, arg);
	case SNDRV_PCM_IOCTL_HW_PARAMS_OLD:
		return klpr_snd_pcm_hw_params_old_user(substream, arg);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	case SNDRV_PCM_IOCTL_DRAIN:
		return (*klpe_snd_pcm_drain)(substream, file);
	case SNDRV_PCM_IOCTL_DROP:
		return (*klpe_snd_pcm_drop)(substream);
	case SNDRV_PCM_IOCTL_PAUSE:
		return (*klpe_snd_pcm_action_lock_irq)(&(*klpe_snd_pcm_action_pause),
					       substream,
					       (int)(unsigned long)arg);
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES:
	case SNDRV_PCM_IOCTL_READI_FRAMES:
		return klpr_snd_pcm_xferi_frames_ioctl(substream, arg);
	case SNDRV_PCM_IOCTL_WRITEN_FRAMES:
	case SNDRV_PCM_IOCTL_READN_FRAMES:
		return klpr_snd_pcm_xfern_frames_ioctl(substream, arg);
	case SNDRV_PCM_IOCTL_REWIND:
		return klpr_snd_pcm_rewind_ioctl(substream, arg);
	case SNDRV_PCM_IOCTL_FORWARD:
		return klpr_snd_pcm_forward_ioctl(substream, arg);
	}
	pcm_dbg(substream->pcm, "unknown ioctl = 0x%x\n", cmd);
	return -ENOTTY;
}

#ifdef CONFIG_COMPAT

/* klp-ccp: from sound/core/pcm_compat.c */
#include <linux/slab.h>

/* klp-ccp: from sound/core/pcm_native.c */
#else
#error "klp-ccp: non-taken branch"
#endif

#ifdef CONFIG_SND_SUPPORT_OLD_API

static void (*klpe_snd_pcm_hw_convert_from_old_params)(struct snd_pcm_hw_params *params,
					       struct snd_pcm_hw_params_old *oparams);

static void (*klpe_snd_pcm_hw_convert_to_old_params)(struct snd_pcm_hw_params_old *oparams,
					     struct snd_pcm_hw_params *params);

static int klpr_snd_pcm_hw_refine_old_user(struct snd_pcm_substream *substream,
				      struct snd_pcm_hw_params_old __user * _oparams)
{
	struct snd_pcm_hw_params *params;
	struct snd_pcm_hw_params_old *oparams = NULL;
	int err;

	params = kmalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return -ENOMEM;

	oparams = memdup_user(_oparams, sizeof(*oparams));
	if (IS_ERR(oparams)) {
		err = PTR_ERR(oparams);
		goto out;
	}
	(*klpe_snd_pcm_hw_convert_from_old_params)(params, oparams);
	err = (*klpe_snd_pcm_hw_refine)(substream, params);
	if (err < 0)
		goto out_old;

	err = (*klpe_fixup_unreferenced_params)(substream, params);
	if (err < 0)
		goto out_old;

	(*klpe_snd_pcm_hw_convert_to_old_params)(oparams, params);
	if (copy_to_user(_oparams, oparams, sizeof(*oparams)))
		err = -EFAULT;
out_old:
	kfree(oparams);
out:
	kfree(params);
	return err;
}

static int klpr_snd_pcm_hw_params_old_user(struct snd_pcm_substream *substream,
				      struct snd_pcm_hw_params_old __user * _oparams)
{
	struct snd_pcm_hw_params *params;
	struct snd_pcm_hw_params_old *oparams = NULL;
	int err;

	params = kmalloc(sizeof(*params), GFP_KERNEL);
	if (!params)
		return -ENOMEM;

	oparams = memdup_user(_oparams, sizeof(*oparams));
	if (IS_ERR(oparams)) {
		err = PTR_ERR(oparams);
		goto out;
	}

	(*klpe_snd_pcm_hw_convert_from_old_params)(params, oparams);
	err = klpp_snd_pcm_hw_params(substream, params);
	if (err < 0)
		goto out_old;

	(*klpe_snd_pcm_hw_convert_to_old_params)(oparams, params);
	if (copy_to_user(_oparams, oparams, sizeof(*oparams)))
		err = -EFAULT;
out_old:
	kfree(oparams);
out:
	kfree(params);
	return err;
}
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_SND_SUPPORT_OLD_API */



#define LP_MODULE "snd_pcm"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__snd_pcm_xrun", (void *)&klpe___snd_pcm_xrun, "snd_pcm" },
	{ "__tracepoint_hw_interval_param",
	  (void *)&klpe___tracepoint_hw_interval_param, "snd_pcm" },
	{ "__tracepoint_hw_mask_param",
	  (void *)&klpe___tracepoint_hw_mask_param, "snd_pcm" },
	{ "do_pcm_hwsync", (void *)&klpe_do_pcm_hwsync, "snd_pcm" },
	{ "fixup_unreferenced_params", (void *)&klpe_fixup_unreferenced_params,
	  "snd_pcm" },
	{ "pcm_lib_apply_appl_ptr", (void *)&klpe_pcm_lib_apply_appl_ptr,
	  "snd_pcm" },
	{ "snd_lookup_minor_data", (void *)&klpe_snd_lookup_minor_data,
	  "snd" },
	{ "snd_major", (void *)&klpe_snd_major, "snd" },
	{ "snd_pcm_action_lock_irq", (void *)&klpe_snd_pcm_action_lock_irq,
	  "snd_pcm" },
	{ "snd_pcm_action_pause", (void *)&klpe_snd_pcm_action_pause,
	  "snd_pcm" },
	{ "snd_pcm_action_reset", (void *)&klpe_snd_pcm_action_reset,
	  "snd_pcm" },
	{ "snd_pcm_action_resume", (void *)&klpe_snd_pcm_action_resume,
	  "snd_pcm" },
	{ "snd_pcm_action_single", (void *)&klpe_snd_pcm_action_single,
	  "snd_pcm" },
	{ "snd_pcm_action_start", (void *)&klpe_snd_pcm_action_start,
	  "snd_pcm" },
	{ "snd_pcm_channel_info", (void *)&klpe_snd_pcm_channel_info,
	  "snd_pcm" },
	{ "snd_pcm_delay", (void *)&klpe_snd_pcm_delay, "snd_pcm" },
	{ "snd_pcm_drain", (void *)&klpe_snd_pcm_drain, "snd_pcm" },
	{ "snd_pcm_drop", (void *)&klpe_snd_pcm_drop, "snd_pcm" },
	{ "snd_pcm_format_physical_width",
	  (void *)&klpe_snd_pcm_format_physical_width, "snd_pcm" },
	{ "snd_pcm_hw_convert_from_old_params",
	  (void *)&klpe_snd_pcm_hw_convert_from_old_params, "snd_pcm" },
	{ "snd_pcm_hw_convert_to_old_params",
	  (void *)&klpe_snd_pcm_hw_convert_to_old_params, "snd_pcm" },
	{ "snd_pcm_hw_param_first", (void *)&klpe_snd_pcm_hw_param_first,
	  "snd_pcm" },
	{ "snd_pcm_hw_param_last", (void *)&klpe_snd_pcm_hw_param_last,
	  "snd_pcm" },
	{ "snd_pcm_hw_refine", (void *)&klpe_snd_pcm_hw_refine, "snd_pcm" },
	{ "snd_pcm_hwsync", (void *)&klpe_snd_pcm_hwsync, "snd_pcm" },
	{ "snd_pcm_info_user", (void *)&klpe_snd_pcm_info_user, "snd_pcm" },
	{ "snd_pcm_link_rwlock", (void *)&klpe_snd_pcm_link_rwlock,
	  "snd_pcm" },
	{ "snd_pcm_link_rwsem", (void *)&klpe_snd_pcm_link_rwsem, "snd_pcm" },
	{ "snd_pcm_prepare", (void *)&klpe_snd_pcm_prepare, "snd_pcm" },
	{ "snd_pcm_set_state", (void *)&klpe_snd_pcm_set_state, "snd_pcm" },
	{ "snd_pcm_status_user", (void *)&klpe_snd_pcm_status_user,
	  "snd_pcm" },
	{ "snd_pcm_stream_lock_irq", (void *)&klpe_snd_pcm_stream_lock_irq,
	  "snd_pcm" },
	{ "snd_pcm_stream_unlock_irq", (void *)&klpe_snd_pcm_stream_unlock_irq,
	  "snd_pcm" },
	{ "snd_pcm_sw_params_user", (void *)&klpe_snd_pcm_sw_params_user,
	  "snd_pcm" },
	{ "snd_pcm_sync_ptr", (void *)&klpe_snd_pcm_sync_ptr, "snd_pcm" },
	{ "snd_pcm_timer_resolution_change",
	  (void *)&klpe_snd_pcm_timer_resolution_change, "snd_pcm" },
	{ "snd_pcm_unlink", (void *)&klpe_snd_pcm_unlink, "snd_pcm" },
	{ "snd_power_wait", (void *)&klpe_snd_power_wait, "snd" },
};

static int bsc1197597_pcm_native_module_notify(struct notifier_block *nb,
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

static struct notifier_block bsc1197597_pcm_native_module_nb = {
	.notifier_call = bsc1197597_pcm_native_module_notify,
	.priority = INT_MIN+1,
};

int bsc1197597_pcm_native_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&bsc1197597_pcm_native_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1197597_pcm_native_cleanup(void)
{
	unregister_module_notifier(&bsc1197597_pcm_native_module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_PCM) */
