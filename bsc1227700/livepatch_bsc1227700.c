/*
 * livepatch_bsc1227700
 *
 * Fix for CVE-2021-47511, bsc#1227700
 *
 *  Upstream commit:
 *  9d2479c96087 ("ALSA: pcm: oss: Fix negative period/buffer sizes")
 *
 *  SLE12-SP5 commit:
 *  748d8c16601bbf308f0a81c7e0a6bbf524118d55
 *
 *  SLE15-SP3 commit:
 *  094796a2bf2698dc8604dc319736ed207fd09c93
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b0df34c3f8feb66914b43048f73e7763cafd4a03
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
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

#if IS_ENABLED(CONFIG_SND_PCM_OSS)

#if !IS_MODULE(CONFIG_SND_PCM_OSS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from sound/core/oss/pcm_oss.c */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/math64.h>
#include <linux/string.h>
#include <linux/compat.h>
#include <sound/core.h>

/* klp-ccp: from sound/core/oss/pcm_oss.c */
#include <sound/pcm.h>

/* klp-ccp: from include/sound/pcm.h */
static int (*klpe_snd_pcm_format_physical_width)(snd_pcm_format_t format);

/* klp-ccp: from sound/core/oss/pcm_oss.c */
#include <sound/pcm_params.h>

/* klp-ccp: from sound/core/oss/pcm_plugin.h */
#ifdef CONFIG_SND_PCM_OSS_PLUGINS
static snd_pcm_sframes_t (*klpe_snd_pcm_plug_client_size)(struct snd_pcm_substream *handle, snd_pcm_uframes_t drv_size);
#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from sound/core/oss/pcm_oss.c */
#include <sound/initval.h>

static unsigned int
(*klpe_snd_pcm_hw_param_value_min)(const struct snd_pcm_hw_params *params,
			   snd_pcm_hw_param_t var, int *dir);

static int
(*klpe_snd_pcm_hw_param_value_max)(const struct snd_pcm_hw_params *params,
			   snd_pcm_hw_param_t var, int *dir);

int klpp_snd_pcm_oss_period_size(struct snd_pcm_substream *substream, 
				   struct snd_pcm_hw_params *oss_params,
				   struct snd_pcm_hw_params *slave_params)
{
	ssize_t s;
	ssize_t oss_buffer_size;
	ssize_t oss_period_size, oss_periods;
	ssize_t min_period_size, max_period_size;
	struct snd_pcm_runtime *runtime = substream->runtime;
	size_t oss_frame_size;

	oss_frame_size = (*klpe_snd_pcm_format_physical_width)(params_format(oss_params)) *
			 params_channels(oss_params) / 8;

	oss_buffer_size = (*klpe_snd_pcm_hw_param_value_max)(slave_params,
						     SNDRV_PCM_HW_PARAM_BUFFER_SIZE,
						     NULL);
	if (oss_buffer_size <= 0)
		return -EINVAL;
	oss_buffer_size = (*klpe_snd_pcm_plug_client_size)(substream,
						   oss_buffer_size * oss_frame_size);
	if (oss_buffer_size <= 0)
		return -EINVAL;
	oss_buffer_size = rounddown_pow_of_two(oss_buffer_size);
	if (atomic_read(&substream->mmap_count)) {
		if (oss_buffer_size > runtime->oss.mmap_bytes)
			oss_buffer_size = runtime->oss.mmap_bytes;
	}

	if (substream->oss.setup.period_size > 16)
		oss_period_size = substream->oss.setup.period_size;
	else if (runtime->oss.fragshift) {
		oss_period_size = 1 << runtime->oss.fragshift;
		if (oss_period_size > oss_buffer_size / 2)
			oss_period_size = oss_buffer_size / 2;
	} else {
		int sd;
		size_t bytes_per_sec = params_rate(oss_params) * (*klpe_snd_pcm_format_physical_width)(params_format(oss_params)) * params_channels(oss_params) / 8;

		oss_period_size = oss_buffer_size;
		do {
			oss_period_size /= 2;
		} while (oss_period_size > bytes_per_sec);
		if (runtime->oss.subdivision == 0) {
			sd = 4;
			if (oss_period_size / sd > 4096)
				sd *= 2;
			if (oss_period_size / sd < 4096)
				sd = 1;
		} else
			sd = runtime->oss.subdivision;
		oss_period_size /= sd;
		if (oss_period_size < 16)
			oss_period_size = 16;
	}

	min_period_size = (*klpe_snd_pcm_plug_client_size)(substream,
						   (*klpe_snd_pcm_hw_param_value_min)(slave_params, SNDRV_PCM_HW_PARAM_PERIOD_SIZE, NULL));
	if (min_period_size > 0) {
		min_period_size *= oss_frame_size;
		min_period_size = roundup_pow_of_two(min_period_size);
		if (oss_period_size < min_period_size)
			oss_period_size = min_period_size;
	}

	max_period_size = (*klpe_snd_pcm_plug_client_size)(substream,
						   (*klpe_snd_pcm_hw_param_value_max)(slave_params, SNDRV_PCM_HW_PARAM_PERIOD_SIZE, NULL));
	if (max_period_size > 0) {
		max_period_size *= oss_frame_size;
		max_period_size = rounddown_pow_of_two(max_period_size);
		if (oss_period_size > max_period_size)
			oss_period_size = max_period_size;
	}

	oss_periods = oss_buffer_size / oss_period_size;

	if (substream->oss.setup.periods > 1)
		oss_periods = substream->oss.setup.periods;

	s = (*klpe_snd_pcm_hw_param_value_max)(slave_params, SNDRV_PCM_HW_PARAM_PERIODS, NULL);
	if (s > 0 && runtime->oss.maxfrags && s > runtime->oss.maxfrags)
		s = runtime->oss.maxfrags;
	if (oss_periods > s)
		oss_periods = s;

	s = (*klpe_snd_pcm_hw_param_value_min)(slave_params, SNDRV_PCM_HW_PARAM_PERIODS, NULL);
	if (s < 2)
		s = 2;
	if (oss_periods < s)
		oss_periods = s;

	while (oss_period_size * oss_periods > oss_buffer_size)
		oss_period_size /= 2;

	if (oss_period_size < 16)
		return -EINVAL;
	runtime->oss.period_bytes = oss_period_size;
	runtime->oss.period_frames = 1;
	runtime->oss.periods = oss_periods;
	return 0;
}


#include "livepatch_bsc1227700.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "snd_pcm_oss"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_pcm_format_physical_width",
	  (void *)&klpe_snd_pcm_format_physical_width, "snd_pcm" },
	{ "snd_pcm_hw_param_value_max",
	  (void *)&klpe_snd_pcm_hw_param_value_max, "snd_pcm_oss" },
	{ "snd_pcm_hw_param_value_min",
	  (void *)&klpe_snd_pcm_hw_param_value_min, "snd_pcm_oss" },
	{ "snd_pcm_plug_client_size", (void *)&klpe_snd_pcm_plug_client_size,
	  "snd_pcm_oss" },
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

int livepatch_bsc1227700_init(void)
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

void livepatch_bsc1227700_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_PCM_OSS) */
