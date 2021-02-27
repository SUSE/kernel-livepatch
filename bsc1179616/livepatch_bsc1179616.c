/*
 * livepatch_bsc1179616
 *
 * Fix for CVE-2020-27786, bsc#1179616
 *
 *  c1f6e3c818dd ("ALSA: rawmidi: Fix racy buffer resize under concurrent
 *                 accesses")
 *
 *  SLE12-SP2 and -SP3 commits:
 *  1c1d0c36995d73cc90f6cb744c89b5fa38919502
 *  32875b8a0c257c0b9924b2a05521ee63d726ba4c
 *
 *  SLE12-SP4 commits
 *  27bd92efbb2ad822a216cc7024c6100d2c4b7bb7
 *  ce80dfa9c8907201c0b3c0bbe8e098b18db76fcb
 *
 *  SLE12-SP5 commits:
 *  27bd92efbb2ad822a216cc7024c6100d2c4b7bb7
 *  a0147ff773f8c58ff4f48411d72d0fe7186eef04
 *
 *  SLE15 commits
 *  3c00a93fae84c7825e2622e25462b8926842b7dc
 *  ce80dfa9c8907201c0b3c0bbe8e098b18db76fcb
 *
 *  SLE15-SP1 commits:
 *  27bd92efbb2ad822a216cc7024c6100d2c4b7bb7
 *  b3ad1de3362970c30e5aeb3bc3f264029b629340
 *
 *  SLE15-SP2 commit:
 *  f2740c06ea19df59bae3aaaca37ff19f6b33144e
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if IS_ENABLED(CONFIG_SND_RAWMIDI)

#if !IS_MODULE(CONFIG_SND_RAWMIDI)
#error "Live patch supports only CONFIG_SND_RAWMIDI=m"
#endif

/* klp-ccp: from sound/core/rawmidi.c */
#include <sound/core.h>
#include <linux/major.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <sound/rawmidi.h>

/* klp-ccp: from include/sound/rawmidi.h */
int klpp_snd_rawmidi_output_params(struct snd_rawmidi_substream *substream,
			      struct snd_rawmidi_params *params);
int klpp_snd_rawmidi_input_params(struct snd_rawmidi_substream *substream,
			     struct snd_rawmidi_params *params);

static int (*klpe_snd_rawmidi_drain_output)(struct snd_rawmidi_substream *substream);
static int (*klpe_snd_rawmidi_drain_input)(struct snd_rawmidi_substream *substream);

/* klp-ccp: from sound/core/rawmidi.c */
#include <sound/initval.h>

static void __reset_runtime_ptrs(struct snd_rawmidi_runtime *runtime,
				 bool is_input)
{
	runtime->drain = 0;
	runtime->appl_ptr = runtime->hw_ptr = 0;
	runtime->avail = is_input ? 0 : runtime->buffer_size;
}

static int klpp_resize_runtime_buffer(struct snd_rawmidi_runtime *runtime,
				 struct snd_rawmidi_params *params,
				 bool is_input)
{
	char *newbuf, *oldbuf;

	if (params->buffer_size < 32 || params->buffer_size > 1024L * 1024L)
		return -EINVAL;
	if (params->avail_min < 1 || params->avail_min > params->buffer_size)
		return -EINVAL;
	if (params->buffer_size != runtime->buffer_size) {
		newbuf = kvzalloc(params->buffer_size, GFP_KERNEL);
		if (!newbuf)
			return -ENOMEM;
		spin_lock_irq(&runtime->lock);
		if (runtime->buffer_ref) {
			spin_unlock_irq(&runtime->lock);
			/*
			 * Fix CVE-2020-27786
			 *  -1 line, +1 line
			 */
			kvfree(newbuf);
			return -EBUSY;
		}
		oldbuf = runtime->buffer;
		runtime->buffer = newbuf;
		runtime->buffer_size = params->buffer_size;
		__reset_runtime_ptrs(runtime, is_input);
		spin_unlock_irq(&runtime->lock);
		kvfree(oldbuf);
	}
	runtime->avail_min = params->avail_min;
	return 0;
}

int klpp_snd_rawmidi_output_params(struct snd_rawmidi_substream *substream,
			      struct snd_rawmidi_params *params)
{
	if (substream->append && substream->use_count > 1)
		return -EBUSY;
	(*klpe_snd_rawmidi_drain_output)(substream);
	substream->active_sensing = !params->no_active_sensing;
	return klpp_resize_runtime_buffer(substream->runtime, params, false);
}

int klpp_snd_rawmidi_input_params(struct snd_rawmidi_substream *substream,
			     struct snd_rawmidi_params *params)
{
	(*klpe_snd_rawmidi_drain_input)(substream);
	return klpp_resize_runtime_buffer(substream->runtime, params, true);
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1179616.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "snd_rawmidi"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_rawmidi_drain_output", (void *)&klpe_snd_rawmidi_drain_output,
	  "snd_rawmidi" },
	{ "snd_rawmidi_drain_input", (void *)&klpe_snd_rawmidi_drain_input,
	  "snd_rawmidi" },
};

static int livepatch_bsc1179616_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1179616_module_nb = {
	.notifier_call = livepatch_bsc1179616_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1179616_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1179616_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1179616_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1179616_module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_RAWMIDI) */
