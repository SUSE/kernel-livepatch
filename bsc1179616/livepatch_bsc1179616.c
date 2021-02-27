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

#include "shadow.h"
#include <linux/livepatch.h>

#define KLP_BSC1179616_BUFFER_REF_ID KLP_SHADOW_ID(1179616, 0)

/* klp-ccp: from sound/core/rawmidi.c */
#include <sound/core.h>
#include <linux/major.h>
#include <linux/init.h>
#include <linux/sched/signal.h>
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
long klpp_snd_rawmidi_kernel_read(struct snd_rawmidi_substream *substream,
			     unsigned char *buf, long count);

/* klp-ccp: from sound/core/rawmidi.c */
#include <sound/info.h>
#include <sound/initval.h>

static inline int snd_rawmidi_ready(struct snd_rawmidi_substream *substream)
{
	struct snd_rawmidi_runtime *runtime = substream->runtime;

	return runtime->avail >= runtime->avail_min;
}

static inline void snd_rawmidi_output_trigger(struct snd_rawmidi_substream *substream, int up)
{
	if (!substream->opened)
		return;
	substream->ops->trigger(substream, up);
}

static void snd_rawmidi_input_trigger(struct snd_rawmidi_substream *substream, int up)
{
	if (!substream->opened)
		return;
	substream->ops->trigger(substream, up);
	if (!up)
		cancel_work_sync(&substream->runtime->event_work);
}

static void __reset_runtime_ptrs(struct snd_rawmidi_runtime *runtime,
				 bool is_input)
{
	runtime->drain = 0;
	runtime->appl_ptr = runtime->hw_ptr = 0;
	runtime->avail = is_input ? 0 : runtime->buffer_size;
}

/* New. */
static int *klpp_snd_rawmidi_buffer_ref(struct snd_rawmidi_runtime *runtime)
{
	int *buffer_ref_shadow;

	buffer_ref_shadow = klp_shadow_get_or_alloc(runtime,
						KLP_BSC1179616_BUFFER_REF_ID,
						sizeof(*buffer_ref_shadow),
						GFP_ATOMIC, NULL, NULL);
	if (!buffer_ref_shadow)
		return NULL;

	(*buffer_ref_shadow)++;
	return buffer_ref_shadow;
}

/* New. */
static void klpp_snd_rawmidi_buffer_unref(struct snd_rawmidi_runtime *runtime,
					  int * const buffer_ref_shadow)
{
	(*buffer_ref_shadow)--;
	if (!*buffer_ref_shadow)
		klp_shadow_free(runtime, KLP_BSC1179616_BUFFER_REF_ID, NULL);
}

/* New. */
static bool
klpp_snd_rawmidi_buffer_referenced(struct snd_rawmidi_runtime *runtime)
{
	int *buffer_ref_shadow;

	buffer_ref_shadow = klp_shadow_get(runtime,
					   KLP_BSC1179616_BUFFER_REF_ID);
	if (!buffer_ref_shadow)
		return false;

	return *buffer_ref_shadow != 0;
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
		/*
		 * Fix CVE-2020-27786
		 *  +5 lines
		 */
		if (klpp_snd_rawmidi_buffer_referenced(runtime)) {
			spin_unlock_irq(&runtime->lock);
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

static long klpp_snd_rawmidi_kernel_read1(struct snd_rawmidi_substream *substream,
				     unsigned char __user *userbuf,
				     unsigned char *kernelbuf, long count)
{
	unsigned long flags;
	long result = 0, count1;
	struct snd_rawmidi_runtime *runtime = substream->runtime;
	unsigned long appl_ptr;
	/*
	 * Fix CVE-2020-27786
	 *  +2 lines
	 */
	int err = 0;
	int *buffer_ref_shadow;

	spin_lock_irqsave(&runtime->lock, flags);
	/*
	 * Fix CVE-2020-27786
	 *  +5 lines
	 */
	buffer_ref_shadow = klpp_snd_rawmidi_buffer_ref(runtime);
	if (!buffer_ref_shadow) {
		spin_unlock_irqrestore(&runtime->lock, flags);
		return -ENOMEM;
	}
	while (count > 0 && runtime->avail) {
		count1 = runtime->buffer_size - runtime->appl_ptr;
		if (count1 > count)
			count1 = count;
		if (count1 > (int)runtime->avail)
			count1 = runtime->avail;

		/* update runtime->appl_ptr before unlocking for userbuf */
		appl_ptr = runtime->appl_ptr;
		runtime->appl_ptr += count1;
		runtime->appl_ptr %= runtime->buffer_size;
		runtime->avail -= count1;

		if (kernelbuf)
			memcpy(kernelbuf + result, runtime->buffer + appl_ptr, count1);
		if (userbuf) {
			spin_unlock_irqrestore(&runtime->lock, flags);
			if (copy_to_user(userbuf + result,
					 runtime->buffer + appl_ptr, count1)) {
				/*
				 * Fix CVE-2020-27786
				 *  -1 line, +1 line
				 */
				err = -EFAULT;
			}
			spin_lock_irqsave(&runtime->lock, flags);
			/*
			 * Fix CVE-2020-27786
			 *  +2 lines
			 */
			if (err)
				goto out;
		}
		result += count1;
		count -= count1;
	}
	/*
	 * Fix CVE-2020-27786
	 *  +2 lines
	 */
out:
	klpp_snd_rawmidi_buffer_unref(runtime, buffer_ref_shadow);
	spin_unlock_irqrestore(&runtime->lock, flags);
	/*
	 * Fix CVE-2020-27786
	 *  -1 line, +1 line
	 */
	return result > 0 ? result : err;
}

long klpp_snd_rawmidi_kernel_read(struct snd_rawmidi_substream *substream,
			     unsigned char *buf, long count)
{
	snd_rawmidi_input_trigger(substream, 1);
	return klpp_snd_rawmidi_kernel_read1(substream, NULL/*userbuf*/, buf, count);
}

ssize_t klpp_snd_rawmidi_read(struct file *file, char __user *buf, size_t count,
				loff_t *offset)
{
	long result;
	int count1;
	struct snd_rawmidi_file *rfile;
	struct snd_rawmidi_substream *substream;
	struct snd_rawmidi_runtime *runtime;

	rfile = file->private_data;
	substream = rfile->input;
	if (substream == NULL)
		return -EIO;
	runtime = substream->runtime;
	snd_rawmidi_input_trigger(substream, 1);
	result = 0;
	while (count > 0) {
		spin_lock_irq(&runtime->lock);
		while (!snd_rawmidi_ready(substream)) {
			wait_queue_entry_t wait;

			if ((file->f_flags & O_NONBLOCK) != 0 || result > 0) {
				spin_unlock_irq(&runtime->lock);
				return result > 0 ? result : -EAGAIN;
			}
			init_waitqueue_entry(&wait, current);
			add_wait_queue(&runtime->sleep, &wait);
			set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_irq(&runtime->lock);
			schedule();
			remove_wait_queue(&runtime->sleep, &wait);
			if (rfile->rmidi->card->shutdown)
				return -ENODEV;
			if (signal_pending(current))
				return result > 0 ? result : -ERESTARTSYS;
			if (!runtime->avail)
				return result > 0 ? result : -EIO;
			spin_lock_irq(&runtime->lock);
		}
		spin_unlock_irq(&runtime->lock);
		count1 = klpp_snd_rawmidi_kernel_read1(substream,
						  (unsigned char __user *)buf,
						  NULL/*kernelbuf*/,
						  count);
		if (count1 < 0)
			return result > 0 ? result : count1;
		result += count1;
		buf += count1;
		count -= count1;
	}
	return result;
}

long klpp_snd_rawmidi_kernel_write1(struct snd_rawmidi_substream *substream,
				      const unsigned char __user *userbuf,
				      const unsigned char *kernelbuf,
				      long count)
{
	unsigned long flags;
	long count1, result;
	struct snd_rawmidi_runtime *runtime = substream->runtime;
	unsigned long appl_ptr;
	/*
	 * Fix CVE-2020-27786
	 *  +1 line
	 */
	int *buffer_ref_shadow;

	if (!kernelbuf && !userbuf)
		return -EINVAL;
	if (snd_BUG_ON(!runtime->buffer))
		return -EINVAL;

	result = 0;
	spin_lock_irqsave(&runtime->lock, flags);
	if (substream->append) {
		if ((long)runtime->avail < count) {
			spin_unlock_irqrestore(&runtime->lock, flags);
			return -EAGAIN;
		}
	}
	/*
	 * Fix CVE-2020-27786
	 *  +5 lines
	 */
	buffer_ref_shadow = klpp_snd_rawmidi_buffer_ref(runtime);
	if (!buffer_ref_shadow) {
		spin_unlock_irqrestore(&runtime->lock, flags);
		return -ENOMEM;
	}
	while (count > 0 && runtime->avail > 0) {
		count1 = runtime->buffer_size - runtime->appl_ptr;
		if (count1 > count)
			count1 = count;
		if (count1 > (long)runtime->avail)
			count1 = runtime->avail;

		/* update runtime->appl_ptr before unlocking for userbuf */
		appl_ptr = runtime->appl_ptr;
		runtime->appl_ptr += count1;
		runtime->appl_ptr %= runtime->buffer_size;
		runtime->avail -= count1;

		if (kernelbuf)
			memcpy(runtime->buffer + appl_ptr,
			       kernelbuf + result, count1);
		else if (userbuf) {
			spin_unlock_irqrestore(&runtime->lock, flags);
			if (copy_from_user(runtime->buffer + appl_ptr,
					   userbuf + result, count1)) {
				spin_lock_irqsave(&runtime->lock, flags);
				result = result > 0 ? result : -EFAULT;
				goto __end;
			}
			spin_lock_irqsave(&runtime->lock, flags);
		}
		result += count1;
		count -= count1;
	}
      __end:
	count1 = runtime->avail < runtime->buffer_size;
	/*
	 * Fix CVE-2020-27786
	 *  +1 line
	 */
	klpp_snd_rawmidi_buffer_unref(runtime, buffer_ref_shadow);
	spin_unlock_irqrestore(&runtime->lock, flags);
	if (count1)
		snd_rawmidi_output_trigger(substream, 1);
	return result;
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
