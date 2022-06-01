/*
 * bsc1197597_pcm_memory
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

/* klp-ccp: from sound/core/pcm_memory.c */
#include <linux/io.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/export.h>
#include <sound/core.h>
#include <sound/pcm.h>

/* klp-ccp: from include/sound/memalloc.h */
static int (*klpe_snd_dma_alloc_pages)(int type, struct device *dev, size_t size,
			struct snd_dma_buffer *dmab);

static void (*klpe_snd_dma_free_pages)(struct snd_dma_buffer *dmab);

/* klp-ccp: from sound/core/pcm_memory.c */
#include <sound/info.h>

/* klp-ccp: from include/sound/info.h */
#ifdef CONFIG_SND_PROC_FS

static int (*klpe_snd_info_get_line)(struct snd_info_buffer *buffer, char *line, int len);
static const char *(*klpe_snd_info_get_str)(char *dest, const char *src, int len);

#else
#error "klp-ccp: non-taken branch"
#endif

/* klp-ccp: from sound/core/pcm_memory.c */
#include <sound/initval.h>

#ifdef CONFIG_SND_VERBOSE_PROCFS

void klpp_snd_pcm_lib_preallocate_proc_write(struct snd_info_entry *entry,
					       struct snd_info_buffer *buffer)
{
	struct snd_pcm_substream *substream = entry->private_data;
	char line[64], str[64];
	size_t size;
	struct snd_dma_buffer new_dmab;

	mutex_lock(&substream->pcm->open_mutex);
	if (substream->runtime) {
		buffer->error = -EBUSY;
		goto unlock;
	}
	if (!(*klpe_snd_info_get_line)(buffer, line, sizeof(line))) {
		(*klpe_snd_info_get_str)(str, line, sizeof(str));
		size = simple_strtoul(str, NULL, 10) * 1024;
		if ((size != 0 && size < 8192) || size > substream->dma_max) {
			buffer->error = -EINVAL;
			goto unlock;
		}
		if (substream->dma_buffer.bytes == size)
			goto unlock;
		memset(&new_dmab, 0, sizeof(new_dmab));
		new_dmab.dev = substream->dma_buffer.dev;
		if (size > 0) {
			if ((*klpe_snd_dma_alloc_pages)(substream->dma_buffer.dev.type,
						substream->dma_buffer.dev.dev,
						size, &new_dmab) < 0) {
				buffer->error = -ENOMEM;
				goto unlock;
			}
			substream->buffer_bytes_max = size;
		} else {
			substream->buffer_bytes_max = UINT_MAX;
		}
		if (substream->dma_buffer.area)
			(*klpe_snd_dma_free_pages)(&substream->dma_buffer);
		substream->dma_buffer = new_dmab;
	} else {
		buffer->error = -EINVAL;
	}
unlock:
	mutex_unlock(&substream->pcm->open_mutex);
}

#else /* !CONFIG_SND_VERBOSE_PROCFS */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_SND_VERBOSE_PROCFS */



#define LP_MODULE "snd_pcm"

#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1197597.h"
#include "../kallsyms_relocs.h"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_dma_alloc_pages", (void *)&klpe_snd_dma_alloc_pages,
	  "snd_pcm" },
	{ "snd_dma_free_pages", (void *)&klpe_snd_dma_free_pages, "snd_pcm" },
	{ "snd_info_get_line", (void *)&klpe_snd_info_get_line, "snd" },
	{ "snd_info_get_str", (void *)&klpe_snd_info_get_str, "snd" },
};

static int bsc1197597_pcm_memory_module_notify(struct notifier_block *nb,
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

static struct notifier_block bsc1197597_pcm_memory_module_nb = {
	.notifier_call = bsc1197597_pcm_memory_module_notify,
	.priority = INT_MIN+1,
};

int bsc1197597_pcm_memory_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LP_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&bsc1197597_pcm_memory_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void bsc1197597_pcm_memory_cleanup(void)
{
	unregister_module_notifier(&bsc1197597_pcm_memory_module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_PCM) */
