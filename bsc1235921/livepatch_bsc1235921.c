/*
 * livepatch_bsc1235921
 *
 * Fix for CVE-2024-57893, bsc#1235921
 *
 *  Upstream commit:
 *  0179488ca992 ("ALSA: seq: oss: Fix races at processing SysEx messages")
 *
 *  SLE12-SP5 commit:
 *  7be38f2bf91ced62fd73a9bb16be66a4088616bf
 *
 *  SLE15-SP3 commit:
 *  c549c09e683b124174841c337a25fece3ed9f245
 *
 *  SLE15-SP4 and -SP5 commit:
 *  f05049d42c30e92fb71583048dada2dbbf53853e
 *
 *  SLE15-SP6 commit:
 *  4d35f612b13a4b53cbf59234a039bde2e4c4ab4a
 *
 *  SLE MICRO-6-0 commit:
 *  4d35f612b13a4b53cbf59234a039bde2e4c4ab4a
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Marco Crivellari <marco.crivellari@suse.com>
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

#if IS_ENABLED(CONFIG_SND_SEQUENCER_OSS)

/* klp-ccp: from sound/core/seq/oss/seq_oss_device.h */
#include <linux/time.h>
#include <linux/wait.h>

/* klp-ccp: from include/sound/core.h */
struct snd_card;

/* klp-ccp: from sound/core/seq/oss/seq_oss_device.h */
#include <sound/seq_oss.h>

/* klp-ccp: from include/sound/seq_device.h */
#define __SOUND_SEQ_DEVICE_H

/* klp-ccp: from sound/core/seq/oss/seq_oss_device.h */
#include <linux/bitops.h>
#include <linux/poll.h>
#include <linux/sched.h>

/* klp-ccp: from sound/core/seq/seq_ports.h */
#include <sound/seq_kernel.h>

/* klp-ccp: from sound/core/seq/oss/seq_oss_device.h */
struct seq_oss_synthinfo {
	struct snd_seq_oss_arg arg;
	struct seq_oss_chinfo *ch;
	struct seq_oss_synth_sysex *sysex;
	int nr_voices;
	int opened;
	int is_midi;
	int midi_mapped;
};

struct seq_oss_devinfo;

static struct seq_oss_synthinfo *(*klpe_snd_seq_oss_synth_info)(struct seq_oss_devinfo *dp,
						 int dev);
static int (*klpe_snd_seq_oss_synth_addr)(struct seq_oss_devinfo *dp, int dev, struct snd_seq_event *ev);

/* klp-ccp: from sound/core/seq/oss/seq_oss_midi.h */
#include <sound/seq_oss_legacy.h>

/* klp-ccp: from sound/core/seq/oss/seq_oss_synth.c */
#include <linux/init.h>
#include <linux/slab.h>

#define MAX_SYSEX_BUFLEN		128

struct seq_oss_synth_sysex {
	int len;
	int skip;
	unsigned char buf[MAX_SYSEX_BUFLEN];
};

static DEFINE_MUTEX(sysex_mutex);

int
klpp_snd_seq_oss_synth_sysex(struct seq_oss_devinfo *dp, int dev, unsigned char *buf, struct snd_seq_event *ev)
{
	int i, send;
	unsigned char *dest;
	struct seq_oss_synth_sysex *sysex;
	struct seq_oss_synthinfo *info;

	info = (*klpe_snd_seq_oss_synth_info)(dp, dev);
	if (!info)
		return -ENXIO;

	mutex_lock(&sysex_mutex);
	sysex = info->sysex;
	if (sysex == NULL) {
		sysex = kzalloc(sizeof(*sysex), GFP_KERNEL);
		if (sysex == NULL) {
			mutex_unlock(&sysex_mutex);
			return -ENOMEM;
		}
		info->sysex = sysex;
	}

	send = 0;
	dest = sysex->buf + sysex->len;
	/* copy 6 byte packet to the buffer */
	for (i = 0; i < 6; i++) {
		if (buf[i] == 0xff) {
			send = 1;
			break;
		}
		dest[i] = buf[i];
		sysex->len++;
		if (sysex->len >= MAX_SYSEX_BUFLEN) {
			sysex->len = 0;
			sysex->skip = 1;
			break;
		}
	}

	if (sysex->len && send) {
		if (sysex->skip) {
			sysex->skip = 0;
			sysex->len = 0;
			mutex_unlock(&sysex_mutex);
			return -EINVAL; /* skip */
		}
		/* copy the data to event record and send it */
		ev->flags = SNDRV_SEQ_EVENT_LENGTH_VARIABLE;
		if ((*klpe_snd_seq_oss_synth_addr)(dp, dev, ev)) {
			mutex_unlock(&sysex_mutex);
			return -EINVAL;
		}
		ev->data.ext.len = sysex->len;
		ev->data.ext.ptr = sysex->buf;
		sysex->len = 0;
		mutex_unlock(&sysex_mutex);
		return 0;
	}

	mutex_unlock(&sysex_mutex);
	return -EINVAL; /* skip */
}

#include "livepatch_bsc1235921.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "snd_seq_oss"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_seq_oss_synth_addr", (void *)&klpe_snd_seq_oss_synth_addr,
	  "snd_seq_oss" },
	{ "snd_seq_oss_synth_info", (void *)&klpe_snd_seq_oss_synth_info,
	  "snd_seq_oss" },
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

int livepatch_bsc1235921_init(void)
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

void livepatch_bsc1235921_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_SEQUENCER_OSS) */
