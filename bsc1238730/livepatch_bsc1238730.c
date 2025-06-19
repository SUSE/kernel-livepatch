/*
 * livepatch_bsc1238730
 *
 * Fix for CVE-2022-49545, bsc#1238730
 *
 *  Upstream commit:
 *  0125de38122f ("ALSA: usb-audio: Cancel pending work at closing a MIDI substream")
 *
 *  SLE12-SP5 commit:
 *  c5aef003d9f59899c5e6aa9d2c71d891b106b0ba
 *
 *  SLE15-SP3 commit:
 *  cb1f0e55c1f7fffaf0f0cdee109f7af82217dc72
 *
 *  SLE15-SP4 and -SP5 commit:
 *  1d7e2005a2d6f1d41d2ba9408b0ceb2330f2990c
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  SLE MICRO-6-0 commit:
 *  Not affected
 *
 *  Copyright (c) 2025 SUSE
 *  Author: Ali Abdallah <ali.abdallah@suse.com>
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

#if IS_ENABLED(CONFIG_SND_USB_AUDIO)

/* klp-ccp: from sound/usb/midi.c */
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/init.h>

/* klp-ccp: from sound/usb/midi.c */
#include <linux/timer.h>
#include <linux/usb.h>

/* klp-ccp: from include/linux/usb.h */
int (*klpe_usb_set_interface)(struct usb_device *dev, int ifnum, int alternate);

/* klp-ccp: from sound/usb/midi.c */
#include <linux/wait.h>

#include <sound/control.h>

/* klp-ccp: from include/sound/control.h */
void (*klpe_snd_ctl_notify)(struct snd_card * card, unsigned int mask, struct snd_ctl_elem_id * id);

/* klp-ccp: from sound/usb/midi.c */
#include <sound/rawmidi.h>

/* klp-ccp: from sound/usb/midi.h */
#define MIDI_MAX_ENDPOINTS 2

void (*klpe_snd_usbmidi_input_stop)(struct list_head *p);
void (*klpe_snd_usbmidi_input_start)(struct list_head *p);

/* klp-ccp: from sound/usb/helper.h */
#define get_iface_desc(iface)	(&(iface)->desc)

/* klp-ccp: from sound/usb/midi.c */
#define OUTPUT_URBS 7

struct snd_usb_midi {
	struct usb_device *dev;
	struct snd_card *card;
	struct usb_interface *iface;
	const struct snd_usb_audio_quirk *quirk;
	struct snd_rawmidi *rmidi;
	const struct usb_protocol_ops *usb_protocol_ops;
	struct list_head list;
	struct timer_list error_timer;
	spinlock_t disc_lock;
	struct rw_semaphore disc_rwsem;
	struct mutex mutex;
	u32 usb_id;
	int next_midi_device;

	struct snd_usb_midi_endpoint {
		struct snd_usb_midi_out_endpoint *out;
		struct snd_usb_midi_in_endpoint *in;
	} endpoints[MIDI_MAX_ENDPOINTS];
	unsigned long input_triggered;
	unsigned int opened[2];
	unsigned char disconnected;
	unsigned char input_running;

	struct snd_kcontrol *roland_load_ctl;
};

struct snd_usb_midi_out_endpoint {
	struct snd_usb_midi *umidi;
	struct out_urb_context {
		struct urb *urb;
		struct snd_usb_midi_out_endpoint *ep;
	} urbs[OUTPUT_URBS];
	unsigned int active_urbs;
	unsigned int drain_urbs;
	int max_transfer;		/* size of urb buffer */
	struct tasklet_struct tasklet;
	unsigned int next_urb;
	spinlock_t buffer_lock;

	struct usbmidi_out_port {
		struct snd_usb_midi_out_endpoint *ep;
		struct snd_rawmidi_substream *substream;
		int active;
		uint8_t cable;		/* cable number << 4 */
		uint8_t state;
		uint8_t data[2];
	} ports[0x10];
	int current_port;

	wait_queue_head_t drain_wait;
};

static void klpr_update_roland_altsetting(struct snd_usb_midi *umidi)
{
	struct usb_interface *intf;
	struct usb_host_interface *hostif;
	struct usb_interface_descriptor *intfd;
	int is_light_load;

	intf = umidi->iface;
	is_light_load = intf->cur_altsetting != intf->altsetting;
	if (umidi->roland_load_ctl->private_value == is_light_load)
		return;
	hostif = &intf->altsetting[umidi->roland_load_ctl->private_value];
	intfd = get_iface_desc(hostif);
	(*klpe_snd_usbmidi_input_stop)(&umidi->list);
	(*klpe_usb_set_interface)(umidi->dev, intfd->bInterfaceNumber,
			  intfd->bAlternateSetting);
	(*klpe_snd_usbmidi_input_start)(&umidi->list);
}

static int klpr_substream_open(struct snd_rawmidi_substream *substream, int dir,
			  int open)
{
	struct snd_usb_midi *umidi = substream->rmidi->private_data;
	struct snd_kcontrol *ctl;

	down_read(&umidi->disc_rwsem);
	if (umidi->disconnected) {
		up_read(&umidi->disc_rwsem);
		return open ? -ENODEV : 0;
	}

	mutex_lock(&umidi->mutex);
	if (open) {
		if (!umidi->opened[0] && !umidi->opened[1]) {
			if (umidi->roland_load_ctl) {
				ctl = umidi->roland_load_ctl;
				ctl->vd[0].access |=
					SNDRV_CTL_ELEM_ACCESS_INACTIVE;
				(*klpe_snd_ctl_notify)(umidi->card,
				       SNDRV_CTL_EVENT_MASK_INFO, &ctl->id);
				klpr_update_roland_altsetting(umidi);
			}
		}
		umidi->opened[dir]++;
		if (umidi->opened[1])
			(*klpe_snd_usbmidi_input_start)(&umidi->list);
	} else {
		umidi->opened[dir]--;
		if (!umidi->opened[1])
			(*klpe_snd_usbmidi_input_stop)(&umidi->list);
		if (!umidi->opened[0] && !umidi->opened[1]) {
			if (umidi->roland_load_ctl) {
				ctl = umidi->roland_load_ctl;
				ctl->vd[0].access &=
					~SNDRV_CTL_ELEM_ACCESS_INACTIVE;
				(*klpe_snd_ctl_notify)(umidi->card,
				       SNDRV_CTL_EVENT_MASK_INFO, &ctl->id);
			}
		}
	}
	mutex_unlock(&umidi->mutex);
	up_read(&umidi->disc_rwsem);
	return 0;
}

int klpp_snd_usbmidi_output_close(struct snd_rawmidi_substream *substream)
{
	struct usbmidi_out_port *port = substream->runtime->private_data;

	tasklet_kill(&port->ep->tasklet);
	return klpr_substream_open(substream, 0, 0);
}

void (*klpe_snd_usbmidi_input_stop)(struct list_head *p);

typeof((*klpe_snd_usbmidi_input_stop)) (*klpe_snd_usbmidi_input_stop);

void (*klpe_snd_usbmidi_input_start)(struct list_head *p);

typeof((*klpe_snd_usbmidi_input_start)) (*klpe_snd_usbmidi_input_start);


#include "livepatch_bsc1238730.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "snd_usbmidi_lib"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "snd_ctl_notify", (void *)&klpe_snd_ctl_notify, "snd" },
	{ "snd_usbmidi_input_start", (void *)&klpe_snd_usbmidi_input_start,
	  "snd_usbmidi_lib" },
	{ "snd_usbmidi_input_stop", (void *)&klpe_snd_usbmidi_input_stop,
	  "snd_usbmidi_lib" },
	{ "usb_set_interface", (void *)&klpe_usb_set_interface, "usbcore" },
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

int livepatch_bsc1238730_init(void)
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

void livepatch_bsc1238730_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND_USB_AUDIO) */
