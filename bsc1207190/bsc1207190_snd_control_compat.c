/*
 * livepatch_bsc1207190
 *
 * Fix for CVE-2023-0266, bsc#1207190 (snd/core/control_compat.c part)
 *
 *  Copyright (c) 2023 SUSE
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

#if IS_ENABLED(CONFIG_SND)

#if !IS_MODULE(CONFIG_SND)
#error "Live patch supports only CONFIG_SND=m"
#endif

#if !IS_ENABLED(CONFIG_COMPAT)
#error "Live patch supports only CONFIG_COMPAT=y"
#endif

/* klp-ccp: from sound/core/control.c */
#include <linux/threads.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/time.h>
#include <linux/sched/signal.h>
#include <sound/core.h>

/* klp-ccp: from include/sound/core.h */
#ifdef CONFIG_PM

static int (*klpe_snd_power_wait)(struct snd_card *card, unsigned int power_state);

#else /* ! CONFIG_PM */
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_PM */

/* klp-ccp: from sound/core/control.c */
#include <sound/info.h>
#include <sound/control.h>

struct snd_kctl_ioctl {
	struct list_head list;		/* list of all ioctls */
	snd_kctl_ioctl_func_t fioctl;
};

static struct rw_semaphore (*klpe_snd_ioctl_rwsem);

#ifdef CONFIG_COMPAT
static struct list_head (*klpe_snd_control_compat_ioctls);
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif

static int (*klpe_snd_ctl_elem_list)(struct snd_card *card,
			     struct snd_ctl_elem_list __user *_list);

static int (*klpe_snd_ctl_elem_info)(struct snd_ctl_file *ctl,
			     struct snd_ctl_elem_info *info);

static int (*klpe_snd_ctl_elem_read)(struct snd_card *card,
			     struct snd_ctl_elem_value *control);

static int (*klpe_snd_ctl_elem_write)(struct snd_card *card, struct snd_ctl_file *file,
			      struct snd_ctl_elem_value *control);

static long (*klpe_snd_ctl_ioctl)(struct file *file, unsigned int cmd, unsigned long arg);

#ifdef CONFIG_COMPAT

/* klp-ccp: from sound/core/control_compat.c */
#include <linux/compat.h>
#include <linux/slab.h>

struct snd_ctl_elem_list32 {
	u32 offset;
	u32 space;
	u32 used;
	u32 count;
	u32 pids;
	unsigned char reserved[50];
} /* don't set packed attribute here */;

static int klpr_snd_ctl_elem_list_compat(struct snd_card *card,
				    struct snd_ctl_elem_list32 __user *data32)
{
	struct snd_ctl_elem_list __user *data;
	compat_caddr_t ptr;
	int err;

	data = compat_alloc_user_space(sizeof(*data));

	/* offset, space, used, count */
	if (copy_in_user(data, data32, 4 * sizeof(u32)))
		return -EFAULT;
	/* pids */
	if (get_user(ptr, &data32->pids) ||
	    put_user(compat_ptr(ptr), &data->pids))
		return -EFAULT;
	err = (*klpe_snd_ctl_elem_list)(card, data);
	if (err < 0)
		return err;
	/* copy the result */
	if (copy_in_user(data32, data, 4 * sizeof(u32)))
		return -EFAULT;
	return 0;
}

struct snd_ctl_elem_info32 {
	struct snd_ctl_elem_id id; // the size of struct is same
	s32 type;
	u32 access;
	u32 count;
	s32 owner;
	union {
		struct {
			s32 min;
			s32 max;
			s32 step;
		} integer;
		struct {
			u64 min;
			u64 max;
			u64 step;
		} integer64;
		struct {
			u32 items;
			u32 item;
			char name[64];
			u64 names_ptr;
			u32 names_length;
		} enumerated;
		unsigned char reserved[128];
	} value;
	unsigned char reserved[64];
} __attribute__((packed));

static int klpr_snd_ctl_elem_info_compat(struct snd_ctl_file *ctl,
				    struct snd_ctl_elem_info32 __user *data32)
{
	struct snd_ctl_elem_info *data;
	int err;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (! data)
		return -ENOMEM;

	err = -EFAULT;
	/* copy id */
	if (copy_from_user(&data->id, &data32->id, sizeof(data->id)))
		goto error;
	/* we need to copy the item index.
	 * hope this doesn't break anything..
	 */
	if (get_user(data->value.enumerated.item, &data32->value.enumerated.item))
		goto error;

	err = (*klpe_snd_power_wait)(ctl->card, SNDRV_CTL_POWER_D0);
	if (err < 0)
		goto error;
	err = (*klpe_snd_ctl_elem_info)(ctl, data);
	if (err < 0)
		goto error;
	/* restore info to 32bit */
	err = -EFAULT;
	/* id, type, access, count */
	if (copy_to_user(&data32->id, &data->id, sizeof(data->id)) ||
	    copy_to_user(&data32->type, &data->type, 3 * sizeof(u32)))
		goto error;
	if (put_user(data->owner, &data32->owner))
		goto error;
	switch (data->type) {
	case SNDRV_CTL_ELEM_TYPE_BOOLEAN:
	case SNDRV_CTL_ELEM_TYPE_INTEGER:
		if (put_user(data->value.integer.min, &data32->value.integer.min) ||
		    put_user(data->value.integer.max, &data32->value.integer.max) ||
		    put_user(data->value.integer.step, &data32->value.integer.step))
			goto error;
		break;
	case SNDRV_CTL_ELEM_TYPE_INTEGER64:
		if (copy_to_user(&data32->value.integer64,
				 &data->value.integer64,
				 sizeof(data->value.integer64)))
			goto error;
		break;
	case SNDRV_CTL_ELEM_TYPE_ENUMERATED:
		if (copy_to_user(&data32->value.enumerated,
				 &data->value.enumerated,
				 sizeof(data->value.enumerated)))
			goto error;
		break;
	default:
		break;
	}
	err = 0;
 error:
	kfree(data);
	return err;
}

struct snd_ctl_elem_value32 {
	struct snd_ctl_elem_id id;
	unsigned int indirect;	/* bit-field causes misalignment */
        union {
		s32 integer[128];
		unsigned char data[512];
#ifndef CONFIG_X86_64
#error "klp-ccp: non-taken branch"
#endif
        } value;
        unsigned char reserved[128];
};

static int get_elem_size(int type, int count)
{
	switch (type) {
	case SNDRV_CTL_ELEM_TYPE_INTEGER64:
		return sizeof(s64) * count;
	case SNDRV_CTL_ELEM_TYPE_ENUMERATED:
		return sizeof(int) * count;
	case SNDRV_CTL_ELEM_TYPE_BYTES:
		return 512;
	case SNDRV_CTL_ELEM_TYPE_IEC958:
		return sizeof(struct snd_aes_iec958);
	default:
		return -1;
	}
}

static int (*klpe_copy_ctl_value_from_user)(struct snd_card *card,
				    struct snd_ctl_elem_value *data,
				    void __user *userdata,
				    void __user *valuep,
				    int *typep, int *countp);

static int copy_ctl_value_to_user(void __user *userdata,
				  void __user *valuep,
				  struct snd_ctl_elem_value *data,
				  int type, int count)
{
	int i, size;

	if (type == SNDRV_CTL_ELEM_TYPE_BOOLEAN ||
	    type == SNDRV_CTL_ELEM_TYPE_INTEGER) {
		for (i = 0; i < count; i++) {
			s32 __user *intp = valuep;
			int val;
			val = data->value.integer.value[i];
			if (put_user(val, &intp[i]))
				return -EFAULT;
		}
	} else {
		size = get_elem_size(type, count);
		if (copy_to_user(valuep, data->value.bytes.data, size))
			return -EFAULT;
	}
	return 0;
}

static int klpp_ctl_elem_read_user(struct snd_card *card,
			      void __user *userdata, void __user *valuep)
{
	struct snd_ctl_elem_value *data;
	int err, type, count;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	err = (*klpe_copy_ctl_value_from_user)(card, data, userdata, valuep,
				       &type, &count);
	if (err < 0)
		goto error;

	err = (*klpe_snd_power_wait)(card, SNDRV_CTL_POWER_D0);
	if (err < 0)
		goto error;
	/*
	 * Fix CVE-2023-0266
	 *  + 1 line
	 */
	down_read(&card->controls_rwsem);
	err = (*klpe_snd_ctl_elem_read)(card, data);
	/*
	 * Fix CVE-2023-0266
	 *  + 1 line
	 */
	up_read(&card->controls_rwsem);
	if (err < 0)
		goto error;
	err = copy_ctl_value_to_user(userdata, valuep, data, type, count);
 error:
	kfree(data);
	return err;
}

static int klpp_ctl_elem_write_user(struct snd_ctl_file *file,
			       void __user *userdata, void __user *valuep)
{
	struct snd_ctl_elem_value *data;
	struct snd_card *card = file->card;
	int err, type, count;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	err = (*klpe_copy_ctl_value_from_user)(card, data, userdata, valuep,
				       &type, &count);
	if (err < 0)
		goto error;

	err = (*klpe_snd_power_wait)(card, SNDRV_CTL_POWER_D0);
	if (err < 0)
		goto error;
	/*
	 * Fix CVE-2023-0266
	 *  + 1 line
	 */
	down_write(&card->controls_rwsem);
	err = (*klpe_snd_ctl_elem_write)(card, file, data);
	/*
	 * Fix CVE-2023-0266
	 *  + 1 line
	 */
	up_write(&card->controls_rwsem);
	if (err < 0)
		goto error;
	err = copy_ctl_value_to_user(userdata, valuep, data, type, count);
 error:
	kfree(data);
	return err;
}

static int klpr_snd_ctl_elem_read_user_compat(struct snd_card *card,
					 struct snd_ctl_elem_value32 __user *data32)
{
	return klpp_ctl_elem_read_user(card, data32, &data32->value);
}

static int klpr_snd_ctl_elem_write_user_compat(struct snd_ctl_file *file,
					  struct snd_ctl_elem_value32 __user *data32)
{
	return klpp_ctl_elem_write_user(file, data32, &data32->value);
}

static int (*klpe_snd_ctl_elem_add_compat)(struct snd_ctl_file *file,
				   struct snd_ctl_elem_info32 __user *data32,
				   int replace);

enum {
	SNDRV_CTL_IOCTL_ELEM_LIST32 = _IOWR('U', 0x10, struct snd_ctl_elem_list32),
	SNDRV_CTL_IOCTL_ELEM_INFO32 = _IOWR('U', 0x11, struct snd_ctl_elem_info32),
	SNDRV_CTL_IOCTL_ELEM_READ32 = _IOWR('U', 0x12, struct snd_ctl_elem_value32),
	SNDRV_CTL_IOCTL_ELEM_WRITE32 = _IOWR('U', 0x13, struct snd_ctl_elem_value32),
	SNDRV_CTL_IOCTL_ELEM_ADD32 = _IOWR('U', 0x17, struct snd_ctl_elem_info32),
	SNDRV_CTL_IOCTL_ELEM_REPLACE32 = _IOWR('U', 0x18, struct snd_ctl_elem_info32),
#ifdef CONFIG_X86_X32
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_X86_X32 */
};

long klpp_snd_ctl_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct snd_ctl_file *ctl;
	struct snd_kctl_ioctl *p;
	void __user *argp = compat_ptr(arg);
	int err;

	ctl = file->private_data;
	if (snd_BUG_ON(!ctl || !ctl->card))
		return -ENXIO;

	switch (cmd) {
	case SNDRV_CTL_IOCTL_PVERSION:
	case SNDRV_CTL_IOCTL_CARD_INFO:
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
	case SNDRV_CTL_IOCTL_POWER:
	case SNDRV_CTL_IOCTL_POWER_STATE:
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
	case SNDRV_CTL_IOCTL_ELEM_REMOVE:
	case SNDRV_CTL_IOCTL_TLV_READ:
	case SNDRV_CTL_IOCTL_TLV_WRITE:
	case SNDRV_CTL_IOCTL_TLV_COMMAND:
		return (*klpe_snd_ctl_ioctl)(file, cmd, (unsigned long)argp);
	case SNDRV_CTL_IOCTL_ELEM_LIST32:
		return klpr_snd_ctl_elem_list_compat(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_INFO32:
		return klpr_snd_ctl_elem_info_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_READ32:
		return klpr_snd_ctl_elem_read_user_compat(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_WRITE32:
		return klpr_snd_ctl_elem_write_user_compat(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_ADD32:
		return (*klpe_snd_ctl_elem_add_compat)(ctl, argp, 0);
	case SNDRV_CTL_IOCTL_ELEM_REPLACE32:
		return (*klpe_snd_ctl_elem_add_compat)(ctl, argp, 1);
#ifdef CONFIG_X86_X32
#error "klp-ccp: non-taken branch"
#endif /* CONFIG_X86_X32 */
	}

	down_read(&(*klpe_snd_ioctl_rwsem));
	list_for_each_entry(p, &(*klpe_snd_control_compat_ioctls), list) {
		if (p->fioctl) {
			err = p->fioctl(ctl->card, ctl, cmd, arg);
			if (err != -ENOIOCTLCMD) {
				up_read(&(*klpe_snd_ioctl_rwsem));
				return err;
			}
		}
	}
	up_read(&(*klpe_snd_ioctl_rwsem));
	return -ENOIOCTLCMD;
}
/* klp-ccp: from sound/core/control.c */
#else
#error "klp-ccp: non-taken branch"
#endif

long (*klpe_snd_ctl_ioctl_compat)(struct file *file, unsigned int cmd, unsigned long arg);



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1207190.h"
#include "bsc1207190_common.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "snd"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "copy_ctl_value_from_user", (void *)&klpe_copy_ctl_value_from_user,
	  "snd" },
	{ "snd_control_compat_ioctls", (void *)&klpe_snd_control_compat_ioctls,
	  "snd" },
	{ "snd_ctl_elem_add_compat", (void *)&klpe_snd_ctl_elem_add_compat,
	  "snd" },
	{ "snd_ctl_elem_info", (void *)&klpe_snd_ctl_elem_info, "snd" },
	{ "snd_ctl_elem_list", (void *)&klpe_snd_ctl_elem_list, "snd" },
	{ "snd_ctl_elem_read", (void *)&klpe_snd_ctl_elem_read, "snd" },
	{ "snd_ctl_elem_write", (void *)&klpe_snd_ctl_elem_write, "snd" },
	{ "snd_ctl_ioctl", (void *)&klpe_snd_ctl_ioctl, "snd" },
	{ "snd_ctl_ioctl_compat", (void *)&klpe_snd_ctl_ioctl_compat, "snd" },
	{ "snd_ioctl_rwsem", (void *)&klpe_snd_ioctl_rwsem, "snd" },
	{ "snd_power_wait", (void *)&klpe_snd_power_wait, "snd" },
};

static int livepatch_bsc1207190_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (strcmp(mod->name, LIVEPATCHED_MODULE)) {
		return 0;
	}
	if (action == MODULE_STATE_GOING) {
		WRITE_ONCE(klpe_snd_ctl_ioctl_compat, NULL);
		return 0;
	}

	if (action != MODULE_STATE_COMING)
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1207190_module_nb = {
	.notifier_call = livepatch_bsc1207190_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1207190_snd_control_compat_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1207190_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1207190_snd_control_compat_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1207190_module_nb);
}

#endif /* IS_ENABLED(CONFIG_SND) */
