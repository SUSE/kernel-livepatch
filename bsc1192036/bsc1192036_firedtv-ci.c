/*
 * bsc1192036_firedtv-ci
 *
 * Fix for CVE-2021-42739, bsc#1192036 (firedtv-ci.c part)
 *
 *  Copyright (c) 2021 SUSE
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

#if IS_ENABLED(CONFIG_DVB_FIREDTV)

#if !IS_MODULE(CONFIG_DVB_FIREDTV)
#error "Live patch supports only CONFIG_DVB_FIREDTV=m"
#endif

/* klp-ccp: from drivers/media/firewire/firedtv-ci.c */
#include <linux/dvb/ca.h>
#include <linux/fs.h>

#include "bsc1192036_common.h"

/* klp-ccp: from drivers/media/dvb-core/dvbdev.h */
struct dvb_device {
	struct list_head list_head;
	const struct file_operations *fops;
	struct dvb_adapter *adapter;
	int type;
	int minor;
	u32 id;

	/* in theory, 'users' can vanish now,
	   but I don't want to change too much now... */
	int readers;
	int writers;
	int users;

	wait_queue_head_t	  wait_queue;
	/* don't really need those !? -- FIXME: use video_usercopy  */
	int (*kernel_ioctl)(struct file *file, unsigned int cmd, void *arg);

#if defined(CONFIG_MEDIA_CONTROLLER_DVB)
#error "klp-ccp: non-taken branch"
#endif
	void *priv;
};

/* klp-ccp: from drivers/media/firewire/firedtv.h */
struct firedtv_tuner_status {
	unsigned active_system:8;
	unsigned searching:1;
	unsigned moving:1;
	unsigned no_rf:1;
	unsigned input:1;
	unsigned selected_antenna:7;
	unsigned ber:32;
	unsigned signal_strength:8;
	unsigned raster_frequency:2;
	unsigned rf_frequency:22;
	unsigned man_dep_info_length:8;
	unsigned front_end_error:1;
	unsigned antenna_error:1;
	unsigned front_end_power_status:1;
	unsigned power_supply:1;
	unsigned carrier_noise_ratio:16;
	unsigned power_supply_voltage:8;
	unsigned antenna_voltage:8;
	unsigned firewire_bus_voltage:8;
	unsigned ca_mmi:1;
	unsigned ca_pmt_reply:1;
	unsigned ca_date_time_request:1;
	unsigned ca_application_info:1;
	unsigned ca_module_present_status:1;
	unsigned ca_dvb_flag:1;
	unsigned ca_error_flag:1;
	unsigned ca_initialization_status:1;
};

static int (*klpe_avc_tuner_status)(struct firedtv *fdtv, struct firedtv_tuner_status *stat);

static int (*klpe_avc_ca_app_info)(struct firedtv *fdtv, unsigned char *app_info,
		    unsigned int *len);
static int (*klpe_avc_ca_info)(struct firedtv *fdtv, unsigned char *app_info,
		unsigned int *len);
static int (*klpe_avc_ca_reset)(struct firedtv *fdtv);

static int (*klpe_avc_ca_enter_menu)(struct firedtv *fdtv);
static int (*klpe_avc_ca_get_mmi)(struct firedtv *fdtv, char *mmi_object, unsigned int *len);

/* klp-ccp: from drivers/media/firewire/firedtv-ci.c */
#define EN50221_TAG_APP_INFO_ENQUIRY	0x9f8020
#define EN50221_TAG_CA_INFO_ENQUIRY	0x9f8030
#define EN50221_TAG_CA_PMT		0x9f8032
#define EN50221_TAG_ENTER_MENU		0x9f8022

static int fdtv_get_ca_flags(struct firedtv_tuner_status *stat)
{
	int flags = 0;

	if (stat->ca_module_present_status == 1)
		flags |= CA_CI_MODULE_PRESENT;
	if (stat->ca_initialization_status == 1 &&
	    stat->ca_error_flag            == 0 &&
	    stat->ca_dvb_flag              == 1)
		flags |= CA_CI_MODULE_READY;
	return flags;
}

static int fdtv_ca_get_caps(void *arg)
{
	struct ca_caps *cap = arg;

	cap->slot_num = 1;
	cap->slot_type = CA_CI;
	cap->descr_num = 1;
	cap->descr_type = CA_ECD;
	return 0;
}

static int klpr_fdtv_ca_get_slot_info(struct firedtv *fdtv, void *arg)
{
	struct firedtv_tuner_status stat;
	struct ca_slot_info *slot = arg;
	int err;

	err = (*klpe_avc_tuner_status)(fdtv, &stat);
	if (err)
		return err;

	if (slot->num != 0)
		return -EACCES;

	slot->type = CA_CI;
	slot->flags = fdtv_get_ca_flags(&stat);
	return 0;
}

static int klpr_fdtv_ca_app_info(struct firedtv *fdtv, void *arg)
{
	struct ca_msg *reply = arg;

	return (*klpe_avc_ca_app_info)(fdtv, reply->msg, &reply->length);
}

static int klpr_fdtv_ca_info(struct firedtv *fdtv, void *arg)
{
	struct ca_msg *reply = arg;

	return (*klpe_avc_ca_info)(fdtv, reply->msg, &reply->length);
}

static int klpr_fdtv_ca_get_mmi(struct firedtv *fdtv, void *arg)
{
	struct ca_msg *reply = arg;

	return (*klpe_avc_ca_get_mmi)(fdtv, reply->msg, &reply->length);
}

static int klpr_fdtv_ca_get_msg(struct firedtv *fdtv, void *arg)
{
	struct firedtv_tuner_status stat;
	int err;

	switch (fdtv->ca_last_command) {
	case EN50221_TAG_APP_INFO_ENQUIRY:
		err = klpr_fdtv_ca_app_info(fdtv, arg);
		break;
	case EN50221_TAG_CA_INFO_ENQUIRY:
		err = klpr_fdtv_ca_info(fdtv, arg);
		break;
	default:
		err = (*klpe_avc_tuner_status)(fdtv, &stat);
		if (err)
			break;
		if (stat.ca_mmi == 1)
			err = klpr_fdtv_ca_get_mmi(fdtv, arg);
		else {
			dev_info(fdtv->device, "unhandled CA message 0x%08x\n",
				 fdtv->ca_last_command);
			err = -EACCES;
		}
	}
	fdtv->ca_last_command = 0;
	return err;
}

static int klpp_fdtv_ca_pmt(struct firedtv *fdtv, void *arg)
{
	struct ca_msg *msg = arg;
	int data_pos;
	int data_length;
	int i;

	data_pos = 4;
	if (msg->msg[3] & 0x80) {
		data_length = 0;
		for (i = 0; i < (msg->msg[3] & 0x7f); i++)
			data_length = (data_length << 8) + msg->msg[data_pos++];
	} else {
		data_length = msg->msg[3];
	}

	/*
	 * Fix CVE-2021-42739
	 *  +2 lines
	 */
	if (data_length > sizeof(msg->msg) - data_pos)
		return -EINVAL;

	return klpp_avc_ca_pmt(fdtv, &msg->msg[data_pos], data_length);
}

static int klpp_fdtv_ca_send_msg(struct firedtv *fdtv, void *arg)
{
	struct ca_msg *msg = arg;
	int err;

	/* Do we need a semaphore for this? */
	fdtv->ca_last_command =
		(msg->msg[0] << 16) + (msg->msg[1] << 8) + msg->msg[2];
	switch (fdtv->ca_last_command) {
	case EN50221_TAG_CA_PMT:
		err = klpp_fdtv_ca_pmt(fdtv, arg);
		break;
	case EN50221_TAG_APP_INFO_ENQUIRY:
		/* handled in ca_get_msg */
		err = 0;
		break;
	case EN50221_TAG_CA_INFO_ENQUIRY:
		/* handled in ca_get_msg */
		err = 0;
		break;
	case EN50221_TAG_ENTER_MENU:
		err = (*klpe_avc_ca_enter_menu)(fdtv);
		break;
	default:
		dev_err(fdtv->device, "unhandled CA message 0x%08x\n",
			fdtv->ca_last_command);
		err = -EACCES;
	}
	return err;
}

int klpp_fdtv_ca_ioctl(struct file *file, unsigned int cmd, void *arg)
{
	struct dvb_device *dvbdev = file->private_data;
	struct firedtv *fdtv = dvbdev->priv;
	struct firedtv_tuner_status stat;
	int err;

	switch (cmd) {
	case CA_RESET:
		err = (*klpe_avc_ca_reset)(fdtv);
		break;
	case CA_GET_CAP:
		err = fdtv_ca_get_caps(arg);
		break;
	case CA_GET_SLOT_INFO:
		err = klpr_fdtv_ca_get_slot_info(fdtv, arg);
		break;
	case CA_GET_MSG:
		err = klpr_fdtv_ca_get_msg(fdtv, arg);
		break;
	case CA_SEND_MSG:
		err = klpp_fdtv_ca_send_msg(fdtv, arg);
		break;
	default:
		dev_info(fdtv->device, "unhandled CA ioctl %u\n", cmd);
		err = -EOPNOTSUPP;
	}

	/* FIXME Is this necessary? */
	(*klpe_avc_tuner_status)(fdtv, &stat);

	return err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1192036.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "firedtv"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "avc_ca_app_info", (void *)&klpe_avc_ca_app_info, "firedtv" },
	{ "avc_ca_enter_menu", (void *)&klpe_avc_ca_enter_menu, "firedtv" },
	{ "avc_ca_get_mmi", (void *)&klpe_avc_ca_get_mmi, "firedtv" },
	{ "avc_ca_info", (void *)&klpe_avc_ca_info, "firedtv" },
	{ "avc_ca_reset", (void *)&klpe_avc_ca_reset, "firedtv" },
	{ "avc_tuner_status", (void *)&klpe_avc_tuner_status, "firedtv" },
};

static int livepatch_bsc1192036_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1192036_module_nb = {
	.notifier_call = livepatch_bsc1192036_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1192036_firewire_firedtv_ci_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1192036_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1192036_firewire_firedtv_ci_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1192036_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DVB_FIREDTV) */
