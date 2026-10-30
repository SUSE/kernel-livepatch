/*
 * livepatch_bsc1277679
 *
 * Fix for CVE-2026-72262, bsc#1277679
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

#if IS_ENABLED(CONFIG_SND_SOC_SOF)

#if !IS_MODULE(CONFIG_SND_SOC_SOF)
#error "Live patch supports only CONFIG=m"
#endif

#include "livepatch_bsc1277679.h"


/* klp-ccp: from sound/soc/sof/sof-priv.h */
#include <linux/device.h>
#include <sound/hdaudio.h>
#include <sound/sof.h>
#include <sound/sof/info.h>
#include <sound/sof/pm.h>
#include <sound/sof/trace.h>
#include <sound/compress_params.h>
#include <uapi/sound/sof/fw.h>
#include <sound/sof/ext_manifest.h>

/* klp-ccp: from sound/soc/sof/sof-audio.h */
#include <linux/workqueue.h>

#include <sound/soc.h>
#include <sound/control.h>
#include <sound/sof/stream.h> /* needs to be included before control.h */
#include <sound/sof/control.h>
#include <sound/sof/dai.h>
#include <sound/sof/topology.h>

struct snd_sof_led_control {
	unsigned int use_led;
	unsigned int direction;
	int led_value;
};

struct snd_sof_control {
	struct snd_soc_component *scomp;
	const char *name;
	int comp_id;
	int min_volume_step; /* min volume step for volume_table */
	int max_volume_step; /* max volume step for volume_table */
	int num_channels;
	unsigned int access;
	int info_type;
	int index; /* pipeline ID */
	void *priv; /* private data copied from topology */
	size_t priv_size; /* size of private data */
	size_t max_size;
	void *ipc_control_data;
	void *old_ipc_control_data;
	int max; /* applicable to volume controls */
	u32 size;	/* cdata size */
	u32 *volume_table; /* volume table computed from tlv data*/

	struct list_head list;	/* list in sdev control list */

	struct snd_sof_led_control led_ctl;

	/* if true, the control's data needs to be updated from Firmware */
	bool comp_data_dirty;
};

/* klp-ccp: from sound/soc/sof/ipc3-control.c */
extern int sof_ipc3_set_get_kcontrol_data(struct snd_sof_control *scontrol,
					  bool set, bool lock);

int klpp_sof_ipc3_bytes_ext_put(struct snd_sof_control *scontrol, const unsigned int __user *binary_data, unsigned int size)
{
	const struct snd_ctl_tlv __user *tlvd = (const struct snd_ctl_tlv __user *)binary_data;
	struct sof_ipc_ctrl_data *cdata = scontrol->ipc_control_data;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_ctl_tlv header;
	int ret = -EINVAL;

	/*
	 * The beginning of bytes data contains a header from where
	 * the length (as bytes) is needed to know the correct copy
	 * length of data from tlvd->tlv.
	 */
	if (copy_from_user(&header, tlvd, sizeof(struct snd_ctl_tlv)))
		return -EFAULT;

	/* make sure TLV info is consistent */
	if (header.length + sizeof(struct snd_ctl_tlv) > size) {
		dev_err_ratelimited(scomp->dev, "Inconsistent TLV, data %d + header %zu > %d\n",
				    header.length, sizeof(struct snd_ctl_tlv), size);
		return -EINVAL;
	}

	/* be->max is coming from topology */
	if (header.length > scontrol->max_size - sizeof(*cdata)) {
		dev_err_ratelimited(scomp->dev, "Bytes data size %u exceeds max %zu\n",
				    header.length, scontrol->max_size - sizeof(*cdata));
		return -EINVAL;
	}

	/* Ensure the data is large enough to contain the ABI header */
	if (header.length < sizeof(struct sof_abi_hdr)) {
		dev_err_ratelimited(scomp->dev,
				    "Bytes data size %u less than ABI header %zu\n",
				    header.length, sizeof(struct sof_abi_hdr));
		return -EINVAL;
	}

	/* Check that header id matches the command */
	if (header.numid != cdata->cmd) {
		dev_err_ratelimited(scomp->dev, "Incorrect command for bytes put %d\n",
				    header.numid);
		return -EINVAL;
	}

	if (!scontrol->old_ipc_control_data) {
		/* Create a backup of the current, valid bytes control */
		scontrol->old_ipc_control_data = kmemdup(scontrol->ipc_control_data,
							 scontrol->max_size, GFP_KERNEL);
		if (!scontrol->old_ipc_control_data)
			return -ENOMEM;
	}

	if (copy_from_user(cdata->data, tlvd->tlv, header.length)) {
		ret = -EFAULT;
		goto err_restore;
	}

	if (cdata->data->magic != SOF_ABI_MAGIC) {
		dev_err_ratelimited(scomp->dev, "Wrong ABI magic 0x%08x\n", cdata->data->magic);
		goto err_restore;
	}

	if (SOF_ABI_VERSION_INCOMPATIBLE(SOF_ABI_VERSION, cdata->data->abi)) {
		dev_err_ratelimited(scomp->dev, "Incompatible ABI version 0x%08x\n",
				    cdata->data->abi);
		goto err_restore;
	}

	/* be->max has been verified to be >= sizeof(struct sof_abi_hdr) */
	if (cdata->data->size > scontrol->max_size - sizeof(*cdata) - sizeof(struct sof_abi_hdr)) {
		dev_err_ratelimited(scomp->dev, "Mismatch in ABI data size (truncated?)\n");
		goto err_restore;
	}

	/* notify DSP of byte control updates */
	if (pm_runtime_active(scomp->dev)) {
		/* Actually send the data to the DSP; this is an opportunity to validate the data */
		return sof_ipc3_set_get_kcontrol_data(scontrol, true, true);
	}

	return 0;

err_restore:
	/* If we have an issue, we restore the old, valid bytes control data */
	if (scontrol->old_ipc_control_data) {
		memcpy(cdata, scontrol->old_ipc_control_data, scontrol->max_size);
		kfree(scontrol->old_ipc_control_data);
		scontrol->old_ipc_control_data = NULL;
	}
	return ret;
}

int klpp__sof_ipc3_bytes_ext_get(struct snd_sof_control *scontrol, const unsigned int __user *binary_data, unsigned int size, bool from_dsp)
{
	struct snd_ctl_tlv __user *tlvd = (struct snd_ctl_tlv __user *)binary_data;
	struct sof_ipc_ctrl_data *cdata = scontrol->ipc_control_data;
	struct snd_soc_component *scomp = scontrol->scomp;
	struct snd_ctl_tlv header;
	size_t data_size;

	/*
	 * Decrement the limit by ext bytes header size to
	 * ensure the user space buffer is not exceeded.
	 */
	if (size < sizeof(struct snd_ctl_tlv))
		return -ENOSPC;

	size -= sizeof(struct snd_ctl_tlv);

	/* set the ABI header values */
	cdata->data->magic = SOF_ABI_MAGIC;
	cdata->data->abi = SOF_ABI_VERSION;

	/* get all the component data from DSP */
	if (from_dsp) {
		int ret = sof_ipc3_set_get_kcontrol_data(scontrol, false, true);

		if (ret < 0)
			return ret;
	}

	/* check data size doesn't exceed max coming from topology */
	if (cdata->data->size > scontrol->max_size - sizeof(*cdata) -
				sizeof(struct sof_abi_hdr)) {
		dev_err_ratelimited(scomp->dev,
				    "User data size %u exceeds max size %zu\n",
				    cdata->data->size,
				    scontrol->max_size - sizeof(*cdata) -
				    sizeof(struct sof_abi_hdr));
		return -EINVAL;
	}

	data_size = cdata->data->size + sizeof(struct sof_abi_hdr);

	/* make sure we don't exceed size provided by user space for data */
	if (data_size > size)
		return -ENOSPC;

	header.numid = cdata->cmd;
	header.length = data_size;
	if (copy_to_user(tlvd, &header, sizeof(struct snd_ctl_tlv)))
		return -EFAULT;

	if (copy_to_user(tlvd->tlv, cdata->data, data_size))
		return -EFAULT;

	return 0;
}


#include <linux/livepatch.h>

extern typeof(sof_ipc3_set_get_kcontrol_data) sof_ipc3_set_get_kcontrol_data
	 KLP_RELOC_SYMBOL(snd_sof, snd_sof, sof_ipc3_set_get_kcontrol_data);

#endif /* IS_ENABLED(CONFIG_SND_SOC_SOF) */
