/*
 * bsc1192036_firedtv-avc
 *
 * Fix for CVE-2021-42739, bsc#1192036 (firedtv-avc.c part)
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

/* klp-ccp: from drivers/media/firewire/firedtv-avc.c */
#include <linux/bug.h>
#include <linux/crc32.h>

/* klp-ccp: from drivers/media/firewire/firedtv-avc.c */
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/stringify.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "bsc1192036_common.h"

/* klp-ccp: from drivers/media/firewire/firedtv-avc.c */
#define AVC_CTYPE_CONTROL		0x0

#define AVC_RESPONSE_ACCEPTED		0x9

#define AVC_SUBUNIT_TYPE_TUNER		(0x05 << 3)

#define AVC_OPCODE_VENDOR		0x00

#define SFE_VENDOR_DE_COMPANYID_0	0x00 /* OUI of Digital Everywhere */
#define SFE_VENDOR_DE_COMPANYID_1	0x12
#define SFE_VENDOR_DE_COMPANYID_2	0x87

#define SFE_VENDOR_OPCODE_HOST2CA		0x56

#define SFE_VENDOR_TAG_CA_PMT			0x02

#define EN50221_LIST_MANAGEMENT_ONLY	0x03

struct avc_command_frame {
	u8 ctype;
	u8 subunit;
	u8 opcode;
	u8 operand[509];
};

struct avc_response_frame {
	u8 response;
	u8 subunit;
	u8 opcode;
	u8 operand[509];
};

static void (*klpe_pad_operands)(struct avc_command_frame *c, int from);

#define AVC_DEBUG_APPLICATION_PMT              0x4000

static int (*klpe_avc_debug);

static void debug_pmt(char *msg, int length)
{
	printk(KERN_INFO "APP PMT -> l=%d\n", length);
	print_hex_dump(KERN_INFO, "APP PMT -> ", DUMP_PREFIX_NONE,
		       16, 1, msg, length, false);
}

static int (*klpe_avc_write)(struct firedtv *fdtv);

int klpp_avc_ca_pmt(struct firedtv *fdtv, char *msg, int length)
{
	struct avc_command_frame *c = (void *)fdtv->avc_data;
	struct avc_response_frame *r = (void *)fdtv->avc_data;
	int list_management;
	int program_info_length;
	int pmt_cmd_id;
	int read_pos;
	int write_pos;
	int es_info_length;
	int crc32_csum;
	int ret;

	if (unlikely((*klpe_avc_debug) & AVC_DEBUG_APPLICATION_PMT))
		debug_pmt(msg, length);

	mutex_lock(&fdtv->avc_mutex);

	c->ctype   = AVC_CTYPE_CONTROL;
	c->subunit = AVC_SUBUNIT_TYPE_TUNER | fdtv->subunit;
	c->opcode  = AVC_OPCODE_VENDOR;

	if (msg[0] != EN50221_LIST_MANAGEMENT_ONLY) {
		dev_info(fdtv->device, "forcing list_management to ONLY\n");
		msg[0] = EN50221_LIST_MANAGEMENT_ONLY;
	}
	/* We take the cmd_id from the programme level only! */
	list_management = msg[0];
	program_info_length = ((msg[4] & 0x0f) << 8) + msg[5];
	if (program_info_length > 0)
		program_info_length--; /* Remove pmt_cmd_id */
	pmt_cmd_id = msg[6];

	c->operand[0] = SFE_VENDOR_DE_COMPANYID_0;
	c->operand[1] = SFE_VENDOR_DE_COMPANYID_1;
	c->operand[2] = SFE_VENDOR_DE_COMPANYID_2;
	c->operand[3] = SFE_VENDOR_OPCODE_HOST2CA;
	c->operand[4] = 0; /* slot */
	c->operand[5] = SFE_VENDOR_TAG_CA_PMT; /* ca tag */
	c->operand[6] = 0; /* more/last */
	/* Use three bytes for length field in case length > 127 */
	c->operand[10] = list_management;
	c->operand[11] = 0x01; /* pmt_cmd=OK_descramble */

	/* TS program map table */

	c->operand[12] = 0x02; /* Table id=2 */
	c->operand[13] = 0x80; /* Section syntax + length */

	c->operand[15] = msg[1]; /* Program number */
	c->operand[16] = msg[2];
	c->operand[17] = msg[3]; /* Version number and current/next */
	c->operand[18] = 0x00; /* Section number=0 */
	c->operand[19] = 0x00; /* Last section number=0 */
	c->operand[20] = 0x1f; /* PCR_PID=1FFF */
	c->operand[21] = 0xff;
	c->operand[22] = (program_info_length >> 8); /* Program info length */
	c->operand[23] = (program_info_length & 0xff);

	/* CA descriptors at programme level */
	read_pos = 6;
	write_pos = 24;
	if (program_info_length > 0) {
		pmt_cmd_id = msg[read_pos++];
		if (pmt_cmd_id != 1 && pmt_cmd_id != 4)
			dev_err(fdtv->device,
				"invalid pmt_cmd_id %d\n", pmt_cmd_id);
		if (program_info_length > sizeof(c->operand) - 4 - write_pos) {
			ret = -EINVAL;
			goto out;
		}

		memcpy(&c->operand[write_pos], &msg[read_pos],
		       program_info_length);
		read_pos += program_info_length;
		write_pos += program_info_length;
	}
	/*
	 * Fix CVE-2021-42739
	 *  -1 line, +5 lines
	 */
	while (read_pos + 4 < length) {
		if (write_pos + 4 >= sizeof(c->operand) - 4) {
			ret = -EINVAL;
			goto out;
		}
		c->operand[write_pos++] = msg[read_pos++];
		c->operand[write_pos++] = msg[read_pos++];
		c->operand[write_pos++] = msg[read_pos++];
		es_info_length =
			((msg[read_pos] & 0x0f) << 8) + msg[read_pos + 1];
		read_pos += 2;
		if (es_info_length > 0)
			es_info_length--; /* Remove pmt_cmd_id */
		c->operand[write_pos++] = es_info_length >> 8;
		c->operand[write_pos++] = es_info_length & 0xff;
		if (es_info_length > 0) {
			/*
			 * Fix CVE-2021-42739
			 *  +4 lines
			 */
			if (read_pos >= length) {
				ret = -EINVAL;
				goto out;
			}
			pmt_cmd_id = msg[read_pos++];
			if (pmt_cmd_id != 1 && pmt_cmd_id != 4)
				dev_err(fdtv->device, "invalid pmt_cmd_id %d at stream level\n",
					pmt_cmd_id);

			/*
			 * Fix CVE-2021-42739
			 *  -2 lines, +2 lines
			 */
			if (es_info_length > sizeof(c->operand) - 4 - write_pos ||
			    es_info_length > length - read_pos) {
				ret = -EINVAL;
				goto out;
			}

			memcpy(&c->operand[write_pos], &msg[read_pos],
			       es_info_length);
			read_pos += es_info_length;
			write_pos += es_info_length;
		}
	}
	write_pos += 4; /* CRC */

	c->operand[7] = 0x82;
	c->operand[8] = (write_pos - 10) >> 8;
	c->operand[9] = (write_pos - 10) & 0xff;
	c->operand[14] = write_pos - 15;

	crc32_csum = crc32_be(0, &c->operand[10], c->operand[12] - 1);
	c->operand[write_pos - 4] = (crc32_csum >> 24) & 0xff;
	c->operand[write_pos - 3] = (crc32_csum >> 16) & 0xff;
	c->operand[write_pos - 2] = (crc32_csum >>  8) & 0xff;
	c->operand[write_pos - 1] = (crc32_csum >>  0) & 0xff;
	(*klpe_pad_operands)(c, write_pos);

	fdtv->avc_data_length = ALIGN(3 + write_pos, 4);
	ret = (*klpe_avc_write)(fdtv);
	if (ret < 0)
		goto out;

	if (r->response != AVC_RESPONSE_ACCEPTED) {
		dev_err(fdtv->device,
			"CA PMT failed with response 0x%x\n", r->response);
		ret = -EACCES;
	}
out:
	mutex_unlock(&fdtv->avc_mutex);

	return ret;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1192036.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "firedtv"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "avc_write", (void *)&klpe_avc_write, "firedtv" },
	{ "pad_operands", (void *)&klpe_pad_operands, "firedtv" },
	{ "avc_debug", (void *)&klpe_avc_debug, "firedtv" },
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

int livepatch_bsc1192036_firewire_firedtv_avc_init(void)
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

void livepatch_bsc1192036_firewire_firedtv_avc_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1192036_module_nb);
}

#endif /* IS_ENABLED(CONFIG_DVB_FIREDTV) */
