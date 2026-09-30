/*
 * livepatch_bsc1272391
 *
 * Fix for CVE-2026-63888, bsc#1272391
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


#include "livepatch_bsc1272391.h"


#define RETPOLINE 1
#define CC_HAVE_ASM_GOTO 1
/* klp-ccp: from drivers/target/iscsi/iscsi_target.c */
#include <crypto/hash.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/idr.h>
#include <linux/delay.h>
#include <linux/sched/signal.h>
#include <asm/unaligned.h>
#include <linux/inet.h>
#include <net/ipv6.h>
#include <scsi/scsi_proto.h>
#include <scsi/iscsi_proto.h>
#include <scsi/scsi_tcq.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
#include <target/iscsi/iscsi_target_core.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_parameters.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_seq_pdu_list.h */
#include <linux/types.h>
#include <linux/cache.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_erl0.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_erl1.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h> /* itt_t */
/* klp-ccp: from drivers/target/iscsi/iscsi_target_erl2.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_login.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_tmr.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_tpg.h */
#include <linux/types.h>
/* klp-ccp: from drivers/target/iscsi/iscsi_target_util.h */
#include <linux/types.h>
#include <scsi/iscsi_proto.h>        /* itt_t */

static int (*klpe_rx_data)(struct iscsi_conn *, struct kvec *, int, int);

/* klp-ccp: from drivers/target/iscsi/iscsi_target.h */
#include <linux/types.h>
#include <linux/spinlock.h>

static int (*klpe_iscsit_reject_cmd)(struct iscsi_cmd *cmd, u8, unsigned char *);

/* klp-ccp: from drivers/target/iscsi/iscsi_target.c */
#include <target/iscsi/iscsi_target_stat.h>
#include <target/iscsi/iscsi_transport.h>

/* klp-ccp: from include/target/iscsi/iscsi_transport.h */
static int (*klpe_iscsit_setup_text_cmd)(struct iscsi_conn *, struct iscsi_cmd *,
				 struct iscsi_text *);
static int (*klpe_iscsit_process_text_cmd)(struct iscsi_conn *, struct iscsi_cmd *,
				   struct iscsi_text *);
/* klp-ccp: from drivers/target/iscsi/iscsi_target.c */
static void (*klpe_iscsit_do_crypto_hash_buf)(struct ahash_request *, const void *,
				      u32, u32, u8 *, u8 *);
static void (*klpe_iscsit_do_crypto_hash_buf)(
	struct ahash_request *hash,
	const void *buf,
	u32 payload_length,
	u32 padding,
	u8 *pad_bytes,
	u8 *data_crc);
int klpp_iscsit_handle_text_cmd(struct iscsi_conn *conn, struct iscsi_cmd *cmd, unsigned char *buf)
{
	struct iscsi_text *hdr = (struct iscsi_text *)buf;
	char *text_in = NULL;
	u32 payload_length = ntoh24(hdr->dlength);
	int rx_size, rc;

	rc = (*klpe_iscsit_setup_text_cmd)(conn, cmd, hdr);
	if (rc < 0)
		return 0;

	rx_size = payload_length;
	if (payload_length) {
		u32 checksum = 0, data_crc = 0;
		u32 padding = 0, pad_bytes = 0;
		int niov = 0, rx_got;
		struct kvec iov[3];

		text_in = kzalloc(payload_length, GFP_KERNEL);
		if (!text_in)
			goto reject;

		cmd->text_in_ptr = text_in;

		memset(iov, 0, 3 * sizeof(struct kvec));
		iov[niov].iov_base	= text_in;
		iov[niov++].iov_len	= payload_length;

		padding = ((-payload_length) & 3);
		if (padding != 0) {
			iov[niov].iov_base = &pad_bytes;
			iov[niov++].iov_len  = padding;
			rx_size += padding;
			pr_debug("Receiving %u additional bytes"
					" for padding.\n", padding);
		}
		if (conn->conn_ops->DataDigest) {
			iov[niov].iov_base	= &checksum;
			iov[niov++].iov_len	= ISCSI_CRC_LEN;
			rx_size += ISCSI_CRC_LEN;
		}

		rx_got = (*klpe_rx_data)(conn, &iov[0], niov, rx_size);
		if (rx_got != rx_size)
			goto reject;

		if (conn->conn_ops->DataDigest) {
			(*klpe_iscsit_do_crypto_hash_buf)(conn->conn_rx_hash,
					text_in, payload_length,
					padding, (u8 *)&pad_bytes,
					(u8 *)&data_crc);

			if (checksum != data_crc) {
				pr_err("Text data CRC32C DataDigest"
					" 0x%08x does not match computed"
					" 0x%08x\n", checksum, data_crc);
				if (!conn->sess->sess_ops->ErrorRecoveryLevel) {
					pr_err("Unable to recover from"
					" Text Data digest failure while in"
						" ERL=0.\n");
					goto reject;
				} else {
					/*
					 * Silently drop this PDU and let the
					 * initiator plug the CmdSN gap.
					 */
					pr_debug("Dropping Text"
					" Command CmdSN: 0x%08x due to"
					" DataCRC error.\n", hdr->cmdsn);
					kfree(text_in);
					cmd->text_in_ptr = NULL;
					return 0;
				}
			} else {
				pr_debug("Got CRC32C DataDigest"
					" 0x%08x for %u bytes of text data.\n",
						checksum, payload_length);
			}
		}
		text_in[payload_length - 1] = '\0';
		pr_debug("Successfully read %d bytes of text"
				" data.\n", payload_length);
	}

	return (*klpe_iscsit_process_text_cmd)(conn, cmd, hdr);

reject:
	kfree(cmd->text_in_ptr);
	cmd->text_in_ptr = NULL;
	return (*klpe_iscsit_reject_cmd)(cmd, ISCSI_REASON_PROTOCOL_ERROR, buf);
}


#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "iscsi_target_mod"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "iscsit_do_crypto_hash_buf", (void *)&klpe_iscsit_do_crypto_hash_buf,
	  "iscsi_target_mod" },
	{ "iscsit_process_text_cmd", (void *)&klpe_iscsit_process_text_cmd,
	  "iscsi_target_mod" },
	{ "iscsit_reject_cmd", (void *)&klpe_iscsit_reject_cmd,
	  "iscsi_target_mod" },
	{ "iscsit_setup_text_cmd", (void *)&klpe_iscsit_setup_text_cmd,
	  "iscsi_target_mod" },
	{ "rx_data", (void *)&klpe_rx_data, "iscsi_target_mod" },
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

int livepatch_bsc1272391_init(void)
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

void livepatch_bsc1272391_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
