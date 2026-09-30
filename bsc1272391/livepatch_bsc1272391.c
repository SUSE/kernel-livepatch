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
#include <target/target_core_backend.h>
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

extern int iscsit_dump_data_payload(struct iscsit_conn *, u32, int);

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

extern struct iscsit_cmd *iscsit_allocate_cmd(struct iscsit_conn *, int);

extern int iscsit_sequence_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			       unsigned char * ,__be32 cmdsn);

extern void iscsit_add_cmd_to_immediate_queue(struct iscsit_cmd *, struct iscsit_conn *, u8);

extern void iscsit_free_cmd(struct iscsit_cmd *, bool);

extern int rx_data(struct iscsit_conn *, struct kvec *, int, int);

/* klp-ccp: from drivers/target/iscsi/iscsi_target.h */
#include <linux/types.h>
#include <linux/spinlock.h>

extern int iscsit_reject_cmd(struct iscsit_cmd *cmd, u8, unsigned char *);
extern void iscsit_set_unsolicited_dataout(struct iscsit_cmd *);

/* klp-ccp: from drivers/target/iscsi/iscsi_target.c */
#include <target/iscsi/iscsi_target_stat.h>
#include <target/iscsi/iscsi_transport.h>

static int iscsit_handle_immediate_data(struct iscsit_cmd *,
			struct iscsi_scsi_req *, u32);
extern void iscsit_do_crypto_hash_buf(struct ahash_request *, const void *,
				      u32, u32, const void *, void *);

extern int iscsit_map_iovec(struct iscsit_cmd *cmd, struct kvec *iov, int nvec,
			    u32 data_offset, u32 data_length);
static void iscsit_unmap_iovec(struct iscsit_cmd *);
static u32 iscsit_do_crypto_hash_sg(struct ahash_request *, struct iscsit_cmd *,
				    u32, u32, u32, u8 *);

int iscsit_add_reject(
	struct iscsit_conn *conn,
	u8 reason,
	unsigned char *buf);

extern typeof(iscsit_add_reject) iscsit_add_reject;

int iscsit_reject_cmd(struct iscsit_cmd *cmd, u8 reason, unsigned char *buf);

extern typeof(iscsit_reject_cmd) iscsit_reject_cmd;

int iscsit_map_iovec(struct iscsit_cmd *cmd, struct kvec *iov, int nvec,
			    u32 data_offset, u32 data_length);

static void iscsit_unmap_iovec(struct iscsit_cmd *cmd)
{
	u32 i;
	struct scatterlist *sg;

	sg = cmd->first_data_sg;

	for (i = 0; i < cmd->kmapped_nents; i++)
		kunmap(sg_page(&sg[i]));
}

static int iscsit_allocate_iovecs(struct iscsit_cmd *cmd)
{
	u32 iov_count = max(1UL, DIV_ROUND_UP(cmd->se_cmd.data_length, PAGE_SIZE));

	iov_count += ISCSI_IOV_DATA_BUFFER;
	cmd->iov_data = kcalloc(iov_count, sizeof(*cmd->iov_data), GFP_KERNEL);
	if (!cmd->iov_data)
		return -ENOMEM;

	cmd->orig_iov_data_count = iov_count;
	return 0;
}

int iscsit_setup_scsi_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			  unsigned char *buf);

extern typeof(iscsit_setup_scsi_cmd) iscsit_setup_scsi_cmd;

void iscsit_set_unsolicited_dataout(struct iscsit_cmd *cmd);

extern typeof(iscsit_set_unsolicited_dataout) iscsit_set_unsolicited_dataout;

int iscsit_process_scsi_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			    struct iscsi_scsi_req *hdr);

extern typeof(iscsit_process_scsi_cmd) iscsit_process_scsi_cmd;

static int
iscsit_get_immediate_data(struct iscsit_cmd *cmd, struct iscsi_scsi_req *hdr,
			  bool dump_payload)
{
	int cmdsn_ret = 0, immed_ret = IMMEDIATE_DATA_NORMAL_OPERATION;
	int rc;

	/*
	 * Special case for Unsupported SAM WRITE Opcodes and ImmediateData=Yes.
	 */
	if (dump_payload) {
		u32 length = min(cmd->se_cmd.data_length - cmd->write_data_done,
				 cmd->first_burst_len);

		pr_debug("Dumping min(%d - %d, %d) = %d bytes of immediate data\n",
			 cmd->se_cmd.data_length, cmd->write_data_done,
			 cmd->first_burst_len, length);
		rc = iscsit_dump_data_payload(cmd->conn, length, 1);
		pr_debug("Finished dumping immediate data\n");
		if (rc < 0)
			immed_ret = IMMEDIATE_DATA_CANNOT_RECOVER;
	} else {
		immed_ret = iscsit_handle_immediate_data(cmd, hdr,
							 cmd->first_burst_len);
	}

	if (immed_ret == IMMEDIATE_DATA_NORMAL_OPERATION) {
		/*
		 * A PDU/CmdSN carrying Immediate Data passed
		 * DataCRC, check against ExpCmdSN/MaxCmdSN if
		 * Immediate Bit is not set.
		 */
		cmdsn_ret = iscsit_sequence_cmd(cmd->conn, cmd,
					(unsigned char *)hdr, hdr->cmdsn);
		if (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER)
			return -1;

		if (cmd->sense_reason || cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			target_put_sess_cmd(&cmd->se_cmd);

			return 0;
		} else if (cmd->unsolicited_data)
			iscsit_set_unsolicited_dataout(cmd);

	} else if (immed_ret == IMMEDIATE_DATA_ERL1_CRC_FAILURE) {
		/*
		 * Immediate Data failed DataCRC and ERL>=1,
		 * silently drop this PDU and let the initiator
		 * plug the CmdSN gap.
		 *
		 * FIXME: Send Unsolicited NOPIN with reserved
		 * TTT here to help the initiator figure out
		 * the missing CmdSN, although they should be
		 * intelligent enough to determine the missing
		 * CmdSN and issue a retry to plug the sequence.
		 */
		cmd->i_state = ISTATE_REMOVE;
		iscsit_add_cmd_to_immediate_queue(cmd, cmd->conn, cmd->i_state);
	} else /* immed_ret == IMMEDIATE_DATA_CANNOT_RECOVER */
		return -1;

	return 0;
}

static int
iscsit_handle_scsi_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			   unsigned char *buf)
{
	struct iscsi_scsi_req *hdr = (struct iscsi_scsi_req *)buf;
	int rc, immed_data;
	bool dump_payload = false;

	rc = iscsit_setup_scsi_cmd(conn, cmd, buf);
	if (rc < 0)
		return 0;
	/*
	 * Allocation iovecs needed for struct socket operations for
	 * traditional iSCSI block I/O.
	 */
	if (iscsit_allocate_iovecs(cmd) < 0) {
		return iscsit_reject_cmd(cmd,
				ISCSI_REASON_BOOKMARK_NO_RESOURCES, buf);
	}
	immed_data = cmd->immediate_data;

	rc = iscsit_process_scsi_cmd(conn, cmd, hdr);
	if (rc < 0)
		return rc;
	else if (rc > 0)
		dump_payload = true;

	if (!immed_data)
		return 0;

	return iscsit_get_immediate_data(cmd, hdr, dump_payload);
}

static u32 iscsit_do_crypto_hash_sg(
	struct ahash_request *hash,
	struct iscsit_cmd *cmd,
	u32 data_offset,
	u32 data_length,
	u32 padding,
	u8 *pad_bytes)
{
	u32 data_crc;
	struct scatterlist *sg;
	unsigned int page_off;

	crypto_ahash_init(hash);

	sg = cmd->first_data_sg;
	page_off = cmd->first_data_sg_off;

	if (data_length && page_off) {
		struct scatterlist first_sg;
		u32 len = min_t(u32, data_length, sg->length - page_off);

		sg_init_table(&first_sg, 1);
		sg_set_page(&first_sg, sg_page(sg), len, sg->offset + page_off);

		ahash_request_set_crypt(hash, &first_sg, NULL, len);
		crypto_ahash_update(hash);

		data_length -= len;
		sg = sg_next(sg);
	}

	while (data_length) {
		u32 cur_len = min_t(u32, data_length, sg->length);

		ahash_request_set_crypt(hash, sg, NULL, cur_len);
		crypto_ahash_update(hash);

		data_length -= cur_len;
		/* iscsit_map_iovec has already checked for invalid sg pointers */
		sg = sg_next(sg);
	}

	if (padding) {
		struct scatterlist pad_sg;

		sg_init_one(&pad_sg, pad_bytes, padding);
		ahash_request_set_crypt(hash, &pad_sg, (u8 *)&data_crc,
					padding);
		crypto_ahash_finup(hash);
	} else {
		ahash_request_set_crypt(hash, NULL, (u8 *)&data_crc, 0);
		crypto_ahash_final(hash);
	}

	return data_crc;
}

void iscsit_do_crypto_hash_buf(struct ahash_request *hash,
	const void *buf, u32 payload_length, u32 padding,
	const void *pad_bytes, void *data_crc);

int
iscsit_check_dataout_hdr(struct iscsit_conn *conn, void *buf,
			 struct iscsit_cmd **out_cmd);

extern typeof(iscsit_check_dataout_hdr) iscsit_check_dataout_hdr;

static int
iscsit_get_dataout(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
		   struct iscsi_data *hdr)
{
	struct kvec *iov;
	u32 checksum, iov_count = 0, padding = 0, rx_got = 0, rx_size = 0;
	u32 payload_length;
	int iov_ret, data_crc_failed = 0;

	payload_length = min_t(u32, cmd->se_cmd.data_length,
			       ntoh24(hdr->dlength));
	rx_size += payload_length;
	iov = &cmd->iov_data[0];

	iov_ret = iscsit_map_iovec(cmd, iov, cmd->orig_iov_data_count - 2,
				   be32_to_cpu(hdr->offset), payload_length);
	if (iov_ret < 0)
		return -1;

	iov_count += iov_ret;

	padding = ((-payload_length) & 3);
	if (padding != 0) {
		iov[iov_count].iov_base	= cmd->pad_bytes;
		iov[iov_count++].iov_len = padding;
		rx_size += padding;
		pr_debug("Receiving %u padding bytes.\n", padding);
	}

	if (conn->conn_ops->DataDigest) {
		iov[iov_count].iov_base = &checksum;
		iov[iov_count++].iov_len = ISCSI_CRC_LEN;
		rx_size += ISCSI_CRC_LEN;
	}

	WARN_ON_ONCE(iov_count > cmd->orig_iov_data_count);
	rx_got = rx_data(conn, &cmd->iov_data[0], iov_count, rx_size);

	iscsit_unmap_iovec(cmd);

	if (rx_got != rx_size)
		return -1;

	if (conn->conn_ops->DataDigest) {
		u32 data_crc;

		data_crc = iscsit_do_crypto_hash_sg(conn->conn_rx_hash, cmd,
						    be32_to_cpu(hdr->offset),
						    payload_length, padding,
						    cmd->pad_bytes);

		if (checksum != data_crc) {
			pr_err("ITT: 0x%08x, Offset: %u, Length: %u,"
				" DataSN: 0x%08x, CRC32C DataDigest 0x%08x"
				" does not match computed 0x%08x\n",
				hdr->itt, hdr->offset, payload_length,
				hdr->datasn, checksum, data_crc);
			data_crc_failed = 1;
		} else {
			pr_debug("Got CRC32C DataDigest 0x%08x for"
				" %u bytes of Data Out\n", checksum,
				payload_length);
		}
	}

	return data_crc_failed;
}

int
iscsit_check_dataout_payload(struct iscsit_cmd *cmd, struct iscsi_data *hdr,
			     bool data_crc_failed);

extern typeof(iscsit_check_dataout_payload) iscsit_check_dataout_payload;

static int iscsit_handle_data_out(struct iscsit_conn *conn, unsigned char *buf)
{
	struct iscsit_cmd *cmd = NULL;
	struct iscsi_data *hdr = (struct iscsi_data *)buf;
	int rc;
	bool data_crc_failed = false;

	rc = iscsit_check_dataout_hdr(conn, buf, &cmd);
	if (rc < 0)
		return 0;
	else if (!cmd)
		return 0;

	rc = iscsit_get_dataout(conn, cmd, hdr);
	if (rc < 0)
		return rc;
	else if (rc > 0)
		data_crc_failed = true;

	return iscsit_check_dataout_payload(cmd, hdr, data_crc_failed);
}

int iscsit_setup_nop_out(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			 struct iscsi_nopout *hdr);

extern typeof(iscsit_setup_nop_out) iscsit_setup_nop_out;

int iscsit_process_nop_out(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			   struct iscsi_nopout *hdr);

extern typeof(iscsit_process_nop_out) iscsit_process_nop_out;

static int iscsit_handle_nop_out(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
				 unsigned char *buf)
{
	unsigned char *ping_data = NULL;
	struct iscsi_nopout *hdr = (struct iscsi_nopout *)buf;
	struct kvec *iov = NULL;
	u32 payload_length = ntoh24(hdr->dlength);
	int ret;

	ret = iscsit_setup_nop_out(conn, cmd, hdr);
	if (ret < 0)
		return 0;
	/*
	 * Handle NOP-OUT payload for traditional iSCSI sockets
	 */
	if (payload_length && hdr->ttt == cpu_to_be32(0xFFFFFFFF)) {
		u32 checksum, data_crc, padding = 0;
		int niov = 0, rx_got, rx_size = payload_length;

		ping_data = kzalloc(payload_length + 1, GFP_KERNEL);
		if (!ping_data) {
			ret = -1;
			goto out;
		}

		iov = &cmd->iov_misc[0];
		iov[niov].iov_base	= ping_data;
		iov[niov++].iov_len	= payload_length;

		padding = ((-payload_length) & 3);
		if (padding != 0) {
			pr_debug("Receiving %u additional bytes"
				" for padding.\n", padding);
			iov[niov].iov_base	= &cmd->pad_bytes;
			iov[niov++].iov_len	= padding;
			rx_size += padding;
		}
		if (conn->conn_ops->DataDigest) {
			iov[niov].iov_base	= &checksum;
			iov[niov++].iov_len	= ISCSI_CRC_LEN;
			rx_size += ISCSI_CRC_LEN;
		}

		WARN_ON_ONCE(niov > ARRAY_SIZE(cmd->iov_misc));
		rx_got = rx_data(conn, &cmd->iov_misc[0], niov, rx_size);
		if (rx_got != rx_size) {
			ret = -1;
			goto out;
		}

		if (conn->conn_ops->DataDigest) {
			iscsit_do_crypto_hash_buf(conn->conn_rx_hash, ping_data,
						  payload_length, padding,
						  cmd->pad_bytes, &data_crc);

			if (checksum != data_crc) {
				pr_err("Ping data CRC32C DataDigest"
				" 0x%08x does not match computed 0x%08x\n",
					checksum, data_crc);
				if (!conn->sess->sess_ops->ErrorRecoveryLevel) {
					pr_err("Unable to recover from"
					" NOPOUT Ping DataCRC failure while in"
						" ERL=0.\n");
					ret = -1;
					goto out;
				} else {
					/*
					 * Silently drop this PDU and let the
					 * initiator plug the CmdSN gap.
					 */
					pr_debug("Dropping NOPOUT"
					" Command CmdSN: 0x%08x due to"
					" DataCRC error.\n", hdr->cmdsn);
					ret = 0;
					goto out;
				}
			} else {
				pr_debug("Got CRC32C DataDigest"
				" 0x%08x for %u bytes of ping data.\n",
					checksum, payload_length);
			}
		}

		ping_data[payload_length] = '\0';
		/*
		 * Attach ping data to struct iscsit_cmd->buf_ptr.
		 */
		cmd->buf_ptr = ping_data;
		cmd->buf_ptr_size = payload_length;

		pr_debug("Got %u bytes of NOPOUT ping"
			" data.\n", payload_length);
		pr_debug("Ping Data: \"%s\"\n", ping_data);
	}

	return iscsit_process_nop_out(conn, cmd, hdr);
out:
	if (cmd)
		iscsit_free_cmd(cmd, false);

	kfree(ping_data);
	return ret;
}

int
iscsit_handle_task_mgt_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			   unsigned char *buf);

extern typeof(iscsit_handle_task_mgt_cmd) iscsit_handle_task_mgt_cmd;

int
iscsit_setup_text_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
		      struct iscsi_text *hdr);

extern typeof(iscsit_setup_text_cmd) iscsit_setup_text_cmd;

int
iscsit_process_text_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			struct iscsi_text *hdr);

extern typeof(iscsit_process_text_cmd) iscsit_process_text_cmd;

static int
klpp_iscsit_handle_text_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
		       unsigned char *buf)
{
	struct iscsi_text *hdr = (struct iscsi_text *)buf;
	char *text_in = NULL;
	u32 payload_length = ntoh24(hdr->dlength);
	int rx_size, rc;

	rc = iscsit_setup_text_cmd(conn, cmd, hdr);
	if (rc < 0)
		return 0;

	rx_size = payload_length;
	if (payload_length) {
		u32 checksum = 0, data_crc = 0;
		u32 padding = 0;
		int niov = 0, rx_got;
		struct kvec iov[2];

		rx_size = ALIGN(payload_length, 4);
		text_in = kzalloc(rx_size, GFP_KERNEL);
		if (!text_in)
			goto reject;

		cmd->text_in_ptr = text_in;

		memset(iov, 0, sizeof(iov));
		iov[niov].iov_base	= text_in;
		iov[niov++].iov_len	= rx_size;

		padding = rx_size - payload_length;
		if (padding)
			pr_debug("Receiving %u additional bytes"
					" for padding.\n", padding);
		if (conn->conn_ops->DataDigest) {
			iov[niov].iov_base	= &checksum;
			iov[niov++].iov_len	= ISCSI_CRC_LEN;
			rx_size += ISCSI_CRC_LEN;
		}

		WARN_ON_ONCE(niov > ARRAY_SIZE(iov));
		rx_got = rx_data(conn, &iov[0], niov, rx_size);
		if (rx_got != rx_size)
			goto reject;

		if (conn->conn_ops->DataDigest) {
			iscsit_do_crypto_hash_buf(conn->conn_rx_hash,
						  text_in,
						  ALIGN(payload_length, 4),
						  0, NULL,
						  &data_crc);

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

	return iscsit_process_text_cmd(conn, cmd, hdr);

reject:
	kfree(cmd->text_in_ptr);
	cmd->text_in_ptr = NULL;
	return iscsit_reject_cmd(cmd, ISCSI_REASON_PROTOCOL_ERROR, buf);
}

int
iscsit_handle_logout_cmd(struct iscsit_conn *conn, struct iscsit_cmd *cmd,
			unsigned char *buf);

extern typeof(iscsit_handle_logout_cmd) iscsit_handle_logout_cmd;

int iscsit_handle_snack(
	struct iscsit_conn *conn,
	unsigned char *buf);

extern typeof(iscsit_handle_snack) iscsit_handle_snack;

static void iscsit_rx_thread_wait_for_tcp(struct iscsit_conn *conn)
{
	if ((conn->sock->sk->sk_shutdown & SEND_SHUTDOWN) ||
	    (conn->sock->sk->sk_shutdown & RCV_SHUTDOWN)) {
		wait_for_completion_interruptible_timeout(
					&conn->rx_half_close_comp,
					ISCSI_RX_THREAD_TCP_TIMEOUT * HZ);
	}
}

static int iscsit_handle_immediate_data(
	struct iscsit_cmd *cmd,
	struct iscsi_scsi_req *hdr,
	u32 length)
{
	int iov_ret, rx_got = 0, rx_size = 0;
	u32 checksum, iov_count = 0, padding = 0;
	struct iscsit_conn *conn = cmd->conn;
	struct kvec *iov;
	void *overflow_buf = NULL;

	BUG_ON(cmd->write_data_done > cmd->se_cmd.data_length);
	rx_size = min(cmd->se_cmd.data_length - cmd->write_data_done, length);
	iov_ret = iscsit_map_iovec(cmd, cmd->iov_data,
				   cmd->orig_iov_data_count - 2,
				   cmd->write_data_done, rx_size);
	if (iov_ret < 0)
		return IMMEDIATE_DATA_CANNOT_RECOVER;

	iov_count = iov_ret;
	iov = &cmd->iov_data[0];
	if (rx_size < length) {
		/*
		 * Special case: length of immediate data exceeds the data
		 * buffer size derived from the CDB.
		 */
		overflow_buf = kmalloc(length - rx_size, GFP_KERNEL);
		if (!overflow_buf) {
			iscsit_unmap_iovec(cmd);
			return IMMEDIATE_DATA_CANNOT_RECOVER;
		}
		cmd->overflow_buf = overflow_buf;
		iov[iov_count].iov_base = overflow_buf;
		iov[iov_count].iov_len = length - rx_size;
		iov_count++;
		rx_size = length;
	}

	padding = ((-length) & 3);
	if (padding != 0) {
		iov[iov_count].iov_base	= cmd->pad_bytes;
		iov[iov_count++].iov_len = padding;
		rx_size += padding;
	}

	if (conn->conn_ops->DataDigest) {
		iov[iov_count].iov_base		= &checksum;
		iov[iov_count++].iov_len	= ISCSI_CRC_LEN;
		rx_size += ISCSI_CRC_LEN;
	}

	WARN_ON_ONCE(iov_count > cmd->orig_iov_data_count);
	rx_got = rx_data(conn, &cmd->iov_data[0], iov_count, rx_size);

	iscsit_unmap_iovec(cmd);

	if (rx_got != rx_size) {
		iscsit_rx_thread_wait_for_tcp(conn);
		return IMMEDIATE_DATA_CANNOT_RECOVER;
	}

	if (conn->conn_ops->DataDigest) {
		u32 data_crc;

		data_crc = iscsit_do_crypto_hash_sg(conn->conn_rx_hash, cmd,
						    cmd->write_data_done, length, padding,
						    cmd->pad_bytes);

		if (checksum != data_crc) {
			pr_err("ImmediateData CRC32C DataDigest 0x%08x"
				" does not match computed 0x%08x\n", checksum,
				data_crc);

			if (!conn->sess->sess_ops->ErrorRecoveryLevel) {
				pr_err("Unable to recover from"
					" Immediate Data digest failure while"
					" in ERL=0.\n");
				iscsit_reject_cmd(cmd,
						ISCSI_REASON_DATA_DIGEST_ERROR,
						(unsigned char *)hdr);
				return IMMEDIATE_DATA_CANNOT_RECOVER;
			} else {
				iscsit_reject_cmd(cmd,
						ISCSI_REASON_DATA_DIGEST_ERROR,
						(unsigned char *)hdr);
				return IMMEDIATE_DATA_ERL1_CRC_FAILURE;
			}
		} else {
			pr_debug("Got CRC32C DataDigest 0x%08x for"
				" %u bytes of Immediate Data\n", checksum,
				length);
		}
	}

	cmd->write_data_done += length;

	if (cmd->write_data_done == cmd->se_cmd.data_length) {
		spin_lock_bh(&cmd->istate_lock);
		cmd->cmd_flags |= ICF_GOT_LAST_DATAOUT;
		cmd->i_state = ISTATE_RECEIVED_LAST_DATAOUT;
		spin_unlock_bh(&cmd->istate_lock);
	}

	return IMMEDIATE_DATA_NORMAL_OPERATION;
}

void iscsit_thread_check_cpumask(
	struct iscsit_conn *conn,
	struct task_struct *p,
	int mode);

extern typeof(iscsit_thread_check_cpumask) iscsit_thread_check_cpumask;

static int klpr_iscsi_target_rx_opcode(struct iscsit_conn *conn, unsigned char *buf)
{
	struct iscsi_hdr *hdr = (struct iscsi_hdr *)buf;
	struct iscsit_cmd *cmd;
	int ret = 0;

	switch (hdr->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_SCSI_CMD:
		cmd = iscsit_allocate_cmd(conn, TASK_INTERRUPTIBLE);
		if (!cmd)
			goto reject;

		ret = iscsit_handle_scsi_cmd(conn, cmd, buf);
		break;
	case ISCSI_OP_SCSI_DATA_OUT:
		ret = iscsit_handle_data_out(conn, buf);
		break;
	case ISCSI_OP_NOOP_OUT:
		cmd = NULL;
		if (hdr->ttt == cpu_to_be32(0xFFFFFFFF)) {
			cmd = iscsit_allocate_cmd(conn, TASK_INTERRUPTIBLE);
			if (!cmd)
				goto reject;
		}
		ret = iscsit_handle_nop_out(conn, cmd, buf);
		break;
	case ISCSI_OP_SCSI_TMFUNC:
		cmd = iscsit_allocate_cmd(conn, TASK_INTERRUPTIBLE);
		if (!cmd)
			goto reject;

		ret = iscsit_handle_task_mgt_cmd(conn, cmd, buf);
		break;
	case ISCSI_OP_TEXT:
		if (hdr->ttt != cpu_to_be32(0xFFFFFFFF)) {
			cmd = iscsit_find_cmd_from_itt(conn, hdr->itt);
			if (!cmd)
				goto reject;
		} else {
			cmd = iscsit_allocate_cmd(conn, TASK_INTERRUPTIBLE);
			if (!cmd)
				goto reject;
		}

		ret = klpp_iscsit_handle_text_cmd(conn, cmd, buf);
		break;
	case ISCSI_OP_LOGOUT:
		cmd = iscsit_allocate_cmd(conn, TASK_INTERRUPTIBLE);
		if (!cmd)
			goto reject;

		ret = iscsit_handle_logout_cmd(conn, cmd, buf);
		if (ret > 0)
			wait_for_completion_timeout(&conn->conn_logout_comp,
					SECONDS_FOR_LOGOUT_COMP * HZ);
		break;
	case ISCSI_OP_SNACK:
		ret = iscsit_handle_snack(conn, buf);
		break;
	default:
		pr_err("Got unknown iSCSI OpCode: 0x%02x\n", hdr->opcode);
		if (!conn->sess->sess_ops->ErrorRecoveryLevel) {
			pr_err("Cannot recover from unknown"
			" opcode while ERL=0, closing iSCSI connection.\n");
			return -1;
		}
		pr_err("Unable to recover from unknown opcode while OFMarker=No,"
		       " closing iSCSI connection.\n");
		ret = -1;
		break;
	}

	return ret;
reject:
	return iscsit_add_reject(conn, ISCSI_REASON_BOOKMARK_NO_RESOURCES, buf);
}

void klpp_iscsit_get_rx_pdu(struct iscsit_conn *conn)
{
	int ret;
	u8 *buffer, *tmp_buf, opcode;
	u32 checksum = 0, digest = 0;
	struct iscsi_hdr *hdr;
	struct kvec iov;

	buffer = kcalloc(ISCSI_HDR_LEN, sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return;

	while (!kthread_should_stop()) {
		/*
		 * Ensure that both TX and RX per connection kthreads
		 * are scheduled to run on the same CPU.
		 */
		iscsit_thread_check_cpumask(conn, current, 0);

		memset(&iov, 0, sizeof(struct kvec));

		iov.iov_base	= buffer;
		iov.iov_len	= ISCSI_HDR_LEN;

		ret = rx_data(conn, &iov, 1, ISCSI_HDR_LEN);
		if (ret != ISCSI_HDR_LEN) {
			iscsit_rx_thread_wait_for_tcp(conn);
			break;
		}

		hdr = (struct iscsi_hdr *) buffer;
		if (hdr->hlength) {
			iov.iov_len = hdr->hlength * 4;
			tmp_buf = krealloc(buffer,
					  ISCSI_HDR_LEN + iov.iov_len,
					  GFP_KERNEL);
			if (!tmp_buf)
				break;

			buffer = tmp_buf;
			iov.iov_base = &buffer[ISCSI_HDR_LEN];

			ret = rx_data(conn, &iov, 1, iov.iov_len);
			if (ret != iov.iov_len) {
				iscsit_rx_thread_wait_for_tcp(conn);
				break;
			}
		}

		if (conn->conn_ops->HeaderDigest) {
			iov.iov_base	= &digest;
			iov.iov_len	= ISCSI_CRC_LEN;

			ret = rx_data(conn, &iov, 1, ISCSI_CRC_LEN);
			if (ret != ISCSI_CRC_LEN) {
				iscsit_rx_thread_wait_for_tcp(conn);
				break;
			}

			iscsit_do_crypto_hash_buf(conn->conn_rx_hash, buffer,
						  ISCSI_HDR_LEN, 0, NULL,
						  &checksum);

			if (digest != checksum) {
				pr_err("HeaderDigest CRC32C failed,"
					" received 0x%08x, computed 0x%08x\n",
					digest, checksum);
				/*
				 * Set the PDU to 0xff so it will intentionally
				 * hit default in the switch below.
				 */
				memset(buffer, 0xff, ISCSI_HDR_LEN);
				atomic_long_inc(&conn->sess->conn_digest_errors);
			} else {
				pr_debug("Got HeaderDigest CRC32C"
						" 0x%08x\n", checksum);
			}
		}

		if (conn->conn_state == TARG_CONN_STATE_IN_LOGOUT)
			break;

		opcode = buffer[0] & ISCSI_OPCODE_MASK;

		if (conn->sess->sess_ops->SessionType &&
		   ((!(opcode & ISCSI_OP_TEXT)) ||
		    (!(opcode & ISCSI_OP_LOGOUT)))) {
			pr_err("Received illegal iSCSI Opcode: 0x%02x"
			" while in Discovery Session, rejecting.\n", opcode);
			iscsit_add_reject(conn, ISCSI_REASON_PROTOCOL_ERROR,
					  buffer);
			break;
		}

		ret = klpr_iscsi_target_rx_opcode(conn, buffer);
		if (ret < 0)
			break;
	}

	kfree(buffer);
}


#include <linux/livepatch.h>

extern typeof(iscsit_add_cmd_to_immediate_queue)
	 iscsit_add_cmd_to_immediate_queue
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_add_cmd_to_immediate_queue);
extern typeof(iscsit_add_reject) iscsit_add_reject
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_add_reject);
extern typeof(iscsit_allocate_cmd) iscsit_allocate_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_allocate_cmd);
extern typeof(iscsit_check_dataout_hdr) iscsit_check_dataout_hdr
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_check_dataout_hdr);
extern typeof(iscsit_check_dataout_payload) iscsit_check_dataout_payload
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_check_dataout_payload);
extern typeof(iscsit_do_crypto_hash_buf) iscsit_do_crypto_hash_buf
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_do_crypto_hash_buf);
extern typeof(iscsit_dump_data_payload) iscsit_dump_data_payload
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_dump_data_payload);
extern typeof(iscsit_find_cmd_from_itt) iscsit_find_cmd_from_itt
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_find_cmd_from_itt);
extern typeof(iscsit_free_cmd) iscsit_free_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_free_cmd);
extern typeof(iscsit_handle_logout_cmd) iscsit_handle_logout_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_handle_logout_cmd);
extern typeof(iscsit_handle_snack) iscsit_handle_snack
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_handle_snack);
extern typeof(iscsit_handle_task_mgt_cmd) iscsit_handle_task_mgt_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_handle_task_mgt_cmd);
extern typeof(iscsit_map_iovec) iscsit_map_iovec
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_map_iovec);
extern typeof(iscsit_process_nop_out) iscsit_process_nop_out
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_process_nop_out);
extern typeof(iscsit_process_scsi_cmd) iscsit_process_scsi_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_process_scsi_cmd);
extern typeof(iscsit_process_text_cmd) iscsit_process_text_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_process_text_cmd);
extern typeof(iscsit_reject_cmd) iscsit_reject_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_reject_cmd);
extern typeof(iscsit_sequence_cmd) iscsit_sequence_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_sequence_cmd);
extern typeof(iscsit_set_unsolicited_dataout) iscsit_set_unsolicited_dataout
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_set_unsolicited_dataout);
extern typeof(iscsit_setup_nop_out) iscsit_setup_nop_out
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_setup_nop_out);
extern typeof(iscsit_setup_scsi_cmd) iscsit_setup_scsi_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_setup_scsi_cmd);
extern typeof(iscsit_setup_text_cmd) iscsit_setup_text_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_setup_text_cmd);
extern typeof(iscsit_thread_check_cpumask) iscsit_thread_check_cpumask
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, iscsit_thread_check_cpumask);
extern typeof(rx_data) rx_data
	 KLP_RELOC_SYMBOL(iscsi_target_mod, iscsi_target_mod, rx_data);
extern typeof(target_put_sess_cmd) target_put_sess_cmd
	 KLP_RELOC_SYMBOL(iscsi_target_mod, target_core_mod, target_put_sess_cmd);
