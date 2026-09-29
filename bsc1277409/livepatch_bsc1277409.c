/*
 * livepatch_bsc1277409
 *
 * Fix for CVE-2026-74394, bsc#1277409
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


#include "livepatch_bsc1277409.h"


/* klp-ccp: from drivers/infiniband/ulp/srpt/ib_srpt.c */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/atomic.h>
#include <linux/inet.h>
#include <rdma/ib_cache.h>
#include <scsi/scsi_proto.h>
#include <scsi/scsi_tcq.h>
#include <target/target_core_base.h>
#include <target/target_core_fabric.h>
/* klp-ccp: from drivers/infiniband/ulp/srpt/ib_srpt.h */
#include <linux/types.h>
#include <linux/list.h>
#include <linux/wait.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cm.h>
#include <rdma/rdma_cm.h>
#include <rdma/rw.h>
#include <scsi/srp.h>
/* klp-ccp: from drivers/infiniband/ulp/srpt/ib_dm_mad.h */
#include <linux/types.h>
#include <rdma/ib_mad.h>

/* klp-ccp: from drivers/infiniband/ulp/srpt/ib_srpt.h */
enum {
	/*
	 * SRP IOControllerProfile attributes for SRP target ports that have
	 * not been defined in <scsi/srp.h>. Source: section B.7, table B.7
	 * in the SRP specification.
	 */
	SRP_PROTOCOL = 0x0108,
	SRP_PROTOCOL_VERSION = 0x0001,
	SRP_IO_SUBCLASS = 0x609e,
	SRP_SEND_TO_IOC = 0x01,
	SRP_SEND_FROM_IOC = 0x02,
	SRP_RDMA_READ_FROM_IOC = 0x08,
	SRP_RDMA_WRITE_FROM_IOC = 0x20,

	/*
	 * srp_login_cmd.req_flags bitmasks. See also table 9 in the SRP
	 * specification.
	 */
	SRP_MTCH_ACTION = 0x03, /* MULTI-CHANNEL ACTION */
	SRP_LOSOLNT = 0x10, /* logout solicited notification */
	SRP_CRSOLNT = 0x20, /* credit request solicited notification */
	SRP_AESOLNT = 0x40, /* asynchronous event solicited notification */

	/*
	 * srp_cmd.sol_nt / srp_tsk_mgmt.sol_not bitmasks. See also tables
	 * 18 and 20 in the SRP specification.
	 */
	SRP_SCSOLNT = 0x02, /* SCSOLNT = successful solicited notification */
	SRP_UCSOLNT = 0x04, /* UCSOLNT = unsuccessful solicited notification */

	/*
	 * srp_rsp.sol_not / srp_t_logout.sol_not bitmasks. See also tables
	 * 16 and 22 in the SRP specification.
	 */
	SRP_SOLNT = 0x01, /* SOLNT = solicited notification */

	/* See also table 24 in the SRP specification. */
	SRP_TSK_MGMT_SUCCESS = 0x00,
	SRP_TSK_MGMT_FUNC_NOT_SUPP = 0x04,
	SRP_TSK_MGMT_FAILED = 0x05,

	/* See also table 21 in the SRP specification. */
	SRP_CMD_SIMPLE_Q = 0x0,
	SRP_CMD_HEAD_OF_Q = 0x1,
	SRP_CMD_ORDERED_Q = 0x2,
	SRP_CMD_ACA = 0x4,

	SRPT_DEF_SG_TABLESIZE = 128,

	MIN_SRPT_SQ_SIZE = 16,
	DEF_SRPT_SQ_SIZE = 4096,
	MAX_SRPT_RQ_SIZE = 128,
	MIN_SRPT_SRQ_SIZE = 4,
	DEFAULT_SRPT_SRQ_SIZE = 4095,
	MAX_SRPT_SRQ_SIZE = 65535,
	MAX_SRPT_RDMA_SIZE = 1U << 24,
	MAX_SRPT_RSP_SIZE = 1024,

	SRP_MAX_ADD_CDB_LEN = 16,
	SRP_MAX_IMM_DATA_OFFSET = 80,
	SRP_MAX_IMM_DATA = 8 * 1024,
	MIN_MAX_REQ_SIZE = 996,
	DEFAULT_MAX_REQ_SIZE_1 = sizeof(struct srp_cmd)/*48*/ +
				 SRP_MAX_ADD_CDB_LEN +
				 sizeof(struct srp_indirect_buf)/*20*/ +
				 128 * sizeof(struct srp_direct_buf)/*16*/,
	DEFAULT_MAX_REQ_SIZE_2 = SRP_MAX_IMM_DATA_OFFSET +
				 sizeof(struct srp_imm_buf) + SRP_MAX_IMM_DATA,
	DEFAULT_MAX_REQ_SIZE = DEFAULT_MAX_REQ_SIZE_1 > DEFAULT_MAX_REQ_SIZE_2 ?
			       DEFAULT_MAX_REQ_SIZE_1 : DEFAULT_MAX_REQ_SIZE_2,

	MIN_MAX_RSP_SIZE = sizeof(struct srp_rsp)/*36*/ + 4,
	DEFAULT_MAX_RSP_SIZE = 256, /* leaves 220 bytes for sense data */

	DEFAULT_MAX_RDMA_SIZE = 65536,
};

enum srpt_command_state {
	SRPT_STATE_NEW		 = 0,
	SRPT_STATE_NEED_DATA	 = 1,
	SRPT_STATE_DATA_IN	 = 2,
	SRPT_STATE_CMD_RSP_SENT	 = 3,
	SRPT_STATE_MGMT		 = 4,
	SRPT_STATE_MGMT_RSP_SENT = 5,
	SRPT_STATE_DONE		 = 6,
};

struct srpt_ioctx {
	struct ib_cqe		cqe;
	void			*buf;
	dma_addr_t		dma;
	uint32_t		offset;
	uint32_t		index;
};

struct srpt_recv_ioctx {
	struct srpt_ioctx	ioctx;
	struct list_head	wait_list;
	int			byte_len;
};

struct srpt_rw_ctx {
	struct rdma_rw_ctx	rw;
	struct scatterlist	*sg;
	unsigned int		nents;
};

struct srpt_send_ioctx {
	struct srpt_ioctx	ioctx;
	struct srpt_rdma_ch	*ch;
	struct srpt_recv_ioctx	*recv_ioctx;

	struct srpt_rw_ctx	s_rw_ctx;
	struct srpt_rw_ctx	*rw_ctxs;

	struct scatterlist	imm_sg;

	struct ib_cqe		rdma_cqe;
	enum srpt_command_state	state;
	struct se_cmd		cmd;
	u8			n_rdma;
	u8			n_rw_ctx;
	bool			queue_status_only;
	u8			sense_data[TRANSPORT_SENSE_BUFFER];
};

enum rdma_ch_state {
	CH_CONNECTING,
	CH_LIVE,
	CH_DISCONNECTING,
	CH_DRAINING,
	CH_DISCONNECTED,
};

struct srpt_rdma_ch {
	struct srpt_nexus	*nexus;
	struct ib_qp		*qp;
	union {
		struct {
			struct ib_cm_id		*cm_id;
		} ib_cm;
		struct {
			struct rdma_cm_id	*cm_id;
		} rdma_cm;
	};
	struct ib_cq		*cq;
	u32			cq_size;
	struct ib_cqe		zw_cqe;
	struct rcu_head		rcu;
	struct kref		kref;
	struct completion	*closed;
	int			rq_size;
	u32			max_rsp_size;
	atomic_t		sq_wr_avail;
	struct srpt_port	*sport;
	int			max_ti_iu_len;
	atomic_t		req_lim;
	atomic_t		req_lim_delta;
	u16			imm_data_offset;
	spinlock_t		spinlock;
	enum rdma_ch_state	state;
	struct kmem_cache	*rsp_buf_cache;
	struct srpt_send_ioctx	**ioctx_ring;
	struct kmem_cache	*req_buf_cache;
	struct srpt_recv_ioctx	**ioctx_recv_ring;
	struct list_head	list;
	struct list_head	cmd_wait_list;
	uint16_t		pkey;
	bool			using_rdma_cm;
	bool			processing_wait_list;
	struct se_session	*sess;
	u8			sess_name[40];
	struct work_struct	release_work;
};

struct srpt_port_attrib {
	u32			srp_max_rdma_size;
	u32			srp_max_rsp_size;
	u32			srp_sq_size;
	bool			use_srq;
};

struct srpt_port {
	struct srpt_device	*sdev;
	struct ib_mad_agent	*mad_agent;
	bool			enabled;
	u8			port;
	u32			sm_lid;
	u32			lid;
	union ib_gid		gid;
	struct work_struct	work;
	char			guid_name[64];
	struct srpt_port_id	*guid_id;
	char			gid_name[64];
	struct srpt_port_id	*gid_id;
	struct srpt_port_attrib port_attrib;
	atomic_t		refcount;
	struct completion	*freed_channels;
	struct mutex		mutex;
	struct list_head	nexus_list;
};

struct srpt_device {
	struct kref		refcnt;
	struct ib_device	*device;
	struct ib_pd		*pd;
	u32			lkey;
	struct ib_srq		*srq;
	struct ib_cm_id		*cm_id;
	int			srq_size;
	struct mutex		sdev_mutex;
	bool			use_srq;
	struct kmem_cache	*req_buf_cache;
	struct srpt_recv_ioctx	**ioctx_ring;
	struct ib_event_handler	event_handler;
	struct list_head	list;
	struct srpt_port        port[];
};

/* klp-ccp: from drivers/infiniband/ulp/srpt/ib_srpt.c */
#define DRV_NAME		"ib_srpt"

#undef pr_fmt
#define pr_fmt(fmt) DRV_NAME " " fmt

extern unsigned srp_max_req_size;

extern void srpt_recv_done(struct ib_cq *cq, struct ib_wc *wc);

static enum srpt_command_state srpt_set_cmd_state(struct srpt_send_ioctx *ioctx,
						  enum srpt_command_state new)
{
	enum srpt_command_state previous;

	previous = ioctx->state;
	if (previous != SRPT_STATE_DONE)
		ioctx->state = new;

	return previous;
}

static int srpt_post_recv(struct srpt_device *sdev, struct srpt_rdma_ch *ch,
			  struct srpt_recv_ioctx *ioctx)
{
	struct ib_sge list;
	struct ib_recv_wr wr;

	BUG_ON(!sdev);
	list.addr = ioctx->ioctx.dma + ioctx->ioctx.offset;
	list.length = srp_max_req_size;
	list.lkey = sdev->lkey;

	ioctx->ioctx.cqe.done = srpt_recv_done;
	wr.wr_cqe = &ioctx->ioctx.cqe;
	wr.next = NULL;
	wr.sg_list = &list;
	wr.num_sge = 1;

	if (sdev->use_srq)
		return ib_post_srq_recv(sdev->srq, &wr, NULL);
	else
		return ib_post_recv(ch->qp, &wr, NULL);
}

extern int srpt_alloc_rw_ctxs(struct srpt_send_ioctx *ioctx,
		struct srp_direct_buf *db, int nbufs, struct scatterlist **sg,
		unsigned *sg_cnt);

static inline void *srpt_get_desc_buf(struct srp_cmd *srp_cmd)
{
	/*
	 * The pointer computations below will only be compiled correctly
	 * if srp_cmd::add_data is declared as s8*, u8*, s8[] or u8[], so check
	 * whether srp_cmd::add_data has been declared as a byte pointer.
	 */
	BUILD_BUG_ON(!__same_type(srp_cmd->add_data[0], (s8)0) &&
		     !__same_type(srp_cmd->add_data[0], (u8)0));

	/*
	 * According to the SRP spec, the lower two bits of the 'ADDITIONAL
	 * CDB LENGTH' field are reserved and the size in bytes of this field
	 * is four times the value specified in bits 3..7. Hence the "& ~3".
	 */
	return srp_cmd->add_data + (srp_cmd->add_cdb_len & ~3);
}

static int klpp_srpt_get_desc_tbl(struct srpt_recv_ioctx *recv_ioctx,
		struct srpt_send_ioctx *ioctx,
		struct srp_cmd *srp_cmd, enum dma_data_direction *dir,
		struct scatterlist **sg, unsigned int *sg_cnt, u64 *data_len,
		u16 imm_data_offset)
{
	BUG_ON(!dir);
	BUG_ON(!data_len);

	/*
	 * The lower four bits of the buffer format field contain the DATA-IN
	 * buffer descriptor format, and the highest four bits contain the
	 * DATA-OUT buffer descriptor format.
	 */
	if (srp_cmd->buf_fmt & 0xf)
		/* DATA-IN: transfer data from target to initiator (read). */
		*dir = DMA_FROM_DEVICE;
	else if (srp_cmd->buf_fmt >> 4)
		/* DATA-OUT: transfer data from initiator to target (write). */
		*dir = DMA_TO_DEVICE;
	else
		*dir = DMA_NONE;

	/* initialize data_direction early as srpt_alloc_rw_ctxs needs it */
	ioctx->cmd.data_direction = *dir;

	if (((srp_cmd->buf_fmt & 0xf) == SRP_DATA_DESC_DIRECT) ||
	    ((srp_cmd->buf_fmt >> 4) == SRP_DATA_DESC_DIRECT)) {
		struct srp_direct_buf *db = srpt_get_desc_buf(srp_cmd);

		*data_len = be32_to_cpu(db->len);
		return srpt_alloc_rw_ctxs(ioctx, db, 1, sg, sg_cnt);
	} else if (((srp_cmd->buf_fmt & 0xf) == SRP_DATA_DESC_INDIRECT) ||
		   ((srp_cmd->buf_fmt >> 4) == SRP_DATA_DESC_INDIRECT)) {
		struct srp_indirect_buf *idb = srpt_get_desc_buf(srp_cmd);
		int nbufs = be32_to_cpu(idb->table_desc.len) /
				sizeof(struct srp_direct_buf);

		if (nbufs >
		    (srp_cmd->data_out_desc_cnt + srp_cmd->data_in_desc_cnt)) {
			pr_err("received unsupported SRP_CMD request type (%u out + %u in != %u / %zu)\n",
			       srp_cmd->data_out_desc_cnt,
			       srp_cmd->data_in_desc_cnt,
			       be32_to_cpu(idb->table_desc.len),
			       sizeof(struct srp_direct_buf));
			return -EINVAL;
		}

		*data_len = be32_to_cpu(idb->len);
		return srpt_alloc_rw_ctxs(ioctx, idb->desc_list, nbufs,
				sg, sg_cnt);
	} else if ((srp_cmd->buf_fmt >> 4) == SRP_DATA_DESC_IMM) {
		struct srp_imm_buf *imm_buf = srpt_get_desc_buf(srp_cmd);
		void *data = (void *)srp_cmd + imm_data_offset;
		uint32_t len = be32_to_cpu(imm_buf->len);
		uint32_t req_size;

		if (check_add_overflow((uint32_t)imm_data_offset, len, &req_size) ||
		    req_size > srp_max_req_size) {
			pr_err("Immediate data (length %d + %d) exceeds request size %d\n",
			       imm_data_offset, len, srp_max_req_size);
			return -EINVAL;
		}
		if (recv_ioctx->byte_len < req_size) {
			pr_err("Received too few data - %d < %d\n",
			       recv_ioctx->byte_len, req_size);
			return -EIO;
		}
		/*
		 * The immediate data buffer descriptor must occur before the
		 * immediate data itself.
		 */
		if ((void *)(imm_buf + 1) > (void *)data) {
			pr_err("Received invalid write request\n");
			return -EINVAL;
		}
		*data_len = len;
		ioctx->recv_ioctx = recv_ioctx;
		if ((uintptr_t)data & 511) {
			pr_warn_once("Internal error - the receive buffers are not aligned properly.\n");
			return -EINVAL;
		}
		sg_init_one(&ioctx->imm_sg, data, len);
		*sg = &ioctx->imm_sg;
		*sg_cnt = 1;
		return 0;
	} else {
		*data_len = 0;
		return 0;
	}
}

static struct srpt_send_ioctx *srpt_get_send_ioctx(struct srpt_rdma_ch *ch)
{
	struct srpt_send_ioctx *ioctx;
	int tag, cpu;

	BUG_ON(!ch);

	tag = sbitmap_queue_get(&ch->sess->sess_tag_pool, &cpu);
	if (tag < 0)
		return NULL;

	ioctx = ch->ioctx_ring[tag];
	BUG_ON(ioctx->ch != ch);
	ioctx->state = SRPT_STATE_NEW;
	WARN_ON_ONCE(ioctx->recv_ioctx);
	ioctx->n_rdma = 0;
	ioctx->n_rw_ctx = 0;
	ioctx->queue_status_only = false;
	/*
	 * transport_init_se_cmd() does not initialize all fields, so do it
	 * here.
	 */
	memset(&ioctx->cmd, 0, sizeof(ioctx->cmd));
	memset(&ioctx->sense_data, 0, sizeof(ioctx->sense_data));
	ioctx->cmd.map_tag = tag;
	ioctx->cmd.map_cpu = cpu;

	return ioctx;
}

static void klpr_srpt_handle_cmd(struct srpt_rdma_ch *ch,
			    struct srpt_recv_ioctx *recv_ioctx,
			    struct srpt_send_ioctx *send_ioctx)
{
	struct se_cmd *cmd;
	struct srp_cmd *srp_cmd;
	struct scatterlist *sg = NULL;
	unsigned sg_cnt = 0;
	u64 data_len;
	enum dma_data_direction dir;
	int rc;

	BUG_ON(!send_ioctx);

	srp_cmd = recv_ioctx->ioctx.buf + recv_ioctx->ioctx.offset;
	cmd = &send_ioctx->cmd;
	cmd->tag = srp_cmd->tag;

	switch (srp_cmd->task_attr) {
	case SRP_CMD_SIMPLE_Q:
		cmd->sam_task_attr = TCM_SIMPLE_TAG;
		break;
	case SRP_CMD_ORDERED_Q:
	default:
		cmd->sam_task_attr = TCM_ORDERED_TAG;
		break;
	case SRP_CMD_HEAD_OF_Q:
		cmd->sam_task_attr = TCM_HEAD_TAG;
		break;
	case SRP_CMD_ACA:
		cmd->sam_task_attr = TCM_ACA_TAG;
		break;
	}

	rc = klpp_srpt_get_desc_tbl(recv_ioctx, send_ioctx, srp_cmd, &dir,
			       &sg, &sg_cnt, &data_len, ch->imm_data_offset);
	if (rc) {
		if (rc != -EAGAIN) {
			pr_err("0x%llx: parsing SRP descriptor table failed.\n",
			       srp_cmd->tag);
		}
		goto busy;
	}

	rc = target_init_cmd(cmd, ch->sess, &send_ioctx->sense_data[0],
			     scsilun_to_int(&srp_cmd->lun), data_len,
			     TCM_SIMPLE_TAG, dir, TARGET_SCF_ACK_KREF);
	if (rc != 0) {
		pr_debug("target_submit_cmd() returned %d for tag %#llx\n", rc,
			 srp_cmd->tag);
		goto busy;
	}

	if (target_submit_prep(cmd, srp_cmd->cdb, sg, sg_cnt, NULL, 0, NULL, 0,
			       GFP_KERNEL))
		return;

	target_submit(cmd);
	return;

busy:
	target_send_busy(cmd);
}

static int srp_tmr_to_tcm(int fn)
{
	switch (fn) {
	case SRP_TSK_ABORT_TASK:
		return TMR_ABORT_TASK;
	case SRP_TSK_ABORT_TASK_SET:
		return TMR_ABORT_TASK_SET;
	case SRP_TSK_CLEAR_TASK_SET:
		return TMR_CLEAR_TASK_SET;
	case SRP_TSK_LUN_RESET:
		return TMR_LUN_RESET;
	case SRP_TSK_CLEAR_ACA:
		return TMR_CLEAR_ACA;
	default:
		return -1;
	}
}

static void srpt_handle_tsk_mgmt(struct srpt_rdma_ch *ch,
				 struct srpt_recv_ioctx *recv_ioctx,
				 struct srpt_send_ioctx *send_ioctx)
{
	struct srp_tsk_mgmt *srp_tsk;
	struct se_cmd *cmd;
	struct se_session *sess = ch->sess;
	int tcm_tmr;
	int rc;

	BUG_ON(!send_ioctx);

	srp_tsk = recv_ioctx->ioctx.buf + recv_ioctx->ioctx.offset;
	cmd = &send_ioctx->cmd;

	pr_debug("recv tsk_mgmt fn %d for task_tag %lld and cmd tag %lld ch %p sess %p\n",
		 srp_tsk->tsk_mgmt_func, srp_tsk->task_tag, srp_tsk->tag, ch,
		 ch->sess);

	srpt_set_cmd_state(send_ioctx, SRPT_STATE_MGMT);
	send_ioctx->cmd.tag = srp_tsk->tag;
	tcm_tmr = srp_tmr_to_tcm(srp_tsk->tsk_mgmt_func);
	rc = target_submit_tmr(&send_ioctx->cmd, sess, NULL,
			       scsilun_to_int(&srp_tsk->lun), srp_tsk, tcm_tmr,
			       GFP_KERNEL, srp_tsk->task_tag,
			       TARGET_SCF_ACK_KREF);
	if (rc != 0) {
		send_ioctx->cmd.se_tmr_req->response = TMR_FUNCTION_REJECTED;
		cmd->se_tfo->queue_tm_rsp(cmd);
	}
	return;
}

bool klpp_srpt_handle_new_iu(struct srpt_rdma_ch *ch, struct srpt_recv_ioctx *recv_ioctx)
{
	struct srpt_send_ioctx *send_ioctx = NULL;
	struct srp_cmd *srp_cmd;
	bool res = false;
	u8 opcode;

	BUG_ON(!ch);
	BUG_ON(!recv_ioctx);

	if (unlikely(ch->state == CH_CONNECTING))
		goto push;

	ib_dma_sync_single_for_cpu(ch->sport->sdev->device,
				   recv_ioctx->ioctx.dma,
				   recv_ioctx->ioctx.offset + srp_max_req_size,
				   DMA_FROM_DEVICE);

	srp_cmd = recv_ioctx->ioctx.buf + recv_ioctx->ioctx.offset;
	opcode = srp_cmd->opcode;
	if (opcode == SRP_CMD || opcode == SRP_TSK_MGMT) {
		send_ioctx = srpt_get_send_ioctx(ch);
		if (unlikely(!send_ioctx))
			goto push;
	}

	if (!list_empty(&recv_ioctx->wait_list)) {
		WARN_ON_ONCE(!ch->processing_wait_list);
		list_del_init(&recv_ioctx->wait_list);
	}

	switch (opcode) {
	case SRP_CMD:
		klpr_srpt_handle_cmd(ch, recv_ioctx, send_ioctx);
		break;
	case SRP_TSK_MGMT:
		srpt_handle_tsk_mgmt(ch, recv_ioctx, send_ioctx);
		break;
	case SRP_I_LOGOUT:
		pr_err("Not yet implemented: SRP_I_LOGOUT\n");
		break;
	case SRP_CRED_RSP:
		pr_debug("received SRP_CRED_RSP\n");
		break;
	case SRP_AER_RSP:
		pr_debug("received SRP_AER_RSP\n");
		break;
	case SRP_RSP:
		pr_err("Received SRP_RSP\n");
		break;
	default:
		pr_err("received IU with unknown opcode 0x%x\n", opcode);
		break;
	}

	if (!send_ioctx || !send_ioctx->recv_ioctx)
		srpt_post_recv(ch->sport->sdev, ch, recv_ioctx);
	res = true;

out:
	return res;

push:
	if (list_empty(&recv_ioctx->wait_list)) {
		WARN_ON_ONCE(ch->processing_wait_list);
		list_add_tail(&recv_ioctx->wait_list, &ch->cmd_wait_list);
	}
	goto out;
}

void srpt_recv_done(struct ib_cq *cq, struct ib_wc *wc);


#include <linux/livepatch.h>

extern typeof(scsilun_to_int) scsilun_to_int
	 KLP_RELOC_SYMBOL(ib_srpt, scsi_mod, scsilun_to_int);
extern typeof(srp_max_req_size) srp_max_req_size
	 KLP_RELOC_SYMBOL(ib_srpt, ib_srpt, srp_max_req_size);
extern typeof(srpt_alloc_rw_ctxs) srpt_alloc_rw_ctxs
	 KLP_RELOC_SYMBOL(ib_srpt, ib_srpt, srpt_alloc_rw_ctxs);
extern typeof(srpt_recv_done) srpt_recv_done
	 KLP_RELOC_SYMBOL(ib_srpt, ib_srpt, srpt_recv_done);
extern typeof(target_init_cmd) target_init_cmd
	 KLP_RELOC_SYMBOL(ib_srpt, target_core_mod, target_init_cmd);
extern typeof(target_send_busy) target_send_busy
	 KLP_RELOC_SYMBOL(ib_srpt, target_core_mod, target_send_busy);
extern typeof(target_submit) target_submit
	 KLP_RELOC_SYMBOL(ib_srpt, target_core_mod, target_submit);
extern typeof(target_submit_prep) target_submit_prep
	 KLP_RELOC_SYMBOL(ib_srpt, target_core_mod, target_submit_prep);
extern typeof(target_submit_tmr) target_submit_tmr
	 KLP_RELOC_SYMBOL(ib_srpt, target_core_mod, target_submit_tmr);
