/*
 * livepatch_bsc1255845
 *
 * Fix for CVE-2022-50717, bsc#1255845
 *
 *  Copyright (c) 2026 SUSE
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

#if IS_ENABLED(CONFIG_NVME_TARGET_TCP)

#if !IS_MODULE(CONFIG_NVME_TARGET_TCP)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/nvme/target/tcp.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/inet.h>
#include <linux/llist.h>
#include <crypto/hash.h>

/* klp-ccp: from drivers/nvme/target/nvmet.h */
#include <linux/dma-mapping.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/kref.h>
#include <linux/percpu-refcount.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/uuid.h>
#include <linux/nvme.h>
#include <linux/configfs.h>
#include <linux/rcupdate.h>
#include <linux/blkdev.h>

struct nvmet_cq {
	u16			qid;
	u16			size;
};

struct nvmet_sq {
	struct nvmet_ctrl	*ctrl;
	struct percpu_ref	ref;
	u16			qid;
	u16			size;
	u32			sqhd;
	bool			sqhd_disabled;
	struct completion	free_done;
	struct completion	confirm_done;
};

struct nvmet_ana_group {
	struct config_group	group;
	struct nvmet_port	*port;
	u32			grpid;
};

struct nvmet_port {
	struct list_head		entry;
	struct nvmf_disc_rsp_page_entry	disc_addr;
	struct config_group		group;
	struct config_group		subsys_group;
	struct list_head		subsystems;
	struct config_group		referrals_group;
	struct list_head		referrals;
	struct list_head		global_entry;
	struct config_group		ana_groups_group;
	struct nvmet_ana_group		ana_default_group;
	enum nvme_ana_state		*ana_state;
	void				*priv;
	bool				enabled;
	int				inline_data_size;
};

struct nvmet_req;
struct nvmet_fabrics_ops {
	struct module *owner;
	unsigned int type;
	unsigned int msdbd;
	bool has_keyed_sgls : 1;
	void (*queue_response)(struct nvmet_req *req);
	int (*add_port)(struct nvmet_port *port);
	void (*remove_port)(struct nvmet_port *port);
	void (*delete_ctrl)(struct nvmet_ctrl *ctrl);
	void (*disc_traddr)(struct nvmet_req *req,
			struct nvmet_port *port, char *traddr);
	u16 (*install_queue)(struct nvmet_sq *nvme_sq);
};

#define NVMET_MAX_INLINE_BIOVEC	8

struct nvmet_req {
	struct nvme_command	*cmd;
	struct nvme_completion	*rsp;
	struct nvmet_sq		*sq;
	struct nvmet_cq		*cq;
	struct nvmet_ns		*ns;
	struct scatterlist	*sg;
	struct bio_vec		inline_bvec[NVMET_MAX_INLINE_BIOVEC];
	union {
		struct {
			struct bio      inline_bio;
		} b;
		struct {
			bool			mpool_alloc;
			struct kiocb            iocb;
			struct bio_vec          *bvec;
			struct work_struct      work;
		} f;
	};
	int			sg_cnt;
	/* data length as parsed from the command: */
	size_t			data_len;
	/* data length as parsed from the SGL descriptor: */
	size_t			transfer_len;

	struct nvmet_port	*port;

	void (*execute)(struct nvmet_req *req);
	const struct nvmet_fabrics_ops *ops;

#ifndef __GENKSYMS__
	u16			error_loc;
	u64			error_slba;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

static bool (*klpe_nvmet_req_init)(struct nvmet_req *req, struct nvmet_cq *cq,
		struct nvmet_sq *sq, const struct nvmet_fabrics_ops *ops);

static void (*klpe_nvmet_req_execute)(struct nvmet_req *req);
static void (*klpe_nvmet_req_complete)(struct nvmet_req *req, u16 status);

/* klp-ccp: from drivers/nvme/target/tcp.c */
#define NVMET_TCP_MAXH2CDATA		0x400000 /* 16M arbitrary limit */

enum nvmet_tcp_send_state {
	NVMET_TCP_SEND_DATA_PDU,
	NVMET_TCP_SEND_DATA,
	NVMET_TCP_SEND_R2T,
	NVMET_TCP_SEND_DDGST,
	NVMET_TCP_SEND_RESPONSE
};

enum nvmet_tcp_recv_state {
	NVMET_TCP_RECV_PDU,
	NVMET_TCP_RECV_DATA,
	NVMET_TCP_RECV_DDGST,
	NVMET_TCP_RECV_ERR,
};

enum {
	NVMET_TCP_F_INIT_FAILED = (1 << 0),
};

struct nvmet_tcp_cmd {
	struct nvmet_tcp_queue		*queue;
	struct nvmet_req		req;

	struct nvme_tcp_cmd_pdu		*cmd_pdu;
	struct nvme_tcp_rsp_pdu		*rsp_pdu;
	struct nvme_tcp_data_pdu	*data_pdu;
	struct nvme_tcp_r2t_pdu		*r2t_pdu;

	u32				rbytes_done;
	u32				wbytes_done;

	u32				pdu_len;
	u32				pdu_recv;
	int				sg_idx;
	int				nr_mapped;
	struct msghdr			recv_msg;
	struct kvec			*iov;
	u32				flags;

	struct list_head		entry;
	struct llist_node		lentry;

	/* send state */
	u32				offset;
	struct scatterlist		*cur_sg;
	enum nvmet_tcp_send_state	state;

	__le32				exp_ddgst;
	__le32				recv_ddgst;
};

enum nvmet_tcp_queue_state {
	NVMET_TCP_Q_CONNECTING,
	NVMET_TCP_Q_LIVE,
	NVMET_TCP_Q_DISCONNECTING,
};

struct nvmet_tcp_queue {
	struct socket		*sock;
	struct nvmet_tcp_port	*port;
	struct work_struct	io_work;
	int			cpu;
	struct nvmet_cq		nvme_cq;
	struct nvmet_sq		nvme_sq;

	/* send state */
	struct nvmet_tcp_cmd	*cmds;
	unsigned int		nr_cmds;
	struct list_head	free_list;
	struct llist_head	resp_list;
	struct list_head	resp_send_list;
	int			send_list_len;
	struct nvmet_tcp_cmd	*snd_cmd;

	/* recv state */
	int			offset;
	int			left;
	enum nvmet_tcp_recv_state rcv_state;
	struct nvmet_tcp_cmd	*cmd;
	union nvme_tcp_pdu	pdu;

	/* digest state */
	bool			hdr_digest;
	bool			data_digest;
	struct ahash_request	*snd_hash;
	struct ahash_request	*rcv_hash;

	spinlock_t		state_lock;
	enum nvmet_tcp_queue_state state;

	struct sockaddr_storage	sockaddr;
	struct sockaddr_storage	sockaddr_peer;
	struct work_struct	release_work;

	int			idx;
	struct list_head	queue_list;

	struct nvmet_tcp_cmd	connect;

	struct page_frag_cache	pf_cache;

	void (*data_ready)(struct sock *);
	void (*state_change)(struct sock *);
	void (*write_space)(struct sock *);
};

static struct nvmet_fabrics_ops (*klpe_nvmet_tcp_ops);

static inline bool nvmet_tcp_has_data_in(struct nvmet_tcp_cmd *cmd)
{
	return nvme_is_write(cmd->req.cmd) &&
		cmd->rbytes_done < cmd->req.transfer_len;
}

static inline bool nvmet_tcp_need_data_in(struct nvmet_tcp_cmd *cmd)
{
	return nvmet_tcp_has_data_in(cmd) && !cmd->req.rsp->status;
}

static inline bool nvmet_tcp_has_inline_data(struct nvmet_tcp_cmd *cmd)
{
	return nvme_is_write(cmd->req.cmd) && cmd->pdu_len &&
		!cmd->rbytes_done;
}

static inline struct nvmet_tcp_cmd *
nvmet_tcp_get_cmd(struct nvmet_tcp_queue *queue)
{
	struct nvmet_tcp_cmd *cmd;

	cmd = list_first_entry_or_null(&queue->free_list,
				struct nvmet_tcp_cmd, entry);
	if (!cmd)
		return NULL;
	list_del_init(&cmd->entry);

	cmd->rbytes_done = cmd->wbytes_done = 0;
	cmd->pdu_len = 0;
	cmd->pdu_recv = 0;
	cmd->iov = NULL;
	cmd->flags = 0;
	return cmd;
}

static inline u8 nvmet_tcp_hdgst_len(struct nvmet_tcp_queue *queue)
{
	return queue->hdr_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}

static inline u8 nvmet_tcp_ddgst_len(struct nvmet_tcp_queue *queue)
{
	return queue->data_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}

static inline void nvmet_tcp_hdgst(struct ahash_request *hash,
		void *pdu, size_t len)
{
	struct scatterlist sg;

	sg_init_one(&sg, pdu, len);
	ahash_request_set_crypt(hash, &sg, pdu + len, len);
	crypto_ahash_digest(hash);
}

static int nvmet_tcp_verify_hdgst(struct nvmet_tcp_queue *queue,
	void *pdu, size_t len)
{
	struct nvme_tcp_hdr *hdr = pdu;
	__le32 recv_digest;
	__le32 exp_digest;

	if (unlikely(!(hdr->flags & NVME_TCP_F_HDGST))) {
		pr_err("queue %d: header digest enabled but no header digest\n",
			queue->idx);
		return -EPROTO;
	}

	recv_digest = *(__le32 *)(pdu + hdr->hlen);
	nvmet_tcp_hdgst(queue->rcv_hash, pdu, len);
	exp_digest = *(__le32 *)(pdu + hdr->hlen);
	if (recv_digest != exp_digest) {
		pr_err("queue %d: header digest error: recv %#x expected %#x\n",
			queue->idx, le32_to_cpu(recv_digest),
			le32_to_cpu(exp_digest));
		return -EPROTO;
	}

	return 0;
}

static int nvmet_tcp_check_ddgst(struct nvmet_tcp_queue *queue, void *pdu)
{
	struct nvme_tcp_hdr *hdr = pdu;
	u8 digest_len = nvmet_tcp_hdgst_len(queue);
	u32 len;

	len = le32_to_cpu(hdr->plen) - hdr->hlen -
		(hdr->flags & NVME_TCP_F_HDGST ? digest_len : 0);

	if (unlikely(len && !(hdr->flags & NVME_TCP_F_DDGST))) {
		pr_err("queue %d: data digest flag is cleared\n", queue->idx);
		return -EPROTO;
	}

	return 0;
}

static void (*klpe_nvmet_tcp_map_pdu_iovec)(struct nvmet_tcp_cmd *cmd);

static void (*klpe_nvmet_tcp_fatal_error)(struct nvmet_tcp_queue *queue);

static int (*klpe_nvmet_tcp_map_data)(struct nvmet_tcp_cmd *cmd);

static void (*klpe_nvmet_tcp_queue_response)(struct nvmet_req *req);

static void nvmet_prepare_receive_pdu(struct nvmet_tcp_queue *queue)
{
	queue->offset = 0;
	queue->left = sizeof(struct nvme_tcp_hdr);
	queue->cmd = NULL;
	queue->rcv_state = NVMET_TCP_RECV_PDU;
}

static int (*klpe_nvmet_tcp_handle_icreq)(struct nvmet_tcp_queue *queue);

static void klpr_nvmet_tcp_handle_req_failure(struct nvmet_tcp_queue *queue,
		struct nvmet_tcp_cmd *cmd, struct nvmet_req *req)
{
	int ret;

	/* recover the expected data transfer length */
	req->data_len = le32_to_cpu(req->cmd->common.dptr.sgl.length);

	if (!nvme_is_write(cmd->req.cmd) ||
	    req->data_len > cmd->req.port->inline_data_size) {
		nvmet_prepare_receive_pdu(queue);
		return;
	}

	ret = (*klpe_nvmet_tcp_map_data)(cmd);
	if (unlikely(ret)) {
		pr_err("queue %d: failed to map data\n", queue->idx);
		(*klpe_nvmet_tcp_fatal_error)(queue);
		return;
	}

	queue->rcv_state = NVMET_TCP_RECV_DATA;
	(*klpe_nvmet_tcp_map_pdu_iovec)(cmd);
	cmd->flags |= NVMET_TCP_F_INIT_FAILED;
}

static int klpp_nvmet_tcp_handle_h2c_data_pdu(struct nvmet_tcp_queue *queue)
{
	struct nvme_tcp_data_pdu *data = &queue->pdu.data;
	struct nvmet_tcp_cmd *cmd;
	unsigned int exp_data_len;

	if (likely(queue->nr_cmds)) {
		if (unlikely(data->ttag >= queue->nr_cmds)) {
			pr_err("queue %d: received out of bound ttag %u, nr_cmds %u\n",
				queue->idx, data->ttag, queue->nr_cmds);
			(*klpe_nvmet_tcp_fatal_error)(queue);
			return -EPROTO;
		}
		cmd = &queue->cmds[data->ttag];
	} else {
		cmd = &queue->connect;
	}

	if (le32_to_cpu(data->data_offset) != cmd->rbytes_done) {
		pr_err("ttag %u unexpected data offset %u (expected %u)\n",
			data->ttag, le32_to_cpu(data->data_offset),
			cmd->rbytes_done);
		goto err_proto;
	}

	exp_data_len = le32_to_cpu(data->hdr.plen) -
			nvmet_tcp_hdgst_len(queue) -
			nvmet_tcp_ddgst_len(queue) -
			sizeof(*data);

	cmd->pdu_len = le32_to_cpu(data->data_length);
	if (unlikely(cmd->pdu_len != exp_data_len ||
		     cmd->pdu_len == 0 ||
		     cmd->pdu_len > NVMET_TCP_MAXH2CDATA)) {
		pr_err("H2CData PDU len %u is invalid\n", cmd->pdu_len);
		goto err_proto;
	}
	cmd->pdu_recv = 0;
	(*klpe_nvmet_tcp_map_pdu_iovec)(cmd);
	queue->cmd = cmd;
	queue->rcv_state = NVMET_TCP_RECV_DATA;

	return 0;

err_proto:
	/* FIXME: use proper transport errors */
	(*klpe_nvmet_tcp_fatal_error)(queue);
	return -EPROTO;
}

static int klpr_nvmet_tcp_done_recv_pdu(struct nvmet_tcp_queue *queue)
{
	struct nvme_tcp_hdr *hdr = &queue->pdu.cmd.hdr;
	struct nvme_command *nvme_cmd = &queue->pdu.cmd.cmd;
	struct nvmet_req *req;
	int ret;

	if (unlikely(queue->state == NVMET_TCP_Q_CONNECTING)) {
		if (hdr->type != nvme_tcp_icreq) {
			pr_err("unexpected pdu type (%d) before icreq\n",
				hdr->type);
			(*klpe_nvmet_tcp_fatal_error)(queue);
			return -EPROTO;
		}
		return (*klpe_nvmet_tcp_handle_icreq)(queue);
	}

	if (hdr->type == nvme_tcp_h2c_data) {
		ret = klpp_nvmet_tcp_handle_h2c_data_pdu(queue);
		if (unlikely(ret))
			return ret;
		return 0;
	}

	queue->cmd = nvmet_tcp_get_cmd(queue);
	if (unlikely(!queue->cmd)) {
		/* This should never happen */
		pr_err("queue %d: out of commands (%d) send_list_len: %d, opcode: %d",
			queue->idx, queue->nr_cmds, queue->send_list_len,
			nvme_cmd->common.opcode);
		(*klpe_nvmet_tcp_fatal_error)(queue);
		return -ENOMEM;
	}

	req = &queue->cmd->req;
	memcpy(req->cmd, nvme_cmd, sizeof(*nvme_cmd));

	if (unlikely(!(*klpe_nvmet_req_init)(req, &queue->nvme_cq,
			&queue->nvme_sq, &(*klpe_nvmet_tcp_ops)))) {
		pr_err("failed cmd %p id %d opcode %d, data_len: %d\n",
			req->cmd, req->cmd->common.command_id,
			req->cmd->common.opcode,
			le32_to_cpu(req->cmd->common.dptr.sgl.length));

		klpr_nvmet_tcp_handle_req_failure(queue, queue->cmd, req);
		return -EAGAIN;
	}

	ret = (*klpe_nvmet_tcp_map_data)(queue->cmd);
	if (unlikely(ret)) {
		pr_err("queue %d: failed to map data\n", queue->idx);
		if (nvmet_tcp_has_inline_data(queue->cmd))
			(*klpe_nvmet_tcp_fatal_error)(queue);
		else
			(*klpe_nvmet_req_complete)(req, ret);
		ret = -EAGAIN;
		goto out;
	}

	if (nvmet_tcp_need_data_in(queue->cmd)) {
		if (nvmet_tcp_has_inline_data(queue->cmd)) {
			queue->rcv_state = NVMET_TCP_RECV_DATA;
			(*klpe_nvmet_tcp_map_pdu_iovec)(queue->cmd);
			return 0;
		}
		/* send back R2T */
		(*klpe_nvmet_tcp_queue_response)(&queue->cmd->req);
		goto out;
	}

	(*klpe_nvmet_req_execute)(&queue->cmd->req);
out:
	nvmet_prepare_receive_pdu(queue);
	return ret;
}

static const u8 (*klpe_nvme_tcp_pdu_sizes)[7];

static inline u8 klpr_nvmet_tcp_pdu_size(u8 type)
{
	size_t idx = type;

	return (idx < ARRAY_SIZE((*klpe_nvme_tcp_pdu_sizes)) &&
		(*klpe_nvme_tcp_pdu_sizes)[idx]) ?
			(*klpe_nvme_tcp_pdu_sizes)[idx] : 0;
}

static inline bool nvmet_tcp_pdu_valid(u8 type)
{
	switch (type) {
	case nvme_tcp_icreq:
	case nvme_tcp_cmd:
	case nvme_tcp_h2c_data:
		/* fallthru */
		return true;
	}

	return false;
}

int klpp_nvmet_tcp_try_recv_pdu(struct nvmet_tcp_queue *queue)
{
	struct nvme_tcp_hdr *hdr = &queue->pdu.cmd.hdr;
	int len;
	struct kvec iov;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };

recv:
	iov.iov_base = (void *)&queue->pdu + queue->offset;
	iov.iov_len = queue->left;
	len = kernel_recvmsg(queue->sock, &msg, &iov, 1,
			iov.iov_len, msg.msg_flags);
	if (unlikely(len < 0))
		return len;

	queue->offset += len;
	queue->left -= len;
	if (queue->left)
		return -EAGAIN;

	if (queue->offset == sizeof(struct nvme_tcp_hdr)) {
		u8 hdgst = nvmet_tcp_hdgst_len(queue);

		if (unlikely(!nvmet_tcp_pdu_valid(hdr->type))) {
			pr_err("unexpected pdu type %d\n", hdr->type);
			(*klpe_nvmet_tcp_fatal_error)(queue);
			return -EIO;
		}

		if (unlikely(hdr->hlen != klpr_nvmet_tcp_pdu_size(hdr->type))) {
			pr_err("pdu %d bad hlen %d\n", hdr->type, hdr->hlen);
			return -EIO;
		}

		queue->left = hdr->hlen - queue->offset + hdgst;
		goto recv;
	}

	if (queue->hdr_digest &&
	    nvmet_tcp_verify_hdgst(queue, &queue->pdu, queue->offset)) {
		(*klpe_nvmet_tcp_fatal_error)(queue); /* fatal */
		return -EPROTO;
	}

	if (queue->data_digest &&
	    nvmet_tcp_check_ddgst(queue, &queue->pdu)) {
		(*klpe_nvmet_tcp_fatal_error)(queue); /* fatal */
		return -EPROTO;
	}

	return klpr_nvmet_tcp_done_recv_pdu(queue);
}


#include "livepatch_bsc1255845.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nvmet_tcp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nvme_tcp_pdu_sizes", (void *)&klpe_nvme_tcp_pdu_sizes,
	  "nvmet_tcp" },
	{ "nvmet_tcp_fatal_error", (void *)&klpe_nvmet_tcp_fatal_error,
	  "nvmet_tcp" },
	{ "nvmet_tcp_handle_icreq", (void *)&klpe_nvmet_tcp_handle_icreq,
	  "nvmet_tcp" },
	{ "nvmet_tcp_map_data", (void *)&klpe_nvmet_tcp_map_data,
	  "nvmet_tcp" },
	{ "nvmet_tcp_map_pdu_iovec", (void *)&klpe_nvmet_tcp_map_pdu_iovec,
	  "nvmet_tcp" },
	{ "nvmet_tcp_ops", (void *)&klpe_nvmet_tcp_ops, "nvmet_tcp" },
	{ "nvmet_tcp_queue_response", (void *)&klpe_nvmet_tcp_queue_response,
	  "nvmet_tcp" },
	{ "nvmet_req_complete", (void *)&klpe_nvmet_req_complete, "nvmet" },
	{ "nvmet_req_execute", (void *)&klpe_nvmet_req_execute, "nvmet" },
	{ "nvmet_req_init", (void *)&klpe_nvmet_req_init, "nvmet" },
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

int livepatch_bsc1255845_init(void)
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

void livepatch_bsc1255845_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_NVME_TARGET_TCP) */
