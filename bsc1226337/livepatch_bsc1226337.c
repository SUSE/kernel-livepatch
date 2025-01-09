/*
 * livepatch_bsc1226337
 *
 * Fix for CVE-XXXX-XXXX, bsc#1226337
 *
 *  Upstream commit:
 *  160f3549a907 ("nvme-tcp: fix UAF when detecting digest errors")
 *
 *  SLE12-SP5 commit:
 *  f1592151a6eec7b623715707a6f53c928eb81663
 *
 *  SLE15-SP2 and -SP3 commit:
 *  e5510ceb68f77919c98c395722abcdcaeda53f47
 *
 *  SLE15-SP4 and -SP5 commit:
 *  9769cb9b91180c7935ea8480381fbfcdd6228ff3
 *  d1c233bb691de7ad48795db5c7022b5e32e3a6d1
 *
 *  SLE15-SP6 commit:
 *  Not affected
 *
 *  Copyright (c) 2024 SUSE
 *  Author: Vincenzo MEZZELA <vincenzo.mezzela@suse.com>
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

#if IS_ENABLED(CONFIG_NVME_TCP)

#if !IS_MODULE(CONFIG_NVME_TCP)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/nvme/host/tcp.c */
#include <linux/nvme-tcp.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/blk-mq.h>
#include <crypto/hash.h>

/* klp-ccp: from drivers/nvme/host/nvme.h */
#include <linux/nvme.h>
#include <linux/cdev.h>

struct nvme_request {
	struct nvme_command	*cmd;
	union nvme_result	result;
	u8			retries;
	u8			flags;
	u16			status;
	struct nvme_ctrl	*ctrl;
};

static inline struct nvme_request *nvme_req(struct request *req)
{
	return blk_mq_rq_to_pdu(req);
}

enum nvme_ctrl_state {
	NVME_CTRL_NEW,
	NVME_CTRL_LIVE,
	NVME_CTRL_ADMIN_ONLY,    /* Only admin queue live */
	NVME_CTRL_RESETTING,
	NVME_CTRL_CONNECTING,
	NVME_CTRL_DELETING,
	NVME_CTRL_DEAD,
};

struct nvme_ctrl {
	bool comp_seen;
	enum nvme_ctrl_state state;
	bool identified;
	spinlock_t lock;
	struct mutex scan_lock;
	const struct nvme_ctrl_ops *ops;
	struct request_queue *admin_q;
	struct request_queue *connect_q;
	struct device *dev;
	int instance;
	int numa_node;
	struct blk_mq_tag_set *tagset;
	struct blk_mq_tag_set *admin_tagset;
	struct list_head namespaces;
	struct rw_semaphore namespaces_rwsem;
	struct device ctrl_device;
	struct device *device;	/* char device */
	struct cdev cdev;
	struct work_struct reset_work;
	struct work_struct delete_work;

	struct nvme_subsystem *subsys;
	struct list_head subsys_entry;

	struct opal_dev *opal_dev;

	char name[12];
	u16 cntlid;

	u32 ctrl_config;
	u16 mtfa;
	u32 queue_count;

	u64 cap;
	u32 page_size;
	u32 max_hw_sectors;
	u32 max_segments;
	u16 crdt[3];
	u16 oncs;
	u16 oacs;
	u16 nssa;
	u16 nr_streams;
	u32 max_namespaces;
	atomic_t abort_limit;
	u8 vwc;
	u32 vs;
	u32 sgls;
	u16 kas;
	u8 npss;
	u8 apsta;
	u32 oaes;
	u32 aen_result;
	u32 ctratt;
	unsigned int shutdown_timeout;
	unsigned int kato;
	bool subsystem;
	unsigned long quirks;
	struct nvme_id_power_state psd[32];
	struct nvme_effects_log *effects;
	struct work_struct scan_work;
	struct work_struct async_event_work;
	struct delayed_work ka_work;
	struct nvme_command ka_cmd;
	struct work_struct fw_act_work;
	unsigned long events;

#ifdef CONFIG_NVME_MULTIPATH
	u8 anacap;
	u8 anatt;
	u32 anagrpmax;
	u32 nanagrpid;
	struct mutex ana_lock;
	struct nvme_ana_rsp_hdr *ana_log_buf;
	size_t ana_log_size;
	struct timer_list anatt_timer;
	struct work_struct ana_work;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	u64 ps_max_latency_us;
	bool apst_enabled;

	/* PCIe only: */
	u32 hmpre;
	u32 hmmin;
	u32 hmminds;
	u16 hmmaxd;

	/* Fabrics only */
	u16 sqsize;
	u32 ioccsz;
	u32 iorcsz;
	u16 icdoff;
	u16 maxcmd;
	int nr_reconnects;
	struct nvmf_ctrl_options *opts;
#ifndef __GENKSYMS__
	struct request_queue *fabrics_q;
	struct delayed_work failfast_work;
	unsigned long flags;

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
};

#ifdef CONFIG_FAULT_INJECTION_DEBUG_FS

static void (*klpe_nvme_should_fail)(struct request *req);
#else
#error "klp-ccp: non-taken branch"
#endif

static inline void klpr_nvme_end_request(struct request *req, __le16 status,
		union nvme_result result)
{
	struct nvme_request *rq = nvme_req(req);

	rq->status = le16_to_cpu(status) >> 1;
	rq->result = result;
	/* inject error when permitted by fault injection framework */
	(*klpe_nvme_should_fail)(req);
	blk_mq_complete_request(req);
}

/* klp-ccp: from drivers/nvme/host/fabrics.h */
#include <linux/in.h>

/* klp-ccp: from drivers/nvme/host/tcp.c */
enum nvme_tcp_send_state {
	NVME_TCP_SEND_CMD_PDU = 0,
	NVME_TCP_SEND_H2C_PDU,
	NVME_TCP_SEND_DATA,
	NVME_TCP_SEND_DDGST,
};

struct nvme_tcp_request {
	struct nvme_request	req;
	void			*pdu;
	struct nvme_tcp_queue	*queue;
	u32			data_len;
	u32			pdu_len;
	u32			pdu_sent;
	u16			ttag;
	struct list_head	entry;
	__le32			ddgst;

	struct bio		*curr_bio;
	struct iov_iter		iter;

	/* send state */
	size_t			offset;
	size_t			data_sent;
	enum nvme_tcp_send_state state;
};

struct nvme_tcp_queue {
	struct socket		*sock;
	struct work_struct	io_work;
	int			io_cpu;

	spinlock_t		lock;
	struct list_head	send_list;

	/* recv state */
	void			*pdu;
	int			pdu_remaining;
	int			pdu_offset;
	size_t			data_remaining;
	size_t			ddgst_remaining;

	/* send state */
	struct nvme_tcp_request *request;

	struct mutex		queue_lock;
	int			queue_size;
	size_t			cmnd_capsule_len;
	struct nvme_tcp_ctrl	*ctrl;
	unsigned long		flags;
	bool			rd_enabled;

	bool			hdr_digest;
	bool			data_digest;
	struct ahash_request	*rcv_hash;
	struct ahash_request	*snd_hash;
	__le32			exp_ddgst;
	__le32			recv_ddgst;

	struct page_frag_cache	pf_cache;

	void (*state_change)(struct sock *);
	void (*data_ready)(struct sock *);
	void (*write_space)(struct sock *);
};

struct nvme_tcp_ctrl {
	/* read only in the hot path */
	struct nvme_tcp_queue	*queues;
	struct blk_mq_tag_set	tag_set;

	/* other member variables */
	struct list_head	list;
	struct blk_mq_tag_set	admin_tag_set;
	struct sockaddr_storage addr;
	struct sockaddr_storage src_addr;
	struct nvme_ctrl	ctrl;

	struct work_struct	err_work;
	struct delayed_work	connect_work;
	struct nvme_tcp_request async_req;
};

static struct workqueue_struct *(*klpe_nvme_tcp_wq);

static inline u8 nvme_tcp_hdgst_len(struct nvme_tcp_queue *queue)
{
	return queue->hdr_digest ? NVME_TCP_DIGEST_LENGTH : 0;
}

static inline size_t nvme_tcp_inline_data_size(struct nvme_tcp_queue *queue)
{
	return queue->cmnd_capsule_len - sizeof(struct nvme_command);
}

static inline bool nvme_tcp_async_req(struct nvme_tcp_request *req)
{
	return req == &req->queue->ctrl->async_req;
}

static inline bool nvme_tcp_has_inline_data(struct nvme_tcp_request *req)
{
	struct request *rq;
	unsigned int bytes;

	if (unlikely(nvme_tcp_async_req(req)))
		return false; /* async events don't have a request */

	rq = blk_mq_rq_from_pdu(req);
	bytes = blk_rq_payload_bytes(rq);

	return rq_data_dir(rq) == WRITE && bytes &&
		bytes <= nvme_tcp_inline_data_size(req->queue);
}

static inline struct page *nvme_tcp_req_cur_page(struct nvme_tcp_request *req)
{
	return req->iter.bvec->bv_page;
}

static inline size_t nvme_tcp_req_cur_offset(struct nvme_tcp_request *req)
{
	return req->iter.bvec->bv_offset + req->iter.iov_offset;
}

static inline size_t nvme_tcp_req_cur_length(struct nvme_tcp_request *req)
{
	return min_t(size_t, req->iter.bvec->bv_len - req->iter.iov_offset,
			req->pdu_len - req->pdu_sent);
}

static inline size_t nvme_tcp_pdu_data_left(struct nvme_tcp_request *req)
{
	return rq_data_dir(blk_mq_rq_from_pdu(req)) == WRITE ?
			req->pdu_len - req->pdu_sent : 0;
}

static inline size_t nvme_tcp_pdu_last_send(struct nvme_tcp_request *req,
		int len)
{
	return nvme_tcp_pdu_data_left(req) <= len;
}

static void (*klpe_nvme_tcp_init_iter)(struct nvme_tcp_request *req,
		unsigned int dir);

static inline void klpr_nvme_tcp_advance_req(struct nvme_tcp_request *req,
		int len)
{
	req->data_sent += len;
	req->pdu_sent += len;
	iov_iter_advance(&req->iter, len);
	if (!iov_iter_count(&req->iter) &&
	    req->data_sent < req->data_len) {
		req->curr_bio = req->curr_bio->bi_next;
		(*klpe_nvme_tcp_init_iter)(req, WRITE);
	}
}

static inline struct nvme_tcp_request *
nvme_tcp_fetch_request(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;

	spin_lock(&queue->lock);
	req = list_first_entry_or_null(&queue->send_list,
			struct nvme_tcp_request, entry);
	if (req)
		list_del(&req->entry);
	spin_unlock(&queue->lock);

	return req;
}

static inline void nvme_tcp_ddgst_final(struct ahash_request *hash,
		__le32 *dgst)
{
	ahash_request_set_crypt(hash, NULL, (u8 *)dgst, 0);
	crypto_ahash_final(hash);
}

static inline void nvme_tcp_ddgst_update(struct ahash_request *hash,
		struct page *page, off_t off, size_t len)
{
	struct scatterlist sg;

	sg_init_marker(&sg, 1);
	sg_set_page(&sg, page, len, off);
	ahash_request_set_crypt(hash, &sg, NULL, len);
	crypto_ahash_update(hash);
}

static inline void nvme_tcp_hdgst(struct ahash_request *hash,
		void *pdu, size_t len)
{
	struct scatterlist sg;

	sg_init_one(&sg, pdu, len);
	ahash_request_set_crypt(hash, &sg, pdu + len, len);
	crypto_ahash_digest(hash);
}

static inline void klpr_nvme_tcp_end_request(struct request *rq, __le16 status)
{
	union nvme_result res = {};

	klpr_nvme_end_request(rq, cpu_to_le16(status << 1), res);
}

static int (*klpe_nvme_tcp_recv_skb)(read_descriptor_t *desc, struct sk_buff *skb,
			     unsigned int offset, size_t len);

static inline void nvme_tcp_done_send_req(struct nvme_tcp_queue *queue)
{
	queue->request = NULL;
}

static void klpr_nvme_tcp_fail_request(struct nvme_tcp_request *req)
{
	klpr_nvme_tcp_end_request(blk_mq_rq_from_pdu(req), NVME_SC_HOST_PATH_ERROR);
}

static int klpr_nvme_tcp_try_send_data(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;

	while (true) {
		struct page *page = nvme_tcp_req_cur_page(req);
		size_t offset = nvme_tcp_req_cur_offset(req);
		size_t len = nvme_tcp_req_cur_length(req);
		bool last = nvme_tcp_pdu_last_send(req, len);
		int ret, flags = MSG_DONTWAIT;

		if (last && !queue->data_digest)
			flags |= MSG_EOR;
		else
			flags |= MSG_MORE;

		if (sendpage_ok(page)) {
			ret = kernel_sendpage(queue->sock, page, offset, len,
					flags);
		} else {
			ret = sock_no_sendpage(queue->sock, page, offset, len,
					flags);
		}
		if (ret <= 0)
			return ret;

		klpr_nvme_tcp_advance_req(req, ret);
		if (queue->data_digest)
			nvme_tcp_ddgst_update(queue->snd_hash, page,
					offset, ret);

		/* fully successful last write*/
		if (last && ret == len) {
			if (queue->data_digest) {
				nvme_tcp_ddgst_final(queue->snd_hash,
					&req->ddgst);
				req->state = NVME_TCP_SEND_DDGST;
				req->offset = 0;
			} else {
				nvme_tcp_done_send_req(queue);
			}
			return 1;
		}
	}
	return -EAGAIN;
}

static int klpr_nvme_tcp_try_send_cmd_pdu(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	struct nvme_tcp_cmd_pdu *pdu = req->pdu;
	bool inline_data = nvme_tcp_has_inline_data(req);
	int flags = MSG_DONTWAIT | (inline_data ? MSG_MORE : MSG_EOR);
	u8 hdgst = nvme_tcp_hdgst_len(queue);
	int len = sizeof(*pdu) + hdgst - req->offset;
	int ret;

	if (queue->hdr_digest && !req->offset)
		nvme_tcp_hdgst(queue->snd_hash, pdu, sizeof(*pdu));

	ret = kernel_sendpage(queue->sock, virt_to_page(pdu),
			offset_in_page(pdu) + req->offset, len,  flags);
	if (unlikely(ret <= 0))
		return ret;

	len -= ret;
	if (!len) {
		if (inline_data) {
			req->state = NVME_TCP_SEND_DATA;
			if (queue->data_digest)
				crypto_ahash_init(queue->snd_hash);
			(*klpe_nvme_tcp_init_iter)(req, WRITE);
		} else {
			nvme_tcp_done_send_req(queue);
		}
		return 1;
	}
	req->offset += ret;

	return -EAGAIN;
}

static int klpr_nvme_tcp_try_send_data_pdu(struct nvme_tcp_request *req)
{
	struct nvme_tcp_queue *queue = req->queue;
	struct nvme_tcp_data_pdu *pdu = req->pdu;
	u8 hdgst = nvme_tcp_hdgst_len(queue);
	int len = sizeof(*pdu) - req->offset + hdgst;
	int ret;

	if (queue->hdr_digest && !req->offset)
		nvme_tcp_hdgst(queue->snd_hash, pdu, sizeof(*pdu));

	ret = kernel_sendpage(queue->sock, virt_to_page(pdu),
			offset_in_page(pdu) + req->offset, len,
			MSG_DONTWAIT | MSG_MORE);
	if (unlikely(ret <= 0))
		return ret;

	len -= ret;
	if (!len) {
		req->state = NVME_TCP_SEND_DATA;
		if (queue->data_digest)
			crypto_ahash_init(queue->snd_hash);
		if (!req->data_sent)
			(*klpe_nvme_tcp_init_iter)(req, WRITE);
		return 1;
	}
	req->offset += ret;

	return -EAGAIN;
}

static int (*klpe_nvme_tcp_try_send_ddgst)(struct nvme_tcp_request *req);

static int klpr_nvme_tcp_try_send(struct nvme_tcp_queue *queue)
{
	struct nvme_tcp_request *req;
	int ret = 1;

	if (!queue->request) {
		queue->request = nvme_tcp_fetch_request(queue);
		if (!queue->request)
			return 0;
	}
	req = queue->request;

	if (req->state == NVME_TCP_SEND_CMD_PDU) {
		ret = klpr_nvme_tcp_try_send_cmd_pdu(req);
		if (ret <= 0)
			goto done;
		if (!nvme_tcp_has_inline_data(req))
			return ret;
	}

	if (req->state == NVME_TCP_SEND_H2C_PDU) {
		ret = klpr_nvme_tcp_try_send_data_pdu(req);
		if (ret <= 0)
			goto done;
	}

	if (req->state == NVME_TCP_SEND_DATA) {
		ret = klpr_nvme_tcp_try_send_data(req);
		if (ret <= 0)
			goto done;
	}

	if (req->state == NVME_TCP_SEND_DDGST)
		ret = (*klpe_nvme_tcp_try_send_ddgst)(req);
done:
	if (ret == -EAGAIN)
		ret = 0;
	return ret;
}

static int klpr_nvme_tcp_try_recv(struct nvme_tcp_queue *queue)
{
	struct sock *sk = queue->sock->sk;
	read_descriptor_t rd_desc;
	int consumed;

	rd_desc.arg.data = queue;
	rd_desc.count = 1;
	lock_sock(sk);
	consumed = tcp_read_sock(sk, &rd_desc, (*klpe_nvme_tcp_recv_skb));
	release_sock(sk);
	return consumed;
}

void klpp_nvme_tcp_io_work(struct work_struct *w)
{
	struct nvme_tcp_queue *queue =
		container_of(w, struct nvme_tcp_queue, io_work);
	unsigned long start = jiffies + msecs_to_jiffies(1);

	do {
		bool pending = false;
		int result;

		result = klpr_nvme_tcp_try_send(queue);
		if (result > 0) {
			pending = true;
		} else if (unlikely(result < 0)) {
			dev_err(queue->ctrl->ctrl.device,
				"failed to send request %d\n", result);
			if (result != -EPIPE)
				klpr_nvme_tcp_fail_request(queue->request);
			nvme_tcp_done_send_req(queue);
			return;
		}

		result = klpr_nvme_tcp_try_recv(queue);
		if (result > 0)
			pending = true;

		if (!pending || !queue->rd_enabled)
			return;

	} while (time_after(jiffies, start)); /* quota is exhausted */

	queue_work_on(queue->io_cpu, (*klpe_nvme_tcp_wq), &queue->io_work);
}


#include "livepatch_bsc1226337.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nvme_tcp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nvme_should_fail", (void *)&klpe_nvme_should_fail, "nvme_core" },
	{ "nvme_tcp_init_iter", (void *)&klpe_nvme_tcp_init_iter, "nvme_tcp" },
	{ "nvme_tcp_recv_skb", (void *)&klpe_nvme_tcp_recv_skb, "nvme_tcp" },
	{ "nvme_tcp_try_send_ddgst", (void *)&klpe_nvme_tcp_try_send_ddgst,
	  "nvme_tcp" },
	{ "nvme_tcp_wq", (void *)&klpe_nvme_tcp_wq, "nvme_tcp" },
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

int livepatch_bsc1226337_init(void)
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

void livepatch_bsc1226337_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED() */
