/*
 * livepatch_bsc1216044
 *
 * Fix for CVE-2023-5178, bsc#1216044
 *
 *  Upstream commit:
 *  d920abd1e7c4 ("nvmet-tcp: Fix a possible UAF in queue intialization setup")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  Not affected
 *
 *  SLE15-SP2 and -SP3 commit:
 *  Not affected
 *
 *  SLE15-SP4 and -SP5 commit:
 *  b965ee191b3b1e29cd8cf00b29814733cd046ac7
 *
 *  Copyright (c) 2023 SUSE
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

#if !IS_MODULE(CONFIG_NVME_TARGET_TCP)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/nvme/target/tcp.c */
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/nvme-tcp.h>
#include <net/sock.h>
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
#include <linux/rcupdate.h>
#include <linux/radix-tree.h>

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
#ifdef CONFIG_NVME_TARGET_AUTH
	struct delayed_work	auth_expired_work;
	bool			authenticated;
	u16			dhchap_tid;
	u16			dhchap_status;
	int			dhchap_step;
	u8			*dhchap_c1;
	u8			*dhchap_c2;
	u32			dhchap_s1;
	u32			dhchap_s2;
	u8			*dhchap_skey;
	int			dhchap_skey_len;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	struct completion	free_done;
	struct completion	confirm_done;
};

#define NVMET_MAX_INLINE_BIOVEC	8

struct nvmet_req {
	struct nvme_command	*cmd;
	struct nvme_completion	*cqe;
	struct nvmet_sq		*sq;
	struct nvmet_cq		*cq;
	struct nvmet_ns		*ns;
	struct scatterlist	*sg;
	struct scatterlist	*metadata_sg;
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
		struct {
			struct bio		inline_bio;
			struct request		*rq;
			struct work_struct      work;
			bool			use_workqueue;
		} p;
#ifdef CONFIG_BLK_DEV_ZONED
		struct {
			struct bio		inline_bio;
			struct work_struct	zmgmt_work;
		} z;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* CONFIG_BLK_DEV_ZONED */
	};
	int			sg_cnt;
	int			metadata_sg_cnt;
	/* data length as parsed from the SGL descriptor: */
	size_t			transfer_len;
	size_t			metadata_len;

	struct nvmet_port	*port;

	void (*execute)(struct nvmet_req *req);
	const struct nvmet_fabrics_ops *ops;

	struct pci_dev		*p2p_dev;
	struct device		*p2p_client;
	u16			error_loc;
	u64			error_slba;
};

/* klp-ccp: from drivers/nvme/target/tcp.c */
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

	unsigned long           poll_end;

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

static void (*klpe_nvmet_tcp_fatal_error)(struct nvmet_tcp_queue *queue);

void klpp_nvmet_tcp_socket_error(struct nvmet_tcp_queue *queue, int status)
{
	queue->rcv_state = NVMET_TCP_RECV_ERR;
	if (status == -EPIPE || status == -ECONNRESET)
		kernel_sock_shutdown(queue->sock, SHUT_RDWR);
	else
		(*klpe_nvmet_tcp_fatal_error)(queue);
}

static void nvmet_prepare_receive_pdu(struct nvmet_tcp_queue *queue)
{
	queue->offset = 0;
	queue->left = sizeof(struct nvme_tcp_hdr);
	queue->cmd = NULL;
	queue->rcv_state = NVMET_TCP_RECV_PDU;
}

static void (*klpe_nvmet_tcp_free_crypto)(struct nvmet_tcp_queue *queue);

static int nvmet_tcp_alloc_crypto(struct nvmet_tcp_queue *queue)
{
	struct crypto_ahash *tfm;

	tfm = crypto_alloc_ahash("crc32c", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	queue->snd_hash = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!queue->snd_hash)
		goto free_tfm;
	ahash_request_set_callback(queue->snd_hash, 0, NULL, NULL);

	queue->rcv_hash = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!queue->rcv_hash)
		goto free_snd_hash;
	ahash_request_set_callback(queue->rcv_hash, 0, NULL, NULL);

	return 0;
free_snd_hash:
	ahash_request_free(queue->snd_hash);
free_tfm:
	crypto_free_ahash(tfm);
	return -ENOMEM;
}

int klpp_nvmet_tcp_handle_icreq(struct nvmet_tcp_queue *queue)
{
	struct nvme_tcp_icreq_pdu *icreq = &queue->pdu.icreq;
	struct nvme_tcp_icresp_pdu *icresp = &queue->pdu.icresp;
	struct msghdr msg = {};
	struct kvec iov;
	int ret;

	if (le32_to_cpu(icreq->hdr.plen) != sizeof(struct nvme_tcp_icreq_pdu)) {
		pr_err("bad nvme-tcp pdu length (%d)\n",
			le32_to_cpu(icreq->hdr.plen));
		(*klpe_nvmet_tcp_fatal_error)(queue);
	}

	if (icreq->pfv != NVME_TCP_PFV_1_0) {
		pr_err("queue %d: bad pfv %d\n", queue->idx, icreq->pfv);
		return -EPROTO;
	}

	if (icreq->hpda != 0) {
		pr_err("queue %d: unsupported hpda %d\n", queue->idx,
			icreq->hpda);
		return -EPROTO;
	}

	queue->hdr_digest = !!(icreq->digest & NVME_TCP_HDR_DIGEST_ENABLE);
	queue->data_digest = !!(icreq->digest & NVME_TCP_DATA_DIGEST_ENABLE);
	if (queue->hdr_digest || queue->data_digest) {
		ret = nvmet_tcp_alloc_crypto(queue);
		if (ret)
			return ret;
	}

	memset(icresp, 0, sizeof(*icresp));
	icresp->hdr.type = nvme_tcp_icresp;
	icresp->hdr.hlen = sizeof(*icresp);
	icresp->hdr.pdo = 0;
	icresp->hdr.plen = cpu_to_le32(icresp->hdr.hlen);
	icresp->pfv = cpu_to_le16(NVME_TCP_PFV_1_0);
	icresp->maxdata = cpu_to_le32(0x400000); /* 16M arbitrary limit */
	icresp->cpda = 0;
	if (queue->hdr_digest)
		icresp->digest |= NVME_TCP_HDR_DIGEST_ENABLE;
	if (queue->data_digest)
		icresp->digest |= NVME_TCP_DATA_DIGEST_ENABLE;

	iov.iov_base = icresp;
	iov.iov_len = sizeof(*icresp);
	ret = kernel_sendmsg(queue->sock, &msg, &iov, 1, iov.iov_len);
	if (ret < 0)
		return ret; /* queue removal will cleanup */

	queue->state = NVMET_TCP_Q_LIVE;
	nvmet_prepare_receive_pdu(queue);
	return 0;
}



#include "livepatch_bsc1216044.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nvmet_tcp"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "nvmet_tcp_fatal_error", (void *)&klpe_nvmet_tcp_fatal_error,
	  "nvmet_tcp" },
	{ "nvmet_tcp_free_crypto", (void *)&klpe_nvmet_tcp_free_crypto,
	  "nvmet_tcp" },
};

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1216044_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_kallsyms_relocs_init();
	if (ret)
		return ret;

	ret = register_module_notifier(&module_nb);
	if (ret)
		return ret;

	rcu_read_lock_sched();
	mod = (*klpe_find_module)(LP_MODULE);
	if (!try_module_get(mod))
		mod = NULL;
	rcu_read_unlock_sched();

	if (mod) {
		ret = klp_resolve_kallsyms_relocs(klp_funcs,
						ARRAY_SIZE(klp_funcs));
	}

	if (ret)
		unregister_module_notifier(&module_nb);
	module_put(mod);

	return ret;
}

void livepatch_bsc1216044_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
