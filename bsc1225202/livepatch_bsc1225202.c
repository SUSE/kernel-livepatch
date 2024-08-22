/*
 * livepatch_bsc1225202
 *
 * Fix for CVE-2021-47378, bsc#1225202
 *
 *  Upstream commit:
 *  9817d763dbe1 ("nvme-rdma: destroy cm id before destroy qp to avoid use after free")
 *
 *  SLE12-SP5 commit:
 *  599a36a1ea13236492bcc3fa184f7cf6ee60f9ad
 *
 *  SLE15-SP2 and -SP3 commit:
 *  132f56c19c93c19b5acef0f8339b57cd4bf06c62
 *
 *  SLE15-SP4 and -SP5 commit:
 *  5768ae053f63cbe9c0d72da1313d6df0f14159cf
 *
 *  Copyright (c) 2024 SUSE
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

/* klp-ccp: from drivers/nvme/host/rdma.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <rdma/mr_pool.h>

static struct ib_pd *(*klpe___ib_alloc_pd)(struct ib_device *device, unsigned int flags,
		const char *caller);

#define klpr_ib_alloc_pd(device, flags) \
	(*klpe___ib_alloc_pd)((device), (flags), KBUILD_MODNAME)

static void (*klpe_ib_dealloc_pd)(struct ib_pd *pd);

static struct ib_cq *(*klpe___ib_alloc_cq)(struct ib_device *dev, void *private,
			    int nr_cqe, int comp_vector,
			    enum ib_poll_context poll_ctx, const char *caller);

#define klpr_ib_alloc_cq(device, priv, nr_cqe, comp_vect, poll_ctx) \
	(*klpe___ib_alloc_cq)((device), (priv), (nr_cqe), (comp_vect), (poll_ctx), KBUILD_MODNAME)

static void (*klpe_ib_free_cq)(struct ib_cq *cq);

/* klp-ccp: from include/rdma/mr_pool.h */
static int (*klpe_ib_mr_pool_init)(struct ib_qp *qp, struct list_head *list, int nr,
		enum ib_mr_type type, u32 max_num_sg);

/* klp-ccp: from drivers/nvme/host/rdma.c */
#include <linux/err.h>
#include <linux/string.h>
#include <linux/atomic.h>
#include <linux/blk-mq.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/scatterlist.h>
#include <linux/nvme.h>
#include <asm/unaligned.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>

static const char *__attribute_const__ (*klpe_rdma_event_msg)(enum rdma_cm_event_type event);

static void (*klpe_rdma_destroy_id)(struct rdma_cm_id *id);

static int (*klpe_rdma_resolve_route)(struct rdma_cm_id *id, unsigned long timeout_ms);

static int (*klpe_rdma_create_qp)(struct rdma_cm_id *id, struct ib_pd *pd,
		   struct ib_qp_init_attr *qp_init_attr);

static void (*klpe_rdma_destroy_qp)(struct rdma_cm_id *id);

static int (*klpe_rdma_connect)(struct rdma_cm_id *id, struct rdma_conn_param *conn_param);

static const char *__attribute_const__ (*klpe_rdma_reject_msg)(struct rdma_cm_id *id,
						int reason);

static const void *(*klpe_rdma_consumer_reject_data)(struct rdma_cm_id *id,
				      struct rdma_cm_event *ev, u8 *data_len);

/* klp-ccp: from drivers/nvme/host/rdma.c */
#include <linux/nvme-rdma.h>
/* klp-ccp: from drivers/nvme/host/nvme.h */
#include <linux/nvme.h>
#include <linux/cdev.h>
#include <linux/kref.h>
#include <linux/blk-mq.h>
#include <linux/rcupdate.h>

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

/* klp-ccp: from drivers/nvme/host/fabrics.h */
#include <linux/in.h>

/* klp-ccp: from drivers/nvme/host/rdma.c */
#define NVME_RDMA_CONNECT_TIMEOUT_MS	3000		/* 3 second */

#define NVME_RDMA_MAX_SEGMENTS		256

#define NVME_RDMA_MAX_INLINE_SEGMENTS	4

struct nvme_rdma_device {
	struct ib_device	*dev;
	struct ib_pd		*pd;
	struct kref		ref;
	struct list_head	entry;
	unsigned int		num_inline_segments;
};

struct nvme_rdma_qe {
	struct ib_cqe		cqe;
	void			*data;
	u64			dma;
};

enum nvme_rdma_queue_flags {
	NVME_RDMA_Q_ALLOCATED		= 0,
	NVME_RDMA_Q_LIVE		= 1,
	NVME_RDMA_Q_TR_READY		= 2,
};

struct nvme_rdma_queue {
	struct nvme_rdma_qe	*rsp_ring;
	int			queue_size;
	size_t			cmnd_capsule_len;
	struct nvme_rdma_ctrl	*ctrl;
	struct nvme_rdma_device	*device;
	struct ib_cq		*ib_cq;
	struct ib_qp		*qp;

	unsigned long		flags;
	struct rdma_cm_id	*cm_id;
	int			cm_error;
	struct completion	cm_done;
	struct mutex		queue_lock;
};

struct nvme_rdma_ctrl {
	/* read only in the hot path */
	struct nvme_rdma_queue	*queues;

	/* other member variables */
	struct blk_mq_tag_set	tag_set;
	struct work_struct	err_work;

	struct nvme_rdma_qe	async_event_sqe;

	struct delayed_work	reconnect_work;

	struct list_head	list;

	struct blk_mq_tag_set	admin_tag_set;
	struct nvme_rdma_device	*device;

	u32			max_fr_pages;

	struct sockaddr_storage addr;
	struct sockaddr_storage src_addr;

	struct nvme_ctrl	ctrl;
	bool			use_inline_data;
};

static struct list_head (*klpe_device_list);
static struct mutex (*klpe_device_list_mutex);

static bool (*klpe_register_always);

static inline int nvme_rdma_queue_idx(struct nvme_rdma_queue *queue)
{
	return queue - queue->ctrl->queues;
}

static void nvme_rdma_free_qe(struct ib_device *ibdev, struct nvme_rdma_qe *qe,
		size_t capsule_size, enum dma_data_direction dir)
{
	ib_dma_unmap_single(ibdev, qe->dma, capsule_size, dir);
	kfree(qe->data);
}

static int nvme_rdma_alloc_qe(struct ib_device *ibdev, struct nvme_rdma_qe *qe,
		size_t capsule_size, enum dma_data_direction dir)
{
	qe->data = kzalloc(capsule_size, GFP_KERNEL);
	if (!qe->data)
		return -ENOMEM;

	qe->dma = ib_dma_map_single(ibdev, qe->data, capsule_size, dir);
	if (ib_dma_mapping_error(ibdev, qe->dma)) {
		kfree(qe->data);
		qe->data = NULL;
		return -ENOMEM;
	}

	return 0;
}

static void nvme_rdma_free_ring(struct ib_device *ibdev,
		struct nvme_rdma_qe *ring, size_t ib_queue_size,
		size_t capsule_size, enum dma_data_direction dir)
{
	int i;

	for (i = 0; i < ib_queue_size; i++)
		nvme_rdma_free_qe(ibdev, &ring[i], capsule_size, dir);
	kfree(ring);
}

static struct nvme_rdma_qe *nvme_rdma_alloc_ring(struct ib_device *ibdev,
		size_t ib_queue_size, size_t capsule_size,
		enum dma_data_direction dir)
{
	struct nvme_rdma_qe *ring;
	int i;

	ring = kcalloc(ib_queue_size, sizeof(struct nvme_rdma_qe), GFP_KERNEL);
	if (!ring)
		return NULL;

	/*
	 * Bind the CQEs (post recv buffers) DMA mapping to the RDMA queue
	 * lifetime. It's safe, since any chage in the underlying RDMA device
	 * will issue error recovery and queue re-creation.
	 */
	for (i = 0; i < ib_queue_size; i++) {
		if (nvme_rdma_alloc_qe(ibdev, &ring[i], capsule_size, dir))
			goto out_free_ring;
	}

	return ring;

out_free_ring:
	nvme_rdma_free_ring(ibdev, ring, i, capsule_size, dir);
	return NULL;
}

static void (*klpe_nvme_rdma_qp_event)(struct ib_event *event, void *context);

static int klpr_nvme_rdma_create_qp(struct nvme_rdma_queue *queue, const int factor)
{
	struct nvme_rdma_device *dev = queue->device;
	struct ib_qp_init_attr init_attr;
	int ret;

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.event_handler = (*klpe_nvme_rdma_qp_event);
	/* +1 for drain */
	init_attr.cap.max_send_wr = factor * queue->queue_size + 1;
	/* +1 for drain */
	init_attr.cap.max_recv_wr = queue->queue_size + 1;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_sge = 1 + dev->num_inline_segments;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.qp_type = IB_QPT_RC;
	init_attr.send_cq = queue->ib_cq;
	init_attr.recv_cq = queue->ib_cq;

	ret = (*klpe_rdma_create_qp)(queue->cm_id, dev->pd, &init_attr);

	queue->qp = queue->cm_id->qp;
	return ret;
}

static void klpr_nvme_rdma_free_dev(struct kref *ref)
{
	struct nvme_rdma_device *ndev =
		container_of(ref, struct nvme_rdma_device, ref);

	mutex_lock(&(*klpe_device_list_mutex));
	list_del(&ndev->entry);
	mutex_unlock(&(*klpe_device_list_mutex));

	(*klpe_ib_dealloc_pd)(ndev->pd);
	kfree(ndev);
}

static void klpr_nvme_rdma_dev_put(struct nvme_rdma_device *dev)
{
	kref_put(&dev->ref, klpr_nvme_rdma_free_dev);
}

static int nvme_rdma_dev_get(struct nvme_rdma_device *dev)
{
	return kref_get_unless_zero(&dev->ref);
}

static struct nvme_rdma_device *
klpr_nvme_rdma_find_get_device(struct rdma_cm_id *cm_id)
{
	struct nvme_rdma_device *ndev;

	mutex_lock(&(*klpe_device_list_mutex));
	list_for_each_entry(ndev, &(*klpe_device_list), entry) {
		if (ndev->dev->node_guid == cm_id->device->node_guid &&
		    nvme_rdma_dev_get(ndev))
			goto out_unlock;
	}

	ndev = kzalloc(sizeof(*ndev), GFP_KERNEL);
	if (!ndev)
		goto out_err;

	ndev->dev = cm_id->device;
	kref_init(&ndev->ref);

	ndev->pd = klpr_ib_alloc_pd(ndev->dev,
		(*klpe_register_always) ? 0 : IB_PD_UNSAFE_GLOBAL_RKEY);
	if (IS_ERR(ndev->pd))
		goto out_free_dev;

	if (!(ndev->dev->attrs.device_cap_flags &
	      IB_DEVICE_MEM_MGT_EXTENSIONS)) {
		dev_err(&ndev->dev->dev,
			"Memory registrations not supported.\n");
		goto out_free_pd;
	}

	ndev->num_inline_segments = min(NVME_RDMA_MAX_INLINE_SEGMENTS,
					ndev->dev->attrs.max_send_sge - 1);
	list_add(&ndev->entry, &(*klpe_device_list));
out_unlock:
	mutex_unlock(&(*klpe_device_list_mutex));
	return ndev;

out_free_pd:
	(*klpe_ib_dealloc_pd)(ndev->pd);
out_free_dev:
	kfree(ndev);
out_err:
	mutex_unlock(&(*klpe_device_list_mutex));
	return NULL;
}

static void (*klpe_nvme_rdma_destroy_queue_ib)(struct nvme_rdma_queue *queue);

static int nvme_rdma_get_max_fr_pages(struct ib_device *ibdev)
{
	return min_t(u32, NVME_RDMA_MAX_SEGMENTS,
		     ibdev->attrs.max_fast_reg_page_list_len);
}

static int klpr_nvme_rdma_create_queue_ib(struct nvme_rdma_queue *queue)
{
	struct ib_device *ibdev;
	const int send_wr_factor = 3;			/* MR, SEND, INV */
	const int cq_factor = send_wr_factor + 1;	/* + RECV */
	int comp_vector, idx = nvme_rdma_queue_idx(queue);
	int ret;

	queue->device = klpr_nvme_rdma_find_get_device(queue->cm_id);
	if (!queue->device) {
		dev_err(queue->cm_id->device->dev.parent,
			"no client data found!\n");
		return -ECONNREFUSED;
	}
	ibdev = queue->device->dev;

	/*
	 * Spread I/O queues completion vectors according their queue index.
	 * Admin queues can always go on completion vector 0.
	 */
	comp_vector = idx == 0 ? idx : idx - 1;

	/* +1 for ib_stop_cq */
	queue->ib_cq = klpr_ib_alloc_cq(ibdev, queue,
				cq_factor * queue->queue_size + 1,
				comp_vector, IB_POLL_SOFTIRQ);
	if (IS_ERR(queue->ib_cq)) {
		ret = PTR_ERR(queue->ib_cq);
		goto out_put_dev;
	}

	ret = klpr_nvme_rdma_create_qp(queue, send_wr_factor);
	if (ret)
		goto out_destroy_ib_cq;

	queue->rsp_ring = nvme_rdma_alloc_ring(ibdev, queue->queue_size,
			sizeof(struct nvme_completion), DMA_FROM_DEVICE);
	if (!queue->rsp_ring) {
		ret = -ENOMEM;
		goto out_destroy_qp;
	}

	ret = (*klpe_ib_mr_pool_init)(queue->qp, &queue->qp->rdma_mrs,
			      queue->queue_size,
			      IB_MR_TYPE_MEM_REG,
			      nvme_rdma_get_max_fr_pages(ibdev));
	if (ret) {
		dev_err(queue->ctrl->ctrl.device,
			"failed to initialize MR pool sized %d for QID %d\n",
			queue->queue_size, idx);
		goto out_destroy_ring;
	}

	set_bit(NVME_RDMA_Q_TR_READY, &queue->flags);

	return 0;

out_destroy_ring:
	nvme_rdma_free_ring(ibdev, queue->rsp_ring, queue->queue_size,
			    sizeof(struct nvme_completion), DMA_FROM_DEVICE);
out_destroy_qp:
	(*klpe_rdma_destroy_qp)(queue->cm_id);
out_destroy_ib_cq:
	(*klpe_ib_free_cq)(queue->ib_cq);
out_put_dev:
	klpr_nvme_rdma_dev_put(queue->device);
	return ret;
}

void klpp_nvme_rdma_free_queue(struct nvme_rdma_queue *queue)
{
	if (!test_and_clear_bit(NVME_RDMA_Q_ALLOCATED, &queue->flags))
		return;

	(*klpe_rdma_destroy_id)(queue->cm_id);
	(*klpe_nvme_rdma_destroy_queue_ib)(queue);
	mutex_destroy(&queue->queue_lock);
}

static void (*klpe_nvme_rdma_error_recovery)(struct nvme_rdma_ctrl *ctrl);

static int (*klpe_nvme_rdma_post_recv)(struct nvme_rdma_queue *queue,
		struct nvme_rdma_qe *qe);

static int klpp_nvme_rdma_conn_established(struct nvme_rdma_queue *queue)
{
	int ret, i;

	for (i = 0; i < queue->queue_size; i++) {
		ret = (*klpe_nvme_rdma_post_recv)(queue, &queue->rsp_ring[i]);
		if (ret)
			return ret;
	}

	return 0;
}

static int klpr_nvme_rdma_conn_rejected(struct nvme_rdma_queue *queue,
		struct rdma_cm_event *ev)
{
	struct rdma_cm_id *cm_id = queue->cm_id;
	int status = ev->status;
	const char *rej_msg;
	const struct nvme_rdma_cm_rej *rej_data;
	u8 rej_data_len;

	rej_msg = (*klpe_rdma_reject_msg)(cm_id, status);
	rej_data = (*klpe_rdma_consumer_reject_data)(cm_id, ev, &rej_data_len);

	if (rej_data && rej_data_len >= sizeof(u16)) {
		u16 sts = le16_to_cpu(rej_data->sts);

		dev_err(queue->ctrl->ctrl.device,
		      "Connect rejected: status %d (%s) nvme status %d (%s).\n",
		      status, rej_msg, sts, nvme_rdma_cm_msg(sts));
	} else {
		dev_err(queue->ctrl->ctrl.device,
			"Connect rejected: status %d (%s).\n", status, rej_msg);
	}

	return -ECONNRESET;
}

static int klpr_nvme_rdma_addr_resolved(struct nvme_rdma_queue *queue)
{
	int ret;

	ret = klpr_nvme_rdma_create_queue_ib(queue);
	if (ret)
		return ret;

	ret = (*klpe_rdma_resolve_route)(queue->cm_id, NVME_RDMA_CONNECT_TIMEOUT_MS);
	if (ret) {
		dev_err(queue->ctrl->ctrl.device,
			"rdma_resolve_route failed (%d).\n",
			queue->cm_error);
		goto out_destroy_queue;
	}

	return 0;

out_destroy_queue:
	(*klpe_nvme_rdma_destroy_queue_ib)(queue);
	return ret;
}

static int klpp_nvme_rdma_route_resolved(struct nvme_rdma_queue *queue)
{
	struct nvme_rdma_ctrl *ctrl = queue->ctrl;
	struct rdma_conn_param param = { };
	struct nvme_rdma_cm_req priv = { };
	int ret;

	param.qp_num = queue->qp->qp_num;
	param.flow_control = 1;

	param.responder_resources = queue->device->dev->attrs.max_qp_rd_atom;
	/* maximum retry count */
	param.retry_count = 7;
	param.rnr_retry_count = 7;
	param.private_data = &priv;
	param.private_data_len = sizeof(priv);

	priv.recfmt = cpu_to_le16(NVME_RDMA_CM_FMT_1_0);
	priv.qid = cpu_to_le16(nvme_rdma_queue_idx(queue));
	/*
	 * set the admin queue depth to the minimum size
	 * specified by the Fabrics standard.
	 */
	if (priv.qid == 0) {
		priv.hrqsize = cpu_to_le16(NVME_AQ_DEPTH);
		priv.hsqsize = cpu_to_le16(NVME_AQ_DEPTH - 1);
	} else {
		/*
		 * current interpretation of the fabrics spec
		 * is at minimum you make hrqsize sqsize+1, or a
		 * 1's based representation of sqsize.
		 */
		priv.hrqsize = cpu_to_le16(queue->queue_size);
		priv.hsqsize = cpu_to_le16(queue->ctrl->ctrl.sqsize);
	}

	ret = (*klpe_rdma_connect)(queue->cm_id, &param);
	if (ret) {
		dev_err(ctrl->ctrl.device,
			"rdma_connect failed (%d).\n", ret);
		return ret;
	}

	return 0;
}

int klpp_nvme_rdma_cm_handler(struct rdma_cm_id *cm_id,
		struct rdma_cm_event *ev)
{
	struct nvme_rdma_queue *queue = cm_id->context;
	int cm_error = 0;

	dev_dbg(queue->ctrl->ctrl.device, "%s (%d): status %d id %p\n",
		(*klpe_rdma_event_msg)(ev->event), ev->event,
		ev->status, cm_id);

	switch (ev->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		cm_error = klpr_nvme_rdma_addr_resolved(queue);
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		cm_error = klpp_nvme_rdma_route_resolved(queue);
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		queue->cm_error = klpp_nvme_rdma_conn_established(queue);
		/* complete cm_done regardless of success/failure */
		complete(&queue->cm_done);
		return 0;
	case RDMA_CM_EVENT_REJECTED:
		cm_error = klpr_nvme_rdma_conn_rejected(queue, ev);
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
		(*klpe_nvme_rdma_destroy_queue_ib)(queue);
		/* fall through */
	case RDMA_CM_EVENT_ADDR_ERROR:
		dev_dbg(queue->ctrl->ctrl.device,
			"CM error event %d\n", ev->event);
		cm_error = -ECONNRESET;
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
	case RDMA_CM_EVENT_ADDR_CHANGE:
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		dev_dbg(queue->ctrl->ctrl.device,
			"disconnect received - connection closed\n");
		(*klpe_nvme_rdma_error_recovery)(queue->ctrl);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/* device removal is handled via the ib_client API */
		break;
	default:
		dev_err(queue->ctrl->ctrl.device,
			"Unexpected RDMA CM event (%d)\n", ev->event);
		(*klpe_nvme_rdma_error_recovery)(queue->ctrl);
		break;
	}

	if (cm_error) {
		queue->cm_error = cm_error;
		complete(&queue->cm_done);
	}

	return 0;
}


#include "livepatch_bsc1225202.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "nvme_rdma"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "__ib_alloc_cq", (void *)&klpe___ib_alloc_cq, "ib_core" },
	{ "__ib_alloc_pd", (void *)&klpe___ib_alloc_pd, "ib_core" },
	{ "ib_dealloc_pd", (void *)&klpe_ib_dealloc_pd, "ib_core" },
	{ "ib_free_cq", (void *)&klpe_ib_free_cq, "ib_core" },
	{ "ib_mr_pool_init", (void *)&klpe_ib_mr_pool_init, "ib_core" },
	{ "device_list", (void *)&klpe_device_list, "nvme_rdma" },
	{ "device_list_mutex", (void *)&klpe_device_list_mutex, "nvme_rdma" },
	{ "nvme_rdma_destroy_queue_ib",
	  (void *)&klpe_nvme_rdma_destroy_queue_ib, "nvme_rdma" },
	{ "nvme_rdma_error_recovery", (void *)&klpe_nvme_rdma_error_recovery,
	  "nvme_rdma" },
	{ "nvme_rdma_post_recv", (void *)&klpe_nvme_rdma_post_recv,
	  "nvme_rdma" },
	{ "nvme_rdma_qp_event", (void *)&klpe_nvme_rdma_qp_event,
	  "nvme_rdma" },
	{ "register_always", (void *)&klpe_register_always, "nvme_rdma" },
	{ "rdma_connect", (void *)&klpe_rdma_connect, "rdma_cm" },
	{ "rdma_consumer_reject_data", (void *)&klpe_rdma_consumer_reject_data,
	  "rdma_cm" },
	{ "rdma_create_qp", (void *)&klpe_rdma_create_qp, "rdma_cm" },
	{ "rdma_destroy_id", (void *)&klpe_rdma_destroy_id, "rdma_cm" },
	{ "rdma_destroy_qp", (void *)&klpe_rdma_destroy_qp, "rdma_cm" },
	{ "rdma_event_msg", (void *)&klpe_rdma_event_msg, "rdma_cm" },
	{ "rdma_reject_msg", (void *)&klpe_rdma_reject_msg, "rdma_cm" },
	{ "rdma_resolve_route", (void *)&klpe_rdma_resolve_route, "rdma_cm" },
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

int livepatch_bsc1225202_init(void)
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

void livepatch_bsc1225202_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
