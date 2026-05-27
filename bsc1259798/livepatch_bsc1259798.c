/*
 * livepatch_bsc1259798
 *
 * Fix for CVE-2026-23243, bsc#1259798
 *
 *  Copyright (c) 2026 SUSE
 *  Author: Lidong Zhong <lidong.zhong@suse.com>
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

#if IS_ENABLED(CONFIG_INFINIBAND_USER_MAD)

#if !IS_MODULE(CONFIG_INFINIBAND_USER_MAD)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/infiniband/core/user_mad.c */
#define pr_fmt(fmt) "user_mad: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/dma-mapping.h>
#include <linux/poll.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/compat.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#include <linux/uaccess.h>

#include <rdma/ib_mad.h>

/* klp-ccp: not from file */
#undef IB_MAD_H
/* klp-ccp: from include/rdma/ib_mad.h */
#if !defined(IB_MAD_H)
#define IB_MAD_H

/* klp-ccp: not from file */
#undef IB_VERBS_H
/* klp-ccp: from include/rdma/ib_verbs.h */
#if !defined(IB_VERBS_H)
#define IB_VERBS_H

static struct ib_ah *(*klpe_rdma_create_user_ah)(struct ib_pd *pd,
				  struct rdma_ah_attr *ah_attr,
				  struct ib_udata *udata);

static int (*klpe_rdma_destroy_ah)(struct ib_ah *ah);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* IB_VERBS_H */

/* klp-ccp: from include/rdma/ib_mad.h */
static int (*klpe_ib_response_mad)(const struct ib_mad_hdr *hdr);

static int (*klpe_ib_post_send_mad)(struct ib_mad_send_buf *send_buf,
		     struct ib_mad_send_buf **bad_send_buf);

static struct ib_mad_send_buf *(*klpe_ib_create_send_mad)(struct ib_mad_agent *mad_agent,
					   u32 remote_qpn, u16 pkey_index,
					   int rmpp_active,
					   int hdr_len, int data_len,
					   gfp_t gfp_mask,
					   u8 base_version);

static int (*klpe_ib_is_mad_class_rmpp)(u8 mgmt_class);

static int (*klpe_ib_get_mad_data_offset)(u8 mgmt_class);

static void *(*klpe_ib_get_rmpp_segment)(struct ib_mad_send_buf *send_buf, int seg_num);

static void (*klpe_ib_free_send_mad)(struct ib_mad_send_buf *send_buf);

static int (*klpe_ib_mad_kernel_rmpp_agent)(const struct ib_mad_agent *agent);

#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif /* IB_MAD_H */
/* klp-ccp: from drivers/infiniband/core/user_mad.c */
#include <rdma/ib_user_mad.h>

/* klp-ccp: from drivers/infiniband/core/core_priv.h */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cgroup_rdma.h>

#include <rdma/ib_verbs.h>

/* klp-ccp: from include/rdma/opa_smi.h */
#define OPA_SMI_H

/* klp-ccp: from include/rdma/ib_smi.h */
#define IB_SMI_H

/* klp-ccp: from drivers/infiniband/core/core_priv.h */
#include <rdma/ib_mad.h>
#include <rdma/restrack.h>

/* klp-ccp: from drivers/infiniband/core/mad_priv.h */
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/workqueue.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/opa_smi.h>

/* klp-ccp: from drivers/infiniband/core/core_priv.h */
#define RDMA_MAX_PORTS 8192

/* klp-ccp: from drivers/infiniband/core/user_mad.c */
enum {
	IB_UMAD_MAX_PORTS  = RDMA_MAX_PORTS,
	IB_UMAD_MAX_AGENTS = 32,

	IB_UMAD_MAJOR      = 231,
	IB_UMAD_MINOR_BASE = 0,
	IB_UMAD_NUM_FIXED_MINOR = 64,
	IB_UMAD_NUM_DYNAMIC_MINOR = IB_UMAD_MAX_PORTS - IB_UMAD_NUM_FIXED_MINOR,
	IB_ISSM_MINOR_BASE        = IB_UMAD_NUM_FIXED_MINOR,
};

struct ib_umad_port {
	struct cdev           cdev;
	struct device	      dev;
	struct cdev           sm_cdev;
	struct device	      sm_dev;
	struct semaphore       sm_sem;

	struct mutex	       file_mutex;
	struct list_head       file_list;

	struct ib_device      *ib_dev;
	struct ib_umad_device *umad_dev;
	int                    dev_num;
	u8                     port_num;
};

struct ib_umad_file {
	struct mutex		mutex;
	struct ib_umad_port    *port;
	struct list_head	recv_list;
	atomic_t		recv_list_size;
	struct list_head	send_list;
	struct list_head	port_list;
	spinlock_t		send_lock;
	wait_queue_head_t	recv_wait;
	struct ib_mad_agent    *agent[IB_UMAD_MAX_AGENTS];
	int			agents_dead;
	u8			use_pkey_index;
	u8			already_used;
};

struct ib_umad_packet {
	struct ib_mad_send_buf *msg;
	struct ib_mad_recv_wc  *recv_wc;
	struct list_head   list;
	int		   length;
	struct ib_user_mad mad;
};

static int hdr_size(struct ib_umad_file *file)
{
	return file->use_pkey_index ? sizeof (struct ib_user_mad_hdr) :
		sizeof (struct ib_user_mad_hdr_old);
}

static struct ib_mad_agent *__get_agent(struct ib_umad_file *file, int id)
{
	return file->agents_dead ? NULL : file->agent[id];
}

static void (*klpe_dequeue_send)(struct ib_umad_file *file,
			 struct ib_umad_packet *packet);

static int klpr_copy_rmpp_mad(struct ib_mad_send_buf *msg, const char __user *buf)
{
	int left, seg;

	/* Copy class specific header */
	if ((msg->hdr_len > IB_MGMT_RMPP_HDR) &&
	    copy_from_user(msg->mad + IB_MGMT_RMPP_HDR, buf + IB_MGMT_RMPP_HDR,
			   msg->hdr_len - IB_MGMT_RMPP_HDR))
		return -EFAULT;

	/* All headers are in place.  Copy data segments. */
	for (seg = 1, left = msg->data_len, buf += msg->hdr_len; left > 0;
	     seg++, left -= msg->seg_size, buf += msg->seg_size) {
		if (copy_from_user((*klpe_ib_get_rmpp_segment)(msg, seg), buf,
				   min(left, msg->seg_size)))
			return -EFAULT;
	}
	return 0;
}

static int same_destination(struct ib_user_mad_hdr *hdr1,
			    struct ib_user_mad_hdr *hdr2)
{
	if (!hdr1->grh_present && !hdr2->grh_present)
	   return (hdr1->lid == hdr2->lid);

	if (hdr1->grh_present && hdr2->grh_present)
	   return !memcmp(hdr1->gid, hdr2->gid, 16);

	return 0;
}

static int klpr_is_duplicate(struct ib_umad_file *file,
			struct ib_umad_packet *packet)
{
	struct ib_umad_packet *sent_packet;
	struct ib_mad_hdr *sent_hdr, *hdr;

	hdr = (struct ib_mad_hdr *) packet->mad.data;
	list_for_each_entry(sent_packet, &file->send_list, list) {
		sent_hdr = (struct ib_mad_hdr *) sent_packet->mad.data;

		if ((hdr->tid != sent_hdr->tid) ||
		    (hdr->mgmt_class != sent_hdr->mgmt_class))
			continue;

		/*
		 * No need to be overly clever here.  If two new operations have
		 * the same TID, reject the second as a duplicate.  This is more
		 * restrictive than required by the spec.
		 */
		if (!(*klpe_ib_response_mad)(hdr)) {
			if (!(*klpe_ib_response_mad)(sent_hdr))
				return 1;
			continue;
		} else if (!(*klpe_ib_response_mad)(sent_hdr))
			continue;

		if (same_destination(&packet->mad.hdr, &sent_packet->mad.hdr))
			return 1;
	}

	return 0;
}

ssize_t klpp_ib_umad_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *pos)
{
	struct ib_umad_file *file = filp->private_data;
	struct ib_umad_packet *packet;
	struct ib_mad_agent *agent;
	struct rdma_ah_attr ah_attr;
	struct ib_ah *ah;
	struct ib_rmpp_mad *rmpp_mad;
	__be64 *tid;
	int ret, hdr_len, copy_offset, rmpp_active;
	size_t data_len;
	u8 base_version;

	if (count < hdr_size(file) + IB_MGMT_RMPP_HDR)
		return -EINVAL;

	packet = kzalloc(sizeof *packet + IB_MGMT_RMPP_HDR, GFP_KERNEL);
	if (!packet)
		return -ENOMEM;

	if (copy_from_user(&packet->mad, buf, hdr_size(file))) {
		ret = -EFAULT;
		goto err;
	}

	if (packet->mad.hdr.id >= IB_UMAD_MAX_AGENTS) {
		ret = -EINVAL;
		goto err;
	}

	buf += hdr_size(file);

	if (copy_from_user(packet->mad.data, buf, IB_MGMT_RMPP_HDR)) {
		ret = -EFAULT;
		goto err;
	}

	mutex_lock(&file->mutex);

	agent = __get_agent(file, packet->mad.hdr.id);
	if (!agent) {
		ret = -EIO;
		goto err_up;
	}

	memset(&ah_attr, 0, sizeof ah_attr);
	ah_attr.type = rdma_ah_find_type(agent->device,
					 file->port->port_num);
	rdma_ah_set_dlid(&ah_attr, be16_to_cpu(packet->mad.hdr.lid));
	rdma_ah_set_sl(&ah_attr, packet->mad.hdr.sl);
	rdma_ah_set_path_bits(&ah_attr, packet->mad.hdr.path_bits);
	rdma_ah_set_port_num(&ah_attr, file->port->port_num);
	if (packet->mad.hdr.grh_present) {
		rdma_ah_set_grh(&ah_attr, NULL,
				be32_to_cpu(packet->mad.hdr.flow_label),
				packet->mad.hdr.gid_index,
				packet->mad.hdr.hop_limit,
				packet->mad.hdr.traffic_class);
		rdma_ah_set_dgid_raw(&ah_attr, packet->mad.hdr.gid);
	}

	ah = (*klpe_rdma_create_user_ah)(agent->qp->pd, &ah_attr, NULL);
	if (IS_ERR(ah)) {
		ret = PTR_ERR(ah);
		goto err_up;
	}

	rmpp_mad = (struct ib_rmpp_mad *) packet->mad.data;
	hdr_len = (*klpe_ib_get_mad_data_offset)(rmpp_mad->mad_hdr.mgmt_class);

	if ((*klpe_ib_is_mad_class_rmpp)(rmpp_mad->mad_hdr.mgmt_class)
	    && (*klpe_ib_mad_kernel_rmpp_agent)(agent)) {
		copy_offset = IB_MGMT_RMPP_HDR;
		rmpp_active = ib_get_rmpp_flags(&rmpp_mad->rmpp_hdr) &
						IB_MGMT_RMPP_FLAG_ACTIVE;
	} else {
		copy_offset = IB_MGMT_MAD_HDR;
		rmpp_active = 0;
	}

	base_version = ((struct ib_mad_hdr *)&packet->mad.data)->base_version;
	if (check_sub_overflow(count, (size_t)(hdr_size(file) + hdr_len), &data_len)) {
		ret = -EINVAL;
		goto err_ah;
	}
	packet->msg = (*klpe_ib_create_send_mad)(agent,
					 be32_to_cpu(packet->mad.hdr.qpn),
					 packet->mad.hdr.pkey_index, rmpp_active,
					 hdr_len, data_len, GFP_KERNEL,
					 base_version);
	if (IS_ERR(packet->msg)) {
		ret = PTR_ERR(packet->msg);
		goto err_ah;
	}

	packet->msg->ah		= ah;
	packet->msg->timeout_ms = packet->mad.hdr.timeout_ms;
	packet->msg->retries	= packet->mad.hdr.retries;
	packet->msg->context[0] = packet;

	/* Copy MAD header.  Any RMPP header is already in place. */
	memcpy(packet->msg->mad, packet->mad.data, IB_MGMT_MAD_HDR);

	if (!rmpp_active) {
		if (copy_from_user(packet->msg->mad + copy_offset,
				   buf + copy_offset,
				   hdr_len + data_len - copy_offset)) {
			ret = -EFAULT;
			goto err_msg;
		}
	} else {
		ret = klpr_copy_rmpp_mad(packet->msg, buf);
		if (ret)
			goto err_msg;
	}

	/*
	 * Set the high-order part of the transaction ID to make MADs from
	 * different agents unique, and allow routing responses back to the
	 * original requestor.
	 */
	if (!(*klpe_ib_response_mad)(packet->msg->mad)) {
		tid = &((struct ib_mad_hdr *) packet->msg->mad)->tid;
		*tid = cpu_to_be64(((u64) agent->hi_tid) << 32 |
				   (be64_to_cpup(tid) & 0xffffffff));
		rmpp_mad->mad_hdr.tid = *tid;
	}

	if (!(*klpe_ib_mad_kernel_rmpp_agent)(agent)
	   && (*klpe_ib_is_mad_class_rmpp)(rmpp_mad->mad_hdr.mgmt_class)
	   && (ib_get_rmpp_flags(&rmpp_mad->rmpp_hdr) & IB_MGMT_RMPP_FLAG_ACTIVE)) {
		spin_lock_irq(&file->send_lock);
		list_add_tail(&packet->list, &file->send_list);
		spin_unlock_irq(&file->send_lock);
	} else {
		spin_lock_irq(&file->send_lock);
		ret = klpr_is_duplicate(file, packet);
		if (!ret)
			list_add_tail(&packet->list, &file->send_list);
		spin_unlock_irq(&file->send_lock);
		if (ret) {
			ret = -EINVAL;
			goto err_msg;
		}
	}

	ret = (*klpe_ib_post_send_mad)(packet->msg, NULL);
	if (ret)
		goto err_send;

	mutex_unlock(&file->mutex);
	return count;

err_send:
	(*klpe_dequeue_send)(file, packet);
err_msg:
	(*klpe_ib_free_send_mad)(packet->msg);
err_ah:
	(*klpe_rdma_destroy_ah)(ah);
err_up:
	mutex_unlock(&file->mutex);
err:
	kfree(packet);
	return ret;
}


#include "livepatch_bsc1259798.h"

#include <linux/kernel.h>
#include <linux/module.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "ib_umad"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "dequeue_send", (void *)&klpe_dequeue_send, "ib_umad" },
	{ "ib_create_send_mad", (void *)&klpe_ib_create_send_mad, "ib_core" },
	{ "ib_free_send_mad", (void *)&klpe_ib_free_send_mad, "ib_core" },
	{ "ib_get_mad_data_offset", (void *)&klpe_ib_get_mad_data_offset,
	  "ib_core" },
	{ "ib_get_rmpp_segment", (void *)&klpe_ib_get_rmpp_segment,
	  "ib_core" },
	{ "ib_is_mad_class_rmpp", (void *)&klpe_ib_is_mad_class_rmpp,
	  "ib_core" },
	{ "ib_mad_kernel_rmpp_agent", (void *)&klpe_ib_mad_kernel_rmpp_agent,
	  "ib_core" },
	{ "ib_post_send_mad", (void *)&klpe_ib_post_send_mad, "ib_core" },
	{ "ib_response_mad", (void *)&klpe_ib_response_mad, "ib_core" },
	{ "rdma_create_user_ah", (void *)&klpe_rdma_create_user_ah,
	  "ib_core" },
	{ "rdma_destroy_ah", (void *)&klpe_rdma_destroy_ah, "ib_core" },
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

int livepatch_bsc1259798_init(void)
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

void livepatch_bsc1259798_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}

#endif /* IS_ENABLED(CONFIG_INFINIBAND_USER_MAD) */
