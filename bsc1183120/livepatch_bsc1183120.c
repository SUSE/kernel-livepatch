/*
 * livepatch_bsc1183120
 *
 * Fix for CVE-2021-27363, bsc#1183120
 *
 *  Upstream commit:
 *  688e8128b7a9 ("scsi: iscsi: Restrict sessions and handles to admin
 *                 capabilities")
 *
 *  SLE12-SP2 and -SP3 commit:
 *  670f56951e6b77bd42bba74a9459bd07307c56ba
 *
 *  SLE12-SP4, SLE12-SP5, SLE15 and SLE15-SP1 commit:
 *  f14c2105dc0b71323c4410fe64c15475d3bb12c5
 *
 *  SLE15-SP2 commit:
 *  826d5cf3adffd826b98978db640a16045e668914
 *
 *
 *  Copyright (c) 2021 SUSE
 *  Author: Nicolai Stange <nstange@suse.de>
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

#if !IS_MODULE(CONFIG_SCSI_ISCSI_ATTRS)
#error "Live patch supports only CONFIG_SCSI_ISCSI_ATTRS=m"
#endif

/* klp-ccp: from drivers/scsi/scsi_transport_iscsi.c */
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/bsg-lib.h>
#include <linux/idr.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

/* klp-ccp: from include/scsi/scsi_host.h */
static int (*klpe_scsi_is_host_device)(const struct device *);

static inline struct Scsi_Host *klpr_dev_to_shost(struct device *dev)
{
	while (!(*klpe_scsi_is_host_device)(dev)) {
		if (!dev->parent)
			return NULL;
		dev = dev->parent;
	}
	return container_of(dev, struct Scsi_Host, shost_gendev);
}

static int (*klpe_scsi_queue_work)(struct Scsi_Host *, struct work_struct *);

static void (*klpe_scsi_host_put)(struct Scsi_Host *t);
static struct Scsi_Host *(*klpe_scsi_host_lookup)(unsigned short);

/* klp-ccp: from drivers/scsi/scsi_transport_iscsi.c */
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_transport_iscsi.h>

/* klp-ccp: from include/scsi/scsi_transport_iscsi.h */
static struct iscsi_endpoint *(*klpe_iscsi_lookup_endpoint)(u64 handle);

static struct device *
(*klpe_iscsi_find_flashnode_conn)(struct iscsi_bus_flash_session *fnode_sess);

/* klp-ccp: from drivers/scsi/scsi_transport_iscsi.c */
#include <scsi/iscsi_if.h>

static int (*klpe_dbg_session);

static int (*klpe_dbg_conn);

#define KLPR_ISCSI_DBG_TRANS_SESSION(_session, dbg_fmt, arg...)	\
	do {								\
		if ((*klpe_dbg_session))				\
			iscsi_cls_session_printk(KERN_INFO, _session,	\
						 "%s: " dbg_fmt,	\
						 __func__, ##arg);	\
	} while (0);

#define KLPR_ISCSI_DBG_TRANS_CONN(_conn, dbg_fmt, arg...)		\
	do {								\
		if ((*klpe_dbg_conn))					\
			iscsi_cls_conn_printk(KERN_INFO, _conn,	\
					      "%s: " dbg_fmt,		\
					      __func__, ##arg);	\
	} while (0);

struct iscsi_internal {
	struct scsi_transport_template t;
	struct iscsi_transport *iscsi_transport;
	struct list_head list;
	struct device dev;

	struct transport_container conn_cont;
	struct transport_container session_cont;
};

#define dev_to_iscsi_internal(_dev) \
	container_of(_dev, struct iscsi_internal, dev)

ssize_t
klpp_show_transport_handle(struct device *dev, struct device_attribute *attr,
		      char *buf)
{
	struct iscsi_internal *priv = dev_to_iscsi_internal(dev);
	/*
	 * Fix CVE-2021-27363
	 *  +2 lines
	 */
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	return sprintf(buf, "%llu\n", (unsigned long long)iscsi_handle(priv->iscsi_transport));
}

static int (*klpe_flashnode_match_index)(struct device *dev, void *data);

static struct iscsi_bus_flash_session *
klpr_iscsi_get_flashnode_by_index(struct Scsi_Host *shost, uint32_t idx)
{
	struct iscsi_bus_flash_session *fnode_sess = NULL;
	struct device *dev;

	dev = device_find_child(&shost->shost_gendev, &idx,
				(*klpe_flashnode_match_index));
	if (dev)
		fnode_sess = iscsi_dev_to_flash_session(dev);

	return fnode_sess;
}

static struct iscsi_cls_session *(*klpe_iscsi_session_lookup)(uint32_t sid);

static struct iscsi_cls_conn *(*klpe_iscsi_conn_lookup)(uint32_t sid, uint32_t cid);

static struct iscsi_internal *
(*klpe_iscsi_if_transport_lookup)(struct iscsi_transport *tt);

static int
(*klpe_iscsi_multicast_skb)(struct sk_buff *skb, uint32_t group, gfp_t gfp);

static int
klpr_iscsi_if_get_stats(struct iscsi_transport *transport, struct nlmsghdr *nlh)
{
	struct iscsi_uevent *ev = nlmsg_data(nlh);
	struct iscsi_stats *stats;
	struct sk_buff *skbstat;
	struct iscsi_cls_conn *conn;
	struct nlmsghdr	*nlhstat;
	struct iscsi_uevent *evstat;
	struct iscsi_internal *priv;
	int len = nlmsg_total_size(sizeof(*ev) +
				   sizeof(struct iscsi_stats) +
				   sizeof(struct iscsi_stats_custom) *
				   ISCSI_STATS_CUSTOM_MAX);
	int err = 0;

	priv = (*klpe_iscsi_if_transport_lookup)(transport);
	if (!priv)
		return -EINVAL;

	conn = (*klpe_iscsi_conn_lookup)(ev->u.get_stats.sid, ev->u.get_stats.cid);
	if (!conn)
		return -EEXIST;

	do {
		int actual_size;

		skbstat = alloc_skb(len, GFP_ATOMIC);
		if (!skbstat) {
			iscsi_cls_conn_printk(KERN_ERR, conn, "can not "
					      "deliver stats: OOM\n");
			return -ENOMEM;
		}

		nlhstat = __nlmsg_put(skbstat, 0, 0, 0,
				      (len - sizeof(*nlhstat)), 0);
		evstat = nlmsg_data(nlhstat);
		memset(evstat, 0, sizeof(*evstat));
		evstat->transport_handle = iscsi_handle(conn->transport);
		evstat->type = nlh->nlmsg_type;
		evstat->u.get_stats.cid =
			ev->u.get_stats.cid;
		evstat->u.get_stats.sid =
			ev->u.get_stats.sid;
		stats = (struct iscsi_stats *)
			((char*)evstat + sizeof(*evstat));
		memset(stats, 0, sizeof(*stats));

		transport->get_stats(conn, stats);
		actual_size = nlmsg_total_size(sizeof(struct iscsi_uevent) +
					       sizeof(struct iscsi_stats) +
					       sizeof(struct iscsi_stats_custom) *
					       stats->custom_length);
		actual_size -= sizeof(*nlhstat);
		actual_size = nlmsg_msg_size(actual_size);
		skb_trim(skbstat, NLMSG_ALIGN(actual_size));
		nlhstat->nlmsg_len = actual_size;

		err = (*klpe_iscsi_multicast_skb)(skbstat, ISCSI_NL_GRP_ISCSID,
					  GFP_ATOMIC);
	} while (err < 0 && err != -ECONNREFUSED);

	return err;
}

static int
klpr_iscsi_if_create_session(struct iscsi_internal *priv, struct iscsi_endpoint *ep,
			struct iscsi_uevent *ev, pid_t pid,
			uint32_t initial_cmdsn,	uint16_t cmds_max,
			uint16_t queue_depth)
{
	struct iscsi_transport *transport = priv->iscsi_transport;
	struct iscsi_cls_session *session;
	struct Scsi_Host *shost;

	session = transport->create_session(ep, cmds_max, queue_depth,
					    initial_cmdsn);
	if (!session)
		return -ENOMEM;

	session->creator = pid;
	shost = klpr_dev_to_shost(session->dev.parent);
	ev->r.c_session_ret.host_no = shost->host_no;
	ev->r.c_session_ret.sid = session->sid;
	KLPR_ISCSI_DBG_TRANS_SESSION(session,
				"Completed creating transport session\n");
	return 0;
}

static int
klpr_iscsi_if_create_conn(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_cls_conn *conn;
	struct iscsi_cls_session *session;

	session = (*klpe_iscsi_session_lookup)(ev->u.c_conn.sid);
	if (!session) {
		printk(KERN_ERR "iscsi: invalid session %d.\n",
		       ev->u.c_conn.sid);
		return -EINVAL;
	}

	conn = transport->create_conn(session, ev->u.c_conn.cid);
	if (!conn) {
		iscsi_cls_session_printk(KERN_ERR, session,
					 "couldn't create a new connection.");
		return -ENOMEM;
	}

	ev->r.c_conn_ret.sid = session->sid;
	ev->r.c_conn_ret.cid = conn->cid;

	KLPR_ISCSI_DBG_TRANS_CONN(conn, "Completed creating transport conn\n");
	return 0;
}

static int
klpr_iscsi_if_destroy_conn(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_cls_conn *conn;

	conn = (*klpe_iscsi_conn_lookup)(ev->u.d_conn.sid, ev->u.d_conn.cid);
	if (!conn)
		return -EINVAL;

	KLPR_ISCSI_DBG_TRANS_CONN(conn, "Destroying transport conn\n");
	if (transport->destroy_conn)
		transport->destroy_conn(conn);

	return 0;
}

static int
klpr_iscsi_set_param(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	char *data = (char*)ev + sizeof(*ev);
	struct iscsi_cls_conn *conn;
	struct iscsi_cls_session *session;
	int err = 0, value = 0;

	session = (*klpe_iscsi_session_lookup)(ev->u.set_param.sid);
	conn = (*klpe_iscsi_conn_lookup)(ev->u.set_param.sid, ev->u.set_param.cid);
	if (!conn || !session)
		return -EINVAL;

	switch (ev->u.set_param.param) {
	case ISCSI_PARAM_SESS_RECOVERY_TMO:
		sscanf(data, "%d", &value);
		if (!session->recovery_tmo_sysfs_override)
			session->recovery_tmo = value;
		break;
	default:
		err = transport->set_param(conn, ev->u.set_param.param,
					   data, ev->u.set_param.len);
	}

	return err;
}

static int klpr_iscsi_if_ep_connect(struct iscsi_transport *transport,
			       struct iscsi_uevent *ev, int msg_type)
{
	struct iscsi_endpoint *ep;
	struct sockaddr *dst_addr;
	struct Scsi_Host *shost = NULL;
	int non_blocking, err = 0;

	if (!transport->ep_connect)
		return -EINVAL;

	if (msg_type == ISCSI_UEVENT_TRANSPORT_EP_CONNECT_THROUGH_HOST) {
		shost = (*klpe_scsi_host_lookup)(ev->u.ep_connect_through_host.host_no);
		if (!shost) {
			printk(KERN_ERR "ep connect failed. Could not find "
			       "host no %u\n",
			       ev->u.ep_connect_through_host.host_no);
			return -ENODEV;
		}
		non_blocking = ev->u.ep_connect_through_host.non_blocking;
	} else
		non_blocking = ev->u.ep_connect.non_blocking;

	dst_addr = (struct sockaddr *)((char*)ev + sizeof(*ev));
	ep = transport->ep_connect(shost, dst_addr, non_blocking);
	if (IS_ERR(ep)) {
		err = PTR_ERR(ep);
		goto release_host;
	}

	ev->r.ep_connect_ret.handle = ep->id;
release_host:
	if (shost)
		(*klpe_scsi_host_put)(shost);
	return err;
}

static int klpr_iscsi_if_ep_disconnect(struct iscsi_transport *transport,
				  u64 ep_handle)
{
	struct iscsi_cls_conn *conn;
	struct iscsi_endpoint *ep;

	if (!transport->ep_disconnect)
		return -EINVAL;

	ep = (*klpe_iscsi_lookup_endpoint)(ep_handle);
	if (!ep)
		return -EINVAL;
	conn = ep->conn;
	if (conn) {
		mutex_lock(&conn->ep_mutex);
		conn->ep = NULL;
		mutex_unlock(&conn->ep_mutex);
	}

	transport->ep_disconnect(ep);
	return 0;
}

static int
klpr_iscsi_if_transport_ep(struct iscsi_transport *transport,
		      struct iscsi_uevent *ev, int msg_type)
{
	struct iscsi_endpoint *ep;
	int rc = 0;

	switch (msg_type) {
	case ISCSI_UEVENT_TRANSPORT_EP_CONNECT_THROUGH_HOST:
	case ISCSI_UEVENT_TRANSPORT_EP_CONNECT:
		rc = klpr_iscsi_if_ep_connect(transport, ev, msg_type);
		break;
	case ISCSI_UEVENT_TRANSPORT_EP_POLL:
		if (!transport->ep_poll)
			return -EINVAL;

		ep = (*klpe_iscsi_lookup_endpoint)(ev->u.ep_poll.ep_handle);
		if (!ep)
			return -EINVAL;

		ev->r.retcode = transport->ep_poll(ep,
						   ev->u.ep_poll.timeout_ms);
		break;
	case ISCSI_UEVENT_TRANSPORT_EP_DISCONNECT:
		rc = klpr_iscsi_if_ep_disconnect(transport,
					    ev->u.ep_disconnect.ep_handle);
		break;
	}
	return rc;
}

static int
klpr_iscsi_tgt_dscvr(struct iscsi_transport *transport,
		struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct sockaddr *dst_addr;
	int err;

	if (!transport->tgt_dscvr)
		return -EINVAL;

	shost = (*klpe_scsi_host_lookup)(ev->u.tgt_dscvr.host_no);
	if (!shost) {
		printk(KERN_ERR "target discovery could not find host no %u\n",
		       ev->u.tgt_dscvr.host_no);
		return -ENODEV;
	}


	dst_addr = (struct sockaddr *)((char*)ev + sizeof(*ev));
	err = transport->tgt_dscvr(shost, ev->u.tgt_dscvr.type,
				   ev->u.tgt_dscvr.enable, dst_addr);
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int
klpr_iscsi_set_host_param(struct iscsi_transport *transport,
		     struct iscsi_uevent *ev)
{
	char *data = (char*)ev + sizeof(*ev);
	struct Scsi_Host *shost;
	int err;

	if (!transport->set_host_param)
		return -ENOSYS;

	shost = (*klpe_scsi_host_lookup)(ev->u.set_host_param.host_no);
	if (!shost) {
		printk(KERN_ERR "set_host_param could not find host no %u\n",
		       ev->u.set_host_param.host_no);
		return -ENODEV;
	}

	err = transport->set_host_param(shost, ev->u.set_host_param.param,
					data, ev->u.set_host_param.len);
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int
klpr_iscsi_set_path(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct iscsi_path *params;
	int err;

	if (!transport->set_path)
		return -ENOSYS;

	shost = (*klpe_scsi_host_lookup)(ev->u.set_path.host_no);
	if (!shost) {
		printk(KERN_ERR "set path could not find host no %u\n",
		       ev->u.set_path.host_no);
		return -ENODEV;
	}

	params = (struct iscsi_path *)((char *)ev + sizeof(*ev));
	err = transport->set_path(shost, params);

	(*klpe_scsi_host_put)(shost);
	return err;
}

static int
klpr_iscsi_set_iface_params(struct iscsi_transport *transport,
		       struct iscsi_uevent *ev, uint32_t len)
{
	char *data = (char *)ev + sizeof(*ev);
	struct Scsi_Host *shost;
	int err;

	if (!transport->set_iface_param)
		return -ENOSYS;

	shost = (*klpe_scsi_host_lookup)(ev->u.set_iface_params.host_no);
	if (!shost) {
		printk(KERN_ERR "set_iface_params could not find host no %u\n",
		       ev->u.set_iface_params.host_no);
		return -ENODEV;
	}

	err = transport->set_iface_param(shost, data, len);
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int
klpr_iscsi_send_ping(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct sockaddr *dst_addr;
	int err;

	if (!transport->send_ping)
		return -ENOSYS;

	shost = (*klpe_scsi_host_lookup)(ev->u.iscsi_ping.host_no);
	if (!shost) {
		printk(KERN_ERR "iscsi_ping could not find host no %u\n",
		       ev->u.iscsi_ping.host_no);
		return -ENODEV;
	}

	dst_addr = (struct sockaddr *)((char *)ev + sizeof(*ev));
	err = transport->send_ping(shost, ev->u.iscsi_ping.iface_num,
				   ev->u.iscsi_ping.iface_type,
				   ev->u.iscsi_ping.payload_size,
				   ev->u.iscsi_ping.pid,
				   dst_addr);
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int
klpr_iscsi_get_chap(struct iscsi_transport *transport, struct nlmsghdr *nlh)
{
	struct iscsi_uevent *ev = nlmsg_data(nlh);
	struct Scsi_Host *shost = NULL;
	struct iscsi_chap_rec *chap_rec;
	struct iscsi_internal *priv;
	struct sk_buff *skbchap;
	struct nlmsghdr *nlhchap;
	struct iscsi_uevent *evchap;
	uint32_t chap_buf_size;
	int len, err = 0;
	char *buf;

	if (!transport->get_chap)
		return -EINVAL;

	priv = (*klpe_iscsi_if_transport_lookup)(transport);
	if (!priv)
		return -EINVAL;

	chap_buf_size = (ev->u.get_chap.num_entries * sizeof(*chap_rec));
	len = nlmsg_total_size(sizeof(*ev) + chap_buf_size);

	shost = (*klpe_scsi_host_lookup)(ev->u.get_chap.host_no);
	if (!shost) {
		printk(KERN_ERR "%s: failed. Could not find host no %u\n",
		       __func__, ev->u.get_chap.host_no);
		return -ENODEV;
	}

	do {
		int actual_size;

		skbchap = alloc_skb(len, GFP_KERNEL);
		if (!skbchap) {
			printk(KERN_ERR "can not deliver chap: OOM\n");
			err = -ENOMEM;
			goto exit_get_chap;
		}

		nlhchap = __nlmsg_put(skbchap, 0, 0, 0,
				      (len - sizeof(*nlhchap)), 0);
		evchap = nlmsg_data(nlhchap);
		memset(evchap, 0, sizeof(*evchap));
		evchap->transport_handle = iscsi_handle(transport);
		evchap->type = nlh->nlmsg_type;
		evchap->u.get_chap.host_no = ev->u.get_chap.host_no;
		evchap->u.get_chap.chap_tbl_idx = ev->u.get_chap.chap_tbl_idx;
		evchap->u.get_chap.num_entries = ev->u.get_chap.num_entries;
		buf = (char *)evchap + sizeof(*evchap);
		memset(buf, 0, chap_buf_size);

		err = transport->get_chap(shost, ev->u.get_chap.chap_tbl_idx,
				    &evchap->u.get_chap.num_entries, buf);

		actual_size = nlmsg_total_size(sizeof(*ev) + chap_buf_size);
		skb_trim(skbchap, NLMSG_ALIGN(actual_size));
		nlhchap->nlmsg_len = actual_size;

		err = (*klpe_iscsi_multicast_skb)(skbchap, ISCSI_NL_GRP_ISCSID,
					  GFP_KERNEL);
	} while (err < 0 && err != -ECONNREFUSED);

exit_get_chap:
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int klpr_iscsi_set_chap(struct iscsi_transport *transport,
			  struct iscsi_uevent *ev, uint32_t len)
{
	char *data = (char *)ev + sizeof(*ev);
	struct Scsi_Host *shost;
	int err = 0;

	if (!transport->set_chap)
		return -ENOSYS;

	shost = (*klpe_scsi_host_lookup)(ev->u.set_path.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.set_path.host_no);
		return -ENODEV;
	}

	err = transport->set_chap(shost, data, len);
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int klpr_iscsi_delete_chap(struct iscsi_transport *transport,
			     struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	int err = 0;

	if (!transport->delete_chap)
		return -ENOSYS;

	shost = (*klpe_scsi_host_lookup)(ev->u.delete_chap.host_no);
	if (!shost) {
		printk(KERN_ERR "%s could not find host no %u\n",
		       __func__, ev->u.delete_chap.host_no);
		return -ENODEV;
	}

	err = transport->delete_chap(shost, ev->u.delete_chap.chap_tbl_idx);
	(*klpe_scsi_host_put)(shost);
	return err;
}

static int klpr_iscsi_set_flashnode_param(struct iscsi_transport *transport,
				     struct iscsi_uevent *ev, uint32_t len)
{
	char *data = (char *)ev + sizeof(*ev);
	struct Scsi_Host *shost;
	struct iscsi_bus_flash_session *fnode_sess;
	struct iscsi_bus_flash_conn *fnode_conn;
	struct device *dev;
	uint32_t idx;
	int err = 0;

	if (!transport->set_flashnode_param) {
		err = -ENOSYS;
		goto exit_set_fnode;
	}

	shost = (*klpe_scsi_host_lookup)(ev->u.set_flashnode.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.set_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	idx = ev->u.set_flashnode.flashnode_idx;
	fnode_sess = klpr_iscsi_get_flashnode_by_index(shost, idx);
	if (!fnode_sess) {
		pr_err("%s could not find flashnode %u for host no %u\n",
		       __func__, idx, ev->u.set_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	dev = (*klpe_iscsi_find_flashnode_conn)(fnode_sess);
	if (!dev) {
		err = -ENODEV;
		goto put_sess;
	}

	fnode_conn = iscsi_dev_to_flash_conn(dev);
	err = transport->set_flashnode_param(fnode_sess, fnode_conn, data, len);
	put_device(dev);

put_sess:
	put_device(&fnode_sess->dev);

put_host:
	(*klpe_scsi_host_put)(shost);

exit_set_fnode:
	return err;
}

static int klpr_iscsi_new_flashnode(struct iscsi_transport *transport,
			       struct iscsi_uevent *ev, uint32_t len)
{
	char *data = (char *)ev + sizeof(*ev);
	struct Scsi_Host *shost;
	int index;
	int err = 0;

	if (!transport->new_flashnode) {
		err = -ENOSYS;
		goto exit_new_fnode;
	}

	shost = (*klpe_scsi_host_lookup)(ev->u.new_flashnode.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.new_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	index = transport->new_flashnode(shost, data, len);

	if (index >= 0)
		ev->r.new_flashnode_ret.flashnode_idx = index;
	else
		err = -EIO;

put_host:
	(*klpe_scsi_host_put)(shost);

exit_new_fnode:
	return err;
}

static int klpr_iscsi_del_flashnode(struct iscsi_transport *transport,
			       struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct iscsi_bus_flash_session *fnode_sess;
	uint32_t idx;
	int err = 0;

	if (!transport->del_flashnode) {
		err = -ENOSYS;
		goto exit_del_fnode;
	}

	shost = (*klpe_scsi_host_lookup)(ev->u.del_flashnode.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.del_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	idx = ev->u.del_flashnode.flashnode_idx;
	fnode_sess = klpr_iscsi_get_flashnode_by_index(shost, idx);
	if (!fnode_sess) {
		pr_err("%s could not find flashnode %u for host no %u\n",
		       __func__, idx, ev->u.del_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	err = transport->del_flashnode(fnode_sess);
	put_device(&fnode_sess->dev);

put_host:
	(*klpe_scsi_host_put)(shost);

exit_del_fnode:
	return err;
}

static int klpr_iscsi_login_flashnode(struct iscsi_transport *transport,
				 struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct iscsi_bus_flash_session *fnode_sess;
	struct iscsi_bus_flash_conn *fnode_conn;
	struct device *dev;
	uint32_t idx;
	int err = 0;

	if (!transport->login_flashnode) {
		err = -ENOSYS;
		goto exit_login_fnode;
	}

	shost = (*klpe_scsi_host_lookup)(ev->u.login_flashnode.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.login_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	idx = ev->u.login_flashnode.flashnode_idx;
	fnode_sess = klpr_iscsi_get_flashnode_by_index(shost, idx);
	if (!fnode_sess) {
		pr_err("%s could not find flashnode %u for host no %u\n",
		       __func__, idx, ev->u.login_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	dev = (*klpe_iscsi_find_flashnode_conn)(fnode_sess);
	if (!dev) {
		err = -ENODEV;
		goto put_sess;
	}

	fnode_conn = iscsi_dev_to_flash_conn(dev);
	err = transport->login_flashnode(fnode_sess, fnode_conn);
	put_device(dev);

put_sess:
	put_device(&fnode_sess->dev);

put_host:
	(*klpe_scsi_host_put)(shost);

exit_login_fnode:
	return err;
}

static int klpr_iscsi_logout_flashnode(struct iscsi_transport *transport,
				  struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct iscsi_bus_flash_session *fnode_sess;
	struct iscsi_bus_flash_conn *fnode_conn;
	struct device *dev;
	uint32_t idx;
	int err = 0;

	if (!transport->logout_flashnode) {
		err = -ENOSYS;
		goto exit_logout_fnode;
	}

	shost = (*klpe_scsi_host_lookup)(ev->u.logout_flashnode.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.logout_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	idx = ev->u.logout_flashnode.flashnode_idx;
	fnode_sess = klpr_iscsi_get_flashnode_by_index(shost, idx);
	if (!fnode_sess) {
		pr_err("%s could not find flashnode %u for host no %u\n",
		       __func__, idx, ev->u.logout_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	dev = (*klpe_iscsi_find_flashnode_conn)(fnode_sess);
	if (!dev) {
		err = -ENODEV;
		goto put_sess;
	}

	fnode_conn = iscsi_dev_to_flash_conn(dev);

	err = transport->logout_flashnode(fnode_sess, fnode_conn);
	put_device(dev);

put_sess:
	put_device(&fnode_sess->dev);

put_host:
	(*klpe_scsi_host_put)(shost);

exit_logout_fnode:
	return err;
}

static int klpr_iscsi_logout_flashnode_sid(struct iscsi_transport *transport,
				      struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct iscsi_cls_session *session;
	int err = 0;

	if (!transport->logout_flashnode_sid) {
		err = -ENOSYS;
		goto exit_logout_sid;
	}

	shost = (*klpe_scsi_host_lookup)(ev->u.logout_flashnode_sid.host_no);
	if (!shost) {
		pr_err("%s could not find host no %u\n",
		       __func__, ev->u.logout_flashnode.host_no);
		err = -ENODEV;
		goto put_host;
	}

	session = (*klpe_iscsi_session_lookup)(ev->u.logout_flashnode_sid.sid);
	if (!session) {
		pr_err("%s could not find session id %u\n",
		       __func__, ev->u.logout_flashnode_sid.sid);
		err = -EINVAL;
		goto put_host;
	}

	err = transport->logout_flashnode_sid(session);

put_host:
	(*klpe_scsi_host_put)(shost);

exit_logout_sid:
	return err;
}

static int
klpr_iscsi_get_host_stats(struct iscsi_transport *transport, struct nlmsghdr *nlh)
{
	struct iscsi_uevent *ev = nlmsg_data(nlh);
	struct Scsi_Host *shost = NULL;
	struct iscsi_internal *priv;
	struct sk_buff *skbhost_stats;
	struct nlmsghdr *nlhhost_stats;
	struct iscsi_uevent *evhost_stats;
	int host_stats_size = 0;
	int len, err = 0;
	char *buf;

	if (!transport->get_host_stats)
		return -ENOSYS;

	priv = (*klpe_iscsi_if_transport_lookup)(transport);
	if (!priv)
		return -EINVAL;

	host_stats_size = sizeof(struct iscsi_offload_host_stats);
	len = nlmsg_total_size(sizeof(*ev) + host_stats_size);

	shost = (*klpe_scsi_host_lookup)(ev->u.get_host_stats.host_no);
	if (!shost) {
		pr_err("%s: failed. Could not find host no %u\n",
		       __func__, ev->u.get_host_stats.host_no);
		return -ENODEV;
	}

	do {
		int actual_size;

		skbhost_stats = alloc_skb(len, GFP_KERNEL);
		if (!skbhost_stats) {
			pr_err("cannot deliver host stats: OOM\n");
			err = -ENOMEM;
			goto exit_host_stats;
		}

		nlhhost_stats = __nlmsg_put(skbhost_stats, 0, 0, 0,
				      (len - sizeof(*nlhhost_stats)), 0);
		evhost_stats = nlmsg_data(nlhhost_stats);
		memset(evhost_stats, 0, sizeof(*evhost_stats));
		evhost_stats->transport_handle = iscsi_handle(transport);
		evhost_stats->type = nlh->nlmsg_type;
		evhost_stats->u.get_host_stats.host_no =
					ev->u.get_host_stats.host_no;
		buf = (char *)evhost_stats + sizeof(*evhost_stats);
		memset(buf, 0, host_stats_size);

		err = transport->get_host_stats(shost, buf, host_stats_size);
		if (err) {
			kfree_skb(skbhost_stats);
			goto exit_host_stats;
		}

		actual_size = nlmsg_total_size(sizeof(*ev) + host_stats_size);
		skb_trim(skbhost_stats, NLMSG_ALIGN(actual_size));
		nlhhost_stats->nlmsg_len = actual_size;

		err = (*klpe_iscsi_multicast_skb)(skbhost_stats, ISCSI_NL_GRP_ISCSID,
					  GFP_KERNEL);
	} while (err < 0 && err != -ECONNREFUSED);

exit_host_stats:
	(*klpe_scsi_host_put)(shost);
	return err;
}

int
klpp_iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh, uint32_t *group)
{
	int err = 0;
	u32 portid;
	struct iscsi_uevent *ev = nlmsg_data(nlh);
	struct iscsi_transport *transport = NULL;
	struct iscsi_internal *priv;
	struct iscsi_cls_session *session;
	struct iscsi_cls_conn *conn;
	struct iscsi_endpoint *ep = NULL;

	/*
	 * Fix CVE-2021-27363
	 *  +3 lines
	 */
	if (!netlink_capable(skb, CAP_SYS_ADMIN))
		return -EPERM;

	if (nlh->nlmsg_type == ISCSI_UEVENT_PATH_UPDATE)
		*group = ISCSI_NL_GRP_UIP;
	else
		*group = ISCSI_NL_GRP_ISCSID;

	priv = (*klpe_iscsi_if_transport_lookup)(iscsi_ptr(ev->transport_handle));
	if (!priv)
		return -EINVAL;
	transport = priv->iscsi_transport;

	if (!try_module_get(transport->owner))
		return -EINVAL;

	portid = NETLINK_CB(skb).portid;

	switch (nlh->nlmsg_type) {
	case ISCSI_UEVENT_CREATE_SESSION:
		err = klpr_iscsi_if_create_session(priv, ep, ev,
					      portid,
					      ev->u.c_session.initial_cmdsn,
					      ev->u.c_session.cmds_max,
					      ev->u.c_session.queue_depth);
		break;
	case ISCSI_UEVENT_CREATE_BOUND_SESSION:
		ep = (*klpe_iscsi_lookup_endpoint)(ev->u.c_bound_session.ep_handle);
		if (!ep) {
			err = -EINVAL;
			break;
		}

		err = klpr_iscsi_if_create_session(priv, ep, ev,
					portid,
					ev->u.c_bound_session.initial_cmdsn,
					ev->u.c_bound_session.cmds_max,
					ev->u.c_bound_session.queue_depth);
		break;
	case ISCSI_UEVENT_DESTROY_SESSION:
		session = (*klpe_iscsi_session_lookup)(ev->u.d_session.sid);
		if (session)
			transport->destroy_session(session);
		else
			err = -EINVAL;
		break;
	case ISCSI_UEVENT_UNBIND_SESSION:
		session = (*klpe_iscsi_session_lookup)(ev->u.d_session.sid);
		if (session)
			(*klpe_scsi_queue_work)(klpr_dev_to_shost(session->dev.parent),
					&session->unbind_work);
		else
			err = -EINVAL;
		break;
	case ISCSI_UEVENT_CREATE_CONN:
		err = klpr_iscsi_if_create_conn(transport, ev);
		break;
	case ISCSI_UEVENT_DESTROY_CONN:
		err = klpr_iscsi_if_destroy_conn(transport, ev);
		break;
	case ISCSI_UEVENT_BIND_CONN:
		session = (*klpe_iscsi_session_lookup)(ev->u.b_conn.sid);
		conn = (*klpe_iscsi_conn_lookup)(ev->u.b_conn.sid, ev->u.b_conn.cid);

		if (conn && conn->ep)
			klpr_iscsi_if_ep_disconnect(transport, conn->ep->id);

		if (!session || !conn) {
			err = -EINVAL;
			break;
		}

		ev->r.retcode =	transport->bind_conn(session, conn,
						ev->u.b_conn.transport_eph,
						ev->u.b_conn.is_leading);
		if (ev->r.retcode || !transport->ep_connect)
			break;

		ep = (*klpe_iscsi_lookup_endpoint)(ev->u.b_conn.transport_eph);
		if (ep) {
			ep->conn = conn;

			mutex_lock(&conn->ep_mutex);
			conn->ep = ep;
			mutex_unlock(&conn->ep_mutex);
		} else
			iscsi_cls_conn_printk(KERN_ERR, conn,
					      "Could not set ep conn "
					      "binding\n");
		break;
	case ISCSI_UEVENT_SET_PARAM:
		err = klpr_iscsi_set_param(transport, ev);
		break;
	case ISCSI_UEVENT_START_CONN:
		conn = (*klpe_iscsi_conn_lookup)(ev->u.start_conn.sid, ev->u.start_conn.cid);
		if (conn)
			ev->r.retcode = transport->start_conn(conn);
		else
			err = -EINVAL;
		break;
	case ISCSI_UEVENT_STOP_CONN:
		conn = (*klpe_iscsi_conn_lookup)(ev->u.stop_conn.sid, ev->u.stop_conn.cid);
		if (conn)
			transport->stop_conn(conn, ev->u.stop_conn.flag);
		else
			err = -EINVAL;
		break;
	case ISCSI_UEVENT_SEND_PDU:
		conn = (*klpe_iscsi_conn_lookup)(ev->u.send_pdu.sid, ev->u.send_pdu.cid);
		if (conn)
			ev->r.retcode =	transport->send_pdu(conn,
				(struct iscsi_hdr*)((char*)ev + sizeof(*ev)),
				(char*)ev + sizeof(*ev) + ev->u.send_pdu.hdr_size,
				ev->u.send_pdu.data_size);
		else
			err = -EINVAL;
		break;
	case ISCSI_UEVENT_GET_STATS:
		err = klpr_iscsi_if_get_stats(transport, nlh);
		break;
	case ISCSI_UEVENT_TRANSPORT_EP_CONNECT:
	case ISCSI_UEVENT_TRANSPORT_EP_POLL:
	case ISCSI_UEVENT_TRANSPORT_EP_DISCONNECT:
	case ISCSI_UEVENT_TRANSPORT_EP_CONNECT_THROUGH_HOST:
		err = klpr_iscsi_if_transport_ep(transport, ev, nlh->nlmsg_type);
		break;
	case ISCSI_UEVENT_TGT_DSCVR:
		err = klpr_iscsi_tgt_dscvr(transport, ev);
		break;
	case ISCSI_UEVENT_SET_HOST_PARAM:
		err = klpr_iscsi_set_host_param(transport, ev);
		break;
	case ISCSI_UEVENT_PATH_UPDATE:
		err = klpr_iscsi_set_path(transport, ev);
		break;
	case ISCSI_UEVENT_SET_IFACE_PARAMS:
		err = klpr_iscsi_set_iface_params(transport, ev,
					     nlmsg_attrlen(nlh, sizeof(*ev)));
		break;
	case ISCSI_UEVENT_PING:
		err = klpr_iscsi_send_ping(transport, ev);
		break;
	case ISCSI_UEVENT_GET_CHAP:
		err = klpr_iscsi_get_chap(transport, nlh);
		break;
	case ISCSI_UEVENT_DELETE_CHAP:
		err = klpr_iscsi_delete_chap(transport, ev);
		break;
	case ISCSI_UEVENT_SET_FLASHNODE_PARAMS:
		err = klpr_iscsi_set_flashnode_param(transport, ev,
						nlmsg_attrlen(nlh,
							      sizeof(*ev)));
		break;
	case ISCSI_UEVENT_NEW_FLASHNODE:
		err = klpr_iscsi_new_flashnode(transport, ev,
					  nlmsg_attrlen(nlh, sizeof(*ev)));
		break;
	case ISCSI_UEVENT_DEL_FLASHNODE:
		err = klpr_iscsi_del_flashnode(transport, ev);
		break;
	case ISCSI_UEVENT_LOGIN_FLASHNODE:
		err = klpr_iscsi_login_flashnode(transport, ev);
		break;
	case ISCSI_UEVENT_LOGOUT_FLASHNODE:
		err = klpr_iscsi_logout_flashnode(transport, ev);
		break;
	case ISCSI_UEVENT_LOGOUT_FLASHNODE_SID:
		err = klpr_iscsi_logout_flashnode_sid(transport, ev);
		break;
	case ISCSI_UEVENT_SET_CHAP:
		err = klpr_iscsi_set_chap(transport, ev,
				     nlmsg_attrlen(nlh, sizeof(*ev)));
		break;
	case ISCSI_UEVENT_GET_HOST_STATS:
		err = klpr_iscsi_get_host_stats(transport, nlh);
		break;
	default:
		err = -ENOSYS;
		break;
	}

	module_put(transport->owner);
	return err;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1183120.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "scsi_transport_iscsi"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "dbg_session", (void *)&klpe_dbg_session, "scsi_transport_iscsi" },
	{ "dbg_conn", (void *)&klpe_dbg_conn, "scsi_transport_iscsi" },
	{ "scsi_is_host_device", (void *)&klpe_scsi_is_host_device,
	  "scsi_mod" },
	{ "scsi_queue_work", (void *)&klpe_scsi_queue_work, "scsi_mod" },
	{ "scsi_host_put", (void *)&klpe_scsi_host_put, "scsi_mod" },
	{ "scsi_host_lookup", (void *)&klpe_scsi_host_lookup, "scsi_mod" },
	{ "iscsi_lookup_endpoint", (void *)&klpe_iscsi_lookup_endpoint,
	  "scsi_transport_iscsi" },
	{ "iscsi_find_flashnode_conn", (void *)&klpe_iscsi_find_flashnode_conn,
	  "scsi_transport_iscsi" },
	{ "flashnode_match_index", (void *)&klpe_flashnode_match_index,
	  "scsi_transport_iscsi" },
	{ "iscsi_session_lookup", (void *)&klpe_iscsi_session_lookup,
	  "scsi_transport_iscsi" },
	{ "iscsi_conn_lookup", (void *)&klpe_iscsi_conn_lookup,
	  "scsi_transport_iscsi" },
	{ "iscsi_if_transport_lookup", (void *)&klpe_iscsi_if_transport_lookup,
	  "scsi_transport_iscsi" },
	{ "iscsi_multicast_skb", (void *)&klpe_iscsi_multicast_skb,
	  "scsi_transport_iscsi" },

};

static int livepatch_bsc1183120_module_notify(struct notifier_block *nb,
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

static struct notifier_block livepatch_bsc1183120_module_nb = {
	.notifier_call = livepatch_bsc1183120_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1183120_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1183120_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1183120_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1183120_module_nb);
}
