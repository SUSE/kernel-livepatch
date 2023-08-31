/*
 * livepatch_bsc1210630
 *
 * Fix for CVE-2023-2176, bsc#1210630
 *
 *  Upstream commit:
 *  732d41c545bb ("RDMA/cma: Make the locking for automatic state transition more clear")
 *  305d568b72f1 ("RDMA/cma: Ensure rdma_addr_cancel() happens before issuing more requests")
 *  22e9f71072fa ("RDMA/cma: Do not change route.addr.src_addr outside state checks")
 *  8d037973d48c ("RDMA/core: Refactor rdma_bind_addr")
 *
 *  SLE12-SP5 and SLE15-SP1 commit:
 *  b3ddeabe44e439af3629f7633f5ef41e6f8c6ee7
 *  e7467515b6150debd50b4d270dfa8ad9aef5ed67
 *  8101e8619ba8b919d178f609496c554d656a99af
 *  39d68892b984f8703f2879c619ebdde9168d406a
 *
 *  SLE15-SP2 and -SP3 commit:
 *  7a43827f29f594eb8a3bf520ad1c8bae02f9078a
 *  8b6288fdf667005cb329f612c890bab9f5302307
 *  c706a03a47052565994799fa1d6bad85539e14d8
 *  58861456d744953af6cbda3ed0d3884795c0a6bf
 *
 *  SLE15-SP4 and -SP5 commit:
 *  fb2fb3e4cc3e8344f45206504660d58b642354d2
 *  68253ee5dcea8af5ee982084ba2146885bbcc5fb
 *  91ac49b1abc0ba19b4bccbf95fb4dcbd96cbd592
 *  a844601c1ef13c551f51e40a9ff8e661dc1ca0b5
 *
 *  Copyright (c) 2023 SUSE
 *  Author: Lukas Hruska <lhruska@suse.cz>
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


#if !IS_MODULE(CONFIG_INFINIBAND) || !IS_ENABLED(CONFIG_INFINIBAND_ADDR_TRANS)
#error "Live patch supports only CONFIG=m"
#endif

/* klp-ccp: from drivers/infiniband/core/cma.c */
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/igmp.h>
#include <linux/xarray.h>
#include <linux/inetdevice.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <net/route.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/ip_fib.h>
#include <rdma/rdma_cm.h>

/* klp-ccp: from include/rdma/ib_addr.h */
static int (*klpe_rdma_resolve_ip)(struct sockaddr *src_addr, const struct sockaddr *dst_addr,
		    struct rdma_dev_addr *addr, unsigned long timeout_ms,
		    void (*callback)(int status, struct sockaddr *src_addr,
				     struct rdma_dev_addr *addr, void *context),
		    bool resolve_by_gid_attr, void *context);

static void (*klpe_rdma_addr_cancel)(struct rdma_dev_addr *addr);

static int (*klpe_rdma_addr_size)(const struct sockaddr *addr);

/* klp-ccp: from include/rdma/rdma_cm.h */
struct rdma_id_private;
static int klpp_rdma_bind_addr_dst(struct rdma_id_private *id_priv,
			      struct sockaddr *addr, const struct sockaddr *daddr);

int klpp_rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr);

int klpp_rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      const struct sockaddr *dst_addr,
		      unsigned long timeout_ms);

/* klp-ccp: from drivers/infiniband/core/cma.c */
#include <rdma/rdma_netlink.h>
#include <rdma/ib.h>

/* klp-ccp: from include/rdma/ib_cache.h */
static int (*klpe_rdma_query_gid)(struct ib_device *device, u32 port_num, int index,
		   union ib_gid *gid);

static int (*klpe_ib_get_cached_pkey)(struct ib_device    *device_handle,
		       u32                  port_num,
		       int                  index,
		       u16                 *pkey);

static int (*klpe_ib_find_cached_pkey)(struct ib_device    *device,
			u32                  port_num,
			u16                  pkey,
			u16                 *index);

static int (*klpe_ib_get_cached_port_state)(struct ib_device *device,
			     u32               port_num,
			      enum ib_port_state *port_active);

/* klp-ccp: from drivers/infiniband/core/cma.c */
#include <rdma/ib_sa.h>
/* klp-ccp: from drivers/infiniband/core/core_priv.h */
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/cgroup_rdma.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <rdma/ib_verbs.h>
#include <rdma/opa_addr.h>
#include <rdma/ib_mad.h>
#include <rdma/restrack.h>
/* klp-ccp: from drivers/infiniband/core/mad_priv.h */
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/workqueue.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/opa_smi.h>
/* klp-ccp: from drivers/infiniband/core/restrack.h */
#include <linux/mutex.h>

static void (*klpe_rdma_restrack_add)(struct rdma_restrack_entry *res);

/* klp-ccp: from drivers/infiniband/core/cma_priv.h */
enum rdma_cm_state {
	RDMA_CM_IDLE,
	RDMA_CM_ADDR_QUERY,
	RDMA_CM_ADDR_RESOLVED,
	RDMA_CM_ROUTE_QUERY,
	RDMA_CM_ROUTE_RESOLVED,
	RDMA_CM_CONNECT,
	RDMA_CM_DISCONNECT,
	RDMA_CM_ADDR_BOUND,
	RDMA_CM_LISTEN,
	RDMA_CM_DEVICE_REMOVAL,
	RDMA_CM_DESTROYING
};

struct rdma_id_private {
	struct rdma_cm_id	id;

	struct rdma_bind_list	*bind_list;
	struct hlist_node	node;
	union {
		struct list_head device_item; /* On cma_device->id_list */
		struct list_head listen_any_item; /* On listen_any_list */
	};
	union {
		/* On rdma_id_private->listen_list */
		struct list_head listen_item;
		struct list_head listen_list;
	};
	struct cma_device	*cma_dev;
	struct list_head	mc_list;

	int			internal_id;
	enum rdma_cm_state	state;
	spinlock_t		lock;
	struct mutex		qp_mutex;

	struct completion	comp;
	refcount_t refcount;
	struct mutex		handler_mutex;

	int			backlog;
	int			timeout_ms;
	struct ib_sa_query	*query;
	int			query_id;
	union {
		struct ib_cm_id	*ib;
		struct iw_cm_id	*iw;
	} cm_id;

	u32			seq_num;
	u32			qkey;
	u32			qp_num;
	u32			options;
	u8			srq;
	u8			tos;
	u8			tos_set:1;
	u8                      timeout_set:1;
	u8			min_rnr_timer_set:1;
	u8			reuseaddr;
	u8			afonly;
	u8			timeout;
	u8			min_rnr_timer;
	u8 used_resolve_ip;
	enum ib_gid_type	gid_type;

	/*
	 * Internal to RDMA/core, don't use in the drivers
	 */
	struct rdma_restrack_entry     res;
	struct rdma_ucm_ece ece;
};

/* klp-ccp: from drivers/infiniband/core/cma.c */
static struct list_head (*klpe_dev_list);

static struct mutex (*klpe_lock);
static struct workqueue_struct *(*klpe_cma_wq);

static
struct xarray *(*klpe_cma_pernet_xa)(struct net *net, enum rdma_ucm_port_space ps);

struct cma_device {
	struct list_head	list;
	struct ib_device	*device;
	struct completion	comp;
	refcount_t refcount;
	struct list_head	id_list;
	enum ib_gid_type	*default_gid_type;
	u8			*default_roce_tos;
};

struct rdma_bind_list {
	enum rdma_ucm_port_space ps;
	struct hlist_head	owners;
	unsigned short		port;
};

static struct rdma_bind_list *klpr_cma_ps_find(struct net *net,
					  enum rdma_ucm_port_space ps, int snum)
{
	struct xarray *xa = (*klpe_cma_pernet_xa)(net, ps);

	return xa_load(xa, snum);
}

enum {
	CMA_OPTION_AFONLY,
};

struct cma_work {
	struct work_struct	work;
	struct rdma_id_private	*id;
	enum rdma_cm_state	old_state;
	enum rdma_cm_state	new_state;
	struct rdma_cm_event	event;
};

static int (*klpe_cma_comp_exch)(struct rdma_id_private *id_priv,
			 enum rdma_cm_state comp, enum rdma_cm_state exch);

static void (*klpe_cma_attach_to_dev)(struct rdma_id_private *id_priv,
			      struct cma_device *cma_dev);

static void (*klpe_cma_release_dev)(struct rdma_id_private *id_priv);

static inline struct sockaddr *cma_src_addr(struct rdma_id_private *id_priv)
{
	return (struct sockaddr *) &id_priv->id.route.addr.src_addr;
}

static inline struct sockaddr *cma_dst_addr(struct rdma_id_private *id_priv)
{
	return (struct sockaddr *) &id_priv->id.route.addr.dst_addr;
}

static inline unsigned short cma_family(struct rdma_id_private *id_priv)
{
	return id_priv->id.route.addr.src_addr.ss_family;
}

static void cma_translate_ib(struct sockaddr_ib *sib, struct rdma_dev_addr *dev_addr)
{
	dev_addr->dev_type = ARPHRD_INFINIBAND;
	rdma_addr_set_sgid(dev_addr, (union ib_gid *) &sib->sib_addr);
	ib_addr_set_pkey(dev_addr, ntohs(sib->sib_pkey));
}

static int (*klpe_cma_translate_addr)(struct sockaddr *addr, struct rdma_dev_addr *dev_addr);

static int (*klpe_cma_acquire_dev_by_src_ip)(struct rdma_id_private *id_priv);

static int klpr_cma_resolve_ib_dev(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev, *cur_dev;
	struct sockaddr_ib *addr;
	union ib_gid gid, sgid, *dgid;
	unsigned int p;
	u16 pkey, index;
	enum ib_port_state port_state;
	int ret;
	int i;

	cma_dev = NULL;
	addr = (struct sockaddr_ib *) cma_dst_addr(id_priv);
	dgid = (union ib_gid *) &addr->sib_addr;
	pkey = ntohs(addr->sib_pkey);

	mutex_lock(&(*klpe_lock));
	list_for_each_entry(cur_dev, &(*klpe_dev_list), list) {
		rdma_for_each_port (cur_dev->device, p) {
			if (!rdma_cap_af_ib(cur_dev->device, p))
				continue;

			if ((*klpe_ib_find_cached_pkey)(cur_dev->device, p, pkey, &index))
				continue;

			if ((*klpe_ib_get_cached_port_state)(cur_dev->device, p, &port_state))
				continue;

			for (i = 0; i < cur_dev->device->port_data[p].immutable.gid_tbl_len;
			     ++i) {
				ret = (*klpe_rdma_query_gid)(cur_dev->device, p, i,
						     &gid);
				if (ret)
					continue;

				if (!memcmp(&gid, dgid, sizeof(gid))) {
					cma_dev = cur_dev;
					sgid = gid;
					id_priv->id.port_num = p;
					goto found;
				}

				if (!cma_dev && (gid.global.subnet_prefix ==
				    dgid->global.subnet_prefix) &&
				    port_state == IB_PORT_ACTIVE) {
					cma_dev = cur_dev;
					sgid = gid;
					id_priv->id.port_num = p;
					goto found;
				}
			}
		}
	}
	mutex_unlock(&(*klpe_lock));
	return -ENODEV;

found:
	(*klpe_cma_attach_to_dev)(id_priv, cma_dev);
	(*klpe_rdma_restrack_add)(&id_priv->res);
	mutex_unlock(&(*klpe_lock));
	addr = (struct sockaddr_ib *)cma_src_addr(id_priv);
	memcpy(&addr->sib_addr, &sgid, sizeof(sgid));
	cma_translate_ib(addr, &id_priv->id.route.addr.dev_addr);
	return 0;
}

static void cma_id_get(struct rdma_id_private *id_priv)
{
	refcount_inc(&id_priv->refcount);
}

static inline bool cma_zero_addr(const struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return ipv4_is_zeronet(((struct sockaddr_in *)addr)->sin_addr.s_addr);
	case AF_INET6:
		return ipv6_addr_any(&((struct sockaddr_in6 *)addr)->sin6_addr);
	case AF_IB:
		return ib_addr_any(&((struct sockaddr_ib *)addr)->sib_addr);
	default:
		return false;
	}
}

static inline bool cma_loopback_addr(const struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return ipv4_is_loopback(
			((struct sockaddr_in *)addr)->sin_addr.s_addr);
	case AF_INET6:
		return ipv6_addr_loopback(
			&((struct sockaddr_in6 *)addr)->sin6_addr);
	case AF_IB:
		return ib_addr_loopback(
			&((struct sockaddr_ib *)addr)->sib_addr);
	default:
		return false;
	}
}

static inline bool cma_any_addr(const struct sockaddr *addr)
{
	return cma_zero_addr(addr) || cma_loopback_addr(addr);
}

static int (*klpe_cma_addr_cmp)(const struct sockaddr *src, const struct sockaddr *dst);

static __be16 cma_port(const struct sockaddr *addr)
{
	struct sockaddr_ib *sib;

	switch (addr->sa_family) {
	case AF_INET:
		return ((struct sockaddr_in *) addr)->sin_port;
	case AF_INET6:
		return ((struct sockaddr_in6 *) addr)->sin6_port;
	case AF_IB:
		sib = (struct sockaddr_ib *) addr;
		return htons((u16) (be64_to_cpu(sib->sib_sid) &
				    be64_to_cpu(sib->sib_sid_mask)));
	default:
		return 0;
	}
}

static inline int cma_any_port(const struct sockaddr *addr)
{
	return !cma_port(addr);
}

static void (*klpe_cma_work_handler)(struct work_struct *_work);

static void klpr_enqueue_resolve_addr_work(struct cma_work *work,
				      struct rdma_id_private *id_priv)
{
	/* Balances with cma_id_put() in cma_work_handler */
	cma_id_get(id_priv);

	work->id = id_priv;
	INIT_WORK(&work->work, (*klpe_cma_work_handler));
	work->old_state = RDMA_CM_ADDR_QUERY;
	work->new_state = RDMA_CM_ADDR_RESOLVED;
	work->event.event = RDMA_CM_EVENT_ADDR_RESOLVED;

	queue_work((*klpe_cma_wq), &work->work);
}

static void cma_set_loopback(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		((struct sockaddr_in *) addr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		break;
	case AF_INET6:
		ipv6_addr_set(&((struct sockaddr_in6 *) addr)->sin6_addr,
			      0, 0, 0, htonl(1));
		break;
	default:
		ib_addr_set(&((struct sockaddr_ib *) addr)->sib_addr,
			    0, 0, 0, htonl(1));
		break;
	}
}

static int klpr_cma_bind_loopback(struct rdma_id_private *id_priv)
{
	struct cma_device *cma_dev, *cur_dev;
	union ib_gid gid;
	enum ib_port_state port_state;
	unsigned int p;
	u16 pkey;
	int ret;

	cma_dev = NULL;
	mutex_lock(&(*klpe_lock));
	list_for_each_entry(cur_dev, &(*klpe_dev_list), list) {
		if (cma_family(id_priv) == AF_IB &&
		    !rdma_cap_ib_cm(cur_dev->device, 1))
			continue;

		if (!cma_dev)
			cma_dev = cur_dev;

		rdma_for_each_port (cur_dev->device, p) {
			if (!(*klpe_ib_get_cached_port_state)(cur_dev->device, p, &port_state) &&
			    port_state == IB_PORT_ACTIVE) {
				cma_dev = cur_dev;
				goto port_found;
			}
		}
	}

	if (!cma_dev) {
		ret = -ENODEV;
		goto out;
	}

	p = 1;

port_found:
	ret = (*klpe_rdma_query_gid)(cma_dev->device, p, 0, &gid);
	if (ret)
		goto out;

	ret = (*klpe_ib_get_cached_pkey)(cma_dev->device, p, 0, &pkey);
	if (ret)
		goto out;

	id_priv->id.route.addr.dev_addr.dev_type =
		(rdma_protocol_ib(cma_dev->device, p)) ?
		ARPHRD_INFINIBAND : ARPHRD_ETHER;

	rdma_addr_set_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	ib_addr_set_pkey(&id_priv->id.route.addr.dev_addr, pkey);
	id_priv->id.port_num = p;
	(*klpe_cma_attach_to_dev)(id_priv, cma_dev);
	(*klpe_rdma_restrack_add)(&id_priv->res);
	cma_set_loopback(cma_src_addr(id_priv));
out:
	mutex_unlock(&(*klpe_lock));
	return ret;
}

static void (*klpe_addr_handler)(int status, struct sockaddr *src_addr,
			 struct rdma_dev_addr *dev_addr, void *context);

static int klpr_cma_resolve_loopback(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	union ib_gid gid;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	if (!id_priv->cma_dev) {
		ret = klpr_cma_bind_loopback(id_priv);
		if (ret)
			goto err;
	}

	rdma_addr_get_sgid(&id_priv->id.route.addr.dev_addr, &gid);
	rdma_addr_set_dgid(&id_priv->id.route.addr.dev_addr, &gid);

	klpr_enqueue_resolve_addr_work(work, id_priv);
	return 0;
err:
	kfree(work);
	return ret;
}

static int klpr_cma_resolve_ib_addr(struct rdma_id_private *id_priv)
{
	struct cma_work *work;
	int ret;

	work = kzalloc(sizeof *work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	if (!id_priv->cma_dev) {
		ret = klpr_cma_resolve_ib_dev(id_priv);
		if (ret)
			goto err;
	}

	rdma_addr_set_dgid(&id_priv->id.route.addr.dev_addr, (union ib_gid *)
		&(((struct sockaddr_ib *) &id_priv->id.route.addr.dst_addr)->sib_addr));

	klpr_enqueue_resolve_addr_work(work, id_priv);
	return 0;
err:
	kfree(work);
	return ret;
}

static int klpp_cma_bind_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
			 const struct sockaddr *dst_addr)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	struct sockaddr_storage zero_sock = {};

	if (src_addr && src_addr->sa_family)
		return klpp_rdma_bind_addr_dst(id_priv, src_addr, dst_addr);

	/*
	 * When the src_addr is not specified, automatically supply an any addr
	 */
	zero_sock.ss_family = dst_addr->sa_family;
	if (IS_ENABLED(CONFIG_IPV6) && dst_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *src_addr6 =
			(struct sockaddr_in6 *)&zero_sock;
		struct sockaddr_in6 *dst_addr6 =
			(struct sockaddr_in6 *)dst_addr;

		src_addr6->sin6_scope_id = dst_addr6->sin6_scope_id;
		if (ipv6_addr_type(&dst_addr6->sin6_addr) & IPV6_ADDR_LINKLOCAL)
			id->route.addr.dev_addr.bound_dev_if =
				dst_addr6->sin6_scope_id;
	} else if (dst_addr->sa_family == AF_IB) {
		((struct sockaddr_ib *)&zero_sock)->sib_pkey =
			((struct sockaddr_ib *)dst_addr)->sib_pkey;
	}
	return klpp_rdma_bind_addr_dst(id_priv, (struct sockaddr *)&zero_sock, dst_addr);
}

static int klpp_resolve_prepare_src(struct rdma_id_private *id_priv,
			       struct sockaddr *src_addr,
			       const struct sockaddr *dst_addr)
{
	int ret;

	if (!(*klpe_cma_comp_exch)(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_ADDR_QUERY)) {
		/* For a well behaved ULP state will be RDMA_CM_IDLE */
		ret = klpp_cma_bind_addr(&id_priv->id, src_addr, dst_addr);
		if (ret)
			return ret;
		if (WARN_ON(!(*klpe_cma_comp_exch)(id_priv, RDMA_CM_ADDR_BOUND,
					   RDMA_CM_ADDR_QUERY)))
			return -EINVAL;
	}

	if (cma_family(id_priv) != dst_addr->sa_family) {
		ret = -EINVAL;
		goto err_state;
	}
	return 0;

err_state:
	(*klpe_cma_comp_exch)(id_priv, RDMA_CM_ADDR_QUERY, RDMA_CM_ADDR_BOUND);
	return ret;
}

int klpp_rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      const struct sockaddr *dst_addr, unsigned long timeout_ms)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);
	int ret;

	ret = klpp_resolve_prepare_src(id_priv, src_addr, dst_addr);
	if (ret)
		return ret;

	if (cma_any_addr(dst_addr)) {
		ret = klpr_cma_resolve_loopback(id_priv);
	} else {
		if (dst_addr->sa_family == AF_IB) {
			ret = klpr_cma_resolve_ib_addr(id_priv);
		} else {
			/*
			 * The FSM can return back to RDMA_CM_ADDR_BOUND after
			 * rdma_resolve_ip() is called, eg through the error
			 * path in addr_handler(). If this happens the existing
			 * request must be canceled before issuing a new one.
			 * Since canceling a request is a bit slow and this
			 * oddball path is rare, keep track once a request has
			 * been issued. The track turns out to be a permanent
			 * state since this is the only cancel as it is
			 * immediately before rdma_resolve_ip().
			 */
			if (id_priv->used_resolve_ip)
				(*klpe_rdma_addr_cancel)(&id->route.addr.dev_addr);
			else
				id_priv->used_resolve_ip = 1;
			ret = (*klpe_rdma_resolve_ip)(cma_src_addr(id_priv), dst_addr,
					      &id->route.addr.dev_addr,
					      timeout_ms, (*klpe_addr_handler),
					      false, id_priv);
		}
	}
	if (ret)
		goto err;

	return 0;
err:
	(*klpe_cma_comp_exch)(id_priv, RDMA_CM_ADDR_QUERY, RDMA_CM_ADDR_BOUND);
	return ret;
}

int klpp_rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr)
{
	struct rdma_id_private *id_priv =
		container_of(id, struct rdma_id_private, id);

	return klpp_rdma_bind_addr_dst(id_priv, addr, cma_dst_addr(id_priv));
}

static void (*klpe_cma_bind_port)(struct rdma_bind_list *bind_list,
			  struct rdma_id_private *id_priv);

static int (*klpe_cma_alloc_port)(enum rdma_ucm_port_space ps,
			  struct rdma_id_private *id_priv, unsigned short snum);

static int klpr_cma_port_is_unique(struct rdma_bind_list *bind_list,
			      struct rdma_id_private *id_priv)
{
	struct rdma_id_private *cur_id;
	struct sockaddr  *daddr = cma_dst_addr(id_priv);
	struct sockaddr  *saddr = cma_src_addr(id_priv);
	__be16 dport = cma_port(daddr);

	lockdep_assert_held(&(*klpe_lock));

	hlist_for_each_entry(cur_id, &bind_list->owners, node) {
		struct sockaddr  *cur_daddr = cma_dst_addr(cur_id);
		struct sockaddr  *cur_saddr = cma_src_addr(cur_id);
		__be16 cur_dport = cma_port(cur_daddr);

		if (id_priv == cur_id)
			continue;

		/* different dest port -> unique */
		if (!cma_any_port(daddr) &&
		    !cma_any_port(cur_daddr) &&
		    (dport != cur_dport))
			continue;

		/* different src address -> unique */
		if (!cma_any_addr(saddr) &&
		    !cma_any_addr(cur_saddr) &&
		    (*klpe_cma_addr_cmp)(saddr, cur_saddr))
			continue;

		/* different dst address -> unique */
		if (!cma_any_addr(daddr) &&
		    !cma_any_addr(cur_daddr) &&
		    (*klpe_cma_addr_cmp)(daddr, cur_daddr))
			continue;

		return -EADDRNOTAVAIL;
	}
	return 0;
}

static unsigned int (*klpe_cma_alloc_any_port_last_used_port);

static int klpr_cma_alloc_any_port(enum rdma_ucm_port_space ps,
			      struct rdma_id_private *id_priv)
{
	int low, high, remaining;
	unsigned int rover;
	struct net *net = id_priv->id.route.addr.dev_addr.net;

	lockdep_assert_held(&(*klpe_lock));

	inet_get_local_port_range(net, &low, &high);
	remaining = (high - low) + 1;
	rover = prandom_u32() % remaining + low;
retry:
	if (*klpe_cma_alloc_any_port_last_used_port != rover) {
		struct rdma_bind_list *bind_list;
		int ret;

		bind_list = klpr_cma_ps_find(net, ps, (unsigned short)rover);

		if (!bind_list) {
			ret = (*klpe_cma_alloc_port)(ps, id_priv, rover);
		} else {
			ret = klpr_cma_port_is_unique(bind_list, id_priv);
			if (!ret)
				(*klpe_cma_bind_port)(bind_list, id_priv);
		}
		/*
		 * Remember previously used port number in order to avoid
		 * re-using same port immediately after it is closed.
		 */
		if (!ret)
			*klpe_cma_alloc_any_port_last_used_port = rover;
		if (ret != -EADDRNOTAVAIL)
			return ret;
	}
	if (--remaining) {
		rover++;
		if ((rover < low) || (rover > high))
			rover = low;
		goto retry;
	}
	return -EADDRNOTAVAIL;
}

static int klpr_cma_check_port(struct rdma_bind_list *bind_list,
			  struct rdma_id_private *id_priv, uint8_t reuseaddr)
{
	struct rdma_id_private *cur_id;
	struct sockaddr *addr, *cur_addr;

	lockdep_assert_held(&(*klpe_lock));

	addr = cma_src_addr(id_priv);
	hlist_for_each_entry(cur_id, &bind_list->owners, node) {
		if (id_priv == cur_id)
			continue;

		if (reuseaddr && cur_id->reuseaddr)
			continue;

		cur_addr = cma_src_addr(cur_id);
		if (id_priv->afonly && cur_id->afonly &&
		    (addr->sa_family != cur_addr->sa_family))
			continue;

		if (cma_any_addr(addr) || cma_any_addr(cur_addr))
			return -EADDRNOTAVAIL;

		if (!(*klpe_cma_addr_cmp)(addr, cur_addr))
			return -EADDRINUSE;
	}
	return 0;
}

static int klpr_cma_use_port(enum rdma_ucm_port_space ps,
			struct rdma_id_private *id_priv)
{
	struct rdma_bind_list *bind_list;
	unsigned short snum;
	int ret;

	lockdep_assert_held(&(*klpe_lock));

	snum = ntohs(cma_port(cma_src_addr(id_priv)));
	if (snum < PROT_SOCK && !capable(CAP_NET_BIND_SERVICE))
		return -EACCES;

	bind_list = klpr_cma_ps_find(id_priv->id.route.addr.dev_addr.net, ps, snum);
	if (!bind_list) {
		ret = (*klpe_cma_alloc_port)(ps, id_priv, snum);
	} else {
		ret = klpr_cma_check_port(bind_list, id_priv, id_priv->reuseaddr);
		if (!ret)
			(*klpe_cma_bind_port)(bind_list, id_priv);
	}
	return ret;
}

static enum rdma_ucm_port_space
cma_select_inet_ps(struct rdma_id_private *id_priv)
{
	switch (id_priv->id.ps) {
	case RDMA_PS_TCP:
	case RDMA_PS_UDP:
	case RDMA_PS_IPOIB:
	case RDMA_PS_IB:
		return id_priv->id.ps;
	default:

		return 0;
	}
}

static enum rdma_ucm_port_space
cma_select_ib_ps(struct rdma_id_private *id_priv)
{
	enum rdma_ucm_port_space ps = 0;
	struct sockaddr_ib *sib;
	u64 sid_ps, mask, sid;

	sib = (struct sockaddr_ib *) cma_src_addr(id_priv);
	mask = be64_to_cpu(sib->sib_sid_mask) & RDMA_IB_IP_PS_MASK;
	sid = be64_to_cpu(sib->sib_sid) & mask;

	if ((id_priv->id.ps == RDMA_PS_IB) && (sid == (RDMA_IB_IP_PS_IB & mask))) {
		sid_ps = RDMA_IB_IP_PS_IB;
		ps = RDMA_PS_IB;
	} else if (((id_priv->id.ps == RDMA_PS_IB) || (id_priv->id.ps == RDMA_PS_TCP)) &&
		   (sid == (RDMA_IB_IP_PS_TCP & mask))) {
		sid_ps = RDMA_IB_IP_PS_TCP;
		ps = RDMA_PS_TCP;
	} else if (((id_priv->id.ps == RDMA_PS_IB) || (id_priv->id.ps == RDMA_PS_UDP)) &&
		   (sid == (RDMA_IB_IP_PS_UDP & mask))) {
		sid_ps = RDMA_IB_IP_PS_UDP;
		ps = RDMA_PS_UDP;
	}

	if (ps) {
		sib->sib_sid = cpu_to_be64(sid_ps | ntohs(cma_port((struct sockaddr *) sib)));
		sib->sib_sid_mask = cpu_to_be64(RDMA_IB_IP_PS_MASK |
						be64_to_cpu(sib->sib_sid_mask));
	}
	return ps;
}

static int klpr_cma_get_port(struct rdma_id_private *id_priv)
{
	enum rdma_ucm_port_space ps;
	int ret;

	if (cma_family(id_priv) != AF_IB)
		ps = cma_select_inet_ps(id_priv);
	else
		ps = cma_select_ib_ps(id_priv);
	if (!ps)
		return -EPROTONOSUPPORT;

	mutex_lock(&(*klpe_lock));
	if (cma_any_port(cma_src_addr(id_priv)))
		ret = klpr_cma_alloc_any_port(ps, id_priv);
	else
		ret = klpr_cma_use_port(ps, id_priv);
	mutex_unlock(&(*klpe_lock));

	return ret;
}

static int cma_check_linklocal(struct rdma_dev_addr *dev_addr,
			       struct sockaddr *addr)
{
	struct sockaddr_in6 *sin6;

	if (addr->sa_family != AF_INET6)
		return 0;

	sin6 = (struct sockaddr_in6 *) addr;

	if (!(ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL))
		return 0;

	if (!sin6->sin6_scope_id)
			return -EINVAL;

	dev_addr->bound_dev_if = sin6->sin6_scope_id;
	return 0;
}

static int klpp_rdma_bind_addr_dst(struct rdma_id_private *id_priv,
			      struct sockaddr *addr, const struct sockaddr *daddr)
{
	struct sockaddr *id_daddr;
	int ret;

	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6 &&
	    addr->sa_family != AF_IB)
		return -EAFNOSUPPORT;

	if (!(*klpe_cma_comp_exch)(id_priv, RDMA_CM_IDLE, RDMA_CM_ADDR_BOUND))
		return -EINVAL;

	ret = cma_check_linklocal(&id_priv->id.route.addr.dev_addr, addr);
	if (ret)
		goto err1;

	memcpy(cma_src_addr(id_priv), addr, (*klpe_rdma_addr_size)(addr));
	if (!cma_any_addr(addr)) {
		ret = (*klpe_cma_translate_addr)(addr, &id_priv->id.route.addr.dev_addr);
		if (ret)
			goto err1;

		ret = (*klpe_cma_acquire_dev_by_src_ip)(id_priv);
		if (ret)
			goto err1;
	}

	if (!(id_priv->options & (1 << CMA_OPTION_AFONLY))) {
		if (addr->sa_family == AF_INET)
			id_priv->afonly = 1;
		else if (addr->sa_family == AF_INET6) {
			struct net *net = id_priv->id.route.addr.dev_addr.net;

			id_priv->afonly = net->ipv6.sysctl.bindv6only;
		}
	}
	id_daddr = cma_dst_addr(id_priv);
	if (daddr != id_daddr)
		memcpy(id_daddr, daddr, (*klpe_rdma_addr_size)(addr));
	id_daddr->sa_family = addr->sa_family;

	ret = klpr_cma_get_port(id_priv);
	if (ret)
		goto err2;

	if (!cma_any_addr(addr))
		(*klpe_rdma_restrack_add)(&id_priv->res);
	return 0;
err2:
	if (id_priv->cma_dev)
		(*klpe_cma_release_dev)(id_priv);
err1:
	(*klpe_cma_comp_exch)(id_priv, RDMA_CM_ADDR_BOUND, RDMA_CM_IDLE);
	return ret;
}


#include "livepatch_bsc1210630.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <generated/utsrelease.h>
#include "../kallsyms_relocs.h"

#define LP_MODULE "rdma_cm"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ NULL, (void *)&klpe_cma_alloc_any_port_last_used_port, "rdma_cm" },
	{ "ib_find_cached_pkey", (void *)&klpe_ib_find_cached_pkey,
	  "ib_core" },
	{ "ib_get_cached_pkey", (void *)&klpe_ib_get_cached_pkey, "ib_core" },
	{ "ib_get_cached_port_state", (void *)&klpe_ib_get_cached_port_state,
	  "ib_core" },
	{ "rdma_addr_cancel", (void *)&klpe_rdma_addr_cancel, "ib_core" },
	{ "rdma_addr_size", (void *)&klpe_rdma_addr_size, "ib_core" },
	{ "rdma_query_gid", (void *)&klpe_rdma_query_gid, "ib_core" },
	{ "rdma_resolve_ip", (void *)&klpe_rdma_resolve_ip, "ib_core" },
	{ "rdma_restrack_add", (void *)&klpe_rdma_restrack_add, "ib_core" },
	{ "addr_handler", (void *)&klpe_addr_handler, "rdma_cm" },
	{ "cma_acquire_dev_by_src_ip", (void *)&klpe_cma_acquire_dev_by_src_ip,
	  "rdma_cm" },
	{ "cma_addr_cmp", (void *)&klpe_cma_addr_cmp, "rdma_cm" },
	{ "cma_alloc_port", (void *)&klpe_cma_alloc_port, "rdma_cm" },
	{ "cma_attach_to_dev", (void *)&klpe_cma_attach_to_dev, "rdma_cm" },
	{ "cma_bind_port", (void *)&klpe_cma_bind_port, "rdma_cm" },
	{ "cma_comp_exch", (void *)&klpe_cma_comp_exch, "rdma_cm" },
	{ "cma_pernet_xa", (void *)&klpe_cma_pernet_xa, "rdma_cm" },
	{ "cma_release_dev", (void *)&klpe_cma_release_dev, "rdma_cm" },
	{ "cma_translate_addr", (void *)&klpe_cma_translate_addr, "rdma_cm" },
	{ "cma_work_handler", (void *)&klpe_cma_work_handler, "rdma_cm" },
	{ "cma_wq", (void *)&klpe_cma_wq, "rdma_cm" },
	{ "dev_list", (void *)&klpe_dev_list, "rdma_cm" },
	{ "lock", (void *)&klpe_lock, "rdma_cm" },
};

static int klp_resolve_last_used_port(void)
{

#if IS_ENABLED(CONFIG_X86_64)

	if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.11-default")) { /* 15.4u1 */
		klp_funcs[0].symname = "last_used_port.91375";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.18-default")) { /* 15.4u2 */
		klp_funcs[0].symname = "last_used_port.91391";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.21-default")) { /* 15.4u3 */
		klp_funcs[0].symname = "last_used_port.91400";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.28-default")) { /* 15.4u4 */
		klp_funcs[0].symname = "last_used_port.91402";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.33-default")) { /* 15.4u5 */
		klp_funcs[0].symname = "last_used_port.91408";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.38-default")) { /* 15.4u6 */
		klp_funcs[0].symname = "last_used_port.91413";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.41-default")) { /* 15.4u7 */
		klp_funcs[0].symname = "last_used_port.91436";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.46-default")) { /* 15.4u8 */
		klp_funcs[0].symname = "last_used_port.91437";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.55-default")) { /* 15.4u10 */
		klp_funcs[0].symname = "last_used_port.91469";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.60-default")) { /* 15.4u11 */
		klp_funcs[0].symname = "last_used_port.91510";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150500.53-default")) { /* 15.5u0 */
		klp_funcs[0].symname = "last_used_port.90376";
	}

#elif IS_ENABLED(CONFIG_PPC64)

	if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.11-default")) { /* 15.4u1 */
		klp_funcs[0].symname = "last_used_port.92415";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.18-default")) { /* 15.4u2 */
		klp_funcs[0].symname = "last_used_port.92431";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.21-default")) { /* 15.4u3 */
		klp_funcs[0].symname = "last_used_port.92436";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.28-default")) { /* 15.4u4 */
		klp_funcs[0].symname = "last_used_port.92436";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.33-default")) { /* 15.4u5 */
		klp_funcs[0].symname = "last_used_port.92443";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.38-default")) { /* 15.4u6 */
		klp_funcs[0].symname = "last_used_port.92447";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.41-default")) { /* 15.4u7 */
		klp_funcs[0].symname = "last_used_port.92470";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.46-default")) { /* 15.4u8 */
		klp_funcs[0].symname = "last_used_port.92472";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.55-default")) { /* 15.4u10 */
		klp_funcs[0].symname = "last_used_port.92504";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.60-default")) { /* 15.4u11 */
		klp_funcs[0].symname = "last_used_port.92428";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150500.53-default")) { /* 15.5u0 */
		klp_funcs[0].symname = "last_used_port.91887";
	}

#elif IS_ENABLED(CONFIG_S390)

	if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.11-default")) { /* 15.4u1 */
		klp_funcs[0].symname = "last_used_port.88566";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.18-default")) { /* 15.4u2 */
		klp_funcs[0].symname = "last_used_port.88582";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.21-default")) { /* 15.4u3 */
		klp_funcs[0].symname = "last_used_port.88591";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.28-default")) { /* 15.4u4 */
		klp_funcs[0].symname = "last_used_port.88591";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.33-default")) { /* 15.4u5 */
		klp_funcs[0].symname = "last_used_port.88597";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.38-default")) { /* 15.4u6 */
		klp_funcs[0].symname = "last_used_port.88605";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.41-default")) { /* 15.4u7 */
		klp_funcs[0].symname = "last_used_port.88628";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.46-default")) { /* 15.4u8 */
		klp_funcs[0].symname = "last_used_port.88629";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.55-default")) { /* 15.4u10 */
		klp_funcs[0].symname = "last_used_port.88661";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150400.24.60-default")) { /* 15.4u11 */
		klp_funcs[0].symname = "last_used_port.88585";
	} else if(!strcmp(UTS_RELEASE, "5.14.21-150500.53-default")) { /* 15.5u0 */
		klp_funcs[0].symname = "last_used_port.87711";
	}

#else
#error "Architecture not supported by livepatch."
#endif
	else {
		WARN(1, "kernel version not supported by livepatch\n");
		return -ENOTSUPP;
	}

	return 0;
}

static int module_notify(struct notifier_block *nb,
			unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LP_MODULE))
		return 0;
	ret = klp_resolve_last_used_port();
	if (ret != 0)
		return ret;
	ret = klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));

	WARN(ret, "%s: delayed kallsyms lookup failed. System is broken and can crash.\n",
		__func__);

	return ret;
}

static struct notifier_block module_nb = {
	.notifier_call = module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1210630_init(void)
{
	int ret;
	struct module *mod;

	ret = klp_resolve_last_used_port();
	if (ret)
		return ret;

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

void livepatch_bsc1210630_cleanup(void)
{
	unregister_module_notifier(&module_nb);
}
