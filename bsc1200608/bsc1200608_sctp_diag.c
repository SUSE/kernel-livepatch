/*
 * bsc1200068_sctp_diag
 *
 * Fix for CVE-2022-20154, bsc#1200608 (net/sctp/diag.c part)
 *
 *  Copyright (c) 2022 SUSE
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

#if !IS_MODULE(CONFIG_INET_SCTP_DIAG)
#error "Live patch supports only CONFIG_INET_SCTP_DIAG=m"
#endif

/* klp-ccp: from net/sctp/sctp_diag.c */
#include <linux/module.h>
#include <linux/inet_diag.h>

/* klp-ccp: from include/linux/inet_diag.h */
static void (*klpe_inet_diag_msg_common_fill)(struct inet_diag_msg *r, struct sock *sk);

static int (*klpe_inet_diag_msg_attrs_fill)(struct sock *sk, struct sk_buff *skb,
			     struct inet_diag_msg *r, int ext,
			     struct user_namespace *user_ns, bool net_admin);

/* klp-ccp: from net/sctp/sctp_diag.c */
#include <linux/sock_diag.h>
#include <net/sctp/sctp.h>

/* klp-ccp: from include/net/sctp/sctp.h */
static int (*klpe_sctp_for_each_endpoint)(int (*cb)(struct sctp_endpoint *, void *), void *p);

/* klp-ccp: from net/sctp/sctp_diag.c */
/*
 * Fix CVE-2022-20154
 *  +1 line
 */
#include "bsc1200608_common.h"

static void (*klpe_sctp_diag_get_info)(struct sock *sk, struct inet_diag_msg *r,
			       void *info);

static void (*klpe_inet_diag_msg_sctpasoc_fill)(struct inet_diag_msg *r,
					struct sock *sk,
					struct sctp_association *asoc);

static int inet_diag_msg_sctpladdrs_fill(struct sk_buff *skb,
					 struct list_head *address_list)
{
	struct sctp_sockaddr_entry *laddr;
	int addrlen = sizeof(struct sockaddr_storage);
	int addrcnt = 0;
	struct nlattr *attr;
	void *info = NULL;

	list_for_each_entry_rcu(laddr, address_list, list)
		addrcnt++;

	attr = nla_reserve(skb, INET_DIAG_LOCALS, addrlen * addrcnt);
	if (!attr)
		return -EMSGSIZE;

	info = nla_data(attr);
	list_for_each_entry_rcu(laddr, address_list, list) {
		memcpy(info, &laddr->a, sizeof(laddr->a));
		memset(info + sizeof(laddr->a), 0, addrlen - sizeof(laddr->a));
		info += addrlen;
	}

	return 0;
}

static int inet_diag_msg_sctpaddrs_fill(struct sk_buff *skb,
					struct sctp_association *asoc)
{
	int addrlen = sizeof(struct sockaddr_storage);
	struct sctp_transport *from;
	struct nlattr *attr;
	void *info = NULL;

	attr = nla_reserve(skb, INET_DIAG_PEERS,
			   addrlen * asoc->peer.transport_count);
	if (!attr)
		return -EMSGSIZE;

	info = nla_data(attr);
	list_for_each_entry(from, &asoc->peer.transport_addr_list,
			    transports) {
		memcpy(info, &from->ipaddr, sizeof(from->ipaddr));
		memset(info + sizeof(from->ipaddr), 0,
		       addrlen - sizeof(from->ipaddr));
		info += addrlen;
	}

	return 0;
}

static int klpr_inet_sctp_diag_fill(struct sock *sk, struct sctp_association *asoc,
			       struct sk_buff *skb,
			       const struct inet_diag_req_v2 *req,
			       struct user_namespace *user_ns,
			       int portid, u32 seq, u16 nlmsg_flags,
			       const struct nlmsghdr *unlh,
			       bool net_admin)
{
	struct sctp_endpoint *ep = sctp_sk(sk)->ep;
	struct list_head *addr_list;
	struct inet_diag_msg *r;
	struct nlmsghdr  *nlh;
	int ext = req->idiag_ext;
	struct sctp_infox infox;
	void *info = NULL;

	nlh = nlmsg_put(skb, portid, seq, unlh->nlmsg_type, sizeof(*r),
			nlmsg_flags);
	if (!nlh)
		return -EMSGSIZE;

	r = nlmsg_data(nlh);
	BUG_ON(!sk_fullsock(sk));

	if (asoc) {
		(*klpe_inet_diag_msg_sctpasoc_fill)(r, sk, asoc);
	} else {
		(*klpe_inet_diag_msg_common_fill)(r, sk);
		r->idiag_state = sk->sk_state;
		r->idiag_timer = 0;
		r->idiag_retrans = 0;
	}

	if ((*klpe_inet_diag_msg_attrs_fill)(sk, skb, r, ext, user_ns, net_admin))
		goto errout;

	if (ext & (1 << (INET_DIAG_SKMEMINFO - 1))) {
		u32 mem[SK_MEMINFO_VARS];
		int amt;

		if (asoc && asoc->ep->sndbuf_policy)
			amt = asoc->sndbuf_used;
		else
			amt = sk_wmem_alloc_get(sk);
		mem[SK_MEMINFO_WMEM_ALLOC] = amt;
		if (asoc && asoc->ep->rcvbuf_policy)
			amt = atomic_read(&asoc->rmem_alloc);
		else
			amt = sk_rmem_alloc_get(sk);
		mem[SK_MEMINFO_RMEM_ALLOC] = amt;
		mem[SK_MEMINFO_RCVBUF] = sk->sk_rcvbuf;
		mem[SK_MEMINFO_SNDBUF] = sk->sk_sndbuf;
		mem[SK_MEMINFO_FWD_ALLOC] = sk->sk_forward_alloc;
		mem[SK_MEMINFO_WMEM_QUEUED] = sk->sk_wmem_queued;
		mem[SK_MEMINFO_OPTMEM] = atomic_read(&sk->sk_omem_alloc);
		mem[SK_MEMINFO_BACKLOG] = sk->sk_backlog.len;
		mem[SK_MEMINFO_DROPS] = atomic_read(&sk->sk_drops);

		if (nla_put(skb, INET_DIAG_SKMEMINFO, sizeof(mem), &mem) < 0)
			goto errout;
	}

	if (ext & (1 << (INET_DIAG_INFO - 1))) {
		struct nlattr *attr;

		attr = nla_reserve_64bit(skb, INET_DIAG_INFO,
					 sizeof(struct sctp_info),
					 INET_DIAG_PAD);
		if (!attr)
			goto errout;

		info = nla_data(attr);
	}
	infox.sctpinfo = (struct sctp_info *)info;
	infox.asoc = asoc;
	(*klpe_sctp_diag_get_info)(sk, r, &infox);

	addr_list = asoc ? &asoc->base.bind_addr.address_list
			 : &ep->base.bind_addr.address_list;
	if (inet_diag_msg_sctpladdrs_fill(skb, addr_list))
		goto errout;

	if (asoc && (ext & (1 << (INET_DIAG_CONG - 1))))
		if (nla_put_string(skb, INET_DIAG_CONG, "reno") < 0)
			goto errout;

	if (asoc && inet_diag_msg_sctpaddrs_fill(skb, asoc))
		goto errout;

	nlmsg_end(skb, nlh);
	return 0;

errout:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

struct sctp_comm_param {
	struct sk_buff *skb;
	struct netlink_callback *cb;
	const struct inet_diag_req_v2 *r;
	const struct nlmsghdr *nlh;
	bool net_admin;
};

/*
 * Fix CVE-2022-20154
 *  -1 line, +1 line
 */
static int klpp_sctp_sock_dump(struct sctp_endpoint *ep, struct sctp_transport *tsp, void *p)
{
	/*
	 * Fix CVE-2022-20154
	 *  -1 line
	 */
	struct sctp_comm_param *commp = p;
	struct sock *sk = ep->base.sk;
	struct sk_buff *skb = commp->skb;
	struct netlink_callback *cb = commp->cb;
	const struct inet_diag_req_v2 *r = commp->r;
	struct sctp_association *assoc;
	int err = 0;

	lock_sock(sk);
	/*
	 * Fix CVE-2022-20154
	 *  +2 lines
	 */
	if (ep != tsp->asoc->ep)
		goto release;
	list_for_each_entry(assoc, &ep->asocs, asocs) {
		if (cb->args[4] < cb->args[1])
			goto next;

		if (r->id.idiag_sport != htons(assoc->base.bind_addr.port) &&
		    r->id.idiag_sport)
			goto next;
		if (r->id.idiag_dport != htons(assoc->peer.port) &&
		    r->id.idiag_dport)
			goto next;

		if (!cb->args[3] &&
		    klpr_inet_sctp_diag_fill(sk, NULL, skb, r,
					sk_user_ns(NETLINK_CB(cb->skb).sk),
					NETLINK_CB(cb->skb).portid,
					cb->nlh->nlmsg_seq,
					NLM_F_MULTI, cb->nlh,
					commp->net_admin) < 0) {
			err = 1;
			goto release;
		}
		cb->args[3] = 1;

		if (klpr_inet_sctp_diag_fill(sk, assoc, skb, r,
					sk_user_ns(NETLINK_CB(cb->skb).sk),
					NETLINK_CB(cb->skb).portid,
					cb->nlh->nlmsg_seq, 0, cb->nlh,
					commp->net_admin) < 0) {
			err = 1;
			goto release;
		}
next:
		cb->args[4]++;
	}
	cb->args[1] = 0;
	cb->args[3] = 0;
	cb->args[4] = 0;
release:
	release_sock(sk);
	return err;
}

/*
 * Fix CVE-2022-20154
 *  -1 line, +1 line
 */
static int klpp_sctp_sock_filter(struct sctp_endpoint *ep, struct sctp_transport *tsp, void *p)
{
	/*
	 * Fix CVE-2022-20154
	 *  -1 line
	 */
	struct sctp_comm_param *commp = p;
	struct sock *sk = ep->base.sk;
	const struct inet_diag_req_v2 *r = commp->r;
	struct sctp_association *assoc =
		list_entry(ep->asocs.next, struct sctp_association, asocs);

	/* find the ep only once through the transports by this condition */
	if (tsp->asoc != assoc)
		return 0;

	if (r->sdiag_family != AF_UNSPEC && sk->sk_family != r->sdiag_family)
		return 0;

	return 1;
}

static int (*klpe_sctp_ep_dump)(struct sctp_endpoint *ep, void *p);

static void (*klpe_sctp_diag_get_info)(struct sock *sk, struct inet_diag_msg *r,
			       void *info);

void klpp_sctp_diag_dump(struct sk_buff *skb, struct netlink_callback *cb,
			   const struct inet_diag_req_v2 *r, struct nlattr *bc)
{
	u32 idiag_states = r->idiag_states;
	struct net *net = sock_net(skb->sk);
	struct sctp_comm_param commp = {
		.skb = skb,
		.cb = cb,
		.r = r,
		.net_admin = netlink_net_capable(cb->skb, CAP_NET_ADMIN),
	};
	int pos = cb->args[2];

	/* eps hashtable dumps
	 * args:
	 * 0 : if it will traversal listen sock
	 * 1 : to record the sock pos of this time's traversal
	 * 4 : to work as a temporary variable to traversal list
	 */
	if (cb->args[0] == 0) {
		if (!(idiag_states & TCPF_LISTEN))
			goto skip;
		if ((*klpe_sctp_for_each_endpoint)((*klpe_sctp_ep_dump), &commp))
			goto done;
skip:
		cb->args[0] = 1;
		cb->args[1] = 0;
		cb->args[4] = 0;
	}

	/* asocs by transport hashtable dump
	 * args:
	 * 1 : to record the assoc pos of this time's traversal
	 * 2 : to record the transport pos of this time's traversal
	 * 3 : to mark if we have dumped the ep info of the current asoc
	 * 4 : to work as a temporary variable to traversal list
	 * 5 : to save the sk we get from travelsing the tsp list.
	 */
	if (!(idiag_states & ~(TCPF_LISTEN | TCPF_CLOSE)))
		goto done;

	/*
	 * Fix CVE-2022-20154
	 *  -1 line, +1 line
	 */
	klpp_sctp_transport_traverse_process(klpp_sctp_sock_filter, klpp_sctp_sock_dump,
				net, &pos, &commp);
	cb->args[2] = pos;

done:
	cb->args[1] = cb->args[4];
	cb->args[4] = 0;
}



#include <linux/kernel.h>
#include <linux/module.h>
#include "livepatch_bsc1200608.h"
#include "bsc1200608_common.h"
#include "../kallsyms_relocs.h"

#define LIVEPATCHED_MODULE "sctp_diag"

static struct klp_kallsyms_reloc klp_funcs[] = {
	{ "inet_diag_msg_attrs_fill", (void *)&klpe_inet_diag_msg_attrs_fill,
	  "inet_diag" },
	{ "inet_diag_msg_common_fill", (void *)&klpe_inet_diag_msg_common_fill,
	  "inet_diag" },
	{ "sctp_for_each_endpoint", (void *)&klpe_sctp_for_each_endpoint,
	  "sctp" },
	{ "inet_diag_msg_sctpasoc_fill",
	  (void *)&klpe_inet_diag_msg_sctpasoc_fill, "sctp_diag" },
	{ "sctp_diag_get_info", (void *)&klpe_sctp_diag_get_info, "sctp_diag" },
	{ "sctp_ep_dump", (void *)&klpe_sctp_ep_dump, "sctp_diag" },
};

static int livepatch_bsc1200608_module_notify(struct notifier_block *nb,
					      unsigned long action, void *data)
{
	struct module *mod = data;
	int ret;

	if (action != MODULE_STATE_COMING || strcmp(mod->name, LIVEPATCHED_MODULE))
		return 0;

	mutex_lock(&module_mutex);
	ret = __klp_resolve_kallsyms_relocs(klp_funcs, ARRAY_SIZE(klp_funcs));
	mutex_unlock(&module_mutex);
	WARN(ret, "livepatch: delayed kallsyms lookup failed. System is broken and can crash.\n");

	return ret;
}

static struct notifier_block livepatch_bsc1200608_module_nb = {
	.notifier_call = livepatch_bsc1200608_module_notify,
	.priority = INT_MIN+1,
};

int livepatch_bsc1200608_sctp_diag_init(void)
{
	int ret;

	mutex_lock(&module_mutex);
	if (find_module(LIVEPATCHED_MODULE)) {
		ret = __klp_resolve_kallsyms_relocs(klp_funcs,
						    ARRAY_SIZE(klp_funcs));
		if (ret)
			goto out;
	}

	ret = register_module_notifier(&livepatch_bsc1200608_module_nb);
out:
	mutex_unlock(&module_mutex);
	return ret;
}

void livepatch_bsc1200608_sctp_diag_cleanup(void)
{
	unregister_module_notifier(&livepatch_bsc1200608_module_nb);
}
