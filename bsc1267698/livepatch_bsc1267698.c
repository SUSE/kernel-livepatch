/*
 * livepatch_bsc1267698
 *
 * Fix for CVE-2026-46227, bsc#1267698
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


#include "livepatch_bsc1267698.h"


/* klp-ccp: from net/sctp/socket.c */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/hash.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/sched/signal.h>
#include <linux/ip.h>
#include <linux/capability.h>
#include <linux/fcntl.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/compat.h>
#include <linux/rhashtable.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <net/inet_common.h>
#include <net/busy_poll.h>
#include <trace/events/sock.h>
#include <linux/socket.h> /* for sa_family_t */
#include <linux/export.h>
#include <net/sock.h>
#include <net/sctp/sctp.h>
#include <net/sctp/sm.h>
#include <net/sctp/stream_sched.h>

extern struct sctp_af *sctp_sockaddr_af(struct sctp_sock *opt,
					union sctp_addr *addr, int len);

static inline int sctp_verify_addr(struct sock *sk, union sctp_addr *addr,
				   int len)
{
	struct sctp_af *af;

	/* Verify basic sockaddr. */
	af = sctp_sockaddr_af(sctp_sk(sk), addr, len);
	if (!af)
		return -EINVAL;

	/* Is this a valid SCTP address?  */
	if (!af->addr_valid(addr, sctp_sk(sk), NULL))
		return -EINVAL;

	if (!sctp_sk(sk)->pf->send_verify(sctp_sk(sk), (addr)))
		return -EINVAL;

	return 0;
}

struct sctp_association *sctp_id2assoc(struct sock *sk, sctp_assoc_t id);

struct sctp_af *sctp_sockaddr_af(struct sctp_sock *opt,
					union sctp_addr *addr, int len);

extern int sctp_connect_new_asoc(struct sctp_endpoint *ep,
				 const union sctp_addr *daddr,
				 const struct sctp_initmsg *init,
				 struct sctp_transport **tp);

extern int sctp_connect_add_peer(struct sctp_association *asoc,
				 union sctp_addr *daddr, int addr_len);

static int sctp_error(struct sock *sk, int flags, int err)
{
	if (err == -EPIPE)
		err = sock_error(sk) ? : -EPIPE;
	if (err == -EPIPE && !(flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);
	return err;
}

static int sctp_msghdr_parse(const struct msghdr *msg,
			     struct sctp_cmsgs *cmsgs);

static int sctp_sendmsg_parse(struct sock *sk, struct sctp_cmsgs *cmsgs,
			      struct sctp_sndrcvinfo *srinfo,
			      const struct msghdr *msg, size_t msg_len)
{
	__u16 sflags;
	int err;

	if (sctp_sstate(sk, LISTENING) && sctp_style(sk, TCP))
		return -EPIPE;

	if (msg_len > sk->sk_sndbuf)
		return -EMSGSIZE;

	memset(cmsgs, 0, sizeof(*cmsgs));
	err = sctp_msghdr_parse(msg, cmsgs);
	if (err) {
		pr_debug("%s: msghdr parse err:%x\n", __func__, err);
		return err;
	}

	memset(srinfo, 0, sizeof(*srinfo));
	if (cmsgs->srinfo) {
		srinfo->sinfo_stream = cmsgs->srinfo->sinfo_stream;
		srinfo->sinfo_flags = cmsgs->srinfo->sinfo_flags;
		srinfo->sinfo_ppid = cmsgs->srinfo->sinfo_ppid;
		srinfo->sinfo_context = cmsgs->srinfo->sinfo_context;
		srinfo->sinfo_assoc_id = cmsgs->srinfo->sinfo_assoc_id;
		srinfo->sinfo_timetolive = cmsgs->srinfo->sinfo_timetolive;
	}

	if (cmsgs->sinfo) {
		srinfo->sinfo_stream = cmsgs->sinfo->snd_sid;
		srinfo->sinfo_flags = cmsgs->sinfo->snd_flags;
		srinfo->sinfo_ppid = cmsgs->sinfo->snd_ppid;
		srinfo->sinfo_context = cmsgs->sinfo->snd_context;
		srinfo->sinfo_assoc_id = cmsgs->sinfo->snd_assoc_id;
	}

	if (cmsgs->prinfo) {
		srinfo->sinfo_timetolive = cmsgs->prinfo->pr_value;
		SCTP_PR_SET_POLICY(srinfo->sinfo_flags,
				   cmsgs->prinfo->pr_policy);
	}

	sflags = srinfo->sinfo_flags;
	if (!sflags && msg_len)
		return 0;

	if (sctp_style(sk, TCP) && (sflags & (SCTP_EOF | SCTP_ABORT)))
		return -EINVAL;

	if (((sflags & SCTP_EOF) && msg_len > 0) ||
	    (!(sflags & (SCTP_EOF | SCTP_ABORT)) && msg_len == 0))
		return -EINVAL;

	if ((sflags & SCTP_ADDR_OVER) && !msg->msg_name)
		return -EINVAL;

	return 0;
}

static int sctp_sendmsg_new_asoc(struct sock *sk, __u16 sflags,
				 struct sctp_cmsgs *cmsgs,
				 union sctp_addr *daddr,
				 struct sctp_transport **tp)
{
	struct sctp_endpoint *ep = sctp_sk(sk)->ep;
	struct sctp_association *asoc;
	struct cmsghdr *cmsg;
	__be32 flowinfo = 0;
	struct sctp_af *af;
	int err;

	*tp = NULL;

	if (sflags & (SCTP_EOF | SCTP_ABORT))
		return -EINVAL;

	if (sctp_style(sk, TCP) && (sctp_sstate(sk, ESTABLISHED) ||
				    sctp_sstate(sk, CLOSING)))
		return -EADDRNOTAVAIL;

	/* Label connection socket for first association 1-to-many
	 * style for client sequence socket()->sendmsg(). This
	 * needs to be done before sctp_assoc_add_peer() as that will
	 * set up the initial packet that needs to account for any
	 * security ip options (CIPSO/CALIPSO) added to the packet.
	 */
	af = sctp_get_af_specific(daddr->sa.sa_family);
	if (!af)
		return -EINVAL;
	err = security_sctp_bind_connect(sk, SCTP_SENDMSG_CONNECT,
					 (struct sockaddr *)daddr,
					 af->sockaddr_len);
	if (err < 0)
		return err;

	err = sctp_connect_new_asoc(ep, daddr, cmsgs->init, tp);
	if (err)
		return err;
	asoc = (*tp)->asoc;

	if (!cmsgs->addrs_msg)
		return 0;

	if (daddr->sa.sa_family == AF_INET6)
		flowinfo = daddr->v6.sin6_flowinfo;

	/* sendv addr list parse */
	for_each_cmsghdr(cmsg, cmsgs->addrs_msg) {
		union sctp_addr _daddr;
		int dlen;

		if (cmsg->cmsg_level != IPPROTO_SCTP ||
		    (cmsg->cmsg_type != SCTP_DSTADDRV4 &&
		     cmsg->cmsg_type != SCTP_DSTADDRV6))
			continue;

		daddr = &_daddr;
		memset(daddr, 0, sizeof(*daddr));
		dlen = cmsg->cmsg_len - sizeof(struct cmsghdr);
		if (cmsg->cmsg_type == SCTP_DSTADDRV4) {
			if (dlen < sizeof(struct in_addr)) {
				err = -EINVAL;
				goto free;
			}

			dlen = sizeof(struct in_addr);
			daddr->v4.sin_family = AF_INET;
			daddr->v4.sin_port = htons(asoc->peer.port);
			memcpy(&daddr->v4.sin_addr, CMSG_DATA(cmsg), dlen);
		} else {
			if (dlen < sizeof(struct in6_addr)) {
				err = -EINVAL;
				goto free;
			}

			dlen = sizeof(struct in6_addr);
			daddr->v6.sin6_flowinfo = flowinfo;
			daddr->v6.sin6_family = AF_INET6;
			daddr->v6.sin6_port = htons(asoc->peer.port);
			memcpy(&daddr->v6.sin6_addr, CMSG_DATA(cmsg), dlen);
		}

		err = sctp_connect_add_peer(asoc, daddr, sizeof(*daddr));
		if (err)
			goto free;
	}

	return 0;

free:
	sctp_association_free(asoc);
	return err;
}

extern int sctp_sendmsg_check_sflags(struct sctp_association *asoc,
				     __u16 sflags, struct msghdr *msg,
				     size_t msg_len);

extern int sctp_sendmsg_to_asoc(struct sctp_association *asoc,
				struct msghdr *msg, size_t msg_len,
				struct sctp_transport *transport,
				struct sctp_sndrcvinfo *sinfo);

static union sctp_addr *sctp_sendmsg_get_daddr(struct sock *sk,
					       const struct msghdr *msg,
					       struct sctp_cmsgs *cmsgs)
{
	union sctp_addr *daddr = NULL;
	int err;

	if (!sctp_style(sk, UDP_HIGH_BANDWIDTH) && msg->msg_name) {
		int len = msg->msg_namelen;

		if (len > sizeof(*daddr))
			len = sizeof(*daddr);

		daddr = (union sctp_addr *)msg->msg_name;

		err = sctp_verify_addr(sk, daddr, len);
		if (err)
			return ERR_PTR(err);
	}

	return daddr;
}

extern void sctp_sendmsg_update_sinfo(struct sctp_association *asoc,
				      struct sctp_sndrcvinfo *sinfo,
				      struct sctp_cmsgs *cmsgs);

int klpp_sctp_sendmsg(struct sock *sk, struct msghdr *msg, size_t msg_len)
{
	struct sctp_endpoint *ep = sctp_sk(sk)->ep;
	struct sctp_transport *transport = NULL;
	struct sctp_sndrcvinfo _sinfo, *sinfo;
	struct sctp_association *asoc, *tmp;
	struct sctp_cmsgs cmsgs;
	union sctp_addr *daddr;
	bool new = false;
	__u16 sflags;
	int err;

	/* Parse and get snd_info */
	err = sctp_sendmsg_parse(sk, &cmsgs, &_sinfo, msg, msg_len);
	if (err)
		goto out;

	sinfo  = &_sinfo;
	sflags = sinfo->sinfo_flags;

	/* Get daddr from msg */
	daddr = sctp_sendmsg_get_daddr(sk, msg, &cmsgs);
	if (IS_ERR(daddr)) {
		err = PTR_ERR(daddr);
		goto out;
	}

	lock_sock(sk);

	/* SCTP_SENDALL process */
	if ((sflags & SCTP_SENDALL) && sctp_style(sk, UDP)) {
		list_for_each_entry_safe(asoc, tmp, &ep->asocs, asocs) {
			err = sctp_sendmsg_check_sflags(asoc, sflags, msg,
							msg_len);
			if (err == 0)
				continue;
			if (err < 0)
				goto out_unlock;

			sctp_sendmsg_update_sinfo(asoc, sinfo, &cmsgs);

			err = sctp_sendmsg_to_asoc(asoc, msg, msg_len,
						   NULL, sinfo);
			if (err < 0)
				goto out_unlock;

			iov_iter_revert(&msg->msg_iter, err);

			/* sctp_sendmsg_to_asoc() may have released the socket
			 * lock (sctp_wait_for_sndbuf), during which other
			 * associations on ep->asocs could have been peeled
			 * off or freed.  @asoc itself is revalidated by the
			 * base.dead and base.sk checks in sctp_wait_for_sndbuf,
			 * so re-derive the cached cursor from it.
			 */
			tmp = list_next_entry(asoc, asocs);
		}

		goto out_unlock;
	}

	/* Get and check or create asoc */
	if (daddr) {
		asoc = sctp_endpoint_lookup_assoc(ep, daddr, &transport);
		if (asoc) {
			err = sctp_sendmsg_check_sflags(asoc, sflags, msg,
							msg_len);
			if (err <= 0)
				goto out_unlock;
		} else {
			err = sctp_sendmsg_new_asoc(sk, sflags, &cmsgs, daddr,
						    &transport);
			if (err)
				goto out_unlock;

			asoc = transport->asoc;
			new = true;
		}

		if (!sctp_style(sk, TCP) && !(sflags & SCTP_ADDR_OVER))
			transport = NULL;
	} else {
		asoc = sctp_id2assoc(sk, sinfo->sinfo_assoc_id);
		if (!asoc) {
			err = -EPIPE;
			goto out_unlock;
		}

		err = sctp_sendmsg_check_sflags(asoc, sflags, msg, msg_len);
		if (err <= 0)
			goto out_unlock;
	}

	/* Update snd_info with the asoc */
	sctp_sendmsg_update_sinfo(asoc, sinfo, &cmsgs);

	/* Send msg to the asoc */
	err = sctp_sendmsg_to_asoc(asoc, msg, msg_len, transport, sinfo);
	if (err < 0 && err != -ESRCH && new)
		sctp_association_free(asoc);

out_unlock:
	release_sock(sk);
out:
	return sctp_error(sk, msg->msg_flags, err);
}

static int sctp_msghdr_parse(const struct msghdr *msg, struct sctp_cmsgs *cmsgs)
{
	struct msghdr *my_msg = (struct msghdr *)msg;
	struct cmsghdr *cmsg;

	for_each_cmsghdr(cmsg, my_msg) {
		if (!CMSG_OK(my_msg, cmsg))
			return -EINVAL;

		/* Should we parse this header or ignore?  */
		if (cmsg->cmsg_level != IPPROTO_SCTP)
			continue;

		/* Strictly check lengths following example in SCM code.  */
		switch (cmsg->cmsg_type) {
		case SCTP_INIT:
			/* SCTP Socket API Extension
			 * 5.3.1 SCTP Initiation Structure (SCTP_INIT)
			 *
			 * This cmsghdr structure provides information for
			 * initializing new SCTP associations with sendmsg().
			 * The SCTP_INITMSG socket option uses this same data
			 * structure.  This structure is not used for
			 * recvmsg().
			 *
			 * cmsg_level    cmsg_type      cmsg_data[]
			 * ------------  ------------   ----------------------
			 * IPPROTO_SCTP  SCTP_INIT      struct sctp_initmsg
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_initmsg)))
				return -EINVAL;

			cmsgs->init = CMSG_DATA(cmsg);
			break;

		case SCTP_SNDRCV:
			/* SCTP Socket API Extension
			 * 5.3.2 SCTP Header Information Structure(SCTP_SNDRCV)
			 *
			 * This cmsghdr structure specifies SCTP options for
			 * sendmsg() and describes SCTP header information
			 * about a received message through recvmsg().
			 *
			 * cmsg_level    cmsg_type      cmsg_data[]
			 * ------------  ------------   ----------------------
			 * IPPROTO_SCTP  SCTP_SNDRCV    struct sctp_sndrcvinfo
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_sndrcvinfo)))
				return -EINVAL;

			cmsgs->srinfo = CMSG_DATA(cmsg);

			if (cmsgs->srinfo->sinfo_flags &
			    ~(SCTP_UNORDERED | SCTP_ADDR_OVER |
			      SCTP_SACK_IMMEDIATELY | SCTP_SENDALL |
			      SCTP_PR_SCTP_MASK | SCTP_ABORT | SCTP_EOF))
				return -EINVAL;
			break;

		case SCTP_SNDINFO:
			/* SCTP Socket API Extension
			 * 5.3.4 SCTP Send Information Structure (SCTP_SNDINFO)
			 *
			 * This cmsghdr structure specifies SCTP options for
			 * sendmsg(). This structure and SCTP_RCVINFO replaces
			 * SCTP_SNDRCV which has been deprecated.
			 *
			 * cmsg_level    cmsg_type      cmsg_data[]
			 * ------------  ------------   ---------------------
			 * IPPROTO_SCTP  SCTP_SNDINFO    struct sctp_sndinfo
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_sndinfo)))
				return -EINVAL;

			cmsgs->sinfo = CMSG_DATA(cmsg);

			if (cmsgs->sinfo->snd_flags &
			    ~(SCTP_UNORDERED | SCTP_ADDR_OVER |
			      SCTP_SACK_IMMEDIATELY | SCTP_SENDALL |
			      SCTP_PR_SCTP_MASK | SCTP_ABORT | SCTP_EOF))
				return -EINVAL;
			break;
		case SCTP_PRINFO:
			/* SCTP Socket API Extension
			 * 5.3.7 SCTP PR-SCTP Information Structure (SCTP_PRINFO)
			 *
			 * This cmsghdr structure specifies SCTP options for sendmsg().
			 *
			 * cmsg_level    cmsg_type      cmsg_data[]
			 * ------------  ------------   ---------------------
			 * IPPROTO_SCTP  SCTP_PRINFO    struct sctp_prinfo
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_prinfo)))
				return -EINVAL;

			cmsgs->prinfo = CMSG_DATA(cmsg);
			if (cmsgs->prinfo->pr_policy & ~SCTP_PR_SCTP_MASK)
				return -EINVAL;

			if (cmsgs->prinfo->pr_policy == SCTP_PR_SCTP_NONE)
				cmsgs->prinfo->pr_value = 0;
			break;
		case SCTP_AUTHINFO:
			/* SCTP Socket API Extension
			 * 5.3.8 SCTP AUTH Information Structure (SCTP_AUTHINFO)
			 *
			 * This cmsghdr structure specifies SCTP options for sendmsg().
			 *
			 * cmsg_level    cmsg_type      cmsg_data[]
			 * ------------  ------------   ---------------------
			 * IPPROTO_SCTP  SCTP_AUTHINFO  struct sctp_authinfo
			 */
			if (cmsg->cmsg_len != CMSG_LEN(sizeof(struct sctp_authinfo)))
				return -EINVAL;

			cmsgs->authinfo = CMSG_DATA(cmsg);
			break;
		case SCTP_DSTADDRV4:
		case SCTP_DSTADDRV6:
			/* SCTP Socket API Extension
			 * 5.3.9/10 SCTP Destination IPv4/6 Address Structure (SCTP_DSTADDRV4/6)
			 *
			 * This cmsghdr structure specifies SCTP options for sendmsg().
			 *
			 * cmsg_level    cmsg_type         cmsg_data[]
			 * ------------  ------------   ---------------------
			 * IPPROTO_SCTP  SCTP_DSTADDRV4 struct in_addr
			 * ------------  ------------   ---------------------
			 * IPPROTO_SCTP  SCTP_DSTADDRV6 struct in6_addr
			 */
			cmsgs->addrs_msg = my_msg;
			break;
		default:
			return -EINVAL;
		}
	}

	return 0;
}


#include <linux/livepatch.h>

extern typeof(sctp_association_free) sctp_association_free
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_association_free);
extern typeof(sctp_connect_add_peer) sctp_connect_add_peer
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_connect_add_peer);
extern typeof(sctp_connect_new_asoc) sctp_connect_new_asoc
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_connect_new_asoc);
extern typeof(sctp_endpoint_lookup_assoc) sctp_endpoint_lookup_assoc
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_endpoint_lookup_assoc);
extern typeof(sctp_get_af_specific) sctp_get_af_specific
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_get_af_specific);
extern typeof(sctp_id2assoc) sctp_id2assoc
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_id2assoc);
extern typeof(sctp_sendmsg_check_sflags) sctp_sendmsg_check_sflags
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_sendmsg_check_sflags);
extern typeof(sctp_sendmsg_to_asoc) sctp_sendmsg_to_asoc
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_sendmsg_to_asoc);
extern typeof(sctp_sendmsg_update_sinfo) sctp_sendmsg_update_sinfo
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_sendmsg_update_sinfo);
extern typeof(sctp_sockaddr_af) sctp_sockaddr_af
	 KLP_RELOC_SYMBOL(sctp, sctp, sctp_sockaddr_af);
