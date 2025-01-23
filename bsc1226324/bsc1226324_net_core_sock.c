/*
 * bsc1226324_net_core_sock
 *
 * Fix for CVE-2024-36971, bsc#1226324
 *
 *  Copyright (c) 2025 SUSE
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

#include <asm/unaligned.h>
#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/errqueue.h>

/* klp-ccp: from net/core/sock.c */
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/poll.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/user_namespace.h>
#include <linux/static_key.h>
#include <linux/memcontrol.h>
#include <linux/prefetch.h>
#include <linux/compat.h>

#include <linux/uaccess.h>

#include <linux/netdevice.h>

#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/request_sock.h>
#include <net/sock.h>
#include <linux/net_tstamp.h>
#include <net/xfrm.h>
#include <linux/ipsec.h>

#include <net/netprio_cgroup.h>

#include <linux/filter.h>
#include <net/sock_reuseport.h>

/* klp-ccp: from net/core/dev.h */
#include <linux/types.h>

#include "bsc1226324_net_sock.h"

/* klp-ccp: from net/core/sock.c */
extern __u32 sysctl_wmem_max __read_mostly;

extern typeof(sysctl_wmem_max) sysctl_wmem_max;

extern __u32 sysctl_rmem_max __read_mostly;

extern typeof(sysctl_rmem_max) sysctl_rmem_max;

extern int sock_set_timeout(long *timeo_p, sockptr_t optval, int optlen,
			    bool old_timeval);

extern int sock_bindtoindex_locked(struct sock *sk, int ifindex);

static int sock_setbindtodevice(struct sock *sk, sockptr_t optval, int optlen)
{
	int ret = -ENOPROTOOPT;
#ifdef CONFIG_NETDEVICES
	struct net *net = sock_net(sk);
	char devname[IFNAMSIZ];
	int index;

	ret = -EINVAL;
	if (optlen < 0)
		goto out;

	/* Bind this socket to a particular device like "eth0",
	 * as specified in the passed interface name. If the
	 * name is "" or the option length is zero the socket
	 * is not bound.
	 */
	if (optlen > IFNAMSIZ - 1)
		optlen = IFNAMSIZ - 1;
	memset(devname, 0, sizeof(devname));

	ret = -EFAULT;
	if (copy_from_sockptr(devname, optval, optlen))
		goto out;

	index = 0;
	if (devname[0] != '\0') {
		struct net_device *dev;

		rcu_read_lock();
		dev = dev_get_by_name_rcu(net, devname);
		if (dev)
			index = dev->ifindex;
		rcu_read_unlock();
		ret = -ENODEV;
		if (!dev)
			goto out;
	}

	sockopt_lock_sock(sk);
	ret = sock_bindtoindex_locked(sk, index);
	sockopt_release_sock(sk);
out:
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	return ret;
}

void sock_set_priority(struct sock *sk, u32 priority);

extern typeof(sock_set_priority) sock_set_priority;

void sock_set_timestamp(struct sock *sk, int optname, bool valbool);

int sock_set_timestamping(struct sock *sk, int optname,
			  struct so_timestamping timestamping);

static void __sock_set_rcvbuf(struct sock *sk, int val)
{
	/* Ensure val * 2 fits into an int, to prevent max_t() from treating it
	 * as a negative value.
	 */
	val = min_t(int, val, INT_MAX / 2);
	sk->sk_userlocks |= SOCK_RCVBUF_LOCK;

	/* We double it on the way in to account for "struct sk_buff" etc.
	 * overhead.   Applications assume that the SO_RCVBUF setting they make
	 * will allow that much actual data to be received on that socket.
	 *
	 * Applications are unaware that "struct sk_buff" and other overheads
	 * allocate from the receive buffer during socket buffer allocation.
	 *
	 * And after considering the possible alternatives, returning the value
	 * we actually used in getsockopt is the most desirable behavior.
	 */
	WRITE_ONCE(sk->sk_rcvbuf, max_t(int, val * 2, SOCK_MIN_RCVBUF));
}

static void __sock_set_mark(struct sock *sk, u32 val)
{
	if (val != sk->sk_mark) {
		WRITE_ONCE(sk->sk_mark, val);
		sk_dst_reset(sk);
	}
}

static void sock_release_reserved_memory(struct sock *sk, int bytes)
{
	/* Round down bytes to multiple of pages */
	bytes = round_down(bytes, PAGE_SIZE);

	WARN_ON(bytes > sk->sk_reserved_mem);
	WRITE_ONCE(sk->sk_reserved_mem, sk->sk_reserved_mem - bytes);
	sk_mem_reclaim(sk);
}

static int sock_reserve_memory(struct sock *sk, int bytes)
{
	long allocated;
	bool charged;
	int pages;

	if (!mem_cgroup_sockets_enabled || !sk->sk_memcg || !sk_has_account(sk))
		return -EOPNOTSUPP;

	if (!bytes)
		return 0;

	pages = sk_mem_pages(bytes);

	/* pre-charge to memcg */
	charged = mem_cgroup_charge_skmem(sk->sk_memcg, pages,
					  GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	if (!charged)
		return -ENOMEM;

	/* pre-charge to forward_alloc */
	sk_memory_allocated_add(sk, pages);
	allocated = sk_memory_allocated(sk);
	/* If the system goes into memory pressure with this
	 * precharge, give up and return error.
	 */
	if (allocated > sk_prot_mem_limits(sk, 1)) {
		sk_memory_allocated_sub(sk, pages);
		mem_cgroup_uncharge_skmem(sk->sk_memcg, pages);
		return -ENOMEM;
	}
	sk_forward_alloc_add(sk, pages << PAGE_SHIFT);

	WRITE_ONCE(sk->sk_reserved_mem,
		   sk->sk_reserved_mem + (pages << PAGE_SHIFT));

	return 0;
}

void sockopt_lock_sock(struct sock *sk);

extern typeof(sockopt_lock_sock) sockopt_lock_sock;

void sockopt_release_sock(struct sock *sk);

extern typeof(sockopt_release_sock) sockopt_release_sock;

bool sockopt_ns_capable(struct user_namespace *ns, int cap);

extern typeof(sockopt_ns_capable) sockopt_ns_capable;

bool sockopt_capable(int cap);

extern typeof(sockopt_capable) sockopt_capable;

int klpp_sk_setsockopt(struct sock *sk, int level, int optname,
		  sockptr_t optval, unsigned int optlen)
{
	struct so_timestamping timestamping;
	struct socket *sock = sk->sk_socket;
	struct sock_txtime sk_txtime;
	int val;
	int valbool;
	struct linger ling;
	int ret = 0;

	/*
	 *	Options without arguments
	 */

	if (optname == SO_BINDTODEVICE)
		return sock_setbindtodevice(sk, optval, optlen);

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	valbool = val ? 1 : 0;

	/* handle options which do not require locking the socket. */
	switch (optname) {
	case SO_PRIORITY:
		if ((val >= 0 && val <= 6) ||
		    sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_RAW) ||
		    sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)) {
			sock_set_priority(sk, val);
			return 0;
		}
		return -EPERM;
	}

	sockopt_lock_sock(sk);

	switch (optname) {
	case SO_DEBUG:
		if (val && !sockopt_capable(CAP_NET_ADMIN))
			ret = -EACCES;
		else
			sock_valbool_flag(sk, SOCK_DBG, valbool);
		break;
	case SO_REUSEADDR:
		sk->sk_reuse = (valbool ? SK_CAN_REUSE : SK_NO_REUSE);
		break;
	case SO_REUSEPORT:
		sk->sk_reuseport = valbool;
		break;
	case SO_TYPE:
	case SO_PROTOCOL:
	case SO_DOMAIN:
	case SO_ERROR:
		ret = -ENOPROTOOPT;
		break;
	case SO_DONTROUTE:
		sock_valbool_flag(sk, SOCK_LOCALROUTE, valbool);
		sk_dst_reset(sk);
		break;
	case SO_BROADCAST:
		sock_valbool_flag(sk, SOCK_BROADCAST, valbool);
		break;
	case SO_SNDBUF:
		/* Don't error on this BSD doesn't and if you think
		 * about it this is right. Otherwise apps have to
		 * play 'guess the biggest size' games. RCVBUF/SNDBUF
		 * are treated in BSD as hints
		 */
		val = min_t(u32, val, READ_ONCE(sysctl_wmem_max));
set_sndbuf:
		/* Ensure val * 2 fits into an int, to prevent max_t()
		 * from treating it as a negative value.
		 */
		val = min_t(int, val, INT_MAX / 2);
		sk->sk_userlocks |= SOCK_SNDBUF_LOCK;
		WRITE_ONCE(sk->sk_sndbuf,
			   max_t(int, val * 2, SOCK_MIN_SNDBUF));
		/* Wake up sending tasks if we upped the value. */
		sk->sk_write_space(sk);
		break;

	case SO_SNDBUFFORCE:
		if (!sockopt_capable(CAP_NET_ADMIN)) {
			ret = -EPERM;
			break;
		}

		/* No negative values (to prevent underflow, as val will be
		 * multiplied by 2).
		 */
		if (val < 0)
			val = 0;
		goto set_sndbuf;

	case SO_RCVBUF:
		/* Don't error on this BSD doesn't and if you think
		 * about it this is right. Otherwise apps have to
		 * play 'guess the biggest size' games. RCVBUF/SNDBUF
		 * are treated in BSD as hints
		 */
		__sock_set_rcvbuf(sk, min_t(u32, val, READ_ONCE(sysctl_rmem_max)));
		break;

	case SO_RCVBUFFORCE:
		if (!sockopt_capable(CAP_NET_ADMIN)) {
			ret = -EPERM;
			break;
		}

		/* No negative values (to prevent underflow, as val will be
		 * multiplied by 2).
		 */
		__sock_set_rcvbuf(sk, max(val, 0));
		break;

	case SO_KEEPALIVE:
		if (sk->sk_prot->keepalive)
			sk->sk_prot->keepalive(sk, valbool);
		sock_valbool_flag(sk, SOCK_KEEPOPEN, valbool);
		break;

	case SO_OOBINLINE:
		sock_valbool_flag(sk, SOCK_URGINLINE, valbool);
		break;

	case SO_NO_CHECK:
		sk->sk_no_check_tx = valbool;
		break;

	case SO_LINGER:
		if (optlen < sizeof(ling)) {
			ret = -EINVAL;	/* 1003.1g */
			break;
		}
		if (copy_from_sockptr(&ling, optval, sizeof(ling))) {
			ret = -EFAULT;
			break;
		}
		if (!ling.l_onoff) {
			sock_reset_flag(sk, SOCK_LINGER);
		} else {
			unsigned long t_sec = ling.l_linger;

			if (t_sec >= MAX_SCHEDULE_TIMEOUT / HZ)
				WRITE_ONCE(sk->sk_lingertime, MAX_SCHEDULE_TIMEOUT);
			else
				WRITE_ONCE(sk->sk_lingertime, t_sec * HZ);
			sock_set_flag(sk, SOCK_LINGER);
		}
		break;

	case SO_BSDCOMPAT:
		break;

	case SO_PASSCRED:
		if (valbool)
			set_bit(SOCK_PASSCRED, &sock->flags);
		else
			clear_bit(SOCK_PASSCRED, &sock->flags);
		break;

	case SO_TIMESTAMP_OLD:
	case SO_TIMESTAMP_NEW:
	case SO_TIMESTAMPNS_OLD:
	case SO_TIMESTAMPNS_NEW:
		sock_set_timestamp(sk, optname, valbool);
		break;

	case SO_TIMESTAMPING_NEW:
	case SO_TIMESTAMPING_OLD:
		if (optlen == sizeof(timestamping)) {
			if (copy_from_sockptr(&timestamping, optval,
					      sizeof(timestamping))) {
				ret = -EFAULT;
				break;
			}
		} else {
			memset(&timestamping, 0, sizeof(timestamping));
			timestamping.flags = val;
		}
		ret = sock_set_timestamping(sk, optname, timestamping);
		break;

	case SO_RCVLOWAT:
		if (val < 0)
			val = INT_MAX;
		if (sock && sock->ops->set_rcvlowat)
			ret = sock->ops->set_rcvlowat(sk, val);
		else
			WRITE_ONCE(sk->sk_rcvlowat, val ? : 1);
		break;

	case SO_RCVTIMEO_OLD:
	case SO_RCVTIMEO_NEW:
		ret = sock_set_timeout(&sk->sk_rcvtimeo, optval,
				       optlen, optname == SO_RCVTIMEO_OLD);
		break;

	case SO_SNDTIMEO_OLD:
	case SO_SNDTIMEO_NEW:
		ret = sock_set_timeout(&sk->sk_sndtimeo, optval,
				       optlen, optname == SO_SNDTIMEO_OLD);
		break;

	case SO_ATTACH_FILTER: {
		struct sock_fprog fprog;

		ret = copy_bpf_fprog_from_user(&fprog, optval, optlen);
		if (!ret)
			ret = sk_attach_filter(&fprog, sk);
		break;
	}
	case SO_ATTACH_BPF:
		ret = -EINVAL;
		if (optlen == sizeof(u32)) {
			u32 ufd;

			ret = -EFAULT;
			if (copy_from_sockptr(&ufd, optval, sizeof(ufd)))
				break;

			ret = sk_attach_bpf(ufd, sk);
		}
		break;

	case SO_ATTACH_REUSEPORT_CBPF: {
		struct sock_fprog fprog;

		ret = copy_bpf_fprog_from_user(&fprog, optval, optlen);
		if (!ret)
			ret = sk_reuseport_attach_filter(&fprog, sk);
		break;
	}
	case SO_ATTACH_REUSEPORT_EBPF:
		ret = -EINVAL;
		if (optlen == sizeof(u32)) {
			u32 ufd;

			ret = -EFAULT;
			if (copy_from_sockptr(&ufd, optval, sizeof(ufd)))
				break;

			ret = sk_reuseport_attach_bpf(ufd, sk);
		}
		break;

	case SO_DETACH_REUSEPORT_BPF:
		ret = reuseport_detach_prog(sk);
		break;

	case SO_DETACH_FILTER:
		ret = sk_detach_filter(sk);
		break;

	case SO_LOCK_FILTER:
		if (sock_flag(sk, SOCK_FILTER_LOCKED) && !valbool)
			ret = -EPERM;
		else
			sock_valbool_flag(sk, SOCK_FILTER_LOCKED, valbool);
		break;

	case SO_PASSSEC:
		if (valbool)
			set_bit(SOCK_PASSSEC, &sock->flags);
		else
			clear_bit(SOCK_PASSSEC, &sock->flags);
		break;
	case SO_MARK:
		if (!sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_RAW) &&
		    !sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)) {
			ret = -EPERM;
			break;
		}

		__sock_set_mark(sk, val);
		break;
	case SO_RCVMARK:
		sock_valbool_flag(sk, SOCK_RCVMARK, valbool);
		break;

	case SO_RXQ_OVFL:
		sock_valbool_flag(sk, SOCK_RXQ_OVFL, valbool);
		break;

	case SO_WIFI_STATUS:
		sock_valbool_flag(sk, SOCK_WIFI_STATUS, valbool);
		break;

	case SO_PEEK_OFF:
		if (sock->ops->set_peek_off)
			ret = sock->ops->set_peek_off(sk, val);
		else
			ret = -EOPNOTSUPP;
		break;

	case SO_NOFCS:
		sock_valbool_flag(sk, SOCK_NOFCS, valbool);
		break;

	case SO_SELECT_ERR_QUEUE:
		sock_valbool_flag(sk, SOCK_SELECT_ERR_QUEUE, valbool);
		break;

#ifdef CONFIG_NET_RX_BUSY_POLL
	case SO_BUSY_POLL:
		if (val < 0)
			ret = -EINVAL;
		else
			WRITE_ONCE(sk->sk_ll_usec, val);
		break;
	case SO_PREFER_BUSY_POLL:
		if (valbool && !sockopt_capable(CAP_NET_ADMIN))
			ret = -EPERM;
		else
			WRITE_ONCE(sk->sk_prefer_busy_poll, valbool);
		break;
	case SO_BUSY_POLL_BUDGET:
		if (val > READ_ONCE(sk->sk_busy_poll_budget) && !sockopt_capable(CAP_NET_ADMIN)) {
			ret = -EPERM;
		} else {
			if (val < 0 || val > U16_MAX)
				ret = -EINVAL;
			else
				WRITE_ONCE(sk->sk_busy_poll_budget, val);
		}
		break;
#else
#error "klp-ccp: a preceeding branch should have been taken"
#endif
	case SO_MAX_PACING_RATE:
		{
		unsigned long ulval = (val == ~0U) ? ~0UL : (unsigned int)val;

		if (sizeof(ulval) != sizeof(val) &&
		    optlen >= sizeof(ulval) &&
		    copy_from_sockptr(&ulval, optval, sizeof(ulval))) {
			ret = -EFAULT;
			break;
		}
		if (ulval != ~0UL)
			cmpxchg(&sk->sk_pacing_status,
				SK_PACING_NONE,
				SK_PACING_NEEDED);
		/* Pairs with READ_ONCE() from sk_getsockopt() */
		WRITE_ONCE(sk->sk_max_pacing_rate, ulval);
		sk->sk_pacing_rate = min(sk->sk_pacing_rate, ulval);
		break;
		}
	case SO_INCOMING_CPU:
		reuseport_update_incoming_cpu(sk, val);
		break;

	case SO_CNX_ADVICE:
		if (val == 1)
			klpp_dst_negative_advice(sk);
		break;

	case SO_ZEROCOPY:
		if (sk->sk_family == PF_INET || sk->sk_family == PF_INET6) {
			if (!(sk_is_tcp(sk) ||
			      (sk->sk_type == SOCK_DGRAM &&
			       sk->sk_protocol == IPPROTO_UDP)))
				ret = -EOPNOTSUPP;
		} else if (sk->sk_family != PF_RDS) {
			ret = -EOPNOTSUPP;
		}
		if (!ret) {
			if (val < 0 || val > 1)
				ret = -EINVAL;
			else
				sock_valbool_flag(sk, SOCK_ZEROCOPY, valbool);
		}
		break;

	case SO_TXTIME:
		if (optlen != sizeof(struct sock_txtime)) {
			ret = -EINVAL;
			break;
		} else if (copy_from_sockptr(&sk_txtime, optval,
			   sizeof(struct sock_txtime))) {
			ret = -EFAULT;
			break;
		} else if (sk_txtime.flags & ~SOF_TXTIME_FLAGS_MASK) {
			ret = -EINVAL;
			break;
		}
		/* CLOCK_MONOTONIC is only used by sch_fq, and this packet
		 * scheduler has enough safe guards.
		 */
		if (sk_txtime.clockid != CLOCK_MONOTONIC &&
		    !sockopt_ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)) {
			ret = -EPERM;
			break;
		}
		sock_valbool_flag(sk, SOCK_TXTIME, true);
		sk->sk_clockid = sk_txtime.clockid;
		sk->sk_txtime_deadline_mode =
			!!(sk_txtime.flags & SOF_TXTIME_DEADLINE_MODE);
		sk->sk_txtime_report_errors =
			!!(sk_txtime.flags & SOF_TXTIME_REPORT_ERRORS);
		break;

	case SO_BINDTOIFINDEX:
		ret = sock_bindtoindex_locked(sk, val);
		break;

	case SO_BUF_LOCK:
		if (val & ~SOCK_BUF_LOCK_MASK) {
			ret = -EINVAL;
			break;
		}
		sk->sk_userlocks = val | (sk->sk_userlocks &
					  ~SOCK_BUF_LOCK_MASK);
		break;

	case SO_RESERVE_MEM:
	{
		int delta;

		if (val < 0) {
			ret = -EINVAL;
			break;
		}

		delta = val - sk->sk_reserved_mem;
		if (delta < 0)
			sock_release_reserved_memory(sk, -delta);
		else
			ret = sock_reserve_memory(sk, delta);
		break;
	}

	case SO_TXREHASH:
		if (val < -1 || val > 1) {
			ret = -EINVAL;
			break;
		}
		if ((u8)val == SOCK_TXREHASH_DEFAULT)
			val = READ_ONCE(sock_net(sk)->core.sysctl_txrehash);
		/* Paired with READ_ONCE() in tcp_rtx_synack()
		 * and sk_getsockopt().
		 */
		WRITE_ONCE(sk->sk_txrehash, (u8)val);
		break;

	default:
		ret = -ENOPROTOOPT;
		break;
	}
	sockopt_release_sock(sk);
	return ret;
}

void __sk_mem_reclaim(struct sock *sk, int amount);

extern typeof(__sk_mem_reclaim) __sk_mem_reclaim;

#include <linux/livepatch.h>

#include "livepatch_bsc1226324.h"

extern typeof(mem_cgroup_charge_skmem) mem_cgroup_charge_skmem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mem_cgroup_charge_skmem);
extern typeof(mem_cgroup_uncharge_skmem) mem_cgroup_uncharge_skmem
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, mem_cgroup_uncharge_skmem);
extern typeof(reuseport_update_incoming_cpu) reuseport_update_incoming_cpu
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, reuseport_update_incoming_cpu);
extern typeof(sk_attach_bpf) sk_attach_bpf
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sk_attach_bpf);
extern typeof(sk_reuseport_attach_bpf) sk_reuseport_attach_bpf
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sk_reuseport_attach_bpf);
extern typeof(sk_reuseport_attach_filter) sk_reuseport_attach_filter
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sk_reuseport_attach_filter);
extern typeof(sock_bindtoindex_locked) sock_bindtoindex_locked
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_bindtoindex_locked);
extern typeof(sock_set_timeout) sock_set_timeout
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_set_timeout);
extern typeof(sock_set_timestamp) sock_set_timestamp
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_set_timestamp);
extern typeof(sock_set_timestamping) sock_set_timestamping
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, sock_set_timestamping);
