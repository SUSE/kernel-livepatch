#ifndef _BSC1226324_sock_h
#define _BSC1226324_sock_h

void klpp_ipv4_negative_advice(struct sock *sk,
			       struct dst_entry *dst);
void klpp_ip6_negative_advice(struct sock *sk,
			      struct dst_entry *dst);
void klpp_xfrm_negative_advice(struct sock *sk,
			       struct dst_entry *dst);

void ipv4_negative_advice(struct dst_entry *dst);
void ip6_negative_advice(struct dst_entry *dst);
void xfrm_negative_advice(struct dst_entry *dst);

static inline void klpp___dst_negative_advice(struct sock *sk);
static inline void klpp_dst_negative_advice(struct sock *sk);

static inline void klpp___dst_negative_advice(struct sock *sk)
{
	struct dst_entry *dst = __sk_dst_get(sk);
	void *orig;

	if (!dst || !dst->ops->negative_advice)
		return;

	orig = dst->ops->negative_advice;

	if (orig == ipv4_negative_advice) {
		klpp_ipv4_negative_advice(sk, dst);
	} else if (orig == ip6_negative_advice) {
		klpp_ip6_negative_advice(sk, dst);
	} else if (orig == xfrm_negative_advice) {
		klpp_xfrm_negative_advice(sk, dst);
	} else {
		struct dst_entry *ndst;

		ndst = dst->ops->negative_advice(dst);

		if (ndst != dst) {
			rcu_assign_pointer(sk->sk_dst_cache, ndst);
			sk_tx_queue_clear(sk);
			sk->sk_dst_pending_confirm = 0;
		}
	}
}

static inline void klpp_dst_negative_advice(struct sock *sk)
{
	sk_rethink_txhash(sk);
	klpp___dst_negative_advice(sk);
}

#include <linux/livepatch.h>
extern typeof(ipv4_negative_advice) ipv4_negative_advice
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ipv4_negative_advice);
extern typeof(ip6_negative_advice) ip6_negative_advice
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, ip6_negative_advice);
extern typeof(xfrm_negative_advice) xfrm_negative_advice
	 KLP_RELOC_SYMBOL(vmlinux, vmlinux, xfrm_negative_advice);

#endif /* _BSC1226324_SOCK_H */
