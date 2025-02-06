#ifndef _LIVEPATCH_BSC1231993_H
#define _LIVEPATCH_BSC1231993_H

#include <net/tcp.h>

/* klp-ccp: from include/net/tcp.h */
static inline s64 klpp_tcp_rto_delta_us(const struct sock *sk)
{
	const struct sk_buff *skb = tcp_rtx_queue_head(sk);
	u32 rto = inet_csk(sk)->icsk_rto;

	if (likely(skb)) {
		u64 rto_time_stamp_us = tcp_skb_timestamp_us(skb) + jiffies_to_usecs(rto);

		return rto_time_stamp_us - tcp_sk(sk)->tcp_mstamp;
	} else {
		WARN_ONCE(1,
			"rtx queue emtpy: "
			"out:%u sacked:%u lost:%u retrans:%u "
			"tlp_high_seq:%u sk_state:%u ca_state:%u "
			"advmss:%u mss_cache:%u pmtu:%u\n",
			tcp_sk(sk)->packets_out, tcp_sk(sk)->sacked_out,
			tcp_sk(sk)->lost_out, tcp_sk(sk)->retrans_out,
			tcp_sk(sk)->tlp_high_seq, sk->sk_state,
			inet_csk(sk)->icsk_ca_state,
			tcp_sk(sk)->advmss, tcp_sk(sk)->mss_cache,
			inet_csk(sk)->icsk_pmtu_cookie);
		return jiffies_to_usecs(rto);
	}

}

int livepatch_bsc1231993_init(void);
void livepatch_bsc1231993_cleanup(void);

struct sock;

void klpp_tcp_rearm_rto(struct sock *sk);
 bool klpp_tcp_schedule_loss_probe(struct sock *sk, bool advancing_rto);

#endif /* _LIVEPATCH_BSC1231993_H */
