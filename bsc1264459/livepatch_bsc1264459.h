#ifndef _LIVEPATCH_BSC1264459_H
#define _LIVEPATCH_BSC1264459_H

#include <linux/types.h>

static inline int livepatch_bsc1264459_init(void) { return 0; }
static inline void livepatch_bsc1264459_cleanup(void) {}

struct flowi4;
struct flowi6;
struct inet_cork;
struct inet_cork_full;
struct ip_options;
struct ip_reply_arg;
struct ipcm6_cookie;
struct ipcm_cookie;
struct rt6_info;
struct rtable;
struct sk_buff;
struct sock;
struct xfrm_state;

int klpp_esp6_input(struct xfrm_state *x, struct sk_buff *skb);
int klpp_esp_input(struct xfrm_state *x, struct sk_buff *skb);
int klpp_ip6_append_data(struct sock *sk, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, size_t length, int transhdrlen, struct ipcm6_cookie *ipc6, struct flowi6 *fl6, struct rt6_info *rt, unsigned int flags);
int klpp_ip_append_data(struct sock *sk, struct flowi4 *fl4, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, int len, int protolen, struct ipcm_cookie *ipc, struct rtable **rt, unsigned int flags);
struct sk_buff *klpp_ip6_make_skb(struct sock *sk, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, size_t length, int transhdrlen, struct ipcm6_cookie *ipc6, struct rt6_info *rt, unsigned int flags, struct inet_cork_full *cork);
struct sk_buff *klpp_ip_make_skb(struct sock *sk, struct flowi4 *fl4, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, int length, int transhdrlen, struct ipcm_cookie *ipc, struct rtable **rtp, struct inet_cork *cork, unsigned int flags);
void klpp_ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb, const struct ip_options *sopt, __be32 daddr, __be32 saddr, const struct ip_reply_arg *arg, unsigned int len, u64 transmit_time, u32 txhash);

#endif /* _LIVEPATCH_BSC1264459_H */
