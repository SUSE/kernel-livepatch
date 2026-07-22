#ifndef _LIVEPATCH_BSC1271370_H
#define _LIVEPATCH_BSC1271370_H

#include <linux/types.h>

static inline int livepatch_bsc1271370_init(void) { return 0; }
static inline void livepatch_bsc1271370_cleanup(void) {}

struct flowi4;
struct inet_cork;
struct ip_options;
struct ip_reply_arg;
struct ipcm_cookie;
struct rtable;
struct sk_buff;
struct sock;

int klpp_ip_append_data(struct sock *sk, struct flowi4 *fl4, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, int len, int protolen, struct ipcm_cookie *ipc, struct rtable **rt, unsigned int flags);
struct sk_buff *klpp_ip_make_skb(struct sock *sk, struct flowi4 *fl4, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, int length, int transhdrlen, struct ipcm_cookie *ipc, struct rtable **rtp, struct inet_cork *cork, unsigned int flags);
void klpp_ip_send_unicast_reply(struct sock *sk, struct sk_buff *skb, const struct ip_options *sopt, __be32 daddr, __be32 saddr, const struct ip_reply_arg *arg, unsigned int len, u64 transmit_time, u32 txhash);

#endif /* _LIVEPATCH_BSC1271370_H */
