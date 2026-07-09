#ifndef _LIVEPATCH_BSC1269495_H
#define _LIVEPATCH_BSC1269495_H

#include <linux/types.h>

static inline int livepatch_bsc1269495_init(void) { return 0; }
static inline void livepatch_bsc1269495_cleanup(void) {}

struct flowi6;
struct inet_cork_full;
struct ipcm6_cookie;
struct rt6_info;
struct sk_buff;
struct sock;

int klpp_ip6_append_data(struct sock *sk, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, size_t length, int transhdrlen, struct ipcm6_cookie *ipc6, struct flowi6 *fl6, struct rt6_info *rt, unsigned int flags);
struct sk_buff *klpp_ip6_make_skb(struct sock *sk, int getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb), void *from, size_t length, int transhdrlen, struct ipcm6_cookie *ipc6, struct rt6_info *rt, unsigned int flags, struct inet_cork_full *cork);

#endif /* _LIVEPATCH_BSC1269495_H */
