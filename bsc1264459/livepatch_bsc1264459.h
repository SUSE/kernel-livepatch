#ifndef _LIVEPATCH_BSC1264459_H
#define _LIVEPATCH_BSC1264459_H

#include <linux/types.h>

int livepatch_bsc1264459_init(void);
void livepatch_bsc1264459_cleanup(void);

int bsc1264459_net_ipv4_ip_output_init(void);
static inline void bsc1264459_net_ipv4_ip_output_cleanup(void) {}

int bsc1264459_net_ipv4_esp4_init(void);
void bsc1264459_net_ipv4_esp4_cleanup(void);

int bsc1264459_net_ipv6_esp6_init(void);
void bsc1264459_net_ipv6_esp6_cleanup(void);


struct flowi4;
struct page;
struct sk_buff;
struct sock;
struct xfrm_state;

int klpp_esp6_input(struct xfrm_state *x, struct sk_buff *skb);
int klpp_esp_input(struct xfrm_state *x, struct sk_buff *skb);
ssize_t klpp_ip_append_page(struct sock *sk, struct flowi4 *fl4, struct page *page, int offset, size_t size, int flags);
#endif /* _LIVEPATCH_BSC1264459_H */
