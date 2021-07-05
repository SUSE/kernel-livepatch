#ifndef _LIVEPATCH_BSC1187687_H
#define _LIVEPATCH_BSC1187687_H

struct sock;
struct sk_buff;
struct sadb_msg;

int klpp_pfkey_dump(struct sock *sk, struct sk_buff *skb, const struct sadb_msg *hdr, void * const *ext_hdrs);


#if IS_MODULE(CONFIG_NET_KEY)

int livepatch_bsc1187687_init(void);
void livepatch_bsc1187687_cleanup(void);

#else /* !IS_MODULE(CONFIG_NET_KEY) */

int livepatch_bsc1187687_init(void);
static inline void livepatch_bsc1187687_cleanup(void) {}

#endif /* IS_MODULE(CONFIG_NET_KEY) */
#endif /* _LIVEPATCH_BSC1187687_H */
