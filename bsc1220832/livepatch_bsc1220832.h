#ifndef _LIVEPATCH_BSC1220832_H
#define _LIVEPATCH_BSC1220832_H

#if IS_ENABLED(CONFIG_NFC)

int livepatch_bsc1220832_init(void);
void livepatch_bsc1220832_cleanup(void);

#include <linux/types.h>

struct nfc_llcp_local;
struct nfc_llcp_sock;

u8 klpp_nfc_llcp_get_sdp_ssap(struct nfc_llcp_local *local,
			 struct nfc_llcp_sock *sock);

void klpp_nfc_llcp_rx_skb(struct nfc_llcp_local *local, struct sk_buff *skb);

struct nfc_llcp_sock *klpp_nfc_llcp_sock_get(struct nfc_llcp_local *local,
					       u8 ssap, u8 dsap);

#else /* !IS_ENABLED(CONFIG_NFC) */

static inline int livepatch_bsc1220832_init(void) { return 0; }
static inline void livepatch_bsc1220832_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_NFC) */

#endif /* _LIVEPATCH_BSC1220832_H */
