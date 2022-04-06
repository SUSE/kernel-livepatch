#ifndef _LIVEPATCH_BSC1197133_H
#define _LIVEPATCH_BSC1197133_H

struct xfrm_state;
struct sk_buff;
struct esp_info;

int klpp_esp_output_head(struct xfrm_state *x, struct sk_buff *skb,
			struct esp_info *esp);

int klpp_esp6_output_head(struct xfrm_state *x, struct sk_buff *skb,
			struct esp_info *esp);

int bsc1197133_esp4_init(void);
void bsc1197133_esp4_cleanup(void);

int bsc1197133_esp6_init(void);
void bsc1197133_esp6_cleanup(void);

int livepatch_bsc1197133_init(void);
void livepatch_bsc1197133_cleanup(void);

#endif /* _LIVEPATCH_BSC1197133_H */
