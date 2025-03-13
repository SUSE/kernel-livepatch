#ifndef _LIVEPATCH_BSC1229640_H
#define _LIVEPATCH_BSC1229640_H

#include <linux/types.h>

int livepatch_bsc1229640_init(void);
void livepatch_bsc1229640_cleanup(void);

int bsc1229640_net_netfilter_nfnetlink_queue_init(void);
void bsc1229640_net_netfilter_nfnetlink_queue_cleanup(void);

struct nf_hook_entry;
struct nf_queue_entry;
struct nf_hook_state;
struct sk_buff;
bool klpp_nf_queue_entry_get_refs(struct nf_queue_entry *entry);
int klpp_nf_queue(struct sk_buff *skb, struct nf_hook_state *state,
	     struct nf_hook_entry **entryp, unsigned int verdict);
int klpp_nfqnl_enqueue_packet(struct nf_queue_entry *entry,
		              unsigned int queuenum);

#endif /* _LIVEPATCH_BSC1229640_H */
