#ifndef _LIVEPATCH_BSC1210779_H
#define _LIVEPATCH_BSC1210779_H

struct tipc_link;
struct sk_buff_head;
struct sk_buff_head;

int klpp_tipc_link_xmit(struct tipc_link *l, struct sk_buff_head *list,
		   struct sk_buff_head *xmitq);

int livepatch_bsc1210779_init(void);
void livepatch_bsc1210779_cleanup(void);

#endif /* _LIVEPATCH_BSC1210779_H */
