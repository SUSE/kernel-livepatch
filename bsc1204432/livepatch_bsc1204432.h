#ifndef _LIVEPATCH_BSC1204432_H
#define _LIVEPATCH_BSC1204432_H

#if IS_ENABLED(CONFIG_MISDN_L1OIP)

int
klpp_l1oip_socket_thread(void *data);

struct work_struct;
void
klpp_l1oip_send_bh(struct work_struct *work);

struct mISDNchannel;
struct sk_buff;
int
klpp_handle_dmsg(struct mISDNchannel *ch, struct sk_buff *skb);
int
klpp_handle_bmsg(struct mISDNchannel *ch, struct sk_buff *skb);

void
klpp_l1oip_cleanup(void);

int livepatch_bsc1204432_init(void);
void livepatch_bsc1204432_cleanup(void);

#else
int livepatch_bsc1204432_init(void) { return 0; }
void livepatch_bsc1204432_cleanup(void) {}


#endif /* IS_ENABLED(CONFIG_MISDN_L1OIP) */

#endif /* _LIVEPATCH_BSC1204432_H */
