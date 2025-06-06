#ifndef _LIVEPATCH_BSC1232929_H
#define _LIVEPATCH_BSC1232929_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1232929_init(void);
void livepatch_bsc1232929_cleanup(void);

struct sco_conn;

struct sock *sco_sock_hold(struct sco_conn *conn);

struct hci_conn;

void klpp_sco_conn_del(struct hci_conn *hcon, int err);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1232929_init(void) { return 0; }
static inline void livepatch_bsc1232929_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */

#endif /* _LIVEPATCH_BSC1232929_H */
