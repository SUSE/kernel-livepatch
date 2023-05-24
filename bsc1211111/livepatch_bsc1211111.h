#ifndef _LIVEPATCH_BSC1211111_H
#define _LIVEPATCH_BSC1211111_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1211111_init(void);
void livepatch_bsc1211111_cleanup(void);

struct hci_conn;

void klpp_hci_conn_cleanup(struct hci_conn *conn);

#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1211111_init(void) { return 0; }
static inline void livepatch_bsc1211111_cleanup(void) {}

#endif /* IS_ENABLED(CONFIG_BT) */

#endif /* _LIVEPATCH_BSC1211111_H */
