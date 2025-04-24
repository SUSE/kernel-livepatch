#ifndef _LIVEPATCH_BSC1235008_H
#define _LIVEPATCH_BSC1235008_H

static inline int livepatch_bsc1235008_init(void) { return 0; }
static inline void livepatch_bsc1235008_cleanup(void) {}
void klpp_hci_conn_del_sysfs(struct hci_conn *conn);

#endif /* _LIVEPATCH_BSC1235008_H */
