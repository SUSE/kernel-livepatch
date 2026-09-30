#ifndef _LIVEPATCH_BSC1272391_H
#define _LIVEPATCH_BSC1272391_H

#include <linux/types.h>

static inline int livepatch_bsc1272391_init(void) { return 0; }
static inline void livepatch_bsc1272391_cleanup(void) {}

struct iscsit_conn;

void klpp_iscsit_get_rx_pdu(struct iscsit_conn *conn);

#endif /* _LIVEPATCH_BSC1272391_H */
