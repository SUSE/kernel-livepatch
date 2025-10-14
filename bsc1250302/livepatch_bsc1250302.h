#ifndef _LIVEPATCH_BSC1250302_H
#define _LIVEPATCH_BSC1250302_H

#if IS_ENABLED(CONFIG_BT)

int livepatch_bsc1250302_init(void);
void livepatch_bsc1250302_cleanup(void);

struct l2cap_conn;
struct l2cap_cmd_hdr;
int klpp_l2cap_connect_create_rsp(struct l2cap_conn *conn,
				    struct l2cap_cmd_hdr *cmd, u16 cmd_len,
				    u8 *data);
#else /* !IS_ENABLED(CONFIG_BT) */

static inline int livepatch_bsc1250302_init(void) { return 0; }
static inline void livepatch_bsc1250302_cleanup(void) {}
#endif /* IS_ENABLED(CONFIG_BT) */

#endif /* _LIVEPATCH_BSC1250302_H */
