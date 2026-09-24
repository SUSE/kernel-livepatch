#ifndef _LIVEPATCH_BSC1272391_H
#define _LIVEPATCH_BSC1272391_H

#include <linux/types.h>

int livepatch_bsc1272391_init(void);
void livepatch_bsc1272391_cleanup(void);


struct iscsi_cmd;
struct iscsi_conn;

int klpp_iscsit_handle_text_cmd(struct iscsi_conn *conn, struct iscsi_cmd *cmd, unsigned char *buf);
#endif /* _LIVEPATCH_BSC1272391_H */
