#ifndef _LIVEPATCH_BSC1272386_H
#define _LIVEPATCH_BSC1272386_H

#include <linux/types.h>

int livepatch_bsc1272386_init(void);
void livepatch_bsc1272386_cleanup(void);

int bsc1272386_drivers_target_iscsi_iscsi_target_nego_init(void);
void bsc1272386_drivers_target_iscsi_iscsi_target_nego_cleanup(void);

int bsc1272386_drivers_target_iscsi_iscsi_target_parameters_init(void);
void bsc1272386_drivers_target_iscsi_iscsi_target_parameters_cleanup(void);


struct iscsi_conn;
struct iscsi_login;
struct iscsi_param_list;

int klpp_iscsi_encode_text_output( u8 phase, u8 sender, char *textbuf, u32 *length, u32 textbuf_size, struct iscsi_param_list *param_list, bool keys_workaround);
int klpp_iscsi_target_do_login(struct iscsi_conn *conn, struct iscsi_login *login);
#endif /* _LIVEPATCH_BSC1272386_H */
