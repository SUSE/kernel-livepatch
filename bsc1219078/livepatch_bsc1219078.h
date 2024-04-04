#ifndef _LIVEPATCH_BSC1219078_H
#define _LIVEPATCH_BSC1219078_H

int livepatch_bsc1219078_init(void);
void livepatch_bsc1219078_cleanup(void);

struct TCP_Server_Info;
struct mid_q_entry;

int
klpp_smb3_receive_transform(struct TCP_Server_Info *server,
		       struct mid_q_entry **mids, char **bufs, int *num_mids);

#endif /* _LIVEPATCH_BSC1219078_H */
