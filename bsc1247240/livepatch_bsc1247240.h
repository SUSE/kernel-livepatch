#ifndef _LIVEPATCH_BSC1247240_H
#define _LIVEPATCH_BSC1247240_H

int livepatch_bsc1247240_init(void);
void livepatch_bsc1247240_cleanup(void);

struct TCP_Server_Info;
struct smb_rqst;
struct crypto_aead;
int klpp_crypt_message(struct TCP_Server_Info *server, int num_rqst,
	      struct smb_rqst *rqst, int enc, struct crypto_aead *tfm);
#endif /* _LIVEPATCH_BSC1247240_H */
