#ifndef _LIVEPATCH_BSC1246001_H
#define _LIVEPATCH_BSC1246001_H

int livepatch_bsc1246001_init(void);
static inline void livepatch_bsc1246001_cleanup(void) {}

struct request_sock;
struct calipso_doi;
struct netlbl_lsm_secattr;

int klpp_calipso_req_setattr(struct request_sock *req,
			       const struct calipso_doi *doi_def,
			       const struct netlbl_lsm_secattr *secattr);


void klpp_calipso_req_delattr(struct request_sock *req);

#endif /* _LIVEPATCH_BSC1246001_H */
