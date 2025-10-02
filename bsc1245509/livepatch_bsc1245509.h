#ifndef _LIVEPATCH_BSC1245509_H
#define _LIVEPATCH_BSC1245509_H

static inline int livepatch_bsc1245509_init(void) { return 0; }
static inline void livepatch_bsc1245509_cleanup(void) {}

int klpp_svc_process_common(struct svc_rqst *rqstp);

#endif /* _LIVEPATCH_BSC1245509_H */
