#ifndef _LIVEPATCH_BSC1234847_H
#define _LIVEPATCH_BSC1234847_H

static inline int livepatch_bsc1234847_init(void) { return 0; }
static inline void livepatch_bsc1234847_cleanup(void) {}

struct htc_target;
struct htc_service_connreq;
enum htc_endpoint_id;

int klpp_htc_connect_service(struct htc_target *target,
		     struct htc_service_connreq *service_connreq,
		     enum htc_endpoint_id *conn_rsp_epid);

#endif /* _LIVEPATCH_BSC1234847_H */
