#ifndef _LIVEPATCH_BSC1210630_H
#define _LIVEPATCH_BSC1210630_H

struct rdma_cm_id;
struct sockaddr;

int klpp_rdma_bind_addr(struct rdma_cm_id *id, struct sockaddr *addr);
int klpp_rdma_listen(struct rdma_cm_id *id, int backlog);
int klpp_rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
		      const struct sockaddr *dst_addr, unsigned long timeout_ms);

int livepatch_bsc1210630_init(void);
void livepatch_bsc1210630_cleanup(void);


#endif /* _LIVEPATCH_BSC1210630_H */
