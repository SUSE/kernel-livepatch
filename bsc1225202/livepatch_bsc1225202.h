#ifndef _LIVEPATCH_BSC1225202_H
#define _LIVEPATCH_BSC1225202_H


int livepatch_bsc1225202_init(void);
void livepatch_bsc1225202_cleanup(void);

struct nvme_rdma_queue;

void klpp_nvme_rdma_free_queue(struct nvme_rdma_queue *queue);

struct rdma_cm_id;
struct rdma_cm_event;

int klpp_nvme_rdma_cm_handler(struct rdma_cm_id *cm_id,
		struct rdma_cm_event *ev);

#endif /* _LIVEPATCH_BSC1225202_H */
